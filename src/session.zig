//! HTTP/3 session layer over `nullq.Connection`.
//!
//! The session owns HTTP/3 stream classification, control stream
//! SETTINGS, message framing, and request/response convenience APIs.
//! It intentionally keeps QPACK in the static/literal profile exposed
//! by `qpack/root.zig`; dynamic-table encoder/decoder streams can be
//! opened for protocol completeness, but their instructions are not
//! interpreted yet.

const std = @import("std");
const nullq = @import("nullq");

const errors_mod = @import("errors.zig");
const frame_mod = @import("frame.zig");
const message_mod = @import("message.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const settings_mod = @import("settings.zig");
const stream_mod = @import("stream.zig");

const varint = nullq.wire.varint;

pub const Error = nullq.conn.state.Error ||
    frame_mod.Error ||
    message_mod.Error ||
    stream_mod.FrameValidationError ||
    settings_mod.Error ||
    qpack.Error ||
    varint.Error ||
    std.mem.Allocator.Error ||
    error{
        CriticalStreamAlreadyOpen,
        QpackStreamsAlreadyOpen,
        InvalidRole,
        WriteStalled,
        UnexpectedStream,
        MissingStream,
        WrongMessageKind,
        ClosedCriticalStream,
        InvalidGoawayId,
        RequestBlockedByGoaway,
    };

pub const Config = struct {
    settings: settings_mod.Settings = .{},
    /// Literal-only QPACK does not require encoder/decoder streams.
    /// Turn this on for peers or tests that expect the critical
    /// QPACK unidirectional streams to exist.
    open_qpack_streams: bool = false,
    max_field_section_size: ?usize = null,
    read_chunk_size: usize = 4096,
    max_data_frame_payload: usize = 16 * 1024,
};

pub const FieldEvent = struct {
    stream_id: u64,
    kind: message_mod.Kind,
    fields: []qpack.FieldLine,
};

pub const DataEvent = struct {
    stream_id: u64,
    kind: message_mod.Kind,
    data: []u8,
};

pub const PushPromiseEvent = struct {
    stream_id: u64,
    push_id: u64,
    field_section: []u8,
};

pub const StreamFinishedEvent = struct {
    stream_id: u64,
    kind: ?message_mod.Kind = null,
};

pub const StreamResetEvent = struct {
    stream_id: u64,
    kind: ?message_mod.Kind = null,
    error_code: u64,
    final_size: u64,

    pub fn errorInfo(self: StreamResetEvent) errors_mod.StreamError {
        return errors_mod.peerStreamError(self.stream_id, self.error_code, self.final_size);
    }
};

pub const RequestRejectedEvent = struct {
    stream_id: u64,
    error_code: u64,

    pub fn errorInfo(self: RequestRejectedEvent) errors_mod.StreamError {
        return errors_mod.localStreamError(self.stream_id, self.error_code, null);
    }
};

pub const UnknownFrameEvent = struct {
    stream_id: u64,
    frame_type: u64,
};

pub const ShutdownState = enum {
    active,
    draining,
    closed,
};

pub const Event = union(enum) {
    peer_settings: settings_mod.Settings,
    headers: FieldEvent,
    data: DataEvent,
    trailers: FieldEvent,
    push_promise: PushPromiseEvent,
    goaway: u64,
    stream_finished: StreamFinishedEvent,
    stream_reset: StreamResetEvent,
    request_rejected: RequestRejectedEvent,
    ignored_unknown_frame: UnknownFrameEvent,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .headers => |event| freeFields(allocator, event.fields),
            .trailers => |event| freeFields(allocator, event.fields),
            .data => |event| allocator.free(event.data),
            .push_promise => |event| allocator.free(event.field_section),
            else => {},
        }
    }
};

const StreamState = struct {
    id: u64,
    rx: std.ArrayList(u8) = .empty,
    uni_kind: ?stream_mod.Kind = null,
    push_id: ?u64 = null,
    control_validator: ?stream_mod.FrameValidator = null,
    message_decoder: ?message_mod.Decoder = null,
    message_encoder: ?message_mod.Encoder = null,
    recv_finished: bool = false,
    recv_reset_seen: bool = false,
    locally_rejected: bool = false,

    fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.rx.deinit(allocator);
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    role: protocol.Role,
    quic: *nullq.Connection,
    config: Config = .{},
    local_settings: settings_mod.Settings = .{},
    peer_settings: ?settings_mod.Settings = null,

    control_stream_id: ?u64 = null,
    qpack_encoder_stream_id: ?u64 = null,
    qpack_decoder_stream_id: ?u64 = null,
    peer_control_stream_id: ?u64 = null,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,
    sent_goaway_id: ?u64 = null,
    peer_goaway_id: ?u64 = null,
    shutdown_state: ShutdownState = .active,
    last_close_error: ?errors_mod.ConnectionError = null,

    streams: std.AutoHashMapUnmanaged(u64, *StreamState) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        role: protocol.Role,
        quic: *nullq.Connection,
        config: Config,
    ) Session {
        return .{
            .allocator = allocator,
            .role = role,
            .quic = quic,
            .config = config,
            .local_settings = config.settings,
        };
    }

    pub fn deinit(self: *Session) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            state.deinit(self.allocator);
            self.allocator.destroy(state);
        }
        self.streams.deinit(self.allocator);
    }

    pub fn start(self: *Session) Error!void {
        if (self.control_stream_id == null) try self.openControlStream();
        if (self.config.open_qpack_streams and
            (self.qpack_encoder_stream_id == null or self.qpack_decoder_stream_id == null))
        {
            try self.openQpackStreams();
        }
    }

    pub fn openRequest(self: *Session, fields: []const qpack.FieldLine) Error!u64 {
        if (self.role != .client) return Error.InvalidRole;
        try self.start();

        const id = self.nextLocalBidiId(0);
        if (!self.peerAllowsRequest(id)) return Error.RequestBlockedByGoaway;

        _ = try self.quic.openBidi(id);
        const state = try self.ensureMessageState(id, .response, .request);
        const encoder = try self.ensureEncoder(state, .request);
        try self.writeHeadersWithEncoder(id, encoder, fields);
        return id;
    }

    pub fn sendRequestData(self: *Session, stream_id: u64, data: []const u8) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        const state = try self.getState(stream_id);
        const encoder = try self.ensureEncoder(state, .request);
        try self.writeDataWithEncoder(stream_id, encoder, data);
    }

    pub fn sendRequestTrailers(self: *Session, stream_id: u64, fields: []const qpack.FieldLine) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        const state = try self.getState(stream_id);
        const encoder = try self.ensureEncoder(state, .request);
        try self.writeTrailersWithEncoder(stream_id, encoder, fields);
    }

    pub fn sendResponseHeaders(self: *Session, stream_id: u64, fields: []const qpack.FieldLine) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.start();

        const state = try self.ensureMessageState(stream_id, .request, .response);
        const encoder = try self.ensureEncoder(state, .response);
        try self.writeHeadersWithEncoder(stream_id, encoder, fields);
    }

    pub fn sendResponseData(self: *Session, stream_id: u64, data: []const u8) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        const state = try self.ensureMessageState(stream_id, .request, .response);
        const encoder = try self.ensureEncoder(state, .response);
        try self.writeDataWithEncoder(stream_id, encoder, data);
    }

    pub fn sendResponseTrailers(self: *Session, stream_id: u64, fields: []const qpack.FieldLine) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        const state = try self.ensureMessageState(stream_id, .request, .response);
        const encoder = try self.ensureEncoder(state, .response);
        try self.writeTrailersWithEncoder(stream_id, encoder, fields);
    }

    pub fn finishStream(self: *Session, stream_id: u64) Error!void {
        try self.quic.streamFinish(stream_id);
    }

    pub fn sendGoaway(self: *Session, id: u64) Error!void {
        try self.validateLocalGoawayId(id);
        if (self.sent_goaway_id) |previous| {
            if (id > previous) return Error.InvalidGoawayId;
        }

        try self.start();
        try self.writeControlFrame(.{ .goaway = id });
        self.sent_goaway_id = id;
        self.enterDraining();
    }

    pub fn stopSending(self: *Session, stream_id: u64, application_error_code: u64) Error!void {
        try self.quic.streamStopSending(stream_id, application_error_code);
    }

    pub fn rejectRequest(self: *Session, stream_id: u64) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.stopSending(stream_id, protocol.ErrorCode.request_rejected);
    }

    pub fn cancelRequest(self: *Session, stream_id: u64) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.stopSending(stream_id, protocol.ErrorCode.request_cancelled);
    }

    pub fn shutdownState(self: *const Session) ShutdownState {
        return self.shutdown_state;
    }

    pub fn lastCloseError(self: *const Session) ?errors_mod.ConnectionError {
        return self.last_close_error;
    }

    pub fn close(self: *Session, error_code: u64, reason: []const u8) void {
        self.shutdown_state = .closed;
        self.last_close_error = errors_mod.localConnectionCode(error_code);
        self.quic.close(false, error_code, reason);
    }

    pub fn drain(self: *Session, events: *std.ArrayList(Event)) Error!void {
        const read_chunk_size = if (self.config.read_chunk_size == 0) 4096 else self.config.read_chunk_size;
        const tmp = try self.allocator.alloc(u8, read_chunk_size);
        defer self.allocator.free(tmp);

        var it = self.quic.streamIterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (self.shouldSkipStream(stream_id)) continue;

            const state = self.ensureIncomingState(stream_id) catch |err| {
                self.closeForError(err);
                return err;
            };

            if (self.shouldRejectIncomingRequest(stream_id)) {
                try self.rejectIncomingRequest(state, tmp, events);
                continue;
            }

            if (entry.value_ptr.*.recv.reset) |reset| {
                try self.observeReset(state, reset.error_code, reset.final_size, events);
                entry.value_ptr.*.recv.markRead();
                continue;
            }

            while (true) {
                const n = try self.quic.streamRead(stream_id, tmp);
                if (n == 0) break;
                try state.rx.appendSlice(self.allocator, tmp[0..n]);
            }

            self.processState(state, events) catch |err| {
                self.closeForError(err);
                return err;
            };
            self.observeFin(state, entry.value_ptr.*.recv.fin_seen, events) catch |err| {
                self.closeForError(err);
                return err;
            };
        }
    }

    fn openControlStream(self: *Session) Error!void {
        const id = self.nextLocalUniId(0);
        _ = try self.quic.openUni(id);
        try self.writeStreamType(id, protocol.StreamType.control);
        self.control_stream_id = id;
        errdefer self.control_stream_id = null;

        try self.writeControlFrame(.{ .settings = self.local_settings });
    }

    fn openQpackStreams(self: *Session) Error!void {
        if (self.qpack_encoder_stream_id != null or self.qpack_decoder_stream_id != null) {
            return Error.QpackStreamsAlreadyOpen;
        }

        const enc_id = self.nextLocalUniId(0);
        _ = try self.quic.openUni(enc_id);
        try self.writeStreamType(enc_id, protocol.StreamType.qpack_encoder);

        const dec_id = self.nextLocalUniId(enc_id + 4);
        _ = try self.quic.openUni(dec_id);
        try self.writeStreamType(dec_id, protocol.StreamType.qpack_decoder);

        self.qpack_encoder_stream_id = enc_id;
        self.qpack_decoder_stream_id = dec_id;
    }

    fn processState(self: *Session, state: *StreamState, events: *std.ArrayList(Event)) Error!void {
        if (stream_mod.isUnidirectional(state.id)) {
            try self.processUniState(state, events);
        } else {
            try self.processMessageState(state, events);
        }
    }

    fn processUniState(self: *Session, state: *StreamState, events: *std.ArrayList(Event)) Error!void {
        if (state.uni_kind == null) {
            const decoded = stream_mod.decodeType(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };
            try self.registerPeerUniStream(state.id, decoded.kind);
            state.uni_kind = decoded.kind;
            try compactRx(state, decoded.bytes_read);
        }

        switch (state.uni_kind.?) {
            .control => try self.processControlState(state, events),
            .qpack_encoder, .qpack_decoder, .unknown => state.rx.clearRetainingCapacity(),
            .push => try self.processPushState(state, events),
        }
    }

    fn processControlState(self: *Session, state: *StreamState, events: *std.ArrayList(Event)) Error!void {
        while (state.rx.items.len > 0) {
            const decoded = frame_mod.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };

            const frame_type = frame_mod.frameType(decoded.frame);
            state.control_validator.?.observe(frame_type) catch |err| {
                self.closeForError(err);
                return err;
            };

            switch (decoded.frame) {
                .settings => |peer| {
                    self.peer_settings = peer;
                    try appendEvent(self.allocator, events, .{ .peer_settings = peer });
                },
                .goaway => |id| {
                    try self.observeGoaway(id);
                    try appendEvent(self.allocator, events, .{ .goaway = id });
                },
                .unknown => |unknown| try appendEvent(self.allocator, events, .{
                    .ignored_unknown_frame = .{
                        .stream_id = state.id,
                        .frame_type = unknown.frame_type,
                    },
                }),
                else => {},
            }

            try compactRx(state, decoded.bytes_read);
        }
    }

    fn processPushState(self: *Session, state: *StreamState, events: *std.ArrayList(Event)) Error!void {
        if (self.role != .client) {
            self.closeForError(Error.UnexpectedStream);
            return Error.UnexpectedStream;
        }

        if (state.push_id == null) {
            const decoded = varint.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };
            state.push_id = decoded.value;
            try compactRx(state, decoded.bytes_read);
            if (state.message_decoder == null) {
                state.message_decoder = message_mod.Decoder.init(.push, .{
                    .max_field_section_size = self.config.max_field_section_size,
                });
            }
        }

        try self.processMessageState(state, events);
    }

    fn processMessageState(self: *Session, state: *StreamState, events: *std.ArrayList(Event)) Error!void {
        const decoder = if (state.message_decoder) |*decoder| decoder else return Error.MissingStream;

        while (state.rx.items.len > 0) {
            const decoded = frame_mod.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };

            const maybe_event = decoder.observe(self.allocator, decoded.frame) catch |err| {
                self.closeForError(err);
                return err;
            };
            if (maybe_event) |message_event| {
                defer message_event.deinit(self.allocator);
                try self.appendMessageEvent(events, state.id, decoder.kind, message_event);
            }

            try compactRx(state, decoded.bytes_read);
        }
    }

    fn rejectIncomingRequest(
        self: *Session,
        state: *StreamState,
        scratch: []u8,
        events: *std.ArrayList(Event),
    ) Error!void {
        while (true) {
            const n = try self.quic.streamRead(state.id, scratch);
            if (n == 0) break;
        }

        state.rx.clearRetainingCapacity();
        if (state.locally_rejected) return;

        try self.rejectRequest(state.id);
        state.locally_rejected = true;
        state.recv_finished = true;
        try appendEvent(self.allocator, events, .{
            .request_rejected = .{
                .stream_id = state.id,
                .error_code = protocol.ErrorCode.request_rejected,
            },
        });
    }

    fn observeFin(
        self: *Session,
        state: *StreamState,
        fin_seen: bool,
        events: *std.ArrayList(Event),
    ) Error!void {
        if (!fin_seen or state.recv_finished) return;

        if (state.uni_kind) |kind| {
            switch (kind) {
                .control, .qpack_encoder, .qpack_decoder => {
                    self.closeForError(Error.ClosedCriticalStream);
                    return Error.ClosedCriticalStream;
                },
                else => {},
            }
        }

        const message_kind = if (state.message_decoder) |*decoder| blk: {
            decoder.finish() catch |err| {
                self.closeForError(err);
                return err;
            };
            break :blk decoder.kind;
        } else null;

        state.recv_finished = true;
        try appendEvent(self.allocator, events, .{
            .stream_finished = .{
                .stream_id = state.id,
                .kind = message_kind,
            },
        });
    }

    fn observeReset(
        self: *Session,
        state: *StreamState,
        error_code: u64,
        final_size: u64,
        events: *std.ArrayList(Event),
    ) Error!void {
        if (state.recv_reset_seen) return;
        state.rx.clearRetainingCapacity();
        state.recv_reset_seen = true;
        state.recv_finished = true;

        const kind: ?message_mod.Kind = if (state.message_decoder) |decoder|
            decoder.kind
        else if (!stream_mod.isUnidirectional(state.id))
            self.incomingMessageKind(state.id) catch null
        else
            null;

        try appendEvent(self.allocator, events, .{
            .stream_reset = .{
                .stream_id = state.id,
                .kind = kind,
                .error_code = error_code,
                .final_size = final_size,
            },
        });
    }

    fn appendMessageEvent(
        self: *Session,
        events: *std.ArrayList(Event),
        stream_id: u64,
        kind: message_mod.Kind,
        event: message_mod.Event,
    ) Error!void {
        const out: Event = switch (event) {
            .headers => |fields| .{ .headers = .{
                .stream_id = stream_id,
                .kind = kind,
                .fields = try cloneFields(self.allocator, fields),
            } },
            .trailers => |fields| .{ .trailers = .{
                .stream_id = stream_id,
                .kind = kind,
                .fields = try cloneFields(self.allocator, fields),
            } },
            .data => |bytes| .{ .data = .{
                .stream_id = stream_id,
                .kind = kind,
                .data = try self.allocator.dupe(u8, bytes),
            } },
            .push_promise => |promise| .{ .push_promise = .{
                .stream_id = stream_id,
                .push_id = promise.push_id,
                .field_section = try self.allocator.dupe(u8, promise.field_section),
            } },
            .ignored_unknown => |frame_type| .{ .ignored_unknown_frame = .{
                .stream_id = stream_id,
                .frame_type = frame_type,
            } },
        };
        try appendEvent(self.allocator, events, out);
    }

    fn ensureIncomingState(self: *Session, stream_id: u64) Error!*StreamState {
        if (self.streams.get(stream_id)) |state| return state;

        if (stream_mod.isUnidirectional(stream_id)) {
            return try self.createState(stream_id);
        }

        const decoder_kind = try self.incomingMessageKind(stream_id);
        const encoder_kind: message_mod.Kind = switch (decoder_kind) {
            .request => .response,
            .response => .request,
            .push => .response,
        };
        return try self.ensureMessageState(stream_id, decoder_kind, encoder_kind);
    }

    fn ensureMessageState(
        self: *Session,
        stream_id: u64,
        decoder_kind: message_mod.Kind,
        encoder_kind: message_mod.Kind,
    ) Error!*StreamState {
        const state = if (self.streams.get(stream_id)) |existing| existing else try self.createState(stream_id);

        if (state.message_decoder) |decoder| {
            if (decoder.kind != decoder_kind) return Error.WrongMessageKind;
        } else {
            state.message_decoder = message_mod.Decoder.init(decoder_kind, .{
                .max_field_section_size = self.config.max_field_section_size,
            });
        }

        _ = try self.ensureEncoder(state, encoder_kind);
        return state;
    }

    fn ensureEncoder(self: *Session, state: *StreamState, kind: message_mod.Kind) Error!*message_mod.Encoder {
        if (state.message_encoder) |*encoder| {
            if (encoder.kind != kind) return Error.WrongMessageKind;
            return encoder;
        }

        state.message_encoder = message_mod.Encoder.init(kind, .{
            .max_field_section_size = self.config.max_field_section_size,
        });
        if (state.message_encoder) |*encoder| return encoder;
        unreachable;
    }

    fn getState(self: *Session, stream_id: u64) Error!*StreamState {
        return self.streams.get(stream_id) orelse Error.MissingStream;
    }

    fn createState(self: *Session, stream_id: u64) Error!*StreamState {
        const state = try self.allocator.create(StreamState);
        errdefer self.allocator.destroy(state);
        state.* = .{ .id = stream_id };
        try self.streams.put(self.allocator, stream_id, state);
        return state;
    }

    fn registerPeerUniStream(self: *Session, stream_id: u64, kind: stream_mod.Kind) Error!void {
        switch (kind) {
            .control => {
                if (self.peer_control_stream_id != null and self.peer_control_stream_id.? != stream_id) {
                    return Error.CriticalStreamAlreadyOpen;
                }
                self.peer_control_stream_id = stream_id;
                if (self.streams.get(stream_id)) |state| {
                    state.control_validator = stream_mod.FrameValidator.init(.control);
                }
            },
            .qpack_encoder => {
                if (self.peer_qpack_encoder_stream_id != null and self.peer_qpack_encoder_stream_id.? != stream_id) {
                    return Error.CriticalStreamAlreadyOpen;
                }
                self.peer_qpack_encoder_stream_id = stream_id;
            },
            .qpack_decoder => {
                if (self.peer_qpack_decoder_stream_id != null and self.peer_qpack_decoder_stream_id.? != stream_id) {
                    return Error.CriticalStreamAlreadyOpen;
                }
                self.peer_qpack_decoder_stream_id = stream_id;
            },
            .push => {
                if (self.role != .client) return Error.UnexpectedStream;
            },
            .unknown => {},
        }
    }

    fn incomingMessageKind(self: *const Session, stream_id: u64) Error!message_mod.Kind {
        const client_initiated = stream_mod.isClientInitiated(stream_id);
        return switch (self.role) {
            .client => if (client_initiated) .response else Error.UnexpectedStream,
            .server => if (client_initiated) .request else Error.UnexpectedStream,
        };
    }

    fn shouldSkipStream(self: *const Session, stream_id: u64) bool {
        return stream_mod.isUnidirectional(stream_id) and self.isLocalInitiated(stream_id);
    }

    fn shouldRejectIncomingRequest(self: *const Session, stream_id: u64) bool {
        if (self.role != .server) return false;
        if (stream_mod.isUnidirectional(stream_id) or !stream_mod.isClientInitiated(stream_id)) return false;
        const limit = self.sent_goaway_id orelse return false;
        return stream_id >= limit;
    }

    fn peerAllowsRequest(self: *const Session, stream_id: u64) bool {
        const limit = self.peer_goaway_id orelse return true;
        return stream_id < limit;
    }

    fn isLocalInitiated(self: *const Session, stream_id: u64) bool {
        const client_initiated = stream_mod.isClientInitiated(stream_id);
        return switch (self.role) {
            .client => client_initiated,
            .server => !client_initiated,
        };
    }

    fn writeControlFrame(self: *Session, frame: frame_mod.Frame) Error!void {
        const stream_id = self.control_stream_id orelse return Error.MissingStream;
        const buf = try self.allocator.alloc(u8, frame_mod.encodedLen(frame));
        defer self.allocator.free(buf);
        const n = try frame_mod.encode(buf, frame);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeHeadersWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        const payload_len = qpack.fieldSectionEncodedLen(fields);
        const len = varint.encodedLen(protocol.FrameType.headers) + varint.encodedLen(payload_len) + payload_len;
        const buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = try encoder.encodeHeaders(buf, fields);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeDataWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        data: []const u8,
    ) Error!void {
        const chunk_size = if (self.config.max_data_frame_payload == 0)
            data.len
        else
            self.config.max_data_frame_payload;
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_size);
            const chunk = data[offset..end];
            const len = varint.encodedLen(protocol.FrameType.data) + varint.encodedLen(chunk.len) + chunk.len;
            const buf = try self.allocator.alloc(u8, len);
            defer self.allocator.free(buf);
            const n = try encoder.encodeData(buf, chunk);
            try self.writeAll(stream_id, buf[0..n]);
            offset = end;
        }
    }

    fn writeTrailersWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        const payload_len = qpack.fieldSectionEncodedLen(fields);
        const len = varint.encodedLen(protocol.FrameType.headers) + varint.encodedLen(payload_len) + payload_len;
        const buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = try encoder.encodeTrailers(buf, fields);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeStreamType(self: *Session, stream_id: u64, stream_type: u64) Error!void {
        var buf: [8]u8 = undefined;
        const n = try varint.encode(&buf, stream_type);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeAll(self: *Session, stream_id: u64, bytes: []const u8) Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = try self.quic.streamWrite(stream_id, rest);
            if (n == 0) return Error.WriteStalled;
            rest = rest[n..];
        }
    }

    fn nextLocalUniId(self: *const Session, first_id: u64) u64 {
        const low_bits: u64 = switch (self.role) {
            .client => 0b10,
            .server => 0b11,
        };
        var id = (first_id & ~@as(u64, 0b11)) | low_bits;
        while (self.quic.stream(id) != null) id += 4;
        return id;
    }

    fn nextLocalBidiId(self: *const Session, first_id: u64) u64 {
        const low_bits: u64 = switch (self.role) {
            .client => 0b00,
            .server => 0b01,
        };
        var id = (first_id & ~@as(u64, 0b11)) | low_bits;
        while (self.quic.stream(id) != null) id += 4;
        return id;
    }

    fn observeGoaway(self: *Session, id: u64) Error!void {
        try self.validatePeerGoawayId(id);
        if (self.peer_goaway_id) |previous| {
            if (id > previous) return Error.InvalidGoawayId;
        }
        self.peer_goaway_id = id;
        self.enterDraining();
    }

    fn enterDraining(self: *Session) void {
        if (self.shutdown_state == .active) self.shutdown_state = .draining;
    }

    fn validateLocalGoawayId(self: *const Session, id: u64) Error!void {
        switch (self.role) {
            .client => {},
            .server => try validateClientBidiStreamId(id),
        }
    }

    fn validatePeerGoawayId(self: *const Session, id: u64) Error!void {
        switch (self.role) {
            .client => try validateClientBidiStreamId(id),
            .server => {},
        }
    }

    fn closeForError(self: *Session, err: anyerror) void {
        const close_error = errors_mod.localConnectionError(err);
        self.shutdown_state = .closed;
        self.last_close_error = close_error;
        self.quic.close(false, close_error.application.code, close_error.reason());
    }
};

fn appendEvent(allocator: std.mem.Allocator, events: *std.ArrayList(Event), event: Event) Error!void {
    events.append(allocator, event) catch |err| {
        event.deinit(allocator);
        return err;
    };
}

fn validateClientBidiStreamId(id: u64) Error!void {
    if (stream_mod.isUnidirectional(id) or !stream_mod.isClientInitiated(id)) {
        return Error.InvalidGoawayId;
    }
}

fn compactRx(state: *StreamState, consumed: usize) Error!void {
    if (consumed == 0) return;
    if (consumed > state.rx.items.len) return Error.InvalidFramePayload;
    const remaining = state.rx.items.len - consumed;
    std.mem.copyForwards(u8, state.rx.items[0..remaining], state.rx.items[consumed..]);
    state.rx.shrinkRetainingCapacity(remaining);
}

fn cloneFields(allocator: std.mem.Allocator, fields: []const qpack.FieldLine) Error![]qpack.FieldLine {
    const out = try allocator.alloc(qpack.FieldLine, fields.len);
    var initialized: usize = 0;
    errdefer {
        freeFields(allocator, out[0..initialized]);
        allocator.free(out);
    }

    for (fields) |field| {
        const name = try allocator.dupe(u8, field.name);
        const value = allocator.dupe(u8, field.value) catch |err| {
            allocator.free(name);
            return err;
        };
        out[initialized] = .{
            .name = name,
            .value = value,
            .sensitive = field.sensitive,
        };
        initialized += 1;
    }

    return out;
}

fn freeFields(allocator: std.mem.Allocator, fields: []qpack.FieldLine) void {
    for (fields) |field| {
        allocator.free(@constCast(field.name));
        allocator.free(@constCast(field.value));
    }
    allocator.free(fields);
}

test "session emits deep-owned message events" {
    const allocator = std.testing.allocator;
    var client_quic: nullq.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{});
    defer session.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };

    const state = try session.ensureMessageState(0, .response, .request);
    var enc = message_mod.Encoder.init(.response, .{});
    var buf: [256]u8 = undefined;
    const n = try enc.encodeHeaders(&buf, &fields);
    try state.rx.appendSlice(allocator, buf[0..n]);

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    try session.processMessageState(state, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    switch (events.items[0]) {
        .headers => |event| {
            try std.testing.expectEqual(message_mod.Kind.response, event.kind);
            try std.testing.expectEqualStrings("200", event.fields[0].value);
        },
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(usize, 0), state.rx.items.len);
}

test "session validates GOAWAY stream ids by role" {
    var quic: nullq.Connection = undefined;
    var server_session = Session.init(std.testing.allocator, .server, &quic, .{});
    try server_session.validateLocalGoawayId(0);
    try server_session.validateLocalGoawayId(4);
    try std.testing.expectError(Error.InvalidGoawayId, server_session.validateLocalGoawayId(1));
    try std.testing.expectError(Error.InvalidGoawayId, server_session.validateLocalGoawayId(2));

    var client_session = Session.init(std.testing.allocator, .client, &quic, .{});
    try client_session.validateLocalGoawayId(1);
    try client_session.validatePeerGoawayId(0);
    try std.testing.expectError(Error.InvalidGoawayId, client_session.validatePeerGoawayId(3));

    try client_session.observeGoaway(8);
    try std.testing.expectEqual(ShutdownState.draining, client_session.shutdownState());
    try client_session.observeGoaway(4);
    try std.testing.expectError(Error.InvalidGoawayId, client_session.observeGoaway(8));
    try std.testing.expect(client_session.peerAllowsRequest(0));
    try std.testing.expect(!client_session.peerAllowsRequest(4));
}

test "session emits stream reset once" {
    const allocator = std.testing.allocator;
    var client_quic: nullq.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{});
    defer session.deinit();

    const state = try session.ensureMessageState(0, .response, .request);

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    try session.observeReset(state, protocol.ErrorCode.request_cancelled, 42, &events);
    try session.observeReset(state, protocol.ErrorCode.request_cancelled, 42, &events);

    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    switch (events.items[0]) {
        .stream_reset => |event| {
            try std.testing.expectEqual(@as(u64, 0), event.stream_id);
            try std.testing.expectEqual(message_mod.Kind.response, event.kind.?);
            try std.testing.expectEqual(protocol.ErrorCode.request_cancelled, event.error_code);
            try std.testing.expectEqual(@as(u64, 42), event.final_size);
            const info = event.errorInfo();
            try std.testing.expectEqual(errors_mod.Source.peer, info.source);
            try std.testing.expectEqual(errors_mod.Category.request, info.application.category);
            try std.testing.expectEqual(errors_mod.Scope.stream, info.application.default_scope);
        },
        else => return error.TestExpectedEqual,
    }
    try std.testing.expect(state.recv_finished);
}
