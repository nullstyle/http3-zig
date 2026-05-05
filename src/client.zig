//! HTTP/3 client-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const errors_mod = @import("errors.zig");
const masque_mod = @import("masque.zig");
const observability_mod = @import("observability.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");
const websocket_mod = @import("websocket.zig");

pub const TlsOptions = struct {
    verify: boringssl.tls.VerifyMode = .system,
    early_data_enabled: bool = false,
    keylog_callback: ?observability_mod.KeylogCallback = null,
};

pub fn initTlsContext(options: TlsOptions) boringssl.tls.Error!boringssl.tls.Context {
    var ctx = try boringssl.tls.Context.initClient(.{
        .verify = options.verify,
        .min_version = @intCast(boringssl.raw.TLS1_3_VERSION),
        .alpn = &protocol.alpn_protocols,
        .early_data_enabled = options.early_data_enabled,
    });
    errdefer ctx.deinit();
    if (options.keylog_callback) |callback| try ctx.setKeylogCallback(callback);
    return ctx;
}

pub const Headers = struct {
    stream_id: u64,
    fields: []qpack.FieldLine,
};

pub const Data = struct {
    stream_id: u64,
    bytes: []const u8,

    pub fn capsule(self: Data) capsule_mod.Error!capsule_mod.Decoded {
        return capsule_mod.decode(self.bytes);
    }

    pub fn capsuleIterator(self: Data) capsule_mod.Iterator {
        return capsule_mod.iter(self.bytes);
    }
};

pub const Datagram = struct {
    stream_id: u64,
    payload: []const u8,
    arrived_in_early_data: bool = false,

    pub fn context(self: Datagram) datagram_mod.Error!datagram_mod.ContextPayload {
        return datagram_mod.decodeContextPayload(self.payload);
    }

    pub fn masqueContext(self: Datagram, registry: *const masque_mod.ContextRegistry) masque_mod.Error!masque_mod.ContextPayload {
        return registry.decodeContextPayload(self.payload);
    }

    pub fn masqueDisposition(self: Datagram, registry: *const masque_mod.ContextRegistry) masque_mod.DatagramDisposition {
        return registry.classifyDatagramPayload(self.payload);
    }

    pub fn connectUdp(self: Datagram, receiver: *const masque_mod.ConnectUdpReceiver) masque_mod.ReceiveDisposition {
        return receiver.classifyDatagramPayload(self.payload);
    }

    pub fn udp(self: Datagram) masque_mod.Error![]const u8 {
        return masque_mod.decodeUdpPayload(self.payload);
    }
};

pub const StreamFinished = struct {
    stream_id: u64,
};

pub const StreamReset = struct {
    stream_id: u64,
    error_code: u64,
    final_size: u64,

    pub fn errorInfo(self: StreamReset) errors_mod.StreamError {
        return errors_mod.peerStreamError(self.stream_id, self.error_code, self.final_size);
    }
};

pub const UnknownFrame = session_mod.UnknownFrameEvent;
pub const ConnectionClosed = session_mod.ConnectionClosedEvent;
pub const DatagramSend = session_mod.DatagramSendEvent;
pub const FlowBlocked = session_mod.FlowBlockedEvent;
pub const ConnectionIdsNeeded = session_mod.ConnectionIdsNeededEvent;
pub const StreamSendState = session_mod.StreamSendState;

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    connect_protocol: ?[]const u8 = null,
    headers: []const qpack.FieldLine = &.{},
    body: ?[]const u8 = null,
    trailers: []const qpack.FieldLine = &.{},
    end_stream: bool = true,
};

pub const RequestHeadOptions = struct {
    method: []const u8 = "GET",
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    connect_protocol: ?[]const u8 = null,
    headers: []const qpack.FieldLine = &.{},
};

pub const Request = struct {
    stream_id: u64,
};

pub const RequestWriter = struct {
    client: *Client,
    stream_id: u64,

    pub fn write(self: *RequestWriter, data: []const u8) session_mod.Error!void {
        if (data.len > 0) try self.client.sendData(self.stream_id, data);
    }

    pub fn sendState(self: *const RequestWriter) session_mod.Error!StreamSendState {
        return try self.client.streamSendState(self.stream_id);
    }

    pub fn canBuffer(self: *const RequestWriter, additional_bytes: usize) session_mod.Error!bool {
        return try self.client.canBufferStreamBytes(self.stream_id, additional_bytes);
    }

    pub fn canWrite(self: *const RequestWriter, data_len: usize) session_mod.Error!bool {
        return try self.client.canSendData(self.stream_id, data_len);
    }

    pub fn datagram(self: *RequestWriter, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagram(self.stream_id, payload);
    }

    pub fn datagramTracked(self: *RequestWriter, payload: []const u8) session_mod.Error!u64 {
        return try self.client.sendDatagramTracked(self.stream_id, payload);
    }

    pub fn datagramWithContext(self: *RequestWriter, context_id: u64, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagramWithContext(self.stream_id, context_id, payload);
    }

    pub fn datagramWithContextTracked(
        self: *RequestWriter,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!u64 {
        return try self.client.sendDatagramWithContextTracked(self.stream_id, context_id, payload);
    }

    pub fn capsule(self: *RequestWriter, capsule_type: u64, value: []const u8) session_mod.Error!void {
        try self.client.sendCapsule(self.stream_id, capsule_type, value);
    }

    pub fn datagramCapsule(self: *RequestWriter, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagramCapsule(self.stream_id, payload);
    }

    pub fn datagramContextCapsule(
        self: *RequestWriter,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.client.sendDatagramContextCapsule(self.stream_id, context_id, payload);
    }

    pub fn trailers(self: *RequestWriter, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.client.sendTrailers(self.stream_id, fields);
    }

    pub fn finish(self: *RequestWriter) session_mod.Error!void {
        try self.client.finish(self.stream_id);
    }

    pub fn reset(self: *RequestWriter, error_code: u64) session_mod.Error!void {
        try self.client.reset(self.stream_id, error_code);
    }

    pub fn abort(self: *RequestWriter) session_mod.Error!void {
        try self.reset(protocol.ErrorCode.request_cancelled);
    }

    pub fn cancel(self: *RequestWriter) session_mod.Error!void {
        try self.client.cancel(self.stream_id);
    }
};

pub const ConnectUdpOptions = masque_mod.ConnectUdpOptions;

pub const ConnectUdpClientStream = struct {
    writer: RequestWriter,

    pub fn streamId(self: *const ConnectUdpClientStream) u64 {
        return self.writer.stream_id;
    }

    pub fn sendUdp(self: *ConnectUdpClientStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!void {
        try masque_mod.validateUdpPayload(payload);
        try self.writer.datagramWithContext(masque_mod.udp_context_id, payload);
    }

    pub fn sendUdpTracked(self: *ConnectUdpClientStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!u64 {
        try masque_mod.validateUdpPayload(payload);
        return try self.writer.datagramWithContextTracked(masque_mod.udp_context_id, payload);
    }

    pub fn sendUdpCapsule(self: *ConnectUdpClientStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!void {
        try masque_mod.validateUdpPayload(payload);
        try self.writer.datagramContextCapsule(masque_mod.udp_context_id, payload);
    }

    pub fn capsule(self: *ConnectUdpClientStream, capsule_type: u64, value: []const u8) session_mod.Error!void {
        try self.writer.capsule(capsule_type, value);
    }

    pub fn finishSend(self: *ConnectUdpClientStream) session_mod.Error!void {
        try self.writer.finish();
    }

    pub fn reset(self: *ConnectUdpClientStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn fail(self: *ConnectUdpClientStream) session_mod.Error!void {
        try self.reset(masque_mod.connect_udp_abort_code);
    }

    pub fn failForError(self: *ConnectUdpClientStream, err: anyerror) session_mod.Error!void {
        try self.reset(masque_mod.streamAbortForError(err).error_code);
    }

    pub fn abort(self: *ConnectUdpClientStream) session_mod.Error!void {
        try self.writer.abort();
    }

    pub fn requestWriter(self: *ConnectUdpClientStream) *RequestWriter {
        return &self.writer;
    }
};

pub const WebSocketConnectOptions = websocket_mod.ConnectOptions;

pub const WebSocketClientStream = struct {
    writer: RequestWriter,

    pub fn streamId(self: *const WebSocketClientStream) u64 {
        return self.writer.stream_id;
    }

    pub fn write(self: *WebSocketClientStream, bytes: []const u8) session_mod.Error!void {
        try self.writer.write(bytes);
    }

    pub fn writeFrameWithOptions(
        self: *WebSocketClientStream,
        frame: websocket_mod.frame.Frame,
        options: websocket_mod.frame.EncodeOptions,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        const allocator = self.writer.client.session.allocator;
        const len = try websocket_mod.frame.encodedLen(frame, options);
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        const n = try websocket_mod.frame.encode(buf, frame, options);
        try self.writer.write(buf[0..n]);
    }

    pub fn writeFrame(
        self: *WebSocketClientStream,
        frame: websocket_mod.frame.Frame,
        masking_key: [4]u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrameWithOptions(frame, .{
            .mask = true,
            .masking_key = masking_key,
        });
    }

    pub fn writeMessage(
        self: *WebSocketClientStream,
        kind: websocket_mod.message.Kind,
        payload: []const u8,
        masking_key: [4]u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrame(.{
            .opcode = websocket_mod.message.opcodeForKind(kind),
            .payload = payload,
        }, masking_key);
    }

    pub fn writeText(
        self: *WebSocketClientStream,
        payload: []const u8,
        masking_key: [4]u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeMessage(.text, payload, masking_key);
    }

    pub fn writeBinary(
        self: *WebSocketClientStream,
        payload: []const u8,
        masking_key: [4]u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeMessage(.binary, payload, masking_key);
    }

    pub fn writeClose(
        self: *WebSocketClientStream,
        code: ?u16,
        reason: []const u8,
        masking_key: [4]u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        const allocator = self.writer.client.session.allocator;
        var stack_buf: [131]u8 = undefined;
        const n = try websocket_mod.frame.encodeClose(&stack_buf, code, reason, .{
            .mask = true,
            .masking_key = masking_key,
        });
        const buf = try allocator.dupe(u8, stack_buf[0..n]);
        defer allocator.free(buf);
        try self.writer.write(buf);
    }

    pub fn finishSend(self: *WebSocketClientStream) session_mod.Error!void {
        try self.writer.finish();
    }

    pub fn reset(self: *WebSocketClientStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn abort(self: *WebSocketClientStream) session_mod.Error!void {
        try self.writer.abort();
    }

    pub fn requestWriter(self: *WebSocketClientStream) *RequestWriter {
        return &self.writer;
    }
};

pub const PushPromise = struct {
    push_id: u64,
    field_section: []u8,
    fields: []qpack.FieldLine,
};

pub const ResponseReader = struct {
    response: *const ResponseState,

    pub fn streamId(self: ResponseReader) u64 {
        return self.response.stream_id;
    }

    pub fn headers(self: ResponseReader) []const qpack.FieldLine {
        return self.response.headerFields();
    }

    pub fn trailers(self: ResponseReader) []const qpack.FieldLine {
        return self.response.trailerFields();
    }

    pub fn body(self: ResponseReader) []const u8 {
        return self.response.bodyBytes();
    }

    pub fn status(self: ResponseReader) ?[]const u8 {
        return self.response.status();
    }

    pub fn webSocketAccepted(self: ResponseReader) bool {
        return self.response.webSocketAccepted();
    }

    pub fn connectUdpAccepted(self: ResponseReader) bool {
        return self.response.connectUdpAccepted();
    }

    pub fn capsuleProtocolEnabled(self: ResponseReader) bool {
        return self.response.capsuleProtocolEnabled();
    }

    pub fn complete(self: ResponseReader) bool {
        return self.response.complete;
    }

    pub fn reset(self: ResponseReader) ?StreamReset {
        return self.response.reset;
    }

    pub fn pushPromises(self: ResponseReader) []const PushPromise {
        return self.response.pushPromises();
    }
};

/// Client-facing view over `session.Event`.
///
/// Slices borrow from the source event. Callers should finish consuming the
/// returned value before deinitializing or clearing the underlying event list.
pub const ResponseEvent = union(enum) {
    settings: settings_mod.Settings,
    headers: Headers,
    data: Data,
    datagram: Datagram,
    datagram_acked: DatagramSend,
    datagram_lost: DatagramSend,
    flow_blocked: FlowBlocked,
    connection_ids_needed: ConnectionIdsNeeded,
    trailers: Headers,
    push_promise: session_mod.PushPromiseEvent,
    push_stream: session_mod.PushStreamEvent,
    cancel_push: session_mod.CancelPushEvent,
    push_headers: Headers,
    push_data: Data,
    push_trailers: Headers,
    push_finished: StreamFinished,
    push_reset: StreamReset,
    finished: StreamFinished,
    reset: StreamReset,
    goaway: u64,
    connection_closed: ConnectionClosed,
    ignored_unknown_frame: UnknownFrame,

    pub fn from(event: session_mod.Event) ?ResponseEvent {
        return switch (event) {
            .peer_settings => |settings| .{ .settings = settings },
            .headers => |headers| if (headers.kind == .response) .{
                .headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else if (headers.kind == .push) .{
                .push_headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else null,
            .data => |data| if (data.kind == .response) .{
                .data = .{ .stream_id = data.stream_id, .bytes = data.data },
            } else if (data.kind == .push) .{
                .push_data = .{ .stream_id = data.stream_id, .bytes = data.data },
            } else null,
            .datagram => |datagram| .{ .datagram = .{
                .stream_id = datagram.stream_id,
                .payload = datagram.payload,
                .arrived_in_early_data = datagram.arrived_in_early_data,
            } },
            .datagram_acked => |acked| .{ .datagram_acked = acked },
            .datagram_lost => |lost| .{ .datagram_lost = lost },
            .flow_blocked => |blocked| .{ .flow_blocked = blocked },
            .connection_ids_needed => |needed| .{ .connection_ids_needed = needed },
            .trailers => |trailers| if (trailers.kind == .response) .{
                .trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else if (trailers.kind == .push) .{
                .push_trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else null,
            .push_promise => |promise| .{ .push_promise = promise },
            .push_stream => |push| .{ .push_stream = push },
            .cancel_push => |cancel| .{ .cancel_push = cancel },
            .stream_finished => |finished| if (finished.kind != null and finished.kind.? == .response) .{
                .finished = .{ .stream_id = finished.stream_id },
            } else if (finished.kind != null and finished.kind.? == .push) .{
                .push_finished = .{ .stream_id = finished.stream_id },
            } else null,
            .stream_reset => |reset| if (reset.kind != null and reset.kind.? == .response) .{
                .reset = .{
                    .stream_id = reset.stream_id,
                    .error_code = reset.error_code,
                    .final_size = reset.final_size,
                },
            } else if (reset.kind != null and reset.kind.? == .push) .{
                .push_reset = .{
                    .stream_id = reset.stream_id,
                    .error_code = reset.error_code,
                    .final_size = reset.final_size,
                },
            } else null,
            .goaway => |id| .{ .goaway = id },
            .connection_closed => |closed| .{ .connection_closed = closed },
            .ignored_unknown_frame => |unknown| .{ .ignored_unknown_frame = unknown },
            .request_rejected => null,
        };
    }
};

pub const ResponseState = struct {
    stream_id: u64,
    headers: ?[]qpack.FieldLine = null,
    body: std.ArrayList(u8) = .empty,
    trailers: ?[]qpack.FieldLine = null,
    push_promises: std.ArrayList(PushPromise) = .empty,
    complete: bool = false,
    reset: ?StreamReset = null,

    pub fn deinit(self: *ResponseState, allocator: std.mem.Allocator) void {
        if (self.headers) |fields| freeFields(allocator, fields);
        if (self.trailers) |fields| freeFields(allocator, fields);
        for (self.push_promises.items) |promise| {
            allocator.free(promise.field_section);
            freeFields(allocator, promise.fields);
        }
        self.push_promises.deinit(allocator);
        self.body.deinit(allocator);
    }

    pub fn reader(self: *const ResponseState) ResponseReader {
        return .{ .response = self };
    }

    pub fn headerFields(self: *const ResponseState) []const qpack.FieldLine {
        return self.headers orelse &.{};
    }

    pub fn trailerFields(self: *const ResponseState) []const qpack.FieldLine {
        return self.trailers orelse &.{};
    }

    pub fn bodyBytes(self: *const ResponseState) []const u8 {
        return self.body.items;
    }

    pub fn status(self: *const ResponseState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":status");
    }

    pub fn webSocketAccepted(self: *const ResponseState) bool {
        return websocket_mod.responseAccepted(self.headerFields());
    }

    pub fn connectUdpAccepted(self: *const ResponseState) bool {
        return masque_mod.responseAccepted(self.headerFields());
    }

    pub fn capsuleProtocolEnabled(self: *const ResponseState) bool {
        return masque_mod.capsuleProtocolEnabled(self.headerFields());
    }

    pub fn pushPromises(self: *const ResponseState) []const PushPromise {
        return self.push_promises.items;
    }

    fn setHeaders(
        self: *ResponseState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.headers) |old| freeFields(allocator, old);
        self.headers = copy;
    }

    fn setTrailers(
        self: *ResponseState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.trailers) |old| freeFields(allocator, old);
        self.trailers = copy;
    }

    fn addPushPromise(
        self: *ResponseState,
        allocator: std.mem.Allocator,
        promise: session_mod.PushPromiseEvent,
    ) std.mem.Allocator.Error!void {
        const field_section = try allocator.dupe(u8, promise.field_section);
        errdefer allocator.free(field_section);
        const fields = try cloneFields(allocator, promise.fields);
        errdefer freeFields(allocator, fields);
        try self.push_promises.append(allocator, .{
            .push_id = promise.push_id,
            .field_section = field_section,
            .fields = fields,
        });
    }

    fn appendBody(
        self: *ResponseState,
        allocator: std.mem.Allocator,
        bytes: []const u8,
        max_body_bytes: ?usize,
    ) ResponseTrackerError!void {
        if (max_body_bytes) |max| {
            if (bytes.len > max or self.body.items.len > max - bytes.len) {
                return error.BodyTooLarge;
            }
        }
        try self.body.appendSlice(allocator, bytes);
    }
};

pub const ResponseTrackerConfig = struct {
    max_body_bytes: ?usize = null,
};

pub const ResponseTrackerError = std.mem.Allocator.Error || error{
    BodyTooLarge,
    PushPromiseTooLarge,
    MissingPushStream,
    DuplicatePushStream,
};

pub const ResponseTracker = struct {
    allocator: std.mem.Allocator,
    config: ResponseTrackerConfig = .{},
    responses: std.AutoHashMapUnmanaged(u64, *ResponseState) = .empty,

    pub fn init(allocator: std.mem.Allocator) ResponseTracker {
        return .{ .allocator = allocator };
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: ResponseTrackerConfig) ResponseTracker {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *ResponseTracker) void {
        var it = self.responses.iterator();
        while (it.next()) |entry| {
            const response = entry.value_ptr.*;
            response.deinit(self.allocator);
            self.allocator.destroy(response);
        }
        self.responses.deinit(self.allocator);
    }

    pub fn get(self: *const ResponseTracker, stream_id: u64) ?*ResponseState {
        return self.responses.get(stream_id);
    }

    pub fn remove(self: *ResponseTracker, stream_id: u64) ?*ResponseState {
        const entry = self.responses.fetchRemove(stream_id) orelse return null;
        return entry.value;
    }

    pub fn observe(
        self: *ResponseTracker,
        event: ResponseEvent,
    ) ResponseTrackerError!?*ResponseState {
        switch (event) {
            .headers => |headers| {
                const response = try self.ensure(headers.stream_id);
                try response.setHeaders(self.allocator, headers.fields);
                return response;
            },
            .data => |data| {
                const response = try self.ensure(data.stream_id);
                try response.appendBody(self.allocator, data.bytes, self.config.max_body_bytes);
                return response;
            },
            .trailers => |trailers| {
                const response = try self.ensure(trailers.stream_id);
                try response.setTrailers(self.allocator, trailers.fields);
                return response;
            },
            .push_promise => |promise| {
                const response = try self.ensure(promise.stream_id);
                try response.addPushPromise(self.allocator, promise);
                return response;
            },
            .finished => |finished| {
                const response = try self.ensure(finished.stream_id);
                response.complete = true;
                return response;
            },
            .reset => |reset| {
                const response = try self.ensure(reset.stream_id);
                response.reset = reset;
                response.complete = true;
                return response;
            },
            .settings,
            .datagram,
            .datagram_acked,
            .datagram_lost,
            .flow_blocked,
            .connection_ids_needed,
            .push_stream,
            .cancel_push,
            .push_headers,
            .push_data,
            .push_trailers,
            .push_finished,
            .push_reset,
            .goaway,
            .connection_closed,
            .ignored_unknown_frame,
            => return null,
        }
    }

    fn ensure(self: *ResponseTracker, stream_id: u64) std.mem.Allocator.Error!*ResponseState {
        if (self.responses.get(stream_id)) |response| return response;

        const response = try self.allocator.create(ResponseState);
        errdefer self.allocator.destroy(response);
        response.* = .{ .stream_id = stream_id };
        try self.responses.put(self.allocator, stream_id, response);
        return response;
    }
};

pub const PushedResponseReader = struct {
    pushed: *const PushedResponseState,

    pub fn pushId(self: PushedResponseReader) u64 {
        return self.pushed.push_id;
    }

    pub fn requestStreamIds(self: PushedResponseReader) []const u64 {
        return self.pushed.requestStreamIds();
    }

    pub fn streamId(self: PushedResponseReader) ?u64 {
        return self.pushed.stream_id;
    }

    pub fn promiseFieldSection(self: PushedResponseReader) []const u8 {
        return self.pushed.promiseFieldSection();
    }

    pub fn promiseFields(self: PushedResponseReader) []const qpack.FieldLine {
        return self.pushed.promiseFields();
    }

    pub fn headers(self: PushedResponseReader) []const qpack.FieldLine {
        return self.pushed.headerFields();
    }

    pub fn trailers(self: PushedResponseReader) []const qpack.FieldLine {
        return self.pushed.trailerFields();
    }

    pub fn body(self: PushedResponseReader) []const u8 {
        return self.pushed.bodyBytes();
    }

    pub fn status(self: PushedResponseReader) ?[]const u8 {
        return self.pushed.status();
    }

    pub fn complete(self: PushedResponseReader) bool {
        return self.pushed.complete;
    }

    pub fn cancelled(self: PushedResponseReader) bool {
        return self.pushed.cancelled;
    }

    pub fn reset(self: PushedResponseReader) ?StreamReset {
        return self.pushed.reset;
    }
};

pub const PushedResponseState = struct {
    push_id: u64,
    request_stream_ids: std.ArrayList(u64) = .empty,
    stream_id: ?u64 = null,
    promise_field_section: ?[]u8 = null,
    promise_fields: ?[]qpack.FieldLine = null,
    headers: ?[]qpack.FieldLine = null,
    body: std.ArrayList(u8) = .empty,
    trailers: ?[]qpack.FieldLine = null,
    complete: bool = false,
    cancelled: bool = false,
    reset: ?StreamReset = null,

    pub fn deinit(self: *PushedResponseState, allocator: std.mem.Allocator) void {
        self.request_stream_ids.deinit(allocator);
        if (self.promise_field_section) |field_section| allocator.free(field_section);
        if (self.promise_fields) |fields| freeFields(allocator, fields);
        if (self.headers) |fields| freeFields(allocator, fields);
        if (self.trailers) |fields| freeFields(allocator, fields);
        self.body.deinit(allocator);
    }

    pub fn reader(self: *const PushedResponseState) PushedResponseReader {
        return .{ .pushed = self };
    }

    pub fn requestStreamIds(self: *const PushedResponseState) []const u64 {
        return self.request_stream_ids.items;
    }

    pub fn promiseFieldSection(self: *const PushedResponseState) []const u8 {
        return self.promise_field_section orelse &.{};
    }

    pub fn promiseFields(self: *const PushedResponseState) []const qpack.FieldLine {
        return self.promise_fields orelse &.{};
    }

    pub fn headerFields(self: *const PushedResponseState) []const qpack.FieldLine {
        return self.headers orelse &.{};
    }

    pub fn trailerFields(self: *const PushedResponseState) []const qpack.FieldLine {
        return self.trailers orelse &.{};
    }

    pub fn bodyBytes(self: *const PushedResponseState) []const u8 {
        return self.body.items;
    }

    pub fn status(self: *const PushedResponseState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":status");
    }

    fn addRequestStreamId(
        self: *PushedResponseState,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) std.mem.Allocator.Error!void {
        for (self.request_stream_ids.items) |existing| {
            if (existing == stream_id) return;
        }
        try self.request_stream_ids.append(allocator, stream_id);
    }

    fn setPromiseFieldSection(
        self: *PushedResponseState,
        allocator: std.mem.Allocator,
        field_section: []const u8,
        fields: []const qpack.FieldLine,
        max_field_section_bytes: ?usize,
    ) ResponseTrackerError!void {
        if (max_field_section_bytes) |max| {
            if (field_section.len > max) return error.PushPromiseTooLarge;
        }
        if (self.promise_field_section != null) return;
        const field_section_copy = try allocator.dupe(u8, field_section);
        errdefer allocator.free(field_section_copy);
        const fields_copy = try cloneFields(allocator, fields);
        self.promise_field_section = field_section_copy;
        self.promise_fields = fields_copy;
    }

    fn setHeaders(
        self: *PushedResponseState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.headers) |old| freeFields(allocator, old);
        self.headers = copy;
    }

    fn setTrailers(
        self: *PushedResponseState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.trailers) |old| freeFields(allocator, old);
        self.trailers = copy;
    }

    fn appendBody(
        self: *PushedResponseState,
        allocator: std.mem.Allocator,
        bytes: []const u8,
        max_body_bytes: ?usize,
    ) ResponseTrackerError!void {
        if (max_body_bytes) |max| {
            if (bytes.len > max or self.body.items.len > max - bytes.len) {
                return error.BodyTooLarge;
            }
        }
        try self.body.appendSlice(allocator, bytes);
    }
};

pub const PushedResponseTrackerConfig = struct {
    max_body_bytes: ?usize = null,
    max_promise_field_section_bytes: ?usize = null,
};

pub const PushedResponseTracker = struct {
    allocator: std.mem.Allocator,
    config: PushedResponseTrackerConfig = .{},
    pushes: std.AutoHashMapUnmanaged(u64, *PushedResponseState) = .empty,
    push_id_by_stream: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    pub fn init(allocator: std.mem.Allocator) PushedResponseTracker {
        return .{ .allocator = allocator };
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: PushedResponseTrackerConfig) PushedResponseTracker {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *PushedResponseTracker) void {
        var it = self.pushes.iterator();
        while (it.next()) |entry| {
            const pushed = entry.value_ptr.*;
            pushed.deinit(self.allocator);
            self.allocator.destroy(pushed);
        }
        self.pushes.deinit(self.allocator);
        self.push_id_by_stream.deinit(self.allocator);
    }

    pub fn get(self: *const PushedResponseTracker, push_id: u64) ?*PushedResponseState {
        return self.pushes.get(push_id);
    }

    pub fn getByStream(self: *const PushedResponseTracker, stream_id: u64) ?*PushedResponseState {
        const push_id = self.push_id_by_stream.get(stream_id) orelse return null;
        return self.get(push_id);
    }

    pub fn remove(self: *PushedResponseTracker, push_id: u64) ?*PushedResponseState {
        const entry = self.pushes.fetchRemove(push_id) orelse return null;
        if (entry.value.stream_id) |stream_id| _ = self.push_id_by_stream.remove(stream_id);
        return entry.value;
    }

    pub fn observe(
        self: *PushedResponseTracker,
        event: ResponseEvent,
    ) ResponseTrackerError!?*PushedResponseState {
        switch (event) {
            .push_promise => |promise| {
                const pushed = try self.ensure(promise.push_id);
                try pushed.addRequestStreamId(self.allocator, promise.stream_id);
                try pushed.setPromiseFieldSection(
                    self.allocator,
                    promise.field_section,
                    promise.fields,
                    self.config.max_promise_field_section_bytes,
                );
                return pushed;
            },
            .push_stream => |push| {
                const pushed = try self.ensure(push.push_id);
                try self.bindStream(pushed, push.stream_id);
                return pushed;
            },
            .push_headers => |headers| {
                const pushed = try self.ensureForStream(headers.stream_id);
                try pushed.setHeaders(self.allocator, headers.fields);
                return pushed;
            },
            .push_data => |data| {
                const pushed = try self.ensureForStream(data.stream_id);
                try pushed.appendBody(self.allocator, data.bytes, self.config.max_body_bytes);
                return pushed;
            },
            .push_trailers => |trailers| {
                const pushed = try self.ensureForStream(trailers.stream_id);
                try pushed.setTrailers(self.allocator, trailers.fields);
                return pushed;
            },
            .push_finished => |finished| {
                const pushed = try self.ensureForStream(finished.stream_id);
                pushed.complete = true;
                return pushed;
            },
            .push_reset => |reset| {
                const pushed = try self.ensureForStream(reset.stream_id);
                pushed.reset = reset;
                pushed.complete = true;
                return pushed;
            },
            .cancel_push => |cancel| {
                const pushed = try self.ensure(cancel.push_id);
                pushed.cancelled = true;
                pushed.complete = true;
                return pushed;
            },
            else => return null,
        }
    }

    fn ensure(self: *PushedResponseTracker, push_id: u64) std.mem.Allocator.Error!*PushedResponseState {
        if (self.pushes.get(push_id)) |pushed| return pushed;

        const pushed = try self.allocator.create(PushedResponseState);
        errdefer self.allocator.destroy(pushed);
        pushed.* = .{ .push_id = push_id };
        try self.pushes.put(self.allocator, push_id, pushed);
        return pushed;
    }

    fn ensureForStream(self: *PushedResponseTracker, stream_id: u64) ResponseTrackerError!*PushedResponseState {
        const push_id = self.push_id_by_stream.get(stream_id) orelse return error.MissingPushStream;
        return self.pushes.get(push_id) orelse error.MissingPushStream;
    }

    fn bindStream(
        self: *PushedResponseTracker,
        pushed: *PushedResponseState,
        stream_id: u64,
    ) ResponseTrackerError!void {
        if (self.push_id_by_stream.get(stream_id)) |existing_push_id| {
            if (existing_push_id != pushed.push_id) return error.DuplicatePushStream;
        } else {
            try self.push_id_by_stream.put(self.allocator, stream_id, pushed.push_id);
        }

        if (pushed.stream_id) |existing_stream_id| {
            if (existing_stream_id != stream_id) return error.DuplicatePushStream;
        } else {
            pushed.stream_id = stream_id;
        }
    }
};

pub const Client = struct {
    session: *session_mod.Session,

    pub fn init(session: *session_mod.Session) Client {
        return .{ .session = session };
    }

    pub fn open(self: *Client, fields: []const qpack.FieldLine) session_mod.Error!u64 {
        return try self.session.openRequest(fields);
    }

    pub fn sendData(self: *Client, stream_id: u64, data: []const u8) session_mod.Error!void {
        try self.session.sendRequestData(stream_id, data);
    }

    pub fn streamSendState(self: *const Client, stream_id: u64) session_mod.Error!StreamSendState {
        return try self.session.streamSendState(stream_id);
    }

    pub fn canBufferStreamBytes(self: *const Client, stream_id: u64, additional_bytes: usize) session_mod.Error!bool {
        return try self.session.canBufferStreamBytes(stream_id, additional_bytes);
    }

    pub fn canSendData(self: *const Client, stream_id: u64, data_len: usize) session_mod.Error!bool {
        return try self.session.canSendData(stream_id, data_len);
    }

    pub fn metrics(self: *const Client) observability_mod.Metrics {
        return self.session.metrics();
    }

    pub fn setObservabilityHooks(self: *Client, hooks: observability_mod.Hooks) void {
        self.session.setObservabilityHooks(hooks);
    }

    pub fn setQuicQlogCallback(
        self: *Client,
        callback: ?observability_mod.QuicQlogCallback,
        user_data: ?*anyopaque,
    ) void {
        self.session.setQuicQlogCallback(callback, user_data);
    }

    pub fn sendDatagram(self: *Client, stream_id: u64, payload: []const u8) session_mod.Error!void {
        try self.session.sendDatagram(stream_id, payload);
    }

    pub fn sendDatagramTracked(self: *Client, stream_id: u64, payload: []const u8) session_mod.Error!u64 {
        return try self.session.sendDatagramTracked(stream_id, payload);
    }

    pub fn sendDatagramWithContext(
        self: *Client,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.session.sendDatagramWithContext(stream_id, context_id, payload);
    }

    pub fn sendDatagramWithContextTracked(
        self: *Client,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!u64 {
        return try self.session.sendDatagramWithContextTracked(stream_id, context_id, payload);
    }

    pub fn sendCapsule(
        self: *Client,
        stream_id: u64,
        capsule_type: u64,
        value: []const u8,
    ) session_mod.Error!void {
        try self.session.sendRequestCapsule(stream_id, capsule_type, value);
    }

    pub fn sendDatagramCapsule(self: *Client, stream_id: u64, payload: []const u8) session_mod.Error!void {
        try self.session.sendRequestDatagramCapsule(stream_id, payload);
    }

    pub fn sendDatagramContextCapsule(
        self: *Client,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.session.sendRequestDatagramContextCapsule(stream_id, context_id, payload);
    }

    pub fn sendTrailers(self: *Client, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendRequestTrailers(stream_id, fields);
    }

    pub fn finish(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    pub fn reset(self: *Client, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetRequest(stream_id, error_code);
    }

    pub fn abort(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.reset(stream_id, protocol.ErrorCode.request_cancelled);
    }

    pub fn cancel(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.cancelRequest(stream_id);
    }

    pub fn cancelPush(self: *Client, push_id: u64) session_mod.Error!void {
        try self.session.cancelPush(push_id);
    }

    pub fn request(
        self: *Client,
        allocator: std.mem.Allocator,
        options: RequestOptions,
    ) session_mod.Error!Request {
        var writer = try self.startRequest(allocator, .{
            .method = options.method,
            .scheme = options.scheme,
            .authority = options.authority,
            .path = options.path,
            .connect_protocol = options.connect_protocol,
            .headers = options.headers,
        });

        if (options.body) |body| {
            try writer.write(body);
        }
        if (options.trailers.len > 0) try writer.trailers(options.trailers);
        if (options.end_stream) try writer.finish();

        return .{ .stream_id = writer.stream_id };
    }

    pub fn startRequest(
        self: *Client,
        allocator: std.mem.Allocator,
        options: RequestHeadOptions,
    ) session_mod.Error!RequestWriter {
        const fields = try buildRequestFields(allocator, options);
        defer allocator.free(fields);
        return .{
            .client = self,
            .stream_id = try self.open(fields),
        };
    }

    pub fn startConnectUdp(
        self: *Client,
        allocator: std.mem.Allocator,
        options: ConnectUdpOptions,
    ) (session_mod.Error || masque_mod.Error)!ConnectUdpClientStream {
        const path = try masque_mod.allocConnectUdpPath(allocator, options);
        defer allocator.free(path);
        const headers = try masque_mod.allocCapsuleProtocolHeaders(
            allocator,
            options.headers,
            options.capsule_protocol,
        );
        defer allocator.free(headers);
        return .{
            .writer = try self.startRequest(allocator, .{
                .method = "CONNECT",
                .scheme = options.scheme,
                .authority = options.authority,
                .path = path,
                .connect_protocol = masque_mod.connect_udp_protocol,
                .headers = headers,
            }),
        };
    }

    pub fn startWebSocket(
        self: *Client,
        allocator: std.mem.Allocator,
        options: WebSocketConnectOptions,
    ) session_mod.Error!WebSocketClientStream {
        return .{
            .writer = try self.startRequest(allocator, .{
                .method = "CONNECT",
                .scheme = options.scheme,
                .authority = options.authority,
                .path = options.path,
                .connect_protocol = websocket_mod.protocol_token,
                .headers = options.headers,
            }),
        };
    }

    pub fn classify(self: *const Client, event: session_mod.Event) ?ResponseEvent {
        _ = self;
        return ResponseEvent.from(event);
    }
};

fn buildRequestFields(
    allocator: std.mem.Allocator,
    options: RequestHeadOptions,
) session_mod.Error![]qpack.FieldLine {
    const protocol_len: usize = if (options.connect_protocol != null) 1 else 0;
    const fields = try allocator.alloc(qpack.FieldLine, 4 + protocol_len + options.headers.len);
    fields[0] = .{ .name = ":method", .value = options.method };
    fields[1] = .{ .name = ":scheme", .value = options.scheme };
    fields[2] = .{ .name = ":path", .value = options.path };
    fields[3] = .{ .name = ":authority", .value = options.authority };
    var pos: usize = 4;
    if (options.connect_protocol) |connect_protocol| {
        fields[pos] = .{ .name = ":protocol", .value = connect_protocol };
        pos += 1;
    }
    for (options.headers, 0..) |header, i| fields[pos + i] = header;
    return fields;
}

fn cloneFields(
    allocator: std.mem.Allocator,
    fields: []const qpack.FieldLine,
) std.mem.Allocator.Error![]qpack.FieldLine {
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

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
