//! HTTP/3 client-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const errors_mod = @import("errors.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");

pub const TlsOptions = struct {
    verify: boringssl.tls.VerifyMode = .system,
    early_data_enabled: bool = false,
};

pub fn initTlsContext(options: TlsOptions) boringssl.tls.Error!boringssl.tls.Context {
    return boringssl.tls.Context.initClient(.{
        .verify = options.verify,
        .min_version = @intCast(boringssl.raw.TLS1_3_VERSION),
        .alpn = &protocol.alpn_protocols,
        .early_data_enabled = options.early_data_enabled,
    });
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

pub const PushPromise = struct {
    push_id: u64,
    field_section: []u8,
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
    trailers: Headers,
    push_promise: session_mod.PushPromiseEvent,
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
            } else null,
            .data => |data| if (data.kind == .response) .{
                .data = .{ .stream_id = data.stream_id, .bytes = data.data },
            } else null,
            .datagram => |datagram| .{ .datagram = .{
                .stream_id = datagram.stream_id,
                .payload = datagram.payload,
                .arrived_in_early_data = datagram.arrived_in_early_data,
            } },
            .datagram_acked => |acked| .{ .datagram_acked = acked },
            .datagram_lost => |lost| .{ .datagram_lost = lost },
            .flow_blocked => |blocked| .{ .flow_blocked = blocked },
            .trailers => |trailers| if (trailers.kind == .response) .{
                .trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else null,
            .push_promise => |promise| .{ .push_promise = promise },
            .stream_finished => |finished| if (finished.kind != null and finished.kind.? == .response) .{
                .finished = .{ .stream_id = finished.stream_id },
            } else null,
            .stream_reset => |reset| if (reset.kind != null and reset.kind.? == .response) .{
                .reset = .{
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
        for (self.push_promises.items) |promise| allocator.free(promise.field_section);
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
        try self.push_promises.append(allocator, .{
            .push_id = promise.push_id,
            .field_section = field_section,
        });
    }
};

pub const ResponseTracker = struct {
    allocator: std.mem.Allocator,
    responses: std.AutoHashMapUnmanaged(u64, *ResponseState) = .empty,

    pub fn init(allocator: std.mem.Allocator) ResponseTracker {
        return .{ .allocator = allocator };
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
    ) std.mem.Allocator.Error!?*ResponseState {
        switch (event) {
            .headers => |headers| {
                const response = try self.ensure(headers.stream_id);
                try response.setHeaders(self.allocator, headers.fields);
                return response;
            },
            .data => |data| {
                const response = try self.ensure(data.stream_id);
                try response.body.appendSlice(self.allocator, data.bytes);
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
