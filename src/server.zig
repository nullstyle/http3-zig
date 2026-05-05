//! HTTP/3 server-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const errors_mod = @import("errors.zig");
const observability_mod = @import("observability.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");
const websocket_mod = @import("websocket.zig");

pub const TlsOptions = struct {
    verify: boringssl.tls.VerifyMode = .none,
    early_data_enabled: bool = false,
    keylog_callback: ?observability_mod.KeylogCallback = null,
};

pub fn initTlsContext(
    options: TlsOptions,
    cert_chain_pem: []const u8,
    private_key_pem: []const u8,
) boringssl.tls.Error!boringssl.tls.Context {
    var ctx = try boringssl.tls.Context.initServer(.{
        .verify = options.verify,
        .min_version = @intCast(boringssl.raw.TLS1_3_VERSION),
        .alpn = &protocol.alpn_protocols,
        .early_data_enabled = options.early_data_enabled,
    });
    errdefer ctx.deinit();
    if (options.keylog_callback) |callback| try ctx.setKeylogCallback(callback);
    try ctx.loadCertChainAndKey(cert_chain_pem, private_key_pem);
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

pub const RequestRejected = session_mod.RequestRejectedEvent;
pub const UnknownFrame = session_mod.UnknownFrameEvent;
pub const ConnectionClosed = session_mod.ConnectionClosedEvent;
pub const DatagramSend = session_mod.DatagramSendEvent;
pub const FlowBlocked = session_mod.FlowBlockedEvent;
pub const ConnectionIdsNeeded = session_mod.ConnectionIdsNeededEvent;
pub const StreamSendState = session_mod.StreamSendState;

pub const ResponseOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    body: ?[]const u8 = null,
    trailers: []const qpack.FieldLine = &.{},
    end_stream: bool = true,
};

pub const ResponseHeadOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
};

pub const Response = struct {
    stream_id: u64,
};

pub const ResponseWriter = struct {
    server: *Server,
    stream_id: u64,

    pub fn write(self: *ResponseWriter, data: []const u8) session_mod.Error!void {
        if (data.len > 0) try self.server.sendData(self.stream_id, data);
    }

    pub fn sendState(self: *const ResponseWriter) session_mod.Error!StreamSendState {
        return try self.server.streamSendState(self.stream_id);
    }

    pub fn canBuffer(self: *const ResponseWriter, additional_bytes: usize) session_mod.Error!bool {
        return try self.server.canBufferStreamBytes(self.stream_id, additional_bytes);
    }

    pub fn canWrite(self: *const ResponseWriter, data_len: usize) session_mod.Error!bool {
        return try self.server.canSendData(self.stream_id, data_len);
    }

    pub fn datagram(self: *ResponseWriter, payload: []const u8) session_mod.Error!void {
        try self.server.sendDatagram(self.stream_id, payload);
    }

    pub fn datagramTracked(self: *ResponseWriter, payload: []const u8) session_mod.Error!u64 {
        return try self.server.sendDatagramTracked(self.stream_id, payload);
    }

    pub fn datagramWithContext(self: *ResponseWriter, context_id: u64, payload: []const u8) session_mod.Error!void {
        try self.server.sendDatagramWithContext(self.stream_id, context_id, payload);
    }

    pub fn datagramWithContextTracked(
        self: *ResponseWriter,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!u64 {
        return try self.server.sendDatagramWithContextTracked(self.stream_id, context_id, payload);
    }

    pub fn capsule(self: *ResponseWriter, capsule_type: u64, value: []const u8) session_mod.Error!void {
        try self.server.sendCapsule(self.stream_id, capsule_type, value);
    }

    pub fn datagramCapsule(self: *ResponseWriter, payload: []const u8) session_mod.Error!void {
        try self.server.sendDatagramCapsule(self.stream_id, payload);
    }

    pub fn datagramContextCapsule(
        self: *ResponseWriter,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.server.sendDatagramContextCapsule(self.stream_id, context_id, payload);
    }

    pub fn trailers(self: *ResponseWriter, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.server.sendTrailers(self.stream_id, fields);
    }

    pub fn finish(self: *ResponseWriter) session_mod.Error!void {
        try self.server.finish(self.stream_id);
    }

    pub fn reset(self: *ResponseWriter, error_code: u64) session_mod.Error!void {
        try self.server.reset(self.stream_id, error_code);
    }

    pub fn abort(self: *ResponseWriter) session_mod.Error!void {
        try self.reset(protocol.ErrorCode.internal_error);
    }
};

pub const WebSocketAcceptOptions = websocket_mod.AcceptOptions;

pub const WebSocketServerStream = struct {
    writer: ResponseWriter,

    pub fn streamId(self: *const WebSocketServerStream) u64 {
        return self.writer.stream_id;
    }

    pub fn write(self: *WebSocketServerStream, bytes: []const u8) session_mod.Error!void {
        try self.writer.write(bytes);
    }

    pub fn writeFrameWithOptions(
        self: *WebSocketServerStream,
        frame: websocket_mod.frame.Frame,
        options: websocket_mod.frame.EncodeOptions,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        const allocator = self.writer.server.session.allocator;
        const len = try websocket_mod.frame.encodedLen(frame, options);
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        const n = try websocket_mod.frame.encode(buf, frame, options);
        try self.writer.write(buf[0..n]);
    }

    pub fn writeFrame(
        self: *WebSocketServerStream,
        frame: websocket_mod.frame.Frame,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrameWithOptions(frame, .{});
    }

    pub fn writeText(
        self: *WebSocketServerStream,
        payload: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrame(.{ .opcode = .text, .payload = payload });
    }

    pub fn writeBinary(
        self: *WebSocketServerStream,
        payload: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrame(.{ .opcode = .binary, .payload = payload });
    }

    pub fn writeClose(
        self: *WebSocketServerStream,
        code: ?u16,
        reason: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        var buf: [127]u8 = undefined;
        const n = try websocket_mod.frame.encodeClose(&buf, code, reason, .{});
        try self.writer.write(buf[0..n]);
    }

    pub fn finishSend(self: *WebSocketServerStream) session_mod.Error!void {
        try self.writer.finish();
    }

    pub fn reset(self: *WebSocketServerStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn abort(self: *WebSocketServerStream) session_mod.Error!void {
        try self.writer.abort();
    }

    pub fn responseWriter(self: *WebSocketServerStream) *ResponseWriter {
        return &self.writer;
    }
};

pub const RequestReader = struct {
    request: *const RequestState,

    pub fn streamId(self: RequestReader) u64 {
        return self.request.stream_id;
    }

    pub fn headers(self: RequestReader) []const qpack.FieldLine {
        return self.request.headerFields();
    }

    pub fn trailers(self: RequestReader) []const qpack.FieldLine {
        return self.request.trailerFields();
    }

    pub fn body(self: RequestReader) []const u8 {
        return self.request.bodyBytes();
    }

    pub fn method(self: RequestReader) ?[]const u8 {
        return self.request.method();
    }

    pub fn scheme(self: RequestReader) ?[]const u8 {
        return self.request.scheme();
    }

    pub fn authority(self: RequestReader) ?[]const u8 {
        return self.request.authority();
    }

    pub fn path(self: RequestReader) ?[]const u8 {
        return self.request.path();
    }

    pub fn protocol(self: RequestReader) ?[]const u8 {
        return self.request.protocol();
    }

    pub fn isExtendedConnect(self: RequestReader) bool {
        return self.request.isExtendedConnect();
    }

    pub fn isWebSocket(self: RequestReader) bool {
        return self.request.isWebSocket();
    }

    pub fn complete(self: RequestReader) bool {
        return self.request.complete;
    }

    pub fn reset(self: RequestReader) ?StreamReset {
        return self.request.reset;
    }

    pub fn rejected(self: RequestReader) ?RequestRejected {
        return self.request.rejected;
    }
};

/// Server-facing view over `session.Event`.
///
/// Slices borrow from the source event. Callers should finish consuming the
/// returned value before deinitializing or clearing the underlying event list.
pub const RequestEvent = union(enum) {
    settings: settings_mod.Settings,
    headers: Headers,
    data: Data,
    datagram: Datagram,
    datagram_acked: DatagramSend,
    datagram_lost: DatagramSend,
    flow_blocked: FlowBlocked,
    connection_ids_needed: ConnectionIdsNeeded,
    trailers: Headers,
    finished: StreamFinished,
    reset: StreamReset,
    rejected: RequestRejected,
    goaway: u64,
    connection_closed: ConnectionClosed,
    ignored_unknown_frame: UnknownFrame,

    pub fn from(event: session_mod.Event) ?RequestEvent {
        return switch (event) {
            .peer_settings => |settings| .{ .settings = settings },
            .headers => |headers| if (headers.kind == .request) .{
                .headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else null,
            .data => |data| if (data.kind == .request) .{
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
            .connection_ids_needed => |needed| .{ .connection_ids_needed = needed },
            .trailers => |trailers| if (trailers.kind == .request) .{
                .trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else null,
            .stream_finished => |finished| if (finished.kind != null and finished.kind.? == .request) .{
                .finished = .{ .stream_id = finished.stream_id },
            } else null,
            .stream_reset => |reset| if (reset.kind != null and reset.kind.? == .request) .{
                .reset = .{
                    .stream_id = reset.stream_id,
                    .error_code = reset.error_code,
                    .final_size = reset.final_size,
                },
            } else null,
            .request_rejected => |rejected| .{ .rejected = rejected },
            .goaway => |id| .{ .goaway = id },
            .connection_closed => |closed| .{ .connection_closed = closed },
            .ignored_unknown_frame => |unknown| .{ .ignored_unknown_frame = unknown },
            .push_promise => null,
        };
    }
};

pub const Server = struct {
    session: *session_mod.Session,

    pub fn init(session: *session_mod.Session) Server {
        return .{ .session = session };
    }

    pub fn sendHeaders(self: *Server, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendResponseHeaders(stream_id, fields);
    }

    pub fn sendData(self: *Server, stream_id: u64, data: []const u8) session_mod.Error!void {
        try self.session.sendResponseData(stream_id, data);
    }

    pub fn streamSendState(self: *const Server, stream_id: u64) session_mod.Error!StreamSendState {
        return try self.session.streamSendState(stream_id);
    }

    pub fn canBufferStreamBytes(self: *const Server, stream_id: u64, additional_bytes: usize) session_mod.Error!bool {
        return try self.session.canBufferStreamBytes(stream_id, additional_bytes);
    }

    pub fn canSendData(self: *const Server, stream_id: u64, data_len: usize) session_mod.Error!bool {
        return try self.session.canSendData(stream_id, data_len);
    }

    pub fn metrics(self: *const Server) observability_mod.Metrics {
        return self.session.metrics();
    }

    pub fn setObservabilityHooks(self: *Server, hooks: observability_mod.Hooks) void {
        self.session.setObservabilityHooks(hooks);
    }

    pub fn setQuicQlogCallback(
        self: *Server,
        callback: ?observability_mod.QuicQlogCallback,
        user_data: ?*anyopaque,
    ) void {
        self.session.setQuicQlogCallback(callback, user_data);
    }

    pub fn sendDatagram(self: *Server, stream_id: u64, payload: []const u8) session_mod.Error!void {
        try self.session.sendDatagram(stream_id, payload);
    }

    pub fn sendDatagramTracked(self: *Server, stream_id: u64, payload: []const u8) session_mod.Error!u64 {
        return try self.session.sendDatagramTracked(stream_id, payload);
    }

    pub fn sendDatagramWithContext(
        self: *Server,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.session.sendDatagramWithContext(stream_id, context_id, payload);
    }

    pub fn sendDatagramWithContextTracked(
        self: *Server,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!u64 {
        return try self.session.sendDatagramWithContextTracked(stream_id, context_id, payload);
    }

    pub fn sendCapsule(
        self: *Server,
        stream_id: u64,
        capsule_type: u64,
        value: []const u8,
    ) session_mod.Error!void {
        try self.session.sendResponseCapsule(stream_id, capsule_type, value);
    }

    pub fn sendDatagramCapsule(self: *Server, stream_id: u64, payload: []const u8) session_mod.Error!void {
        try self.session.sendResponseDatagramCapsule(stream_id, payload);
    }

    pub fn sendDatagramContextCapsule(
        self: *Server,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.session.sendResponseDatagramContextCapsule(stream_id, context_id, payload);
    }

    pub fn sendTrailers(self: *Server, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendResponseTrailers(stream_id, fields);
    }

    pub fn finish(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    pub fn reset(self: *Server, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetResponse(stream_id, error_code);
    }

    pub fn abort(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.reset(stream_id, protocol.ErrorCode.internal_error);
    }

    pub fn reject(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.session.rejectRequest(stream_id);
    }

    pub fn goaway(self: *Server, id: u64) session_mod.Error!void {
        try self.session.sendGoaway(id);
    }

    pub fn respond(
        self: *Server,
        allocator: std.mem.Allocator,
        stream_id: u64,
        options: ResponseOptions,
    ) session_mod.Error!Response {
        var writer = try self.startResponse(allocator, stream_id, .{
            .status = options.status,
            .headers = options.headers,
        });

        if (options.body) |body| {
            try writer.write(body);
        }
        if (options.trailers.len > 0) try writer.trailers(options.trailers);
        if (options.end_stream) try writer.finish();

        return .{ .stream_id = stream_id };
    }

    pub fn startResponse(
        self: *Server,
        allocator: std.mem.Allocator,
        stream_id: u64,
        options: ResponseHeadOptions,
    ) session_mod.Error!ResponseWriter {
        const fields = try buildResponseFields(allocator, options);
        defer allocator.free(fields);
        try self.sendHeaders(stream_id, fields);
        return .{
            .server = self,
            .stream_id = stream_id,
        };
    }

    pub fn acceptWebSocket(
        self: *Server,
        allocator: std.mem.Allocator,
        request: RequestReader,
        options: WebSocketAcceptOptions,
    ) (session_mod.Error || websocket_mod.Error)!WebSocketServerStream {
        if (!request.isWebSocket()) return error.NotWebSocket;
        if (!websocket_mod.isAcceptedStatus(options.status)) return error.InvalidAcceptStatus;
        return .{
            .writer = try self.startResponse(allocator, request.streamId(), .{
                .status = options.status,
                .headers = options.headers,
            }),
        };
    }

    pub fn classify(self: *const Server, event: session_mod.Event) ?RequestEvent {
        _ = self;
        return RequestEvent.from(event);
    }
};

pub const RequestState = struct {
    stream_id: u64,
    headers: ?[]qpack.FieldLine = null,
    body: std.ArrayList(u8) = .empty,
    trailers: ?[]qpack.FieldLine = null,
    complete: bool = false,
    reset: ?StreamReset = null,
    rejected: ?RequestRejected = null,

    pub fn deinit(self: *RequestState, allocator: std.mem.Allocator) void {
        if (self.headers) |fields| freeFields(allocator, fields);
        if (self.trailers) |fields| freeFields(allocator, fields);
        self.body.deinit(allocator);
    }

    pub fn reader(self: *const RequestState) RequestReader {
        return .{ .request = self };
    }

    pub fn headerFields(self: *const RequestState) []const qpack.FieldLine {
        return self.headers orelse &.{};
    }

    pub fn trailerFields(self: *const RequestState) []const qpack.FieldLine {
        return self.trailers orelse &.{};
    }

    pub fn bodyBytes(self: *const RequestState) []const u8 {
        return self.body.items;
    }

    pub fn method(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":method");
    }

    pub fn scheme(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":scheme");
    }

    pub fn authority(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":authority");
    }

    pub fn path(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":path");
    }

    pub fn protocol(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":protocol");
    }

    pub fn isExtendedConnect(self: *const RequestState) bool {
        return self.protocol() != null;
    }

    pub fn isWebSocket(self: *const RequestState) bool {
        return websocket_mod.isRequest(self.headerFields());
    }

    fn setHeaders(
        self: *RequestState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.headers) |old| freeFields(allocator, old);
        self.headers = copy;
    }

    fn setTrailers(
        self: *RequestState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.trailers) |old| freeFields(allocator, old);
        self.trailers = copy;
    }

    fn appendBody(
        self: *RequestState,
        allocator: std.mem.Allocator,
        bytes: []const u8,
        max_body_bytes: ?usize,
    ) RequestTrackerError!void {
        if (max_body_bytes) |max| {
            if (bytes.len > max or self.body.items.len > max - bytes.len) {
                return error.BodyTooLarge;
            }
        }
        try self.body.appendSlice(allocator, bytes);
    }
};

pub const RequestTrackerConfig = struct {
    max_body_bytes: ?usize = null,
};

pub const RequestTrackerError = std.mem.Allocator.Error || error{
    BodyTooLarge,
};

pub const RequestTracker = struct {
    allocator: std.mem.Allocator,
    config: RequestTrackerConfig = .{},
    requests: std.AutoHashMapUnmanaged(u64, *RequestState) = .empty,

    pub fn init(allocator: std.mem.Allocator) RequestTracker {
        return .{ .allocator = allocator };
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: RequestTrackerConfig) RequestTracker {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *RequestTracker) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            const request = entry.value_ptr.*;
            request.deinit(self.allocator);
            self.allocator.destroy(request);
        }
        self.requests.deinit(self.allocator);
    }

    pub fn get(self: *const RequestTracker, stream_id: u64) ?*RequestState {
        return self.requests.get(stream_id);
    }

    pub fn remove(self: *RequestTracker, stream_id: u64) ?*RequestState {
        const entry = self.requests.fetchRemove(stream_id) orelse return null;
        return entry.value;
    }

    pub fn observe(
        self: *RequestTracker,
        event: RequestEvent,
    ) RequestTrackerError!?*RequestState {
        switch (event) {
            .headers => |headers| {
                const request = try self.ensure(headers.stream_id);
                try request.setHeaders(self.allocator, headers.fields);
                return request;
            },
            .data => |data| {
                const request = try self.ensure(data.stream_id);
                try request.appendBody(self.allocator, data.bytes, self.config.max_body_bytes);
                return request;
            },
            .trailers => |trailers| {
                const request = try self.ensure(trailers.stream_id);
                try request.setTrailers(self.allocator, trailers.fields);
                return request;
            },
            .finished => |finished| {
                const request = try self.ensure(finished.stream_id);
                request.complete = true;
                return request;
            },
            .reset => |reset| {
                const request = try self.ensure(reset.stream_id);
                request.reset = reset;
                request.complete = true;
                return request;
            },
            .rejected => |rejected| {
                const request = try self.ensure(rejected.stream_id);
                request.rejected = rejected;
                request.complete = true;
                return request;
            },
            .settings,
            .datagram,
            .datagram_acked,
            .datagram_lost,
            .flow_blocked,
            .connection_ids_needed,
            .goaway,
            .connection_closed,
            .ignored_unknown_frame,
            => return null,
        }
    }

    fn ensure(self: *RequestTracker, stream_id: u64) std.mem.Allocator.Error!*RequestState {
        if (self.requests.get(stream_id)) |request| return request;

        const request = try self.allocator.create(RequestState);
        errdefer self.allocator.destroy(request);
        request.* = .{ .stream_id = stream_id };
        try self.requests.put(self.allocator, stream_id, request);
        return request;
    }
};

fn buildResponseFields(
    allocator: std.mem.Allocator,
    options: ResponseHeadOptions,
) session_mod.Error![]qpack.FieldLine {
    const fields = try allocator.alloc(qpack.FieldLine, 1 + options.headers.len);
    fields[0] = .{ .name = ":status", .value = options.status };
    for (options.headers, 0..) |header, i| fields[1 + i] = header;
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
