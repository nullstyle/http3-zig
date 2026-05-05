//! HTTP/3 server-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const errors_mod = @import("errors.zig");
const masque_mod = @import("masque.zig");
const observability_mod = @import("observability.zig");
const priority_mod = @import("priority.zig");
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

pub const RequestRejected = session_mod.RequestRejectedEvent;
pub const UnknownFrame = session_mod.UnknownFrameEvent;
pub const ConnectionClosed = session_mod.ConnectionClosedEvent;
pub const PriorityUpdate = session_mod.PriorityUpdateEvent;
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

pub const PushHeadOptions = struct {
    promise_headers: []const qpack.FieldLine,
    response: ResponseHeadOptions = .{},
};

pub const PushOptions = struct {
    promise_headers: []const qpack.FieldLine,
    response: ResponseOptions = .{},
};

pub const PushPromisePolicy = struct {
    /// Promise `:scheme` must match the request `:scheme`.
    require_same_scheme: bool = true,
    /// Promise `:authority` must match the request `:authority`.
    require_same_authority: bool = true,
    /// Promise method must be a safe, cache-oriented method (`GET` or `HEAD`).
    require_cacheable_method: bool = true,
};

pub const PushPromisePolicyError = error{
    MissingRequestScheme,
    MissingRequestAuthority,
    MissingPromiseMethod,
    MissingPromiseScheme,
    MissingPromiseAuthority,
    MissingPromisePath,
    CrossSchemePush,
    CrossAuthorityPush,
    UncacheablePushMethod,
    ExtendedConnectPush,
};

pub const PushPromiseRequestOptions = struct {
    method: []const u8 = "GET",
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    path: []const u8,
    headers: []const qpack.FieldLine = &.{},
    policy: PushPromisePolicy = .{},
};

pub const PushFromRequestHeadOptions = struct {
    promise: PushPromiseRequestOptions,
    response: ResponseHeadOptions = .{},
};

pub const PushFromRequestOptions = struct {
    promise: PushPromiseRequestOptions,
    response: ResponseOptions = .{},
};

pub const Push = session_mod.LocalPush;

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

pub const PushWriter = struct {
    server: *Server,
    request_stream_id: u64,
    push_id: u64,
    stream_id: u64,

    pub fn write(self: *PushWriter, data: []const u8) session_mod.Error!void {
        if (data.len > 0) try self.server.sendPushData(self.stream_id, data);
    }

    pub fn sendState(self: *const PushWriter) session_mod.Error!StreamSendState {
        return try self.server.streamSendState(self.stream_id);
    }

    pub fn canBuffer(self: *const PushWriter, additional_bytes: usize) session_mod.Error!bool {
        return try self.server.canBufferStreamBytes(self.stream_id, additional_bytes);
    }

    pub fn canWrite(self: *const PushWriter, data_len: usize) session_mod.Error!bool {
        return try self.server.canSendData(self.stream_id, data_len);
    }

    pub fn trailers(self: *PushWriter, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.server.sendPushTrailers(self.stream_id, fields);
    }

    pub fn finish(self: *PushWriter) session_mod.Error!void {
        try self.server.finish(self.stream_id);
    }

    pub fn reset(self: *PushWriter, error_code: u64) session_mod.Error!void {
        try self.server.resetPush(self.stream_id, error_code);
    }

    pub fn abort(self: *PushWriter) session_mod.Error!void {
        try self.reset(protocol.ErrorCode.internal_error);
    }

    pub fn cancel(self: *PushWriter) session_mod.Error!void {
        try self.server.cancelPush(self.push_id);
    }
};

pub const ConnectUdpAcceptOptions = masque_mod.AcceptOptions;

pub const ConnectUdpServerStream = struct {
    writer: ResponseWriter,

    pub fn streamId(self: *const ConnectUdpServerStream) u64 {
        return self.writer.stream_id;
    }

    pub fn sendUdp(self: *ConnectUdpServerStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!void {
        try masque_mod.validateUdpPayload(payload);
        try self.writer.datagramWithContext(masque_mod.udp_context_id, payload);
    }

    pub fn sendUdpTracked(self: *ConnectUdpServerStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!u64 {
        try masque_mod.validateUdpPayload(payload);
        return try self.writer.datagramWithContextTracked(masque_mod.udp_context_id, payload);
    }

    pub fn sendUdpCapsule(self: *ConnectUdpServerStream, payload: []const u8) (session_mod.Error || masque_mod.Error)!void {
        try masque_mod.validateUdpPayload(payload);
        try self.writer.datagramContextCapsule(masque_mod.udp_context_id, payload);
    }

    pub fn capsule(self: *ConnectUdpServerStream, capsule_type: u64, value: []const u8) session_mod.Error!void {
        try self.writer.capsule(capsule_type, value);
    }

    pub fn finishSend(self: *ConnectUdpServerStream) session_mod.Error!void {
        try self.writer.finish();
    }

    pub fn reset(self: *ConnectUdpServerStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn fail(self: *ConnectUdpServerStream) session_mod.Error!void {
        try self.reset(masque_mod.connect_udp_abort_code);
    }

    pub fn failForError(self: *ConnectUdpServerStream, err: anyerror) session_mod.Error!void {
        try self.reset(masque_mod.streamAbortForError(err).error_code);
    }

    pub fn abort(self: *ConnectUdpServerStream) session_mod.Error!void {
        try self.writer.abort();
    }

    pub fn responseWriter(self: *ConnectUdpServerStream) *ResponseWriter {
        return &self.writer;
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

    pub fn writeMessage(
        self: *WebSocketServerStream,
        kind: websocket_mod.message.Kind,
        payload: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeFrame(.{
            .opcode = websocket_mod.message.opcodeForKind(kind),
            .payload = payload,
        });
    }

    pub fn writeText(
        self: *WebSocketServerStream,
        payload: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeMessage(.text, payload);
    }

    pub fn writeBinary(
        self: *WebSocketServerStream,
        payload: []const u8,
    ) (session_mod.Error || websocket_mod.frame.Error)!void {
        try self.writeMessage(.binary, payload);
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

    pub fn priority(self: RequestReader) priority_mod.Error!?priority_mod.Priority {
        return try self.request.priority();
    }

    pub fn isExtendedConnect(self: RequestReader) bool {
        return self.request.isExtendedConnect();
    }

    pub fn isWebSocket(self: RequestReader) bool {
        return self.request.isWebSocket();
    }

    pub fn isConnectUdp(self: RequestReader) bool {
        return self.request.isConnectUdp();
    }

    pub fn capsuleProtocolEnabled(self: RequestReader) bool {
        return self.request.capsuleProtocolEnabled();
    }

    pub fn connectUdpTarget(self: RequestReader, allocator: std.mem.Allocator) masque_mod.Error!masque_mod.OwnedConnectUdpTarget {
        return try masque_mod.parseConnectUdpTarget(
            allocator,
            self.path() orelse return error.InvalidConnectUdpPath,
            masque_mod.default_connect_udp_path_prefix,
        );
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
    cancel_push: session_mod.CancelPushEvent,
    priority_update: PriorityUpdate,
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
            .cancel_push => |cancel| .{ .cancel_push = cancel },
            .priority_update => |update| .{ .priority_update = update },
            .goaway => |id| .{ .goaway = id },
            .connection_closed => |closed| .{ .connection_closed = closed },
            .ignored_unknown_frame => |unknown| .{ .ignored_unknown_frame = unknown },
            .push_promise => null,
            .push_stream => null,
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

    pub fn sendPushData(self: *Server, stream_id: u64, data: []const u8) session_mod.Error!void {
        try self.session.sendPushData(stream_id, data);
    }

    pub fn sendPushTrailers(self: *Server, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendPushTrailers(stream_id, fields);
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

    pub fn resetPush(self: *Server, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetStream(stream_id, error_code);
    }

    pub fn cancelPush(self: *Server, push_id: u64) session_mod.Error!void {
        try self.session.cancelPush(push_id);
    }

    pub fn priorityForRequest(self: *const Server, stream_id: u64) ?priority_mod.Priority {
        return self.session.priorityForRequest(stream_id);
    }

    pub fn priorityForPush(self: *const Server, push_id: u64) ?priority_mod.Priority {
        return self.session.priorityForPush(push_id);
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

    pub fn push(
        self: *Server,
        allocator: std.mem.Allocator,
        request_stream_id: u64,
        options: PushOptions,
    ) session_mod.Error!Push {
        var writer = try self.startPush(allocator, request_stream_id, .{
            .promise_headers = options.promise_headers,
            .response = .{
                .status = options.response.status,
                .headers = options.response.headers,
            },
        });

        if (options.response.body) |body| {
            try writer.write(body);
        }
        if (options.response.trailers.len > 0) try writer.trailers(options.response.trailers);
        if (options.response.end_stream) try writer.finish();

        return .{
            .request_stream_id = writer.request_stream_id,
            .push_id = writer.push_id,
            .stream_id = writer.stream_id,
        };
    }

    pub fn pushFromRequest(
        self: *Server,
        allocator: std.mem.Allocator,
        request: RequestReader,
        options: PushFromRequestOptions,
    ) (session_mod.Error || PushPromisePolicyError)!Push {
        var writer = try self.startPushFromRequest(allocator, request, .{
            .promise = options.promise,
            .response = .{
                .status = options.response.status,
                .headers = options.response.headers,
            },
        });

        if (options.response.body) |body| {
            try writer.write(body);
        }
        if (options.response.trailers.len > 0) try writer.trailers(options.response.trailers);
        if (options.response.end_stream) try writer.finish();

        return .{
            .request_stream_id = writer.request_stream_id,
            .push_id = writer.push_id,
            .stream_id = writer.stream_id,
        };
    }

    pub fn startPush(
        self: *Server,
        allocator: std.mem.Allocator,
        request_stream_id: u64,
        options: PushHeadOptions,
    ) session_mod.Error!PushWriter {
        const response_fields = try buildResponseFields(allocator, options.response);
        defer allocator.free(response_fields);
        const push_info = try self.session.startPush(
            request_stream_id,
            options.promise_headers,
            response_fields,
        );
        return .{
            .server = self,
            .request_stream_id = push_info.request_stream_id,
            .push_id = push_info.push_id,
            .stream_id = push_info.stream_id,
        };
    }

    pub fn startPushFromRequest(
        self: *Server,
        allocator: std.mem.Allocator,
        request: RequestReader,
        options: PushFromRequestHeadOptions,
    ) (session_mod.Error || PushPromisePolicyError)!PushWriter {
        const promise_fields = try allocPushPromiseFields(allocator, request, options.promise);
        defer allocator.free(promise_fields);
        return try self.startPush(allocator, request.streamId(), .{
            .promise_headers = promise_fields,
            .response = options.response,
        });
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

    pub fn acceptConnectUdp(
        self: *Server,
        allocator: std.mem.Allocator,
        request: RequestReader,
        options: ConnectUdpAcceptOptions,
    ) (session_mod.Error || masque_mod.Error)!ConnectUdpServerStream {
        if (!request.isConnectUdp()) return error.NotConnectUdp;
        if (!masque_mod.isAcceptedStatus(options.status)) return error.InvalidAcceptStatus;
        const headers = try masque_mod.allocCapsuleProtocolHeaders(
            allocator,
            options.headers,
            options.capsule_protocol,
        );
        defer allocator.free(headers);
        return .{
            .writer = try self.startResponse(allocator, request.streamId(), .{
                .status = options.status,
                .headers = headers,
            }),
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

    pub fn priority(self: *const RequestState) priority_mod.Error!?priority_mod.Priority {
        return try priority_mod.fromFieldLines(self.headerFields());
    }

    pub fn isExtendedConnect(self: *const RequestState) bool {
        return self.protocol() != null;
    }

    pub fn isWebSocket(self: *const RequestState) bool {
        return websocket_mod.isRequest(self.headerFields());
    }

    pub fn isConnectUdp(self: *const RequestState) bool {
        return masque_mod.isConnectUdpRequest(self.headerFields());
    }

    pub fn capsuleProtocolEnabled(self: *const RequestState) bool {
        return masque_mod.capsuleProtocolEnabled(self.headerFields());
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
            .cancel_push,
            .priority_update,
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

pub fn allocPushPromiseFields(
    allocator: std.mem.Allocator,
    request: RequestReader,
    options: PushPromiseRequestOptions,
) (std.mem.Allocator.Error || PushPromisePolicyError)![]qpack.FieldLine {
    const scheme = options.scheme orelse request.scheme() orelse return error.MissingRequestScheme;
    const authority = options.authority orelse request.authority() orelse return error.MissingRequestAuthority;
    const fields = try allocator.alloc(qpack.FieldLine, 4 + options.headers.len);
    fields[0] = .{ .name = ":method", .value = options.method };
    fields[1] = .{ .name = ":scheme", .value = scheme };
    fields[2] = .{ .name = ":path", .value = options.path };
    fields[3] = .{ .name = ":authority", .value = authority };
    for (options.headers, 0..) |header, i| fields[4 + i] = header;
    errdefer allocator.free(fields);

    try validatePushPromisePolicy(request, fields, options.policy);
    return fields;
}

pub fn validatePushPromisePolicy(
    request: RequestReader,
    promise_fields: []const qpack.FieldLine,
    policy: PushPromisePolicy,
) PushPromisePolicyError!void {
    if (fieldValue(promise_fields, ":protocol") != null) return error.ExtendedConnectPush;

    const method = fieldValue(promise_fields, ":method") orelse return error.MissingPromiseMethod;
    if (policy.require_cacheable_method and !isCacheablePushMethod(method)) {
        return error.UncacheablePushMethod;
    }

    const promise_scheme = fieldValue(promise_fields, ":scheme") orelse return error.MissingPromiseScheme;
    const promise_authority = fieldValue(promise_fields, ":authority") orelse return error.MissingPromiseAuthority;
    const promise_path = fieldValue(promise_fields, ":path") orelse return error.MissingPromisePath;
    if (promise_path.len == 0) return error.MissingPromisePath;

    if (policy.require_same_scheme) {
        const request_scheme = request.scheme() orelse return error.MissingRequestScheme;
        if (!std.ascii.eqlIgnoreCase(request_scheme, promise_scheme)) {
            return error.CrossSchemePush;
        }
    }

    if (policy.require_same_authority) {
        const request_authority = request.authority() orelse return error.MissingRequestAuthority;
        if (!std.ascii.eqlIgnoreCase(request_authority, promise_authority)) {
            return error.CrossAuthorityPush;
        }
    }
}

pub fn isCacheablePushMethod(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "GET") or std.ascii.eqlIgnoreCase(method, "HEAD");
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
