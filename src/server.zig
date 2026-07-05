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
const webtransport_mod = @import("webtransport.zig");

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

    /// Sends a QUIC FIN on the response send side. Identical wire
    /// effect to `ResponseWriter.finish` on the underlying writer.
    pub fn finish(self: *ConnectUdpServerStream) session_mod.Error!void {
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

    /// Sends a QUIC FIN on the response send side. The receive side
    /// may keep delivering frames until the peer FINs / RESETs.
    pub fn finish(self: *WebSocketServerStream) session_mod.Error!void {
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

pub const WebTransportAcceptOptions = webtransport_mod.AcceptOptions;

/// Server-side WebTransport session handle, layered over the Extended
/// CONNECT response that accepted the session
/// (draft-ietf-webtrans-http3-15 §3).
///
/// Mirrors `WebTransportClientStream` on the response side. The server
/// can open both unidirectional and bidirectional WebTransport streams
/// via `openUniStream` / `openBidiStream`. The bidi case is the
/// WebTransport carve-out from RFC 9114 §6.1 ¶3 (which otherwise
/// forbids server-initiated bidi streams in HTTP/3); see
/// `openBidiStream` below for the per-call details.
pub const WebTransportServerStream = struct {
    writer: ResponseWriter,

    pub fn streamId(self: *const WebTransportServerStream) u64 {
        return self.writer.stream_id;
    }

    pub fn sessionId(self: *const WebTransportServerStream) u64 {
        return self.writer.stream_id;
    }

    pub fn sendDatagram(self: *WebTransportServerStream, payload: []const u8) session_mod.Error!void {
        try self.writer.datagram(payload);
    }

    pub fn sendDatagramTracked(self: *WebTransportServerStream, payload: []const u8) session_mod.Error!u64 {
        return try self.writer.datagramTracked(payload);
    }

    pub fn openUniStream(self: *WebTransportServerStream) session_mod.Error!u64 {
        return try self.writer.server.session.openWebTransportUniStream(self.sessionId());
    }

    /// Opens a server-initiated bidirectional WebTransport stream
    /// (draft-ietf-webtrans-http3 §4.2). HTTP/3 normally forbids the
    /// server from initiating bidi streams; the WebTransport extension
    /// carves out exactly this case for cross-peer application
    /// streams. The underlying QUIC stream id has the
    /// server-initiated-bidi pattern (low bits `0b01`); the prefix
    /// (frame type `0x41` + Session ID) is written automatically.
    pub fn openBidiStream(self: *WebTransportServerStream) session_mod.Error!u64 {
        return try self.writer.server.session.openWebTransportBidiStream(self.sessionId());
    }

    pub fn writeStream(
        self: *WebTransportServerStream,
        stream_id: u64,
        bytes: []const u8,
    ) session_mod.Error!void {
        try self.writer.server.session.writeWebTransportStream(stream_id, bytes);
    }

    pub fn finishStream(self: *WebTransportServerStream, stream_id: u64) session_mod.Error!void {
        try self.writer.server.session.finishWebTransportStream(stream_id);
    }

    pub fn resetStream(
        self: *WebTransportServerStream,
        stream_id: u64,
        app_error_code: u32,
    ) session_mod.Error!void {
        try self.writer.server.session.resetWebTransportStream(stream_id, app_error_code);
    }

    pub fn resetStreamWithCode(
        self: *WebTransportServerStream,
        stream_id: u64,
        wire_code: u64,
    ) session_mod.Error!void {
        try self.writer.server.session.resetWebTransportStreamWithCode(stream_id, wire_code);
    }

    pub fn sendDrain(self: *WebTransportServerStream) (session_mod.Error || webtransport_mod.Error)!void {
        var buf: [16]u8 = undefined;
        const n = try webtransport_mod.encodeDrainSession(&buf);
        try self.writer.write(buf[0..n]);
    }

    /// Sends a WebTransport flow-control capsule (`WT_MAX_DATA`)
    /// advertising a higher receive limit to the peer.
    pub fn sendMaxData(self: *WebTransportServerStream, value: u64) session_mod.Error!void {
        try self.writer.server.session.sendWebTransportMaxData(self.sessionId(), value);
    }

    /// Sends `WT_MAX_STREAMS_BIDI`.
    pub fn sendMaxStreamsBidi(self: *WebTransportServerStream, value: u64) session_mod.Error!void {
        try self.writer.server.session.sendWebTransportMaxStreams(self.sessionId(), .bidi, value);
    }

    /// Sends `WT_MAX_STREAMS_UNI`.
    pub fn sendMaxStreamsUni(self: *WebTransportServerStream, value: u64) session_mod.Error!void {
        try self.writer.server.session.sendWebTransportMaxStreams(self.sessionId(), .uni, value);
    }

    /// Folds an inbound capsule decoded from the CONNECT stream's body
    /// into the per-session flow-control state. Mirror of
    /// `WebTransportClientStream.observeCapsule`.
    pub fn observeCapsule(
        self: *WebTransportServerStream,
        decoded: capsule_mod.Capsule,
    ) session_mod.Error!void {
        try self.writer.server.session.observeWebTransportCapsule(self.sessionId(), decoded);
    }

    pub fn flowState(self: *const WebTransportServerStream) ?session_mod.WTSessionFlowSnapshot {
        return self.writer.server.session.webTransportFlowSnapshot(self.sessionId());
    }

    pub fn close(
        self: *WebTransportServerStream,
        code: u32,
        reason: []const u8,
    ) (session_mod.Error || webtransport_mod.Error)!void {
        var stack_buf: [16 + 4 + webtransport_mod.max_close_reason_len]u8 = undefined;
        const n = try webtransport_mod.encodeCloseSession(&stack_buf, code, reason);
        try self.writer.write(stack_buf[0..n]);
        try self.writer.finish();
    }

    /// Sends a QUIC FIN on the CONNECT control stream's response side —
    /// implicit close per draft-ietf-webtrans-http3-15 §5.4. After this
    /// returns, the local WT registry entry is also torn down (see
    /// `Session.finishStream`). For an explicit close with code +
    /// reason, prefer `close(code, reason)`.
    pub fn finish(self: *WebTransportServerStream) session_mod.Error!void {
        try self.writer.finish();
    }

    pub fn reset(self: *WebTransportServerStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn abort(self: *WebTransportServerStream) session_mod.Error!void {
        try self.writer.abort();
    }

    /// Pragmatic escape hatch for advanced operations on the underlying
    /// CONNECT response writer — raw `capsule` emit,
    /// `sendState` / `canBuffer` / `canWrite` plumbing.
    ///
    /// WARNING: calling `datagramCapsule` / `datagramContextCapsule`
    /// through the returned writer is NOT a valid WebTransport datagram
    /// send — the WebTransport draft mandates the QUIC-DATAGRAM path.
    /// Use `WebTransportServerStream.sendDatagram` /
    /// `sendDatagramTracked` for WT datagrams. Capsule sends through
    /// this accessor are out-of-spec for WT (they target the CONNECT
    /// stream's body, not WT's per-session datagram channel) and only
    /// make sense in non-WT contexts. See README's `## Datagram sends`
    /// section for the full comparison.
    pub fn responseWriter(self: *WebTransportServerStream) *ResponseWriter {
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

    pub fn isWebTransport(self: RequestReader) bool {
        return self.request.isWebTransport();
    }

    pub fn webTransportAvailableProtocolsRaw(self: RequestReader) ?[]const u8 {
        return self.request.webTransportAvailableProtocolsRaw();
    }

    pub fn webTransportSubprotocols(
        self: RequestReader,
        allocator: std.mem.Allocator,
    ) (webtransport_mod.Error || std.mem.Allocator.Error)!webtransport_mod.ParsedAvailableProtocols {
        return self.request.webTransportSubprotocols(allocator);
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
    webtransport_stream_opened: session_mod.WebTransportStreamOpenedEvent,
    webtransport_stream_data: session_mod.WebTransportStreamDataEvent,
    webtransport_stream_finished: session_mod.WebTransportStreamFinishedEvent,
    webtransport_stream_reset: session_mod.WebTransportStreamResetEvent,
    webtransport_flow_violated: session_mod.WebTransportFlowViolationEvent,
    goaway: u64,
    connection_closed: ConnectionClosed,
    ignored_unknown_frame: UnknownFrame,

    pub fn from(event: session_mod.Event) ?RequestEvent {
        return switch (event) {
            .peer_settings => |settings| .{ .settings = settings },
            .headers => |headers| if (headers.kind == .request) .{
                .headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else null,
            // 1xx interim responses are server-emitted by definition;
            // server-side request observers never see them.
            .interim_headers => null,
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
            .webtransport_stream_opened => |opened| .{ .webtransport_stream_opened = opened },
            .webtransport_stream_data => |data| .{ .webtransport_stream_data = data },
            .webtransport_stream_finished => |finished| .{ .webtransport_stream_finished = finished },
            .webtransport_stream_reset => |reset| .{ .webtransport_stream_reset = reset },
            .webtransport_flow_violated => |v| .{ .webtransport_flow_violated = v },
        };
    }
};

pub const Server = struct {
    session: *session_mod.Session,

    /// Server-side top-level configuration knobs.
    ///
    /// All fields default to the same permissive values the underlying
    /// `session_mod.Config` uses (so an unconfigured `Config{}` is a 1:1
    /// pass-through). Hand-tuning is still supported, but most users
    /// should opt into the `production` preset for v0.1.0:
    ///
    /// ```zig
    /// var session = http3_zig.Session.init(
    ///     allocator, .server, &quic_conn,
    ///     http3_zig.Server.Config.production.toSessionConfig(),
    /// );
    /// ```
    ///
    /// The struct only enumerates fields with a meaningful production
    /// vs. default split; everything else stays at session-level
    /// defaults.
    pub const Config = struct {
        /// Cap on concurrent peer-opened streams the session will
        /// track. `null` preserves the legacy unbounded behaviour.
        /// Mirrors `session_mod.Config.max_concurrent_peer_streams`.
        max_concurrent_peer_streams: ?usize = null,

        /// Cap on encoded HEADERS payload bytes per QPACK field
        /// section. `null` preserves the legacy unbounded behaviour.
        /// Mirrors `session_mod.Config.max_field_section_size` (it is
        /// also re-advertised via SETTINGS when this knob is set).
        max_field_section_size: ?u64 = null,

        /// Cap on bytes a single peer-opened WebTransport stream may
        /// buffer while waiting for its session under
        /// `BufferedStreamPolicy.buffer`. `null` preserves the legacy
        /// unbounded behaviour. Mirrors
        /// `session_mod.Config.wt_max_buffered_bytes_per_stream`.
        wt_max_buffered_bytes_per_stream: ?usize = null,

        /// Policy for peer-opened WebTransport streams whose Session
        /// ID references a session that has not yet been confirmed.
        /// Mirrors `session_mod.Config.buffered_stream_policy`.
        buffered_stream_policy: session_mod.BufferedStreamPolicy = .pass_through,

        /// Cap on aggregate owned event payload bytes emitted by one
        /// `drain` call. `null` preserves the legacy unbounded
        /// behaviour. Mirrors
        /// `session_mod.Config.max_event_payload_bytes_per_drain`.
        max_event_payload_bytes_per_drain: ?usize = null,

        /// Cap on the number of events emitted by one `drain` call.
        /// `null` preserves the legacy unbounded behaviour. Mirrors
        /// `session_mod.Config.max_events_per_drain`.
        max_events_per_drain: ?usize = null,

        /// Cap on tracked RFC 9218 priority hints (the per-request and
        /// per-push maps, each). `null` preserves the legacy unbounded
        /// behaviour. Mirrors `session_mod.Config.max_tracked_priorities`.
        max_tracked_priorities: ?usize = null,

        /// Cap on tracked received PUSH_PROMISE field sections (client
        /// role). `null` preserves the legacy behaviour. Mirrors
        /// `session_mod.Config.max_tracked_push_promises`.
        max_tracked_push_promises: ?usize = null,

        /// Cap on unconfirmed pending WebTransport sessions (server role).
        /// `null` preserves the legacy behaviour. Mirrors
        /// `session_mod.Config.max_pending_wt_sessions`.
        max_pending_wt_sessions: ?usize = null,

        /// Production-grade defaults: tighter resource caps, strict
        /// buffering policies. Uses defaults for any field not listed.
        ///
        /// Override list (with rationale):
        ///   - `max_concurrent_peer_streams = 256`
        ///       Defense-in-depth cap on peer-opened streams the
        ///       session will track; protects against a peer that
        ///       opens streams without finishing them. Tighter than
        ///       QUIC's MAX_STREAMS budget (which is generous by
        ///       design).
        ///   - `max_field_section_size = 16 KiB`
        ///       Bounds encoded HEADERS payload bytes per field
        ///       section, limiting the cost of an oversized header
        ///       attack. 16 KiB is comfortable for ordinary REST
        ///       traffic.
        ///   - `wt_max_buffered_bytes_per_stream = 16 KiB`
        ///       Bounds bytes a single peer-opened WebTransport stream
        ///       may buffer while waiting for its session
        ///       (draft-ietf-webtrans-http3-15 §4.5).
        ///   - `buffered_stream_policy = .reject`
        ///       Reject peer-opened WT streams whose session has not
        ///       yet been confirmed instead of buffering or surfacing
        ///       them. Avoids unbounded buffering of bytes for a
        ///       session that may never confirm.
        ///   - `max_event_payload_bytes_per_drain = 4 MiB`
        ///       Caps owned payload bytes a single `drain` may emit,
        ///       providing backpressure on bursts of large frames.
        ///   - `max_events_per_drain = 512`
        ///       Caps event count per `drain`, providing structural
        ///       backpressure independent of payload size.
        ///   - `max_tracked_priorities = 1024`
        ///       Bounds cached RFC 9218 priority hints so a peer flooding
        ///       PRIORITY_UPDATE for distinct ids can't grow them without
        ///       limit; excess updates for new ids are dropped.
        ///   - `max_tracked_push_promises = 256`
        ///       Bounds tracked received PUSH_PROMISE field sections;
        ///       exceeding closes with H3_EXCESSIVE_LOAD.
        ///   - `max_pending_wt_sessions = 256`
        ///       Bounds unconfirmed pending WebTransport sessions;
        ///       exceeding closes with H3_EXCESSIVE_LOAD.
        pub const production: @This() = .{
            .max_concurrent_peer_streams = 256,
            .max_field_section_size = 16 * 1024,
            .wt_max_buffered_bytes_per_stream = 16 * 1024,
            .buffered_stream_policy = .reject,
            .max_event_payload_bytes_per_drain = 4 * 1024 * 1024,
            .max_events_per_drain = 512,
            .max_tracked_priorities = 1024,
            .max_tracked_push_promises = 256,
            .max_pending_wt_sessions = 256,
        };

        /// Project the preset onto a `session_mod.Config`, leaving all
        /// other knobs at their session-level defaults.
        ///
        /// `max_field_section_size` is also re-advertised via the
        /// connection's local SETTINGS so the peer respects the
        /// tighter cap; this matches the wiring in
        /// `session_mod.Config.production`.
        pub fn toSessionConfig(self: Config) session_mod.Config {
            var session_config: session_mod.Config = .{
                .max_concurrent_peer_streams = self.max_concurrent_peer_streams,
                .max_field_section_size = self.max_field_section_size,
                .wt_max_buffered_bytes_per_stream = self.wt_max_buffered_bytes_per_stream,
                .buffered_stream_policy = self.buffered_stream_policy,
                .max_event_payload_bytes_per_drain = self.max_event_payload_bytes_per_drain,
                .max_events_per_drain = self.max_events_per_drain,
                .max_tracked_priorities = self.max_tracked_priorities,
                .max_tracked_push_promises = self.max_tracked_push_promises,
                .max_pending_wt_sessions = self.max_pending_wt_sessions,
            };
            if (self.max_field_section_size) |max| {
                session_config.settings.max_field_section_size = max;
            }
            return session_config;
        }
    };

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

    /// Clean half-close — QUIC FIN on the response send side. No error
    /// code; bytes already sent are committed. See `Session.finishStream`.
    pub fn finish(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    /// Outbound abort — RESET_STREAM with `error_code`, dropping our own
    /// in-flight response bytes. To also stop receiving the request body,
    /// follow with `rejectRequest` on the session. See `Session.resetResponse`.
    pub fn reset(self: *Server, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetResponse(stream_id, error_code);
    }

    /// Convenience: outbound abort with `internal_error`. Equivalent to
    /// `reset(stream_id, protocol.ErrorCode.internal_error)`.
    pub fn abort(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.reset(stream_id, protocol.ErrorCode.internal_error);
    }

    /// Outbound abort of a server-push response stream — RESET_STREAM
    /// on the push stream. `stream_id` here is the push stream id, not
    /// the parent request stream id.
    pub fn resetPush(self: *Server, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetStream(stream_id, error_code);
    }

    /// Emits a CANCEL_PUSH frame for `push_id` on the control stream
    /// (RFC 9114 §7.2.3). Independent of any push response stream — used
    /// before the push stream is created, or to revoke a promised push.
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
        try websocket_mod.validateClientRequestVersion(request.headers());
        if (!websocket_mod.isAcceptedStatus(options.status)) return error.InvalidAcceptStatus;
        return .{
            .writer = try self.startResponse(allocator, request.streamId(), .{
                .status = options.status,
                .headers = options.headers,
            }),
        };
    }

    /// Accepts a WebTransport session bootstrap (draft-ietf-webtrans-http3-15
    /// §3.3) by sending a `2xx` response on the CONNECT stream. The peer
    /// MUST advertise all three of `SETTINGS_WT_ENABLED`, `H3_DATAGRAM`,
    /// and `ENABLE_CONNECT_PROTOCOL` per draft-15 §9.2; this method
    /// enforces that eagerly so the server doesn't commit to a session
    /// the client cannot drive.
    ///
    /// Errors:
    /// - `error.PeerSettingsNotReceived` — the SETTINGS frame from the
    ///   peer hasn't landed yet. Pump the session loop and retry.
    /// - `error.PeerDidNotEnableWebTransport` — the peer's SETTINGS are
    ///   present but missing one or more of the three required entries.
    /// - `error.NotWebTransport` — the request itself isn't a WT CONNECT.
    /// - `error.InvalidAcceptStatus` — `options.status` isn't 2xx.
    ///
    /// When `options.subprotocol` is non-null, the server must have advertised
    /// the chosen token in the client's `wt-available-protocols` list — this
    /// helper enforces that with `error.SubprotocolNotOffered` and emits the
    /// `wt-protocol` response header on success.
    pub fn acceptWebTransport(
        self: *Server,
        allocator: std.mem.Allocator,
        request: RequestReader,
        options: WebTransportAcceptOptions,
    ) (session_mod.Error || webtransport_mod.Error)!WebTransportServerStream {
        if (!request.isWebTransport()) return error.NotWebTransport;
        if (!webtransport_mod.isAcceptedStatus(options.status)) return error.InvalidAcceptStatus;
        const peer = self.session.peer_settings orelse return webtransport_mod.Error.PeerSettingsNotReceived;
        if (!webtransport_mod.peerEnabled(peer)) return webtransport_mod.Error.PeerDidNotEnableWebTransport;

        var writer: ResponseWriter = undefined;
        if (options.subprotocol) |selected| {
            try webtransport_mod.validateSubprotocolToken(selected);
            const offered = request.webTransportAvailableProtocolsRaw() orelse "";
            if (!webtransport_mod.isOfferedProtocol(offered, selected)) {
                return error.SubprotocolNotOffered;
            }
            const combined = try allocator.alloc(qpack.FieldLine, options.headers.len + 1);
            defer allocator.free(combined);
            combined[0] = .{
                .name = webtransport_mod.protocol_header,
                .value = selected,
            };
            for (options.headers, 0..) |header, i| combined[i + 1] = header;
            writer = try self.startResponse(allocator, request.streamId(), .{
                .status = options.status,
                .headers = combined,
            });
        } else {
            writer = try self.startResponse(allocator, request.streamId(), .{
                .status = options.status,
                .headers = options.headers,
            });
        }

        // Mark the CONNECT stream as a confirmed WebTransport session.
        // Any peer-opened streams that arrive afterwards referencing this
        // Session ID dispatch immediately; bytes already buffered for
        // this session are replayed at the start of the next drain.
        try self.session.confirmWebTransportSession(request.streamId());
        return .{ .writer = writer };
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

    pub fn isWebTransport(self: *const RequestState) bool {
        return webtransport_mod.isRequest(self.headerFields());
    }

    /// Raw `wt-available-protocols` header value, or null if the client
    /// did not offer subprotocols.
    pub fn webTransportAvailableProtocolsRaw(self: *const RequestState) ?[]const u8 {
        return webtransport_mod.requestAvailableProtocolsRaw(self.headerFields());
    }

    /// Parses the client-offered WebTransport subprotocols. Caller frees
    /// the returned `tokens` slice via `ParsedAvailableProtocols.deinit`.
    /// The token sub-slices borrow from the request state's headers, so
    /// the request must outlive their use.
    pub fn webTransportSubprotocols(
        self: *const RequestState,
        allocator: std.mem.Allocator,
    ) (webtransport_mod.Error || std.mem.Allocator.Error)!webtransport_mod.ParsedAvailableProtocols {
        const value = self.webTransportAvailableProtocolsRaw() orelse {
            return .{ .tokens = try allocator.alloc([]const u8, 0) };
        };
        return webtransport_mod.parseAvailableProtocols(allocator, value);
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

/// Owned per-stream HTTP request state that outlives the drained
/// event batch — buffered headers, body, trailers, plus `complete` /
/// `reset` flags addressed by request stream id.
///
/// Scope: the tracker accumulates state for the **HTTP request
/// message on a request stream**. That includes a normal HTTP request
/// and the **CONNECT bootstrap request** for an extended-CONNECT
/// tunnel (WebTransport, WebSocket, CONNECT-UDP) — the CONNECT
/// request itself is an HTTP message and surfaces through the
/// tracker.
///
/// Out of scope: WebTransport substream data, peer-opened WT streams,
/// `webtransport_stream_*` events, and per-WT-stream lifecycle. The
/// tracker's `observe` switch has explicit no-op arms for these — they
/// are NOT tracker bugs. Applications that want to buffer a WT
/// substream's data need their own per-substream state, driven by
/// `webtransport_stream_data` events on the raw event stream.
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
            .webtransport_stream_opened,
            .webtransport_stream_data,
            .webtransport_stream_finished,
            .webtransport_stream_reset,
            .webtransport_flow_violated,
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
