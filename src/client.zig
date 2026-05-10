//! HTTP/3 client-side helpers.

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

    /// Sends an HTTP/3 Datagram (RFC 9297 §2) over a QUIC DATAGRAM frame —
    /// the unreliable, low-latency path. Gated on the QUIC transport
    /// parameter `max_datagram_frame_size > 0` AND
    /// `SETTINGS_H3_DATAGRAM = 1`. This is the WebTransport-spec'd path
    /// for WT datagrams; for CONNECT-UDP / MASQUE multiplexing prefer
    /// `datagramWithContext`. For the reliable on-stream fallback see
    /// `datagramCapsule`. See README's `## Datagram sends` section for
    /// the comparison table.
    pub fn datagram(self: *RequestWriter, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagram(self.stream_id, payload);
    }

    /// Tracked variant of `datagram` — returns the QUIC datagram-id for
    /// later correlation with `datagram_acked` / `datagram_lost` events.
    pub fn datagramTracked(self: *RequestWriter, payload: []const u8) session_mod.Error!u64 {
        return try self.client.sendDatagramTracked(self.stream_id, payload);
    }

    /// Same as `datagram` but with an HTTP Datagram Context-ID prefix
    /// (RFC 9297 §2.1 / draft-ietf-masque-h3-datagram). Used by MASQUE
    /// CONNECT-UDP (context-id 0) and any other context-id-multiplexed
    /// protocol. NOT used by WebTransport (which has no context-id).
    /// See README's `## Datagram sends` section.
    pub fn datagramWithContext(self: *RequestWriter, context_id: u64, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagramWithContext(self.stream_id, context_id, payload);
    }

    /// Tracked variant of `datagramWithContext`.
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

    /// Sends an HTTP Datagram via the Capsule Protocol fallback (RFC 9297
    /// §3.4) — wraps the payload in a `DATAGRAM` capsule on the request
    /// stream. Reliable, ordered with stream bytes, gated only on
    /// `SETTINGS_H3_DATAGRAM = 1`. Useful when QUIC DATAGRAM frames are
    /// dropped by middleboxes or when `max_datagram_frame_size = 0` but
    /// the peer still set `SETTINGS_H3_DATAGRAM = 1`. NOT the
    /// WebTransport-spec'd path for WT datagrams (the draft mandates
    /// QUIC DATAGRAM); use `datagram` for WT. See README's
    /// `## Datagram sends` section.
    pub fn datagramCapsule(self: *RequestWriter, payload: []const u8) session_mod.Error!void {
        try self.client.sendDatagramCapsule(self.stream_id, payload);
    }

    /// Same as `datagramCapsule` but with an HTTP Datagram Context-ID
    /// prefix — the MASQUE-style multiplexing path on the reliable
    /// capsule fallback. See README's `## Datagram sends` section.
    pub fn datagramContextCapsule(
        self: *RequestWriter,
        context_id: u64,
        payload: []const u8,
    ) session_mod.Error!void {
        try self.client.sendDatagramContextCapsule(self.stream_id, context_id, payload);
    }

    pub fn updatePriority(self: *RequestWriter, priority: priority_mod.Priority) session_mod.Error!void {
        try self.client.sendPriorityUpdateForRequest(self.stream_id, priority);
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

    /// Sends a QUIC FIN on the send side. Identical wire effect to
    /// `RequestWriter.finish` on the underlying writer.
    pub fn finish(self: *ConnectUdpClientStream) session_mod.Error!void {
        try self.writer.finish();
    }

    /// Deprecated: use `finish`. Will be removed in v0.3.
    pub fn finishSend(self: *ConnectUdpClientStream) session_mod.Error!void {
        try self.finish();
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

    /// Sends a QUIC FIN on the send side. The receive side may keep
    /// delivering frames until the peer FINs / RESETs.
    pub fn finish(self: *WebSocketClientStream) session_mod.Error!void {
        try self.writer.finish();
    }

    /// Deprecated: use `finish`. Will be removed in v0.3.
    pub fn finishSend(self: *WebSocketClientStream) session_mod.Error!void {
        try self.finish();
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

pub const WebTransportConnectOptions = webtransport_mod.ConnectOptions;

/// Client-side WebTransport session handle, layered over the Extended
/// CONNECT request stream that bootstrapped the session
/// (draft-ietf-webtrans-http3 §3).
///
/// The handle exposes:
///   - datagram send/receive via the existing HTTP/3 Datagram path,
///   - WebTransport stream creation (uni + client-initiated bidi) with the
///     mandatory stream-prefix written automatically,
///   - DRAIN_WEBTRANSPORT_SESSION / CLOSE_WEBTRANSPORT_SESSION capsule sends,
///   - underlying request-writer access for callers who need raw header /
///     trailer / capsule control.
pub const WebTransportClientStream = struct {
    writer: RequestWriter,

    pub fn streamId(self: *const WebTransportClientStream) u64 {
        return self.writer.stream_id;
    }

    /// The WebTransport Session ID is the request stream ID of the CONNECT
    /// request that opened the session (draft-ietf-webtrans-http3 §2.3).
    pub fn sessionId(self: *const WebTransportClientStream) u64 {
        return self.writer.stream_id;
    }

    pub fn sendDatagram(self: *WebTransportClientStream, payload: []const u8) session_mod.Error!void {
        try self.writer.datagram(payload);
    }

    pub fn sendDatagramTracked(self: *WebTransportClientStream, payload: []const u8) session_mod.Error!u64 {
        return try self.writer.datagramTracked(payload);
    }

    /// Opens a new client-initiated WebTransport unidirectional stream and
    /// writes the WebTransport stream prefix. Returns the underlying QUIC
    /// stream id for subsequent `writeStream` / `finishStream` /
    /// `resetStream` calls.
    pub fn openUniStream(self: *WebTransportClientStream) session_mod.Error!u64 {
        return try self.writer.client.session.openWebTransportUniStream(self.sessionId());
    }

    /// Opens a new client-initiated WebTransport bidirectional stream and
    /// writes the WebTransport bidi-frame prefix.
    pub fn openBidiStream(self: *WebTransportClientStream) session_mod.Error!u64 {
        return try self.writer.client.session.openWebTransportBidiStream(self.sessionId());
    }

    pub fn writeStream(
        self: *WebTransportClientStream,
        stream_id: u64,
        bytes: []const u8,
    ) session_mod.Error!void {
        try self.writer.client.session.writeWebTransportStream(stream_id, bytes);
    }

    pub fn finishStream(self: *WebTransportClientStream, stream_id: u64) session_mod.Error!void {
        try self.writer.client.session.finishWebTransportStream(stream_id);
    }

    pub fn resetStream(
        self: *WebTransportClientStream,
        stream_id: u64,
        app_error_code: u32,
    ) session_mod.Error!void {
        try self.writer.client.session.resetWebTransportStream(stream_id, app_error_code);
    }

    pub fn resetStreamWithCode(
        self: *WebTransportClientStream,
        stream_id: u64,
        wire_code: u64,
    ) session_mod.Error!void {
        try self.writer.client.session.resetWebTransportStreamWithCode(stream_id, wire_code);
    }

    /// Sends a `DRAIN_WEBTRANSPORT_SESSION` capsule on the CONNECT stream;
    /// the peer is expected to stop opening new streams but may finish
    /// in-flight work (draft-ietf-webtrans-http3 §5.5).
    pub fn sendDrain(self: *WebTransportClientStream) (session_mod.Error || webtransport_mod.Error)!void {
        var buf: [16]u8 = undefined;
        const n = try webtransport_mod.encodeDrainSession(&buf);
        try self.writer.write(buf[0..n]);
    }

    /// Sends a WebTransport flow-control capsule (`WT_MAX_DATA`)
    /// advertising a higher receive limit to the peer. Updates
    /// `flowState().local_max_data` to match.
    pub fn sendMaxData(self: *WebTransportClientStream, value: u64) session_mod.Error!void {
        try self.writer.client.session.sendWebTransportMaxData(self.sessionId(), value);
    }

    /// Sends `WT_MAX_STREAMS_BIDI`. Mirror of `sendMaxData` for the
    /// peer's allowed concurrent bidi streams.
    pub fn sendMaxStreamsBidi(self: *WebTransportClientStream, value: u64) session_mod.Error!void {
        try self.writer.client.session.sendWebTransportMaxStreams(self.sessionId(), .bidi, value);
    }

    /// Sends `WT_MAX_STREAMS_UNI`.
    pub fn sendMaxStreamsUni(self: *WebTransportClientStream, value: u64) session_mod.Error!void {
        try self.writer.client.session.sendWebTransportMaxStreams(self.sessionId(), .uni, value);
    }

    /// Folds an inbound capsule decoded from the CONNECT stream's body
    /// into the per-session flow-control state. Call this when
    /// iterating capsules out of `response_updated.body()` events for
    /// the CONNECT stream — the session uses the resulting state to
    /// gate `writeStream` / `openUniStream` / `openBidiStream`.
    /// Capsules outside the WebTransport family are ignored.
    pub fn observeCapsule(
        self: *WebTransportClientStream,
        decoded: capsule_mod.Capsule,
    ) session_mod.Error!void {
        try self.writer.client.session.observeWebTransportCapsule(self.sessionId(), decoded);
    }

    /// Read-only snapshot of the per-session flow-control counters and
    /// peer-advertised limits.
    pub fn flowState(self: *const WebTransportClientStream) ?session_mod.WTSessionFlowSnapshot {
        return self.writer.client.session.webTransportFlowSnapshot(self.sessionId());
    }

    /// Sends a `CLOSE_WEBTRANSPORT_SESSION` capsule and finishes the CONNECT
    /// stream. After this call returns, the session MUST NOT carry further
    /// application traffic (draft-ietf-webtrans-http3 §5.4).
    pub fn close(
        self: *WebTransportClientStream,
        code: u32,
        reason: []const u8,
    ) (session_mod.Error || webtransport_mod.Error)!void {
        var stack_buf: [16 + 4 + webtransport_mod.max_close_reason_len]u8 = undefined;
        const n = try webtransport_mod.encodeCloseSession(&stack_buf, code, reason);
        try self.writer.write(stack_buf[0..n]);
        try self.writer.finish();
    }

    /// Sends a QUIC FIN on the CONNECT control stream's send side —
    /// implicit close per draft-ietf-webtrans-http3-15 §5.4. After this
    /// returns, the local WT registry entry is also torn down (see
    /// `Session.finishStream`). For an explicit close with code +
    /// reason, prefer `close(code, reason)`.
    pub fn finish(self: *WebTransportClientStream) session_mod.Error!void {
        try self.writer.finish();
    }

    /// Deprecated: use `finish`. Will be removed in v0.3.
    pub fn finishSend(self: *WebTransportClientStream) session_mod.Error!void {
        try self.finish();
    }

    pub fn reset(self: *WebTransportClientStream, error_code: u64) session_mod.Error!void {
        try self.writer.reset(error_code);
    }

    pub fn abort(self: *WebTransportClientStream) session_mod.Error!void {
        try self.writer.abort();
    }

    /// Pragmatic escape hatch for advanced operations on the underlying
    /// CONNECT request writer — `updatePriority`, raw `capsule` emit,
    /// `sendState` / `canBuffer` / `canWrite` plumbing.
    ///
    /// WARNING: calling `datagramCapsule` / `datagramContextCapsule`
    /// through the returned writer is NOT a valid WebTransport datagram
    /// send — the WebTransport draft mandates the QUIC-DATAGRAM path.
    /// Use `WebTransportClientStream.sendDatagram` /
    /// `sendDatagramTracked` for WT datagrams. Capsule sends through
    /// this accessor are out-of-spec for WT (they target the CONNECT
    /// stream's body, not WT's per-session datagram channel) and only
    /// make sense in non-WT contexts. See README's `## Datagram sends`
    /// section for the full comparison.
    pub fn requestWriter(self: *WebTransportClientStream) *RequestWriter {
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

    pub fn priority(self: ResponseReader) priority_mod.Error!?priority_mod.Priority {
        return try self.response.priority();
    }

    pub fn webSocketAccepted(self: ResponseReader) bool {
        return self.response.webSocketAccepted();
    }

    pub fn connectUdpAccepted(self: ResponseReader) bool {
        return self.response.connectUdpAccepted();
    }

    pub fn webTransportAccepted(self: ResponseReader) bool {
        return self.response.webTransportAccepted();
    }

    pub fn webTransportSubprotocol(self: ResponseReader) ?[]const u8 {
        return self.response.webTransportSubprotocol();
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
    /// 1xx informational response (RFC 9110 §15.2). Surfaced before
    /// the final `headers` event when the server sends an interim
    /// status (e.g. `100 Continue`, `103 Early Hints`).
    interim_headers: Headers,
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
    webtransport_stream_opened: session_mod.WebTransportStreamOpenedEvent,
    webtransport_stream_data: session_mod.WebTransportStreamDataEvent,
    webtransport_stream_finished: session_mod.WebTransportStreamFinishedEvent,
    webtransport_stream_reset: session_mod.WebTransportStreamResetEvent,
    webtransport_flow_violated: session_mod.WebTransportFlowViolationEvent,
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
            .interim_headers => |headers| if (headers.kind == .response) .{
                .interim_headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
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
            .priority_update => null,
            .webtransport_stream_opened => |opened| .{ .webtransport_stream_opened = opened },
            .webtransport_stream_data => |data| .{ .webtransport_stream_data = data },
            .webtransport_stream_finished => |finished| .{ .webtransport_stream_finished = finished },
            .webtransport_stream_reset => |reset| .{ .webtransport_stream_reset = reset },
            .webtransport_flow_violated => |v| .{ .webtransport_flow_violated = v },
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

    pub fn priority(self: *const ResponseState) priority_mod.Error!?priority_mod.Priority {
        return try priority_mod.fromFieldLines(self.headerFields());
    }

    pub fn webSocketAccepted(self: *const ResponseState) bool {
        return websocket_mod.responseAccepted(self.headerFields());
    }

    pub fn connectUdpAccepted(self: *const ResponseState) bool {
        return masque_mod.responseAccepted(self.headerFields());
    }

    pub fn webTransportAccepted(self: *const ResponseState) bool {
        return webtransport_mod.responseAccepted(self.headerFields());
    }

    /// Server-selected WebTransport subprotocol from the response's
    /// `wt-protocol` header. Returns null if the server did not select
    /// one. Borrows from the headers slice — keep the response state
    /// alive while the slice is in use.
    pub fn webTransportSubprotocol(self: *const ResponseState) ?[]const u8 {
        return webtransport_mod.responseSelectedProtocolRaw(self.headerFields());
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

/// Owned per-stream HTTP response state that outlives the drained
/// event batch — buffered headers, body, trailers, push promises, plus
/// `complete` / `reset` flags addressed by request stream id.
///
/// Scope: the tracker accumulates state for the **HTTP request/response
/// exchange on a request stream**. That includes a normal HTTP
/// request/response and the **CONNECT bootstrap exchange** for an
/// extended-CONNECT tunnel (WebTransport, WebSocket, CONNECT-UDP) — the
/// CONNECT request and its 2xx response are HTTP messages and surface
/// through the tracker.
///
/// Out of scope: WebTransport substream data, peer-opened WT streams,
/// `webtransport_stream_*` events, and per-WT-stream lifecycle. The
/// tracker's `observe` switch has explicit no-op arms for these — they
/// are NOT tracker bugs. Applications that want to buffer a WT
/// substream's data need their own per-substream state, driven by
/// `webtransport_stream_data` events on the raw event stream.
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
            // Interim 1xx headers do NOT update the response tracker
            // (they don't replace the final headers; they sit in
            // front of them in the event stream). The application
            // observes them directly via ClientObservation.interim_headers.
            .interim_headers,
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
            .webtransport_stream_opened,
            .webtransport_stream_data,
            .webtransport_stream_finished,
            .webtransport_stream_reset,
            .webtransport_flow_violated,
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

    pub fn priority(self: PushedResponseReader) priority_mod.Error!?priority_mod.Priority {
        return try self.pushed.priority();
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

    pub fn priority(self: *const PushedResponseState) priority_mod.Error!?priority_mod.Priority {
        return try priority_mod.fromFieldLines(self.headerFields());
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

/// Owned per-push state that outlives the drained event batch —
/// promise field section, response headers, body, trailers, completion
/// flag, reset/cancel records, addressed by `push_id` (with a
/// `push_id_by_stream` index for stream-id lookups).
///
/// Scope: like `ResponseTracker`, this accumulates state for an
/// **HTTP request/response exchange** — specifically the
/// PUSH_PROMISE / push-stream pairing (RFC 9114 §4.6). That is an
/// HTTP message exchange, and the tracker is the right place for it.
///
/// Out of scope: WebTransport substreams (server push and WT live on
/// different stream classes; the WT carve-out of server-initiated
/// bidi streams from RFC 9114 §6.1 ¶3 is unrelated to push). For WT
/// substream data accumulation see `webtransport_stream_data` events.
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

    /// Client-side top-level configuration knobs.
    ///
    /// All fields default to the same permissive values the underlying
    /// `session_mod.Config` uses (so an unconfigured `Config{}` is a 1:1
    /// pass-through). Hand-tuning is still supported, but most users
    /// should opt into the `production` preset for v0.1.0:
    ///
    /// ```zig
    /// var session = http3_zig.Session.init(
    ///     allocator, .client, &quic_conn,
    ///     http3_zig.Client.Config.production.toSessionConfig(),
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
        max_field_section_size: ?usize = null,

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
        pub const production: @This() = .{
            .max_concurrent_peer_streams = 256,
            .max_field_section_size = 16 * 1024,
            .wt_max_buffered_bytes_per_stream = 16 * 1024,
            .buffered_stream_policy = .reject,
            .max_event_payload_bytes_per_drain = 4 * 1024 * 1024,
            .max_events_per_drain = 512,
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
            };
            if (self.max_field_section_size) |max| {
                session_config.settings.max_field_section_size = @intCast(max);
            }
            return session_config;
        }
    };

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

    /// Clean half-close — QUIC FIN on the send side. No error code;
    /// bytes already sent are committed. See `Session.finishStream`.
    pub fn finish(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    /// Outbound abort — RESET_STREAM with `error_code`, dropping our own
    /// in-flight bytes. To also discard the response, follow with `cancel`.
    /// See `Session.resetRequest`.
    pub fn reset(self: *Client, stream_id: u64, error_code: u64) session_mod.Error!void {
        try self.session.resetRequest(stream_id, error_code);
    }

    /// Convenience: outbound abort with `request_cancelled`. Equivalent to
    /// `reset(stream_id, protocol.ErrorCode.request_cancelled)`.
    pub fn abort(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.reset(stream_id, protocol.ErrorCode.request_cancelled);
    }

    /// Inbound abort — QUIC STOP_SENDING with `request_cancelled`,
    /// asking the server to stop sending us the response body. Does NOT
    /// drop our request send buffer — pair with `reset` for a full
    /// bidirectional abort. See `Session.cancelRequest`.
    pub fn cancel(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.cancelRequest(stream_id);
    }

    pub fn cancelPush(self: *Client, push_id: u64) session_mod.Error!void {
        try self.session.cancelPush(push_id);
    }

    pub fn sendPriorityUpdateForRequest(
        self: *Client,
        stream_id: u64,
        priority: priority_mod.Priority,
    ) session_mod.Error!void {
        try self.session.sendPriorityUpdateForRequest(stream_id, priority);
    }

    pub fn sendPriorityUpdateForPush(
        self: *Client,
        push_id: u64,
        priority: priority_mod.Priority,
    ) session_mod.Error!void {
        try self.session.sendPriorityUpdateForPush(push_id, priority);
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
        // RFC 6455 §4.1 / RFC 9220 §4.2: the client MUST include
        // `Sec-WebSocket-Version: 13` in the bootstrap CONNECT request.
        // Inject it ahead of caller-supplied headers; `startRequest`
        // deep-copies headers, so a stack-local slice is fine.
        const combined = try allocator.alloc(qpack.FieldLine, options.headers.len + 1);
        defer allocator.free(combined);
        combined[0] = .{
            .name = websocket_mod.version_header_name,
            .value = websocket_mod.version_token,
        };
        for (options.headers, 0..) |header, i| combined[i + 1] = header;

        return .{
            .writer = try self.startRequest(allocator, .{
                .method = "CONNECT",
                .scheme = options.scheme,
                .authority = options.authority,
                .path = options.path,
                .connect_protocol = websocket_mod.protocol_token,
                .headers = combined,
            }),
        };
    }

    /// Bootstraps a WebTransport session (draft-ietf-webtrans-http3-15 §3.2)
    /// over an Extended CONNECT request. The peer MUST advertise all three
    /// of `SETTINGS_WT_ENABLED`, `H3_DATAGRAM`, and
    /// `ENABLE_CONNECT_PROTOCOL` per draft-15 §9.2; this method enforces
    /// that eagerly so the application doesn't commit to a session the
    /// peer cannot drive.
    ///
    /// Errors:
    /// - `error.PeerSettingsNotReceived` — the SETTINGS frame from the
    ///   peer hasn't landed yet. Pump the session loop and retry.
    /// - `error.PeerDidNotEnableWebTransport` — the peer's SETTINGS are
    ///   present but missing one or more of the three required entries.
    ///
    /// When `options.subprotocols` is non-empty, a `wt-available-protocols`
    /// header is added to the request carrying the comma-separated list of
    /// offered subprotocols. The server's choice (if any) is surfaced on the
    /// response via `ResponseReader.webTransportSubprotocol()`.
    pub fn startWebTransport(
        self: *Client,
        allocator: std.mem.Allocator,
        options: WebTransportConnectOptions,
    ) (session_mod.Error || webtransport_mod.Error)!WebTransportClientStream {
        const peer = self.session.peer_settings orelse return webtransport_mod.Error.PeerSettingsNotReceived;
        if (!webtransport_mod.peerEnabled(peer)) return webtransport_mod.Error.PeerDidNotEnableWebTransport;

        var writer: RequestWriter = undefined;
        if (options.subprotocols.len == 0) {
            writer = try self.startRequest(allocator, .{
                .method = "CONNECT",
                .scheme = options.scheme,
                .authority = options.authority,
                .path = options.path,
                .connect_protocol = webtransport_mod.protocol_token,
                .headers = options.headers,
            });
        } else {
            const available_value = try webtransport_mod.allocAvailableProtocols(allocator, options.subprotocols);
            defer allocator.free(available_value);

            const combined = try allocator.alloc(qpack.FieldLine, options.headers.len + 1);
            defer allocator.free(combined);
            combined[0] = .{
                .name = webtransport_mod.available_protocols_header,
                .value = available_value,
            };
            for (options.headers, 0..) |header, i| combined[i + 1] = header;

            writer = try self.startRequest(allocator, .{
                .method = "CONNECT",
                .scheme = options.scheme,
                .authority = options.authority,
                .path = options.path,
                .connect_protocol = webtransport_mod.protocol_token,
                .headers = combined,
            });
        }

        // Register the CONNECT stream as a pending WebTransport session.
        // The session moves to `.established` when the client observes a
        // 2xx response on this stream (handled in
        // session.processMessageState).
        try self.session.markWebTransportSessionPending(writer.stream_id);
        return .{ .writer = writer };
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
    // RFC 9114 §4.4 ¶3: classic CONNECT (`:method = "CONNECT"`,
    // no `:protocol`) MUST omit `:scheme` and `:path`. Extended
    // CONNECT (with `:protocol`) keeps both. Auto-detect rather
    // than expose another knob — the caller can still pass empty
    // strings if they prefer to be explicit; this just stops us
    // from emitting fields the validator would (correctly) reject.
    const is_classic_connect = std.mem.eql(u8, options.method, "CONNECT") and
        options.connect_protocol == null;
    const pseudo_count: usize = if (is_classic_connect) 2 else 4;
    const protocol_len: usize = if (options.connect_protocol != null) 1 else 0;
    const fields = try allocator.alloc(qpack.FieldLine, pseudo_count + protocol_len + options.headers.len);
    fields[0] = .{ .name = ":method", .value = options.method };
    var pos: usize = 1;
    if (!is_classic_connect) {
        fields[pos] = .{ .name = ":scheme", .value = options.scheme };
        pos += 1;
        fields[pos] = .{ .name = ":path", .value = options.path };
        pos += 1;
    }
    fields[pos] = .{ .name = ":authority", .value = options.authority };
    pos += 1;
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
