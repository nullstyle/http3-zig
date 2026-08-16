//! HTTP/3 session layer over `quic.Connection`.
//!
//! The session owns HTTP/3 stream classification, control stream
//! SETTINGS, message framing, and request/response convenience APIs.
//! QPACK defaults to the non-blocking static/literal profile, with opt-in
//! dynamic table state wired through the HTTP/3 QPACK encoder/decoder streams.

const std = @import("std");
const quic = @import("quic");

const errors_mod = @import("errors.zig");
const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const frame_mod = @import("frame.zig");
const headers_mod = @import("headers.zig");
const message_mod = @import("message.zig");
const observability_mod = @import("observability.zig");
const priority_mod = @import("priority.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const settings_mod = @import("settings.zig");
const stream_mod = @import("stream.zig");
const webtransport_mod = @import("webtransport.zig");
const earlydata = @import("earlydata.zig");

const varint = quic.wire.varint;

pub const Error = quic.conn.state.Error ||
    frame_mod.Error ||
    capsule_mod.Error ||
    datagram_mod.Error ||
    message_mod.Error ||
    priority_mod.Error ||
    stream_mod.FrameValidationError ||
    settings_mod.Error ||
    qpack.Error ||
    varint.Error ||
    std.mem.Allocator.Error ||
    error{
        /// A second control / QPACK encoder / QPACK decoder uni stream was
        /// opened locally; only one of each is allowed (RFC 9114 §6.2).
        CriticalStreamAlreadyOpen,
        /// `start()` was called after the QPACK encoder + decoder streams
        /// were already opened — internal state-machine guard.
        QpackStreamsAlreadyOpen,
        /// A role-specific method was called from the wrong role
        /// (e.g. `sendResponseHeaders` on a client session, or
        /// `cancelRequest` on a server session).
        InvalidRole,
        /// The underlying QUIC stream's send buffer accepted zero bytes —
        /// either the stream is fully blocked by flow control or its local
        /// `max_stream_send_buffered` cap is hit. Caller should drain
        /// acknowledgements (run a pump) and retry.
        WriteStalled,
        /// `rememberPeerSettings` was called after the peer's real SETTINGS
        /// already arrived; remembered settings only make sense before the
        /// resumed connection's SETTINGS land (RFC 9114 §7.2.4.2).
        RememberedSettingsTooLate,
        /// The server's SETTINGS on a connection that ACCEPTED 0-RTT are
        /// incompatible with what the client remembered (RFC 9114
        /// §7.2.4.2 ¶5-¶6). The session closes with H3_SETTINGS_ERROR.
        RememberedSettingsViolated,
        /// Internal classification: peer used a stream type that the
        /// session machine doesn't expect at this point in the lifecycle
        /// (e.g. server opening a request stream).
        UnexpectedStream,
        /// Caller passed a `stream_id` that the session doesn't know
        /// about (never opened, or already torn down).
        MissingStream,
        /// Internal state mismatch — a method was called for the wrong
        /// `Kind` of message stream (request/response/push). Indicates a
        /// caller bug, not a peer protocol error.
        WrongMessageKind,
        /// Peer closed (FIN or RESET) one of the critical uni streams
        /// (control, QPACK encoder, QPACK decoder). Per RFC 9114 §6.2
        /// this is a connection-level error; surfaced before the
        /// session enters a closed state so the caller can observe it.
        ClosedCriticalStream,
        /// `sendGoaway` rejected the supplied id: not the right parity
        /// for the role, or not monotonically non-increasing relative
        /// to a previously sent value (RFC 9114 §5.2).
        InvalidGoawayId,
        /// Push id was outside the allowed range (negative parity, beyond
        /// the peer-advertised `MAX_PUSH_ID`, or unknown when referenced).
        InvalidPushId,
        /// PRIORITY_UPDATE targeted a stream id that doesn't exist or
        /// isn't a request/push stream (RFC 9218 §7.2).
        InvalidPriorityTarget,
        /// Two PUSH_PROMISE frames carried the same push id but
        /// different field sections (RFC 9114 §7.2.5 — receiver MUST
        /// reject).
        InconsistentPushPromise,
        /// Client tried to open a new request after the peer sent a
        /// GOAWAY whose id covers this stream (RFC 9114 §5.2).
        RequestBlockedByGoaway,
        /// Server tried to start a push after it had already sent a
        /// GOAWAY covering the next push id, or the peer's GOAWAY
        /// covers it.
        PushBlockedByGoaway,
        /// Peer never advertised a non-zero `MAX_PUSH_ID`; pushes are
        /// forbidden until they do.
        PushNotEnabled,
        /// Next push id would exceed the peer-advertised `MAX_PUSH_ID`.
        PushLimitExceeded,
        /// Peer didn't advertise `SETTINGS_H3_DATAGRAM = 1` (RFC 9297
        /// §2.2.1). Datagram and DATAGRAM-capsule sends are gated on
        /// this. The local-receive path also surfaces it if a datagram
        /// arrives before our own SETTINGS opt-in.
        DatagramNotEnabled,
        /// Encoded datagram exceeds the peer-advertised
        /// `max_datagram_frame_size` QUIC transport parameter.
        DatagramTooLarge,
        /// Capsule value exceeds the local `Config.max_capsule_value_size`
        /// cap. Caller-initiated; not a protocol violation.
        CapsuleTooLarge,
        /// `Config.max_stream_send_buffered` would be exceeded by the
        /// requested write. Caller should run a pump to flush
        /// acknowledgements and retry.
        SendBufferFull,
        /// A single drained event's payload exceeds
        /// `Config.max_event_payload_size`. The session emits the
        /// `connection_closed` event with `H3_EXCESSIVE_LOAD` and
        /// surfaces this so the caller stops draining.
        EventPayloadTooLarge,
        /// One pump's drain exceeded `Config.max_events_per_drain` or
        /// `Config.max_event_payload_bytes_per_drain`. Soft signal —
        /// the caller can drain again immediately to pick up where
        /// this batch left off.
        EventQueueFull,
        /// Local send would exceed the peer-advertised WT_MAX_DATA
        /// limit (draft-ietf-webtrans-http3 §5.6.4). The session
        /// auto-emits WT_DATA_BLOCKED before returning this error.
        WebTransportFlowControlExceeded,
        /// Local stream open would exceed the peer-advertised
        /// WT_MAX_STREAMS_BIDI / _UNI limit (§5.6.2). The session
        /// auto-emits the matching WT_STREAMS_BLOCKED capsule before
        /// returning this error.
        WebTransportStreamLimitExceeded,
        /// A WebTransport primitive was invoked with a session or
        /// stream id that has no known WebTransport state (not in
        /// `wt_sessions`, or a stream with no session association).
        UnknownWebTransportSession,
        /// A peer-opened stream would push the session's tracked
        /// stream count past `Config.max_concurrent_peer_streams`.
        /// The session sends STOP_SENDING with
        /// `H3_REQUEST_REJECTED` and surfaces this error so the
        /// session pump can advance without dispatching the stream.
        PeerStreamLimitExceeded,
        /// A new PUSH_PROMISE would push `received_push_promises` past
        /// `Config.max_tracked_push_promises` (client). The session closes
        /// the connection with H3_EXCESSIVE_LOAD.
        ExcessivePushPromises,
        /// A new WebTransport CONNECT would push the pending-session
        /// count past `Config.max_pending_wt_sessions` (server). The
        /// session closes the connection with H3_EXCESSIVE_LOAD.
        ExcessivePendingWebTransportSessions,
        /// Accepting/confirming a WebTransport session would push the
        /// ESTABLISHED count past `Config.max_wt_sessions` (or, client
        /// side on a draft-07 connection, past the peer's advertised
        /// session willingness). Per-request soft error — never a
        /// connection error; servers answer with
        /// `Server.rejectWebTransport` (429 or a reset).
        WebTransportSessionLimitReached,
        /// A modern-era WebTransport verb (`sendMaxData`,
        /// `sendMaxStreams*`) was invoked on a session whose resolved
        /// draft era predates session-level flow control. The browser
        /// eras have no flow-control capsules; the send is refused
        /// rather than emitting bytes the peer never defined.
        WebTransportEraUnsupported,
        /// Locally-initiated WebTransport stream open after the peer
        /// has sent `DRAIN_WEBTRANSPORT_SESSION`
        /// (draft-ietf-webtrans-http3 §5.5). Existing streams may
        /// still flow; new opens are forbidden.
        WebTransportSessionDraining,
        /// A send-side method was called after `Session.close()` ran
        /// (or the session locally observed a fatal error). Distinct
        /// from the QUIC-level errors that would otherwise surface
        /// from the underlying connection — gives the application a
        /// clean signal to stop driving the session and tear it down.
        SessionClosed,
    };

pub const ProductionOptions = struct {
    qpack_decoder_table_capacity: u64 = 4096,
    qpack_blocked_streams: u64 = 16,
    qpack_encoder_table_capacity: usize = 0,
    qpack_indexing: qpack.IndexingPolicy = qpack.IndexingPolicy.static_only,
    enable_qpack_huffman: bool = true,
    max_field_lines: usize = 128,
    max_decoded_field_section_bytes: usize = 128 * 1024,
    max_field_section_size: u64 = 64 * 1024,
    /// Declared-length cap for incoming non-DATA frames (see
    /// `Config.max_incoming_frame_length`). 128 KiB comfortably clears the
    /// 64 KiB `max_field_section_size` while bounding control/GREASE frames.
    max_incoming_frame_length: u64 = 128 * 1024,
    max_data_frame_payload: usize = 16 * 1024,
    max_datagram_payload_size: usize = 16 * 1024,
    max_capsule_value_size: usize = 64 * 1024,
    max_stream_send_buffered: usize = 1 * 1024 * 1024,
    max_event_payload_size: usize = 1 * 1024 * 1024,
    max_event_payload_bytes_per_drain: usize = 4 * 1024 * 1024,
    max_events_per_drain: usize = 512,
    /// Maximum number of concurrent peer-opened streams the session
    /// will track. A peer that opens streams without finishing them
    /// otherwise grows the internal `streams` map unboundedly. Once
    /// the cap is hit, further peer-opened streams are rejected
    /// (request streams: STOP_SENDING with `H3_REQUEST_REJECTED`;
    /// uni streams of unknown type: STOP_SENDING with the same code).
    /// Locally-opened streams do NOT count against this cap.
    /// QUIC's MAX_STREAMS already bounds per-direction stream
    /// counts; this is a defense-in-depth knob at the HTTP/3 layer
    /// covering the case where MAX_STREAMS is generous but session
    /// state shouldn't grow proportionally.
    max_concurrent_peer_streams: usize = 1024,
    /// See `Config.max_tracked_priorities`. Caps the RFC 9218 priority-hint
    /// maps; a PRIORITY_UPDATE for a new id beyond the cap is dropped.
    max_tracked_priorities: usize = 1024,
    /// See `Config.max_tracked_push_promises`. Caps tracked received
    /// PUSH_PROMISE field sections; a new promise beyond the cap closes
    /// with H3_EXCESSIVE_LOAD.
    max_tracked_push_promises: usize = 256,
    /// See `Config.max_pending_wt_sessions`. Caps unconfirmed pending
    /// WebTransport sessions; a new one beyond the cap closes with
    /// H3_EXCESSIVE_LOAD.
    max_pending_wt_sessions: usize = 256,
    /// Maximum bytes a single peer-opened WebTransport stream may
    /// buffer while waiting for its session to be confirmed under
    /// `BufferedStreamPolicy.buffer`. A stream that exceeds this
    /// cap is reset with `WEBTRANSPORT_BUFFERED_STREAM_REJECTED`
    /// and dropped from the buffered list. Combined with
    /// `max_concurrent_peer_streams`, the effective session-wide
    /// buffered cap is `max_concurrent_peer_streams *
    /// wt_max_buffered_bytes_per_stream`. Draft-15 §4.5 suggests
    /// "endpoints SHOULD limit the number of buffered bytes."
    wt_max_buffered_bytes_per_stream: usize = 64 * 1024,
    /// Aggregate cap for bytes held across all peer-opened WebTransport
    /// streams waiting for session confirmation under
    /// `BufferedStreamPolicy.buffer`. This gives production users a direct
    /// total-memory budget instead of relying only on the product of the
    /// per-stream cap and the concurrent-stream cap.
    wt_max_total_buffered_bytes: usize = 4 * 1024 * 1024,
    enable_connect_protocol: bool = false,
    enable_datagram: bool = false,
    /// Advertise WebTransport via `SETTINGS_WT_ENABLED`
    /// (draft-ietf-webtrans-http3 §9.2). Both client and server MUST
    /// send the setting with a non-zero value to bootstrap a session.
    /// WebTransport additionally requires
    /// `enable_connect_protocol = true` and `enable_datagram = true`;
    /// `production()` enables both implicitly when `enable_webtransport`
    /// is set. Draft-15 removed the numeric `WT_MAX_SESSIONS` knob — the
    /// peer is now expected to use stream/transport flow control rather
    /// than a SETTINGS-advertised session count.
    enable_webtransport: bool = false,
    /// Additionally advertise the draft-02 browser-era bootstrap
    /// (`SETTINGS_ENABLE_WEBTRANSPORT`) — what shipped Chrome and
    /// shipped Firefox speak. Default off so the default wire surface
    /// stays modern-only; flip it for browser-facing deployments. The
    /// draft-07 era knob arrives with the session-cap work (its
    /// SETTINGS value IS a session cap, and advertisement must equal
    /// enforcement).
    enable_webtransport_draft02: bool = false,
    /// Additionally advertise the draft-07 browser-era bootstrap
    /// (`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`) — quiche peers and Chrome
    /// behind its default-off flag. The advertised value IS the session
    /// cap: `max_wt_sessions` (defaulted to 256 here when this is set)
    /// is both advertised and enforced, never one without the other.
    enable_webtransport_draft07: bool = false,
    /// Cap on established WebTransport sessions (see
    /// `Config.max_wt_sessions`). Null = 256 when a draft-07 era knob
    /// requires an advertised value, otherwise uncapped.
    max_wt_sessions: ?usize = null,
    /// Initial per-session WebTransport flow-control credit this endpoint
    /// advertises via the draft-15 §9.2 SETTINGS
    /// (`SETTINGS_WT_INITIAL_MAX_DATA` / `_STREAMS_UNI` / `_STREAMS_BIDI`).
    /// When set, the peer may send up to this much data / open this many
    /// streams on every WT session before an explicit capsule arrives —
    /// and this endpoint enforces the limit on receive from session open.
    /// `null` (the default) advertises nothing: no initial credit and no
    /// receive-side enforcement until the application grants it with a
    /// `WT_MAX_DATA` / `WT_MAX_STREAMS` capsule, preserving prior behavior.
    wt_initial_max_data: ?u64 = null,
    wt_initial_max_streams_uni: ?u64 = null,
    wt_initial_max_streams_bidi: ?u64 = null,
    /// Policy for peer-opened WebTransport streams that arrive before
    /// the corresponding session has been confirmed
    /// (draft-ietf-webtrans-http3 §4.5).
    buffered_stream_policy: BufferedStreamPolicy = .pass_through,
    max_push_id: ?u64 = null,
    push_policy: PushPolicy = .accept,
};

pub const Config = struct {
    settings: settings_mod.Settings = .{},
    /// Literal/static QPACK does not require encoder/decoder streams. Dynamic
    /// QPACK enables them automatically; this flag keeps the explicit stream
    /// setup available for peers and tests that expect the streams to exist.
    enable_qpack_streams: bool = false,
    /// Maximum dynamic table capacity this endpoint will use as an encoder.
    /// The effective capacity is also bounded by the peer's
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    qpack_encoder_table_capacity: usize = 0,
    /// Static-only by default. Set dynamic insert/reference modes to opt into
    /// QPACK encoder-stream instructions and dynamic field-section references.
    qpack_indexing: qpack.IndexingPolicy = qpack.IndexingPolicy.static_only,
    enable_qpack_huffman: bool = false,
    /// Optional cap on decoded QPACK field-line count per field section.
    max_field_lines: ?usize = null,
    /// Optional cap on decoded field names/values plus field-line storage per
    /// QPACK field section. Only consulted when `max_field_section_size` is
    /// unset — RFC 9114 §4.2.2 ties the settings-facing limit to DECODED
    /// bytes (name + value + 32 per field), so `max_field_section_size`
    /// drives the decode budget whenever it is set.
    max_decoded_field_section_bytes: ?usize = null,
    /// Advertised as SETTINGS_MAX_FIELD_SECTION_SIZE and enforced per
    /// RFC 9114 §4.2.2 on the DECODED field section (name + value + 32
    /// bytes per field). The read-loop declared-length pre-gate applies
    /// 2x slack because Huffman encoding can expand a section ~1.6x.
    max_field_section_size: ?u64 = null,
    /// Optional cap on the DECLARED length of an incoming non-DATA HTTP/3
    /// frame (SETTINGS/GOAWAY/CANCEL_PUSH/MAX_PUSH_ID/PRIORITY_UPDATE and
    /// unknown/GREASE frames; HEADERS/PUSH_PROMISE are additionally bounded
    /// by `max_field_section_size`). The frame is rejected on its declared
    /// length — before its payload is reassembled into the per-stream rx
    /// buffer — so untrusted receive buffering is bounded by this value
    /// rather than by the QUIC stream flow-control window (which an embedder
    /// may set far above the header cap). DATA frames are intentionally
    /// exempt: they are legitimately large and bounded by QUIC flow control
    /// plus the application body budget. Null preserves the legacy behavior;
    /// `production()` defaults to 128 KiB.
    max_incoming_frame_length: ?u64 = null,
    read_chunk_size: usize = 4096,
    max_data_frame_payload: usize = 16 * 1024,
    max_datagram_payload_size: usize = 64 * 1024,
    /// Optional cap on outgoing Capsule Protocol value bytes before reliable
    /// DATA-frame capsule payloads are allocated.
    max_capsule_value_size: ?usize = null,
    /// Client-only opt-in for server push. Null means do not send MAX_PUSH_ID.
    max_push_id: ?u64 = null,
    /// RFC 9114 §7.2.8: send GREASE — one reserved SETTINGS entry in the
    /// initial SETTINGS frame and one reserved-type unidirectional stream at
    /// session start — so peers' mandatory unknown-codepoint tolerance stays
    /// exercised by every session, not just by adversaries. Values are
    /// deterministic (no RNG dependency); disable for byte-exact wire tests.
    enable_grease: bool = true,
    /// Optional cap on per-stream bytes buffered in quic but not yet
    /// acknowledged. Leave null to preserve unbounded legacy behavior.
    max_stream_send_buffered: ?usize = null,
    /// Optional cap on owned payload bytes copied for any single emitted event.
    /// DATA, DATAGRAM, push-promise blocks, close reasons, and cloned field
    /// lines count toward this limit.
    max_event_payload_size: ?usize = null,
    /// Optional cap on aggregate owned event payload bytes emitted by one
    /// `drain` call.
    max_event_payload_bytes_per_drain: ?usize = null,
    /// Optional cap on the number of events emitted by one `drain` call.
    max_events_per_drain: ?usize = null,
    /// Optional cap on the number of concurrent peer-opened streams the
    /// session will track. A peer that opens streams without finishing
    /// them otherwise grows the internal `streams` map unboundedly.
    /// Null preserves the legacy unbounded behavior; `production()`
    /// defaults to 1024.
    max_concurrent_peer_streams: ?usize = null,
    /// Opt-in eager reclaim of bidirectional streams the peer has RESET.
    /// A peer RESET leaves a request/response stream half-closed (its
    /// receive side is terminal, but the local send side is still open),
    /// so its `StreamState` lingers in the `streams` map — bounded by
    /// `max_concurrent_peer_streams`, but never released — until the local
    /// side also closes. When true, a peer RESET tears the local side down
    /// immediately (the peer has abandoned the exchange, so there is
    /// nothing left to send) and the per-drain GC reclaims the entry the
    /// same pass the `stream_reset` event is surfaced. Off by default: some
    /// applications take deliberate action on a reset and expect the stream
    /// to persist until they close it — with this on, referencing the
    /// stream id after its `stream_reset` event is a use-after-reclaim.
    /// Scope is deliberately narrow (peer RESET of a plain bidi stream):
    /// peer FIN is *not* reclaimed, because a server legitimately keeps
    /// sending a response after the client's request FIN, and reclaiming
    /// there would drop in-flight responses.
    reclaim_peer_reset_streams: bool = false,
    /// Optional cap on tracked RFC 9218 priority hints — applied to the
    /// per-request (`request_priorities`) and per-push (`push_priorities`)
    /// maps independently. A peer flooding PRIORITY_UPDATE for distinct
    /// stream/push ids otherwise grows these unboundedly, and they are not
    /// reclaimed when a stream closes. Priorities are advisory, so an
    /// update for a new id beyond the cap is dropped (RFC 9218 §7 permits
    /// ignoring PRIORITY_UPDATE). Null preserves the legacy unbounded
    /// behavior; `production()` defaults to 1024.
    max_tracked_priorities: ?usize = null,
    /// Optional cap on tracked received PUSH_PROMISE field sections
    /// (`received_push_promises`, client only). A server promising distinct
    /// push ids up to the advertised MAX_PUSH_ID otherwise grows this
    /// unboundedly. A new promise beyond the cap closes the connection with
    /// H3_EXCESSIVE_LOAD. Null preserves the legacy behavior (bounded only
    /// by MAX_PUSH_ID); `production()` defaults to 256.
    max_tracked_push_promises: ?usize = null,
    /// Optional cap on ESTABLISHED WebTransport sessions. The modern
    /// draft has no SETTINGS-advertised session count — over-cap
    /// sessions are refused at accept time with 429 / a reset via
    /// `Server.rejectWebTransport` — while on a draft-07 connection
    /// this value doubles as the advertised
    /// `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` (advertisement always
    /// equals enforcement). `checkWebTransportSessionCapacity` /
    /// `acceptWebTransport` enforce it; null = uncapped.
    /// `production()` defaults it to 256 whenever the draft-07 era is
    /// enabled. Orthogonal to `max_pending_wt_sessions` below (DoS
    /// hygiene on unconfirmed CONNECTs vs protocol policy on live
    /// sessions).
    max_wt_sessions: ?usize = null,
    /// Optional cap on unconfirmed pending WebTransport sessions
    /// (pending entries in `wt_sessions`, server only) — CONNECT streams that began a
    /// WT handshake but have not been accepted or torn down. A peer opening
    /// many WT CONNECTs without completing them otherwise grows this up to
    /// MAX_STREAMS_BIDI. A new pending session beyond the cap closes the
    /// connection with H3_EXCESSIVE_LOAD. Null preserves the legacy
    /// behavior; `production()` defaults to 256.
    max_pending_wt_sessions: ?usize = null,
    /// Optional cap on bytes a single peer-opened WebTransport stream
    /// may buffer while waiting for its session under
    /// `BufferedStreamPolicy.buffer`. Null preserves the legacy
    /// unbounded behavior; `production()` defaults to 64 KiB.
    /// (draft-ietf-webtrans-http3 §4.5)
    wt_max_buffered_bytes_per_stream: ?usize = null,
    /// Optional aggregate cap on bytes held across all peer-opened
    /// WebTransport streams waiting for session confirmation under
    /// `BufferedStreamPolicy.buffer`. Null preserves the legacy behavior;
    /// `production()` defaults to 4 MiB.
    /// (draft-ietf-webtrans-http3 §4.5)
    wt_max_total_buffered_bytes: ?usize = null,
    /// Optional typed HTTP/3 trace callback. Metrics are always tracked; the
    /// callback lets embedders translate events into logs or qlog JSON.
    observability: observability_mod.Hooks = .{},
    /// Client-only policy for valid incoming PUSH_PROMISE frames.
    push_policy: PushPolicy = .accept,
    /// Policy for peer-opened WebTransport streams whose Session ID
    /// references a WebTransport session that has not yet been confirmed.
    buffered_stream_policy: BufferedStreamPolicy = .pass_through,

    pub fn production(options: ProductionOptions) Config {
        // WebTransport requires both Extended CONNECT and HTTP/3
        // Datagrams. The production preset auto-enables them whenever
        // `enable_webtransport` is set so callers don't have to remember
        // the prerequisites.
        const enable_connect_protocol = options.enable_connect_protocol or
            options.enable_webtransport or options.enable_webtransport_draft02 or
            options.enable_webtransport_draft07;
        const enable_datagram = options.enable_datagram or
            options.enable_webtransport or options.enable_webtransport_draft02 or
            options.enable_webtransport_draft07;
        // Advertisement equals enforcement: when draft-07 is enabled its
        // SETTINGS value and the enforced cap derive from ONE option.
        const wt_session_cap: ?usize = options.max_wt_sessions orelse
            (if (options.enable_webtransport_draft07) @as(?usize, 256) else null);

        return .{
            .settings = .{
                .qpack_max_table_capacity = options.qpack_decoder_table_capacity,
                .qpack_blocked_streams = options.qpack_blocked_streams,
                .max_field_section_size = options.max_field_section_size,
                .enable_connect_protocol = enable_connect_protocol,
                .h3_datagram = enable_datagram,
                .wt_enabled = options.enable_webtransport,
                .wt_draft02 = options.enable_webtransport_draft02,
                .wt_draft07_max_sessions = if (options.enable_webtransport_draft07)
                    @as(?u64, @intCast(wt_session_cap.?))
                else
                    null,
                .wt_initial_max_data = options.wt_initial_max_data,
                .wt_initial_max_streams_uni = options.wt_initial_max_streams_uni,
                .wt_initial_max_streams_bidi = options.wt_initial_max_streams_bidi,
            },
            .qpack_encoder_table_capacity = options.qpack_encoder_table_capacity,
            .qpack_indexing = options.qpack_indexing,
            .enable_qpack_huffman = options.enable_qpack_huffman,
            .max_field_lines = options.max_field_lines,
            .max_decoded_field_section_bytes = options.max_decoded_field_section_bytes,
            .max_field_section_size = options.max_field_section_size,
            .max_incoming_frame_length = options.max_incoming_frame_length,
            .max_data_frame_payload = options.max_data_frame_payload,
            .max_datagram_payload_size = options.max_datagram_payload_size,
            .max_capsule_value_size = options.max_capsule_value_size,
            .max_push_id = options.max_push_id,
            .max_stream_send_buffered = options.max_stream_send_buffered,
            .max_event_payload_size = options.max_event_payload_size,
            .max_event_payload_bytes_per_drain = options.max_event_payload_bytes_per_drain,
            .max_events_per_drain = options.max_events_per_drain,
            .max_concurrent_peer_streams = options.max_concurrent_peer_streams,
            .max_tracked_priorities = options.max_tracked_priorities,
            .max_tracked_push_promises = options.max_tracked_push_promises,
            .max_wt_sessions = wt_session_cap,
            .max_pending_wt_sessions = options.max_pending_wt_sessions,
            .wt_max_buffered_bytes_per_stream = options.wt_max_buffered_bytes_per_stream,
            .wt_max_total_buffered_bytes = options.wt_max_total_buffered_bytes,
            .push_policy = options.push_policy,
            .buffered_stream_policy = options.buffered_stream_policy,
        };
    }
};

pub const BufferedStreamPolicy = enum {
    /// Surface peer-opened WebTransport stream events even when the
    /// referenced session has not yet been confirmed. Backwards-compatible
    /// behaviour; the application is responsible for correlating the
    /// stream with its session.
    pass_through,
    /// Reset peer-opened WebTransport streams whose Session ID does not
    /// match a confirmed session, using the reserved
    /// `WEBTRANSPORT_BUFFERED_STREAM_REJECTED` (0x3994bd84) wire code per
    /// draft-ietf-webtrans-http3 §4.5.
    reject,
    /// Hold peer-opened WebTransport stream bytes until the referenced
    /// session is confirmed, then replay the dispatch in order. Streams
    /// whose session is never confirmed (or is closed before
    /// confirmation) are abandoned.
    buffer,
};

pub const PushPolicy = enum {
    /// Emit valid PUSH_PROMISE events and accept matching push streams.
    accept,
    /// Emit valid PUSH_PROMISE events, immediately send CANCEL_PUSH, and abort
    /// any matching push stream that has already arrived.
    cancel_promises,
};

pub const FieldEvent = struct {
    stream_id: u64,
    kind: message_mod.Kind,
    fields: []qpack.FieldLine,
    /// Server-side, `kind == .request` only: any of this request stream's
    /// bytes arrived in 0-RTT packets (sticky, `Connection.
    /// streamArrivedInEarlyData`). Mirrors the datagram provenance flag.
    /// Always false client-side and for non-request kinds.
    arrived_in_early_data: bool = false,
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
    fields: []qpack.FieldLine,
};

pub const PushStreamEvent = struct {
    stream_id: u64,
    push_id: u64,
};

pub const CancelPushEvent = struct {
    push_id: u64,
};

pub const PriorityTarget = union(enum) {
    request_stream: u64,
    push: u64,
};

pub const PriorityUpdateEvent = struct {
    target: PriorityTarget,
    priority: priority_mod.Priority,
    priority_field_value: []u8,
};

pub const LocalPush = struct {
    request_stream_id: u64,
    push_id: u64,
    stream_id: u64,
};

pub const DatagramEvent = struct {
    stream_id: u64,
    payload: []u8,
    arrived_in_early_data: bool = false,
};

// quic-zig 0.5.0 re-exports these ConnectionEvent-payload types at the top
// level, so name them there instead of reaching into the internal `conn.*` /
// `conn.state.*` tier (not covered by quic-zig's stability guarantee).
pub const DatagramSendEvent = quic.DatagramSendEvent;
pub const FlowBlockedEvent = quic.FlowBlockedInfo;
pub const FlowBlockedKind = quic.FlowBlockedKind;
pub const FlowBlockedSource = quic.FlowBlockedSource;
pub const ConnectionIdsNeededEvent = quic.ConnectionIdReplenishInfo;

pub const StreamSendState = struct {
    stream_id: u64,
    written_bytes: u64,
    acked_bytes: u64,
    buffered_bytes: u64,
    has_pending: bool,
    flow_blocked: ?FlowBlockedEvent = null,

    pub fn overLimit(self: StreamSendState, max_buffered: usize) bool {
        return self.buffered_bytes > @as(u64, @intCast(max_buffered));
    }
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
    /// `.local` only for client-side malformed-response aborts
    /// (RFC 9114 §4.1.2); peer resets keep the default.
    source: errors_mod.Source = .peer,

    pub fn errorInfo(self: StreamResetEvent) errors_mod.StreamError {
        return switch (self.source) {
            .peer => errors_mod.peerStreamError(self.stream_id, self.error_code, self.final_size),
            .local => errors_mod.localStreamError(self.stream_id, self.error_code, self.final_size),
        };
    }
};

pub const RequestRejectedEvent = struct {
    stream_id: u64,
    error_code: u64,

    pub fn errorInfo(self: RequestRejectedEvent) errors_mod.StreamError {
        return errors_mod.localStreamError(self.stream_id, self.error_code, null);
    }
};

pub const ConnectionClosedEvent = struct {
    source: quic.CloseSource,
    error_space: quic.CloseErrorSpace,
    error_code: u64,
    frame_type: u64,
    reason: []u8,
    reason_truncated: bool,
    at_us: ?u64,
    draining_deadline_us: ?u64,
    application: ?errors_mod.ApplicationError,

    pub fn deinit(self: ConnectionClosedEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }

    pub fn applicationError(self: ConnectionClosedEvent) ?errors_mod.ApplicationError {
        if (self.error_space != .application) return null;
        return self.application orelse errors_mod.applicationError(self.error_code);
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

/// One in-flight request/response exchange, yielded by
/// `Session.openRequestStreams`. Plain scalars — safe to copy and hold
/// across drains (though the stream it names may close in the meantime).
pub const OpenRequestStream = struct {
    stream_id: u64,
    /// Connection-clock time (`quic.Connection.last_activity_us`,
    /// i.e. the same `now_us` domain the embedder feeds
    /// `handle`/`tick`/`poll`) at which the session last surfaced an
    /// event for this stream — or the stream's creation time if no
    /// event has fired yet. Zero only before any packet activity.
    /// Compare against the loop's current `now_us` to enforce
    /// per-request deadlines.
    last_event_us: u64,
};

/// Iterator over in-flight request streams; see
/// `Session.openRequestStreams`. Borrows the session's stream table:
/// iterate to completion before calling anything that can create or
/// reclaim streams (`drain`, `openRequest`, …). Rejecting or resetting
/// mid-iteration is safe today but collect-then-act is the robust
/// pattern — see the embedding guide's "Request deadlines" section.
pub const OpenRequestStreamIterator = struct {
    session: *const Session,
    inner: std.AutoHashMapUnmanaged(u64, *StreamState).Iterator,

    pub fn next(self: *OpenRequestStreamIterator) ?OpenRequestStream {
        while (self.inner.next()) |entry| {
            const state = entry.value_ptr.*;
            if (!self.session.isOpenRequestState(state)) continue;
            return .{
                .stream_id = state.id,
                .last_event_us = state.last_event_us,
            };
        }
        return null;
    }
};

/// 0-RTT disposition on a resumed client connection (RFC 9114 §7.2.4.2).
/// Emitted at most once, from `drain`, when the transport learns the
/// outcome. On `rejected` no application action is required to complete
/// staged requests — the transport retransmits 0-RTT stream data verbatim
/// at 1-RTT (quic's pinned requeue contract); the event exists so apps
/// with non-idempotent semantics can cancel/reset affected streams.
pub const EarlyDataEvent = struct {
    status: Status,
    /// BoringSSL's rejection reason ("" when accepted). Static storage —
    /// not owned by the event; `freeEvent` ignores it.
    reason: []const u8,

    pub const Status = enum { accepted, rejected };
};

/// Re-export of `webtransport.StreamKind`. The session-level events
/// (`WebTransportStreamOpenedEvent`, `WebTransportStreamDataEvent`,
/// etc.) carry this kind so applications can branch on uni vs bidi
/// without re-deriving it from the stream id. Same enum as
/// `webtransport.StreamKind` — kept under the `session.` namespace
/// for ergonomic access from event handlers.
pub const WebTransportStreamKind = webtransport_mod.StreamKind;

/// Typed handle to one WebTransport substream. Returned by the client/
/// server facades' `openUniStream`/`openBidiStream` and constructible from
/// event data via their `streamHandle`; every verb delegates to the
/// `Session.*WebTransportStream` primitives, which stay public as the
/// raw-u64 escape hatch. The type distinction is the point: a session
/// facade's `finish()`/`reset()` (CONNECT-stream scope, ends the session)
/// and a substream's `finish()`/`reset()` are now different types, where a
/// bare substream id passed to a session-level method used to FIN or reset
/// the CONNECT stream and implicitly close the whole session (draft
/// §4.6/§5.4). Deliberately carries no capsule or datagram surface —
/// substream code cannot reach the WT-out-of-spec capsule-datagram path.
/// A plain value: copyable, storable in application maps, no deinit.
pub const WebTransportStream = struct {
    session: *Session,
    /// CONNECT stream id of the owning WebTransport session.
    session_id: u64,
    /// QUIC stream id of this substream — public so applications can
    /// correlate with `WebTransportStream*Event.stream_id`.
    stream_id: u64,
    kind: WebTransportStreamKind,

    /// Send bytes on the substream (`Session.writeWebTransportStream`).
    pub fn write(self: WebTransportStream, bytes: []const u8) Error!void {
        try self.session.writeWebTransportStream(self.stream_id, bytes);
    }

    /// FIN this substream's send side (`Session.finishWebTransportStream`).
    pub fn finish(self: WebTransportStream) Error!void {
        try self.session.finishWebTransportStream(self.stream_id);
    }

    /// Reset with an application error code, translated through the
    /// WebTransport-to-HTTP/3 mapping (draft §4.6).
    pub fn reset(self: WebTransportStream, app_error_code: u32) Error!void {
        try self.session.resetWebTransportStream(self.stream_id, app_error_code);
    }

    /// Reset with a reserved wire code, bypassing the §4.6 mapping.
    pub fn resetWithCode(self: WebTransportStream, wire_code: u64) Error!void {
        try self.session.resetWebTransportStreamWithCode(self.stream_id, wire_code);
    }

    /// Send-side progress snapshot (`Session.streamSendState`).
    pub fn sendState(self: WebTransportStream) Error!StreamSendState {
        return self.session.streamSendState(self.stream_id);
    }

    /// Backpressure probe (`Session.canBufferStreamBytes`).
    pub fn canBuffer(self: WebTransportStream, additional_bytes: usize) Error!bool {
        return self.session.canBufferStreamBytes(self.stream_id, additional_bytes);
    }

    /// Transport send-window headroom for this substream
    /// (`Session.streamSendWindow`): bytes a `write` could hand to the
    /// transport as NEW data right now, or null when the stream is
    /// unknown to the transport. Complements `canBuffer` (H3-side
    /// buffering cap) with the QUIC-side flow-control view; the WT
    /// session-level budget is `flowState()`. Unstable tier — rides on
    /// an upstream-Unstable accessor.
    pub fn writable(self: WebTransportStream) ?usize {
        const window = self.session.streamSendWindow(self.stream_id) orelse return null;
        return window.writable;
    }
};

pub const WebTransportStreamOpenedEvent = struct {
    stream_id: u64,
    session_id: u64,
    kind: WebTransportStreamKind,
};

pub const WebTransportStreamDataEvent = struct {
    stream_id: u64,
    session_id: u64,
    kind: WebTransportStreamKind,
    data: []u8,
};

pub const WebTransportStreamFinishedEvent = struct {
    stream_id: u64,
    session_id: u64,
    kind: WebTransportStreamKind,
};

pub const WebTransportFlowViolationKind = enum {
    /// Peer sent data that would push `peer_data_received` past our
    /// advertised `local_max_data`.
    data_overflow,
    /// Peer opened a bidi stream that would exceed our advertised
    /// `local_max_streams_bidi`.
    streams_bidi_overflow,
    /// Peer opened a uni stream that would exceed our advertised
    /// `local_max_streams_uni`.
    streams_uni_overflow,
};

pub const WebTransportFlowViolationEvent = struct {
    stream_id: u64,
    session_id: u64,
    kind: WebTransportFlowViolationKind,
    /// The value the peer overflowed (our advertised limit).
    limit: u64,
};

pub const WebTransportStreamResetEvent = struct {
    stream_id: u64,
    session_id: u64,
    kind: WebTransportStreamKind,
    /// Raw QUIC stream error code on the wire.
    error_code: u64,
    /// 32-bit application code recovered via the WebTransport
    /// HTTP/3 → app mapping (draft-ietf-webtrans-http3 §4.6). `null` if
    /// the wire code lands on a reserved stride boundary or one of the
    /// `WEBTRANSPORT_BUFFERED_STREAM_REJECTED` / `WEBTRANSPORT_SESSION_GONE`
    /// reserved codes — the raw wire code is always preserved alongside.
    application_error_code: ?u32,
    final_size: u64,
};

/// Which per-session WebTransport limit a flow-control capsule refers to.
pub const WebTransportLimitKind = enum { data, streams_bidi, streams_uni };

pub const WebTransportSessionEstablishedEvent = struct {
    session_id: u64,
};

pub const WebTransportSessionClosedHow = enum {
    /// The peer's CLOSE_WEBTRANSPORT_SESSION capsule ended the session
    /// (`code`/`reason` carry its payload).
    close_capsule,
    /// The peer FIN'd the CONNECT stream without a CLOSE capsule.
    fin,
    /// The peer reset the CONNECT stream (`wire_error_code` preserved).
    reset,
    /// We terminated the session locally for a protocol violation;
    /// `wire_error_code` is the WT_* code we sent on the CONNECT reset
    /// (or H3_MESSAGE_ERROR for a malformed capsule stream).
    protocol_violation,
};

pub const WebTransportSessionClosedEvent = struct {
    session_id: u64,
    how: WebTransportSessionClosedHow,
    /// 32-bit application close code — present only for `.close_capsule`.
    code: ?u32,
    /// Owned UTF-8 close reason; empty when none. Freed via
    /// `event.deinit` like every owned payload.
    reason: []u8,
    /// `.reset`: the RESET wire code. `.protocol_violation`: the code we
    /// sent. Null otherwise.
    wire_error_code: ?u64,
};

pub const WebTransportSessionDrainingEvent = struct {
    session_id: u64,
};

pub const WebTransportPeerBlockedEvent = struct {
    session_id: u64,
    kind: WebTransportLimitKind,
    /// The limit value the peer reports being blocked at (the capsule's
    /// payload varint).
    offered_limit: u64,
};

pub const WebTransportCreditGrantedEvent = struct {
    session_id: u64,
    kind: WebTransportLimitKind,
    /// The new, strictly-greater limit now in force for our sends.
    limit: u64,
};

pub const WebTransportUnknownCapsuleEvent = struct {
    session_id: u64,
    capsule_type: u64,
    /// Owned raw value bytes, byte-exact as received (so intermediaries
    /// can re-encode). Freed via `event.deinit`.
    value: []u8,
};

/// Drained from `Session.poll()` and returned to the application. The
/// union is shared between client and server sessions; some variants
/// only fire on one role. Each variant carries a `Role:` tag in its
/// doc comment indicating where it can be observed:
///
///   - `client`  — only fires when `Session.role == .client`
///   - `server`  — only fires when `Session.role == .server`
///   - `both`    — fires on either role
///
/// A summary of the role split is documented in the comment block
/// directly below the union, so a future API split (separate
/// `ClientEvent` / `ServerEvent` unions) can be derived mechanically
/// from the tags.
pub const Event = union(enum) {
    /// 0-RTT disposition on a resumed client connection — see
    /// `EarlyDataEvent`. Emitted at most once, before any other event of
    /// the drain that resolves it.
    ///
    /// Role: client
    early_data: EarlyDataEvent,
    /// Peer's HTTP/3 SETTINGS frame, decoded from the control stream.
    /// Emitted exactly once per session, after the first SETTINGS
    /// frame has been received and validated.
    ///
    /// Role: both
    peer_settings: settings_mod.Settings,
    /// Final HEADERS section on a request, response, or push stream.
    /// The `kind` field on `FieldEvent` distinguishes context:
    ///   - `kind == .request`  → server-side: incoming request headers
    ///   - `kind == .response` → client-side: server's final response
    ///   - `kind == .push`     → client-side: pushed response headers
    /// (Push promise *frames* surface separately as `push_promise`.)
    ///
    /// Role: both
    headers: FieldEvent,
    /// 1xx informational response (RFC 9110 §15.2). Surfaced on the
    /// client side when the server emits a 1xx status before the
    /// final response. The application MAY observe more
    /// `interim_headers` events; exactly one final `headers` event
    /// (with `:status` outside 1xx) follows. Never emitted on
    /// requests or pushes — the message decoder rejects interim
    /// headers on those kinds.
    ///
    /// Role: client
    interim_headers: FieldEvent,
    /// A DATA frame's payload on a request, response, or push stream.
    /// The `kind` on `DataEvent` mirrors `headers` semantics
    /// (request body server-side; response/push body client-side).
    ///
    /// Role: both
    data: DataEvent,
    /// An HTTP/3 DATAGRAM (RFC 9297) addressed to a stream on this
    /// session. Both peers may send and receive DATAGRAMs once
    /// `SETTINGS_H3_DATAGRAM = 1` has been negotiated.
    ///
    /// Role: both
    datagram: DatagramEvent,
    /// QUIC-level acknowledgement that a previously-sent DATAGRAM
    /// frame was acknowledged by the peer. Bubbled up from the
    /// transport.
    ///
    /// Role: both
    datagram_acked: DatagramSendEvent,
    /// QUIC-level signal that a previously-sent DATAGRAM frame was
    /// declared lost by the loss detector. Bubbled up from the
    /// transport.
    ///
    /// Role: both
    datagram_lost: DatagramSendEvent,
    /// QUIC flow-control hint: the connection or one of its streams
    /// is blocked from sending. Bubbled up from the transport.
    ///
    /// Role: both
    flow_blocked: FlowBlockedEvent,
    /// QUIC connection-id pool replenishment hint. Bubbled up from
    /// the transport so the application can issue NEW_CONNECTION_ID
    /// frames as needed. Role-agnostic.
    ///
    /// Role: both
    connection_ids_needed: ConnectionIdsNeededEvent,
    /// Trailing HEADERS section on a request, response, or push
    /// stream. `kind` mirrors `headers` semantics.
    ///
    /// Role: both
    trailers: FieldEvent,
    /// Server promised a pushed response via a PUSH_PROMISE frame on
    /// a request stream. Only clients accept PUSH_PROMISE — servers
    /// emit them but never receive them. The matching response
    /// content arrives later as a `push_stream` followed by
    /// `headers`/`data`/`trailers` with `kind == .push`.
    ///
    /// Role: client
    push_promise: PushPromiseEvent,
    /// A new server-pushed unidirectional stream has been opened and
    /// its push id parsed. Only clients see push streams — the
    /// server-side rejects push uni streams as `UnexpectedStream`.
    ///
    /// Role: client
    push_stream: PushStreamEvent,
    /// Peer sent a CANCEL_PUSH frame on the control stream. Both
    /// sides may receive CANCEL_PUSH (RFC 9114 §7.2.3): clients use
    /// it to learn the server abandoned a promised push; servers use
    /// it to learn the client refuses a not-yet-sent push.
    ///
    /// Role: both
    cancel_push: CancelPushEvent,
    /// Peer sent a PRIORITY_UPDATE frame (RFC 9218). Only servers
    /// receive PRIORITY_UPDATE in this implementation — the receiver
    /// rejects it with `FrameUnexpected` on the client side.
    ///
    /// Role: server
    priority_update: PriorityUpdateEvent,
    /// Peer sent a GOAWAY frame on the control stream. Both sides
    /// may receive GOAWAY: a client's GOAWAY contains a push id
    /// limit, a server's GOAWAY contains a stream id limit. The
    /// `u64` payload is the raw id from the wire.
    ///
    /// Role: both
    goaway: u64,
    /// A bidi stream's receive half closed cleanly (FIN observed).
    /// `StreamFinishedEvent.kind` records the message kind if the
    /// stream was a request/response/push (null for raw streams,
    /// e.g. WebTransport CONNECT streams whose body has not yet
    /// classified the message).
    ///
    /// Role: both
    stream_finished: StreamFinishedEvent,
    /// A bidi or peer-uni stream was reset by the peer. Carries the
    /// peer's RESET_STREAM error code and final size. On the client
    /// side, a locally detected malformed response (RFC 9114 §4.1.2)
    /// also surfaces here with `source == .local` and
    /// `error_code == H3_MESSAGE_ERROR`.
    ///
    /// Role: both
    stream_reset: StreamResetEvent,
    /// The session refused an incoming request via STOP_SENDING with
    /// `H3_REQUEST_REJECTED` (RFC 9114 §4.1.2), or aborted a malformed
    /// request with `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2 — the
    /// `error_code` field carries whichever code applied). Only servers
    /// reject requests this way — emitted by `Session.rejectRequest`,
    /// the post-GOAWAY auto-reject path, and the malformed-request path.
    ///
    /// Role: server
    request_rejected: RequestRejectedEvent,
    /// The underlying QUIC connection has entered draining or closed
    /// state. Mirrors the transport's CloseEvent verbatim plus the
    /// resolved HTTP/3 application error code, if any.
    ///
    /// Role: both
    connection_closed: ConnectionClosedEvent,
    /// An unknown frame type was observed and skipped (RFC 9114
    /// §7.2.8). Surfaced for observability — applications normally
    /// ignore it. Both control- and message-stream paths can emit
    /// this event.
    ///
    /// Role: both
    ignored_unknown_frame: UnknownFrameEvent,
    /// A peer-opened WebTransport stream (uni or bidi) has had its
    /// prefix parsed and its session id resolved. Both client and
    /// server WT sessions may accept peer-opened streams.
    ///
    /// Role: both
    webtransport_stream_opened: WebTransportStreamOpenedEvent,
    /// Bytes arrived on a WebTransport stream. Body-only — the
    /// stream-prefix bytes are stripped before this event is
    /// emitted.
    ///
    /// Role: both
    webtransport_stream_data: WebTransportStreamDataEvent,
    /// A WebTransport stream's receive half closed cleanly (FIN).
    ///
    /// Role: both
    webtransport_stream_finished: WebTransportStreamFinishedEvent,
    /// A WebTransport stream was reset by the peer. The wire error
    /// code is preserved alongside the recovered 32-bit application
    /// code (per draft-ietf-webtrans-http3 §4.6).
    ///
    /// Role: both
    webtransport_stream_reset: WebTransportStreamResetEvent,
    /// The peer violated our advertised WebTransport flow-control
    /// limits (data overflow, bidi-streams overflow, or uni-streams
    /// overflow per draft-ietf-webtrans-http3 §5.6). The offending
    /// stream has already been reset with `WEBTRANSPORT_SESSION_GONE`
    /// before the event is delivered.
    ///
    /// Role: both
    webtransport_flow_violated: WebTransportFlowViolationEvent,
    /// A WebTransport session reached `.established` (server: accept
    /// completed; client: 2xx observed). Emitted at the top of the next
    /// drain, BEFORE any replayed `webtransport_stream_*` events for
    /// streams that were buffered against the session.
    ///
    /// Role: both
    webtransport_session_established: WebTransportSessionEstablishedEvent,
    /// A WebTransport session ended — via the peer's CLOSE capsule, a
    /// CONNECT FIN/RESET, or a local protocol-violation termination
    /// (see `how`). By the time this event is delivered the session's
    /// registry state is gone and every live substream has been swept
    /// with `WEBTRANSPORT_SESSION_GONE`.
    ///
    /// Role: both
    webtransport_session_closed: WebTransportSessionClosedEvent,
    /// The peer sent DRAIN_WEBTRANSPORT_SESSION: stop opening new
    /// streams, existing ones may run to completion
    /// (draft-ietf-webtrans-http3 §5.5). Local opens on the session now
    /// fail with `WebTransportSessionDraining`.
    ///
    /// Role: both
    webtransport_session_draining: WebTransportSessionDrainingEvent,
    /// The peer reports being blocked on one of OUR advertised limits
    /// (WT_DATA_BLOCKED / WT_STREAMS_BLOCKED_*). Granting more credit
    /// (`sendMaxData` / `sendMaxStreams*`) is application policy.
    ///
    /// Role: both
    webtransport_peer_blocked: WebTransportPeerBlockedEvent,
    /// The peer strictly raised a limit that gates OUR sends
    /// (WT_MAX_DATA / WT_MAX_STREAMS_*). This is the wakeup an
    /// application blocked on `WebTransportFlowControlExceeded` /
    /// `WebTransportStreamLimitExceeded` waits for. Non-increasing
    /// capsules are ignored and emit nothing (monotonic fold).
    ///
    /// Role: both
    webtransport_credit_granted: WebTransportCreditGrantedEvent,
    /// A capsule outside the known WebTransport family arrived on the
    /// session's CONNECT stream. Byte-exact value preserved so
    /// intermediaries can forward it; applications normally ignore it
    /// (unknown capsules MUST be ignored per RFC 9297 §3.2).
    ///
    /// Role: both
    webtransport_unknown_capsule: WebTransportUnknownCapsuleEvent,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .headers => |event| freeFields(allocator, event.fields),
            .interim_headers => |event| freeFields(allocator, event.fields),
            .trailers => |event| freeFields(allocator, event.fields),
            .data => |event| allocator.free(event.data),
            .datagram => |event| allocator.free(event.payload),
            .push_promise => |event| {
                allocator.free(event.field_section);
                freeFields(allocator, event.fields);
            },
            .priority_update => |event| allocator.free(event.priority_field_value),
            .connection_closed => |event| event.deinit(allocator),
            .webtransport_stream_data => |event| allocator.free(event.data),
            .webtransport_session_closed => |event| allocator.free(event.reason),
            .webtransport_unknown_capsule => |event| allocator.free(event.value),
            else => {},
        }
    }
};

/// Releases the deep-cloned bytes attached to every drained session event.
/// Use the allocator passed to `Session.init`, not the allocator that backs
/// the caller's event list — a mismatch is silent memory corruption that
/// this function cannot detect. Prefer the session-bound
/// `Session.clearEvents` / `Session.freeEvents`, which bind the right
/// allocator implicitly.
pub fn deinitEvents(allocator: std.mem.Allocator, events: []const Event) void {
    for (events) |event| event.deinit(allocator);
}

/// Releases every drained event payload, then clears the event list while
/// retaining its capacity for the next `Session.drain` call. Same allocator
/// contract (and the same trap) as `deinitEvents`; prefer the session-bound
/// `Session.clearEvents` when a session pointer is in scope.
pub fn clearEvents(allocator: std.mem.Allocator, events: *std.ArrayList(Event)) void {
    deinitEvents(allocator, events.items);
    events.clearRetainingCapacity();
}

// ---------------------------------------------------------------------------
// Event role split (audit summary)
//
// The `Event` union above is intentionally shared between client and
// server sessions for v0.1.0 — applications switch on the variant tag.
// The lists below document which variants can fire on which role, so a
// future API split (separate `ClientEvent` / `ServerEvent` unions) can
// be derived mechanically. Keep this in sync with the per-variant
// `Role:` doc tags.
//
// Client-only (3):
//   - interim_headers   — 1xx informational responses (RFC 9110 §15.2)
//   - push_promise      — server promised a push (RFC 9114 §7.2.1)
//   - push_stream       — server-pushed uni stream prefix observed
//
// Server-only (2):
//   - priority_update   — peer PRIORITY_UPDATE; rejected on clients
//   - request_rejected  — STOP_SENDING with H3_REQUEST_REJECTED
//
// Both roles (26):
//   - peer_settings, headers, data, trailers, datagram,
//     datagram_acked, datagram_lost, flow_blocked,
//     connection_ids_needed, cancel_push, goaway, stream_finished,
//     stream_reset, connection_closed, ignored_unknown_frame,
//     webtransport_stream_opened, webtransport_stream_data,
//     webtransport_stream_finished, webtransport_stream_reset,
//     webtransport_flow_violated, webtransport_session_established,
//     webtransport_session_closed, webtransport_session_draining,
//     webtransport_peer_blocked, webtransport_credit_granted,
//     webtransport_unknown_capsule
//
// For the "both" variants whose payload carries a message kind
// (`headers`, `data`, `trailers`), the `kind` field on the payload
// further distinguishes context: `kind == .request` only ever appears
// on a server (incoming request); `kind == .response` and
// `kind == .push` only ever appear on a client.
// ---------------------------------------------------------------------------

const BidiKind = enum {
    /// HTTP/3 request/response stream (the normal case).
    request,
    /// WebTransport bidirectional stream
    /// (draft-ietf-webtrans-http3 §4.2). The first varint on the wire is
    /// the WebTransport bidi-stream marker `0x41`, followed by the Session
    /// ID varint, followed by raw application bytes.
    webtransport,
};

const StreamState = struct {
    id: u64,
    rx: std.ArrayList(u8) = .empty,
    uni_kind: ?stream_mod.Kind = null,
    /// Bidi-stream classification (request vs WebTransport). Lazily set on
    /// the first byte of inbound data so the decision can wait for enough
    /// bytes to peek at the leading varint.
    bidi_kind: ?BidiKind = null,
    /// WebTransport Session ID (the CONNECT request stream ID) once the
    /// stream's prefix has been parsed. Null until the prefix arrives.
    wt_session_id: ?u64 = null,
    /// True when the WebTransport stream has parsed its prefix but is
    /// holding bytes in `rx` because the corresponding session is not
    /// yet confirmed and the configured `BufferedStreamPolicy` is
    /// `.buffer`. Cleared once the session is confirmed (via the
    /// drain-time replay path) or when the session is rejected.
    wt_buffered: bool = false,
    /// Tombstone on a WT CONNECT stream: a CLOSE_WEBTRANSPORT_SESSION
    /// capsule was ingested (the session registry entry is gone by
    /// then). Capsules MUST NOT follow CLOSE — any further body bytes
    /// on this stream are a message error (H3_MESSAGE_ERROR abort of
    /// the CONNECT stream, not a connection error).
    wt_close_observed: bool = false,
    /// True when a FIN arrived on a buffered WebTransport stream
    /// before the session was confirmed. Holding the FIN here lets
    /// the replay path emit `webtransport_stream_finished` *after* the
    /// matching `_opened` and `_data` events, in the order the
    /// application expects. Without this defer the FIN would race
    /// ahead of (or replace) the open event entirely.
    wt_buffered_fin: bool = false,
    /// True once the buffered-stream replay path has emitted this
    /// stream's `webtransport_stream_opened` event. Dedupes the open
    /// across budget-limited replay drains: the replay emits
    /// opened -> data -> finished from H3-side buffers (`rx` +
    /// `wt_buffered_fin`), and under a tight `max_events_per_drain`
    /// those events span multiple drains. quic-zig 0.4.0 reaps a peer
    /// stream once its recv side is terminal, so the replay must be
    /// self-contained and cannot fall back to re-reading the stream via
    /// the main `streamIterator` drain path.
    wt_replay_opened: bool = false,
    /// Sticky record that quic-zig reported the peer's FIN for this stream,
    /// captured inline with the draining read via `streamReadFin`. quic-zig
    /// reaps a peer stream once its recv side is terminal (FIN received + all
    /// bytes read), after which the FIN is no longer observable from the
    /// iterator; holding it here lets a stream parked mid-processing
    /// (blocked_on_qpack) still surface its FIN when it is re-processed on a
    /// later drain.
    quic_recv_fin_seen: bool = false,
    push_id: ?u64 = null,
    control_validator: ?stream_mod.FrameValidator = null,
    message_decoder: ?message_mod.Decoder = null,
    message_encoder: ?message_mod.Encoder = null,
    blocked_on_qpack: bool = false,
    recv_finished: bool = false,
    recv_reset_seen: bool = false,
    locally_rejected: bool = false,
    /// True once we've called `quic.streamFinish` or `quic.streamReset`
    /// on this stream — i.e. the local send side is closed. Combined
    /// with `recv_finished` / `recv_reset_seen` (peer-side closure)
    /// drives the per-drain GC pass that reclaims `Session.streams`
    /// entries. Tracked separately from QUIC's send-state because
    /// quic-zig retains its own stream entry until the connection
    /// teardown — http3-zig handles its registry independently.
    locally_finished: bool = false,
    /// Connection-clock time (`quic.Connection.last_activity_us`,
    /// i.e. the embedder's `now_us` domain) at which the session last
    /// surfaced an event for this stream. Stamped at creation and again
    /// in `appendReservedEvent` — the single choke point every emitted
    /// event flows through — so request-deadline enforcement (see
    /// `Session.openRequestStreams`) also times out streams that opened
    /// and then went silent. Zero only before any packet activity.
    last_event_us: u64 = 0,

    fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.rx.deinit(allocator);
    }

    /// True when no further events will surface for this stream — the
    /// receive side is closed (FIN observed or RESET seen) AND the
    /// local send side is closed (or the stream is unidirectional with
    /// only one applicable direction). Used by `Session.gcClosedStreams`.
    fn isFullyClosed(self: *const StreamState) bool {
        const recv_done = self.recv_finished or self.recv_reset_seen;
        // Peer-opened uni: classified by `uni_kind` set during inbound
        // dispatch. Receive-only — `recv_done` is sufficient.
        if (self.uni_kind != null) return recv_done;
        // Locally-opened unidirectional: peer never sends back, so
        // `locally_finished` alone closes the lifecycle.
        if (stream_mod.isUnidirectional(self.id)) return self.locally_finished;
        // Bidi (request, response, push, WT CONNECT, WT bidi):
        // both directions must be closed.
        return self.locally_finished and recv_done;
    }

    /// Returns `.uni` if this is a WebTransport unidirectional stream,
    /// `.bidi` if it's a WebTransport bidi stream, or null otherwise.
    fn webTransportKind(self: *const StreamState) ?WebTransportStreamKind {
        if (self.uni_kind) |kind| switch (kind) {
            .webtransport_uni => return .uni,
            else => {},
        };
        if (self.bidi_kind) |kind| switch (kind) {
            .webtransport => return .bidi,
            else => {},
        };
        return null;
    }
};

const DrainBudget = struct {
    max_payload_size: ?usize,
    max_payload_bytes: ?usize,
    max_events: ?usize,
    payload_bytes: usize = 0,
    events: usize = 0,

    fn reserve(self: *DrainBudget, owned_payload_bytes: usize) Error!void {
        if (self.max_events) |max| {
            if (self.events >= max) return Error.EventQueueFull;
        }
        if (self.max_payload_size) |max| {
            if (owned_payload_bytes > max) return Error.EventPayloadTooLarge;
        }
        if (self.max_payload_bytes) |max| {
            if (owned_payload_bytes > max or self.payload_bytes > max - owned_payload_bytes) {
                return Error.EventQueueFull;
            }
        }
        self.events += 1;
        self.payload_bytes += owned_payload_bytes;
    }
};

/// Per-WebTransport-session flow-control state
/// (draft-ietf-webtrans-http3 §5.6). The state lives for the lifetime of
/// a confirmed WebTransport session; each session is keyed by its
/// CONNECT stream id (the Session ID).
///
/// Optional fields are null until the corresponding limit has been
/// observed on the wire (peer-advertised) or set by the application
/// (locally-advertised). The send-side gates in
/// `openWebTransport{Uni,Bidi}Stream` and `writeWebTransportStream`
/// enforce non-null peer limits — meaning absence of a limit is treated
/// as "no enforcement", which preserves the pre-flow-control behaviour
/// for callers that don't care.
/// Internal mutable per-WT-session flow-control state. Not part of the
/// public API: applications observe a read-only `WTSessionFlowSnapshot`
/// via `WebTransportClientStream.flowState()` /
/// `WebTransportServerStream.flowState()`. Direct mutation would corrupt
/// the session's accounting (peer_data_received, BLOCKED bookkeeping,
/// drain bit) — the wrapping `Session` updates these fields under the
/// invariants documented at each call site.
/// Unified per-session WebTransport state, heap-boxed in
/// `Session.wt_sessions` so pointers into it stay stable across map
/// growth. Created `.pending` when the CONNECT handshake starts and
/// flipped to `.established` at confirmation. Flow-control credit is
/// seeded at CREATION (draft-ietf-webtrans-http3 §9.2), so pending
/// sessions are gated and counted like established ones.
const WTSessionState = struct {
    phase: enum { pending, established },
    /// Era inherited from the connection at creation (draft16 for
    /// direct-confirm unit fixtures that never exchanged SETTINGS).
    /// Gates flow-control seeding, capsule folding, and the modern
    /// capsule send verbs.
    draft: webtransport_mod.WtDraft = .draft16,
    flow: WTSessionFlowState,
    /// Per-session incremental capsule reassembly across DATA-frame
    /// boundaries (a capsule may legally span frames). Fed by the
    /// native ingestion path from the CONNECT stream's DATA; complete
    /// capsules fold into `flow` and emit typed events.
    reassembler: capsule_mod.Reassembler = .{},
    /// Set when the session transitions to `.established`; the next
    /// drain emits `webtransport_session_established` (before any
    /// buffered-stream replay events) and clears it.
    established_event_pending: bool = false,

    fn deinit(self: *WTSessionState, allocator: std.mem.Allocator) void {
        self.reassembler.deinit(allocator);
    }
};

const WTSessionFlowState = struct {
    session_id: u64,

    // ---------- Peer-advertised limits (gate our sends) ----------

    /// Maximum total bytes the peer is willing to receive across all
    /// WT streams in this session. Updated by `WT_MAX_DATA` capsules.
    peer_max_data: ?u64 = null,
    /// Maximum bidirectional WT streams the peer is willing to accept.
    peer_max_streams_bidi: ?u64 = null,
    /// Maximum unidirectional WT streams the peer is willing to accept.
    peer_max_streams_uni: ?u64 = null,

    // ---------- Locally-advertised limits (we advertise to peer) ----------

    /// Last `WT_MAX_DATA` value we sent to the peer.
    local_max_data: ?u64 = null,
    local_max_streams_bidi: ?u64 = null,
    local_max_streams_uni: ?u64 = null,

    // ---------- Counters ----------

    /// Total bytes we have sent on WT streams in this session
    /// (counted at `writeWebTransportStream` time, before flow-control
    /// gating).
    local_data_sent: u64 = 0,
    local_streams_opened_bidi: u64 = 0,
    local_streams_opened_uni: u64 = 0,

    /// Total bytes we have surfaced as `webtransport_stream_data`
    /// events in this session. Useful for the application to decide
    /// when to advertise a higher `local_max_data`.
    peer_data_received: u64 = 0,
    peer_streams_opened_bidi: u64 = 0,
    peer_streams_opened_uni: u64 = 0,

    // ---------- BLOCKED-emission bookkeeping ----------

    /// The peer-advertised `WT_MAX_DATA` value we last emitted a
    /// `WT_DATA_BLOCKED` capsule against. Re-emit only when the
    /// limit changes, so a steadily-blocked sender doesn't spam.
    sent_data_blocked_for: ?u64 = null,
    sent_streams_blocked_bidi_for: ?u64 = null,
    sent_streams_blocked_uni_for: ?u64 = null,

    // ---------- Drain state ----------

    /// True once we've received `DRAIN_WEBTRANSPORT_SESSION` from the
    /// peer (draft-ietf-webtrans-http3 §5.5). After this point new
    /// stream opens are gated and the session is in a draining state
    /// — the peer expects existing streams to finish but no new ones
    /// to start. Local-side opens return
    /// `error.WebTransportSessionDraining`.
    received_drain: bool = false,
};

/// Read-only view of `WTSessionFlowState` exposed to applications via
/// `WebTransportClientStream.flowState()` /
/// `WebTransportServerStream.flowState()`. Borrows nothing from the
/// session — safe to copy and inspect outside any pump.
pub const WTSessionFlowSnapshot = struct {
    /// Draft era the session resolved to (see `WtDraft`); browser-era
    /// sessions report null limits everywhere below by construction.
    draft: webtransport_mod.WtDraft = .draft16,
    session_id: u64,
    peer_max_data: ?u64,
    peer_max_streams_bidi: ?u64,
    peer_max_streams_uni: ?u64,
    local_max_data: ?u64,
    local_max_streams_bidi: ?u64,
    local_max_streams_uni: ?u64,
    local_data_sent: u64,
    local_streams_opened_bidi: u64,
    local_streams_opened_uni: u64,
    peer_data_received: u64,
    peer_streams_opened_bidi: u64,
    peer_streams_opened_uni: u64,
    /// True once the peer has sent `DRAIN_WEBTRANSPORT_SESSION`
    /// (draft-ietf-webtrans-http3 §5.5). Locally-initiated stream
    /// opens after this point will fail with
    /// `error.WebTransportSessionDraining`.
    received_drain: bool,

    pub fn fromState(s: *const WTSessionFlowState) WTSessionFlowSnapshot {
        return .{
            .session_id = s.session_id,
            .peer_max_data = s.peer_max_data,
            .peer_max_streams_bidi = s.peer_max_streams_bidi,
            .peer_max_streams_uni = s.peer_max_streams_uni,
            .local_max_data = s.local_max_data,
            .local_max_streams_bidi = s.local_max_streams_bidi,
            .local_max_streams_uni = s.local_max_streams_uni,
            .local_data_sent = s.local_data_sent,
            .local_streams_opened_bidi = s.local_streams_opened_bidi,
            .local_streams_opened_uni = s.local_streams_opened_uni,
            .peer_data_received = s.peer_data_received,
            .peer_streams_opened_bidi = s.peer_streams_opened_bidi,
            .peer_streams_opened_uni = s.peer_streams_opened_uni,
            .received_drain = s.received_drain,
        };
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    role: protocol.Role,
    quic: *quic.Connection,
    config: Config = .{},
    local_settings: settings_mod.Settings = .{},
    peer_settings: ?settings_mod.Settings = null,
    /// WebTransport draft era resolved from the SETTINGS intersection
    /// (newest common era; null until peer SETTINGS arrive or when the
    /// sets don't intersect). Resolved ONCE — HTTP/3 SETTINGS arrive
    /// exactly once — and NEVER from remembered 0-RTT settings
    /// (extended CONNECT is denied in early data). Sessions inherit
    /// this at creation: mixed-era sessions on one connection are
    /// impossible by construction.
    wt_negotiated_draft: ?webtransport_mod.WtDraft = null,
    /// RFC 9114 §7.2.4.2: settings remembered from the ticket-issuing
    /// connection, installed via `rememberPeerSettings`. Consulted only by
    /// the datagram gates until the real SETTINGS arrive; validated (when
    /// 0-RTT was accepted) then discarded at that point.
    remembered_peer_settings: ?settings_mod.Settings = null,
    /// Latch: the at-most-once `early_data` event was emitted, or never
    /// will be (handshake completed without an attempt).
    early_data_resolved: bool = false,

    control_stream_id: ?u64 = null,
    qpack_encoder_stream_id: ?u64 = null,
    qpack_decoder_stream_id: ?u64 = null,
    peer_control_stream_id: ?u64 = null,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,
    sent_goaway_id: ?u64 = null,
    /// GOAWAY was sent while established WebTransport sessions were
    /// live: the transport-level `beginGracefulShutdown()` is DEFERRED
    /// until the last of them ends, because it refuses new local stream
    /// opens and draft-16 requires established WT sessions to keep
    /// working (stream opens included) across an H3 GOAWAY. During the
    /// deferral window the H3-layer gates alone enforce GOAWAY (the
    /// transport keeps granting the peer stream credit — quic-zig
    /// confirms the latch is a pure boolean with exactly two effect
    /// sites, safe to set at any later point in the connection's life).
    graceful_shutdown_deferred: bool = false,
    peer_goaway_id: ?u64 = null,
    /// Highest client-initiated bidirectional stream id observed from the
    /// peer (server role only — bumped in `ensureIncomingState` before any
    /// per-stream rejection, so even auto-rejected streams count). This is
    /// the "was or might be processed" bound RFC 9114 §5.2 asks a server's
    /// GOAWAY id to cover. Null until the first such stream arrives, and
    /// always null on clients. Read via `highestPeerRequestStreamId`.
    highest_peer_request_stream_id: ?u64 = null,
    /// Highest push id observed from the peer (client role only — stamped
    /// in `validateReceivedPushId`, the choke point every received push id
    /// passes through). The client-side analogue of
    /// `highest_peer_request_stream_id` for `gracefulGoawayId`.
    highest_peer_push_id: ?u64 = null,
    peer_max_push_id: ?u64 = null,
    next_push_id: u64 = 0,
    shutdown_state: ShutdownState = .active,
    last_close_error: ?errors_mod.ConnectionError = null,
    metrics_counters: observability_mod.Metrics = .{},

    qpack_encoder_table: qpack.DynamicTable,
    qpack_decoder_table: qpack.DynamicTable,
    qpack_encoder_state: qpack.QpackEncoderState,
    qpack_decoder_state: qpack.QpackDecoderState,
    qpack_encoder_capacity: usize = 0,

    streams: std.AutoHashMapUnmanaged(u64, *StreamState) = .empty,
    received_push_promises: std.AutoHashMapUnmanaged(u64, []qpack.FieldLine) = .empty,
    request_priorities: std.AutoHashMapUnmanaged(u64, priority_mod.Priority) = .empty,
    push_priorities: std.AutoHashMapUnmanaged(u64, priority_mod.Priority) = .empty,

    /// Unified WebTransport session registry keyed by CONNECT stream id
    /// (see `WTSessionState`). `.pending`: handshake started (server:
    /// request received, response not sent; client: request sent, 2xx
    /// not yet observed). `.established`: confirmed (server: 2xx sent;
    /// client: 2xx observed) — streams referencing an established
    /// `session_id` dispatch immediately; everything else is governed
    /// by `Config.buffered_stream_policy`. The per-session flow-control
    /// state (`WTSessionFlowState` — peer-advertised limits, our usage
    /// counters, BLOCKED-emission bookkeeping) exists for BOTH phases:
    /// §9.2 SETTINGS credit is seeded at creation, so opens and
    /// receive-side accounting against a not-yet-confirmed session are
    /// gated and counted instead of bypassing limits.
    wt_sessions: std.AutoHashMapUnmanaged(u64, *WTSessionState) = .empty,
    /// Count of `.pending` entries in `wt_sessions`, kept alongside so
    /// the `max_pending_wt_sessions` DoS gate and
    /// `webTransportPendingCount` stay O(1). Maintained exclusively by
    /// the mark/confirm/end transitions.
    wt_pending_count: usize = 0,
    /// Stream ids of WebTransport streams currently held by the
    /// `.buffer` policy, recorded in the order they entered the
    /// buffered state. The replay path walks this list (not the
    /// `streams` hash map) so that buffered open events surface in
    /// the same order the peer opened them — `BufferedStreamPolicy.buffer`'s
    /// docs explicitly promise this. Entries are removed once the
    /// stream is replayed or rejected.
    wt_buffered_streams: std.ArrayList(u64) = .empty,

    /// Per-drain scratch buffers — reused across `drain()` calls instead
    /// of being alloc'd + freed every drain. Sized lazily on first use
    /// (and grown if a config knob changes between drains). Released
    /// in `deinit`. Not part of the public API surface.
    drain_read_scratch: []u8 = &.{},
    drain_datagram_scratch: []u8 = &.{},

    pub fn init(
        allocator: std.mem.Allocator,
        role: protocol.Role,
        conn: *quic.Connection,
        config: Config,
    ) Session {
        return .{
            .allocator = allocator,
            .role = role,
            .quic = conn,
            .config = config,
            .local_settings = config.settings,
            .qpack_encoder_table = qpack.DynamicTable.init(allocator, config.qpack_encoder_table_capacity),
            .qpack_decoder_table = qpack.DynamicTable.init(
                allocator,
                @intCast(config.settings.qpack_max_table_capacity),
            ),
            .qpack_encoder_state = qpack.QpackEncoderState.init(allocator, 0),
            .qpack_decoder_state = qpack.QpackDecoderState.init(allocator, config.settings.qpack_blocked_streams),
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
        var promises = self.received_push_promises.valueIterator();
        while (promises.next()) |fields| freeFields(self.allocator, fields.*);
        self.received_push_promises.deinit(self.allocator);
        self.request_priorities.deinit(self.allocator);
        self.push_priorities.deinit(self.allocator);
        var wt_it = self.wt_sessions.valueIterator();
        while (wt_it.next()) |sess_ptr| {
            sess_ptr.*.deinit(self.allocator);
            self.allocator.destroy(sess_ptr.*);
        }
        self.wt_sessions.deinit(self.allocator);
        self.wt_buffered_streams.deinit(self.allocator);
        self.qpack_encoder_table.deinit();
        self.qpack_decoder_table.deinit();
        self.qpack_encoder_state.deinit();
        self.qpack_decoder_state.deinit();
        if (self.drain_read_scratch.len > 0) self.allocator.free(self.drain_read_scratch);
        if (self.drain_datagram_scratch.len > 0) self.allocator.free(self.drain_datagram_scratch);
    }

    /// Lazily (re)allocates `scratch.*` to hold at least `needed` bytes
    /// using `self.allocator`, then returns the prefix slice. Used by
    /// `drain` and `drainDatagrams` to reuse buffers across calls
    /// instead of paying alloc+free per drain. Grows monotonically —
    /// the scratch is freed in `deinit`.
    fn ensureDrainScratch(self: *Session, scratch: *[]u8, needed: usize) Error![]u8 {
        if (scratch.len < needed) {
            if (scratch.len > 0) self.allocator.free(scratch.*);
            scratch.* = try self.allocator.alloc(u8, needed);
        }
        return scratch.*[0..needed];
    }

    /// Releases the deep-cloned bytes attached to `event` using the
    /// session's allocator. Equivalent to `event.deinit(session.allocator)`
    /// but binds the right allocator implicitly — the caller doesn't
    /// have to remember that the bytes were cloned out of the session's
    /// allocator (not the events list's allocator). No-op for variants
    /// whose payload is plain scalars; safe to call on every drained
    /// event.
    pub fn freeEvent(self: *const Session, event: Event) void {
        event.deinit(self.allocator);
    }

    /// Releases the deep-cloned bytes attached to every drained event using
    /// the allocator stored by this session.
    pub fn freeEvents(self: *const Session, events: []const Event) void {
        deinitEvents(self.allocator, events);
    }

    /// Releases every drained event payload using the session allocator, then
    /// clears the caller-owned list while retaining its capacity.
    ///
    /// This is the recommended cleanup call: event payloads are deep-cloned
    /// out of the *session's* allocator, and this binding supplies that
    /// allocator implicitly, so it cannot be run with the wrong one. The
    /// free-standing `http3_zig.clearEvents(allocator, …)` /
    /// `deinitEvents(allocator, …)` forms exist for contexts without a
    /// session pointer, but silently corrupt memory if handed any allocator
    /// other than the one passed to `Session.init` (e.g. the events list's).
    /// `TransportEndpoint.clearEvents` delegates here and is equally safe.
    pub fn clearEvents(self: *const Session, events: *std.ArrayList(Event)) void {
        deinitEvents(self.allocator, events.items);
        events.clearRetainingCapacity();
    }

    pub fn start(self: *Session) Error!void {
        // `start()` is idempotent — multiple callers (driver
        // auto-start, public send-side methods) hit it at every
        // entry point. After local close we just no-op rather
        // than error so the driver's own auto-start doesn't
        // become a source of `SessionClosed` errors. The actual
        // post-close gating lives on the public send-side
        // entry points (sendDatagram*, openRequest, finishStream,
        // …), which return `Error.SessionClosed` directly.
        if (self.shutdown_state == .closed) return;
        if (self.control_stream_id == null) try self.openControlStream();
        if (self.usesQpackStreams() and
            (self.qpack_encoder_stream_id == null or self.qpack_decoder_stream_id == null))
        {
            try self.openQpackStreams();
        }
    }

    /// Install the peer SETTINGS remembered from the connection that issued
    /// the resumption ticket (RFC 9114 §7.2.4.2 ¶5): the client MUST comply
    /// with them until the resumed connection's real SETTINGS arrive.
    /// Client role, before any SETTINGS exchange. In v1 the remembered
    /// settings feed the datagram gates only — the QPACK encoder stays
    /// static-only pre-SETTINGS and extended CONNECT stays gated on real
    /// SETTINGS — so every request staged in 0-RTT remains protocol-valid
    /// under ANY server settings if the attempt is rejected.
    /// CONTRACT (mutual with quic's requeueRejectedEarlyData pin, quic-zig
    /// 72719a7): rejected 0-RTT stream bytes are retransmitted VERBATIM at
    /// 1-RTT on the same stream ids, with no app intervention. The v1
    /// restrictions above are what keep that replay always-valid; if quic
    /// ever adds a reset-streams rejection policy, revisit both together.
    pub fn rememberPeerSettings(self: *Session, remembered: settings_mod.Settings) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        if (self.peer_settings != null) return Error.RememberedSettingsTooLate;
        self.remembered_peer_settings = remembered;
    }

    /// Snapshot of the transport's 0-RTT disposition
    /// (`Connection.earlyDataStatus`). Event consumers get the same
    /// information at most once via `Event.early_data`.
    pub fn earlyDataStatus(self: *Session) quic.EarlyDataStatus {
        return self.quic.earlyDataStatus();
    }

    /// Server-side request provenance: any of this stream's bytes arrived
    /// in 0-RTT packets (`Connection.streamArrivedInEarlyData`; sticky).
    /// Null when the transport no longer tracks the stream.
    pub fn requestArrivedInEarlyData(self: *const Session, stream_id: u64) ?bool {
        return self.quic.streamArrivedInEarlyData(stream_id);
    }

    /// By-value transport statistics snapshot (`Connection.stats`): wire
    /// bytes/packets, loss, the active path's cwnd/RTT/PMTU, open
    /// streams, and close state. Complements `observability.Metrics`
    /// (HTTP/3 semantics) with transport reality; passed through
    /// verbatim, so the struct is upstream-Unstable — fields may be
    /// added with quic minors. Safe to hold across drains and teardown.
    pub fn transportStats(self: *const Session) quic.ConnectionStats {
        return self.quic.stats();
    }

    /// By-value send-window snapshot for one stream
    /// (`Connection.streamSendWindow`, quic v0.13.0): `{connection,
    /// stream, queued, writable}` where `writable = min(connection,
    /// stream) -| queued` — new-data bytes only, retransmissions
    /// invisible, congestion deliberately excluded. Null for unknown
    /// streams and peer-initiated unis. Upstream-UNSTABLE struct passed
    /// through verbatim (same caveat as `transportStats`); note the
    /// `connection` component is one shared pool across streams — do
    /// not sum per-stream snapshots.
    pub fn streamSendWindow(self: *const Session, stream_id: u64) ?quic.SendWindow {
        return self.quic.streamSendWindow(stream_id);
    }

    /// quic v0.13.0's one-shot `ConnectionEvent.early_data` replaces the
    /// old per-drain `earlyDataStatus()` poll, which could MISS a
    /// rejection: after rejecting 0-RTT the transport restarts the TLS
    /// handshake, from which point the polled status reads
    /// `.not_offered` again — only a drain landing inside that window
    /// ever observed `.rejected`. The event has no window: rejection is
    /// keyed off quic's internal requeue latch and guaranteed to arrive
    /// AFTER the verbatim 1-RTT requeue ran.
    fn observeEarlyDataOutcome(
        self: *Session,
        status: quic.EarlyDataStatus,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        if (self.role != .client or self.early_data_resolved) return;
        switch (status) {
            .accepted => {
                self.early_data_resolved = true;
                try self.appendEvent(events, budget, .{ .early_data = .{
                    .status = .accepted,
                    .reason = "",
                } });
            },
            .rejected => {
                self.early_data_resolved = true;
                // §7.2.4.2 ¶7: rejection discards the remembered state;
                // the new SETTINGS simply apply when they arrive.
                self.remembered_peer_settings = null;
                try self.appendEvent(events, budget, .{ .early_data = .{
                    .status = .rejected,
                    .reason = self.quic.earlyDataReason(),
                } });
            },
            else => {},
        }
    }

    pub fn openRequest(self: *Session, fields: []const qpack.FieldLine) Error!u64 {
        if (self.role != .client) return Error.InvalidRole;
        if (self.shutdown_state == .closed) return Error.SessionClosed;
        try self.start();
        try self.ensureExtendedConnectAllowed(fields);

        // peekNextBidi (quic-zig 0.5.0) returns the id openNextBidi would use,
        // without consuming it, so the GOAWAY gate runs on the real next id
        // before we open — and it is reap-safe (a monotonic counter, not a
        // scan of the live stream table that could reuse a reaped id).
        const id = self.quic.peekNextBidi();
        if (!self.peerAllowsRequest(id)) return Error.RequestBlockedByGoaway;

        _ = try self.quic.openNextBidi();
        const state = try self.ensureMessageState(id, .response, .request);
        // RFC 9114 §4.1.2 / RFC 9110 §9.3.2: a response to HEAD never
        // has content — mark the decoder so a non-zero Content-Length
        // with zero DATA bytes is accepted instead of rejected.
        if (headers_mod.isHeadRequest(fields)) {
            state.message_decoder.?.options.is_head_request = true;
        }
        const encoder = try self.ensureEncoder(state, .request);
        try self.writeHeadersWithEncoder(id, encoder, fields);
        self.trace(.{
            .name = .request_opened,
            .role = self.role,
            .stream_id = id,
            .count = fields.len,
        });
        return id;
    }

    /// Opens a locally-initiated WebTransport unidirectional stream and writes
    /// the WebTransport stream prefix (`StreamType.webtransport_uni_stream` +
    /// varint Session ID) per draft-ietf-webtrans-http3 §4.1. The returned
    /// stream is a raw byte stream — the application owns subsequent writes
    /// via `writeWebTransportStream` and finishes via
    /// `finishWebTransportStream`.
    pub fn openWebTransportUniStream(self: *Session, session_id: u64) Error!u64 {
        try self.start();
        try self.gateWebTransportStreamOpen(session_id, .uni);

        // Adopt quic-zig 0.4.0's role-aware next-id helper rather than
        // scanning the live stream table for a free id. quic-zig now reaps
        // terminal streams (0.3.0+), so a `stream(id) == null` scan reuses a
        // reaped id and clobbers our own StreamState registry entry (a leak).
        // `openNextUni` keeps a monotonic per-type counter that never reuses
        // an id, and leaves the id unconsumed on StreamLimitExceeded so a
        // retry after the peer raises the limit reuses it.
        const stream_id = (try self.quic.openNextUni()).id;
        errdefer self.quic.streamReset(stream_id, protocol.ErrorCode.internal_error) catch {};

        // Pre-register state with `wt_session_id` set so subsequent
        // `writeWebTransportStream` calls can find the session's
        // flow-control state and gate the byte count against
        // `peer_max_data`. Without this, `gateWebTransportSendBytes`
        // would silently skip enforcement on uni streams.
        const state = try self.createState(stream_id);
        // createState registered the state in self.streams; the errdefer
        // above only resets the QUIC stream. Free the state too if a later
        // step (prefix write, flow bump) fails.
        errdefer {
            _ = self.streams.remove(stream_id);
            state.deinit(self.allocator);
            self.allocator.destroy(state);
        }
        state.wt_session_id = session_id;

        try self.writeWebTransportStreamPrefix(
            stream_id,
            webtransport_mod.StreamPrefix.uni_stream_type,
            session_id,
        );
        if (self.webTransportFlowMut(session_id)) |flow| flow.local_streams_opened_uni += 1;
        return stream_id;
    }

    /// Opens a locally-initiated WebTransport bidirectional stream and writes
    /// the WebTransport bidi-frame prefix (`FrameType.webtransport_bidi_stream`
    /// + varint Session ID) per draft-ietf-webtrans-http3 §4.2. Server-side
    /// callers carve out the bidi slot reserved for WebTransport sessions —
    /// the underlying QUIC stream is server-initiated bidi, which HTTP/3
    /// otherwise leaves unused.
    ///
    /// State is pre-registered with `bidi_kind = .webtransport` and the
    /// supplied `session_id` so that when the peer writes bytes back on
    /// the stream, `processBidiState` doesn't try to re-peek those
    /// (application-data) bytes as a fresh WT prefix.
    pub fn openWebTransportBidiStream(self: *Session, session_id: u64) Error!u64 {
        try self.start();
        try self.gateWebTransportStreamOpen(session_id, .bidi);

        // openNextBidi (quic-zig 0.5.0): reap-safe next local bidi id.
        const stream_id = (try self.quic.openNextBidi()).id;
        errdefer self.quic.streamReset(stream_id, protocol.ErrorCode.internal_error) catch {};

        const state = try self.createState(stream_id);
        state.bidi_kind = .webtransport;
        state.wt_session_id = session_id;

        try self.writeWebTransportStreamPrefix(
            stream_id,
            webtransport_mod.StreamPrefix.bidi_frame_type,
            session_id,
        );
        if (self.webTransportFlowMut(session_id)) |flow| flow.local_streams_opened_bidi += 1;
        return stream_id;
    }

    fn writeWebTransportStreamPrefix(
        self: *Session,
        stream_id: u64,
        prefix_type: u64,
        session_id: u64,
    ) Error!void {
        var prefix_buf: [16]u8 = undefined;
        var pos: usize = 0;
        pos += try varint.encode(prefix_buf[pos..], prefix_type);
        pos += try varint.encode(prefix_buf[pos..], session_id);
        try self.writeAll(stream_id, prefix_buf[0..pos]);
    }

    /// Writes raw bytes onto a WebTransport stream. No HTTP/3 frame wrapping —
    /// the bytes go straight to the underlying QUIC stream.
    ///
    /// If the stream's WT session has a peer-advertised `WT_MAX_DATA`
    /// limit set (folded natively from the CONNECT stream's capsule
    /// protocol), the write is
    /// gated against it: a write that would push `local_data_sent`
    /// past the limit returns
    /// `Error.WebTransportFlowControlExceeded` and the session
    /// auto-emits a `WT_DATA_BLOCKED` capsule on the CONNECT stream
    /// (once per limit value, so a steadily-blocked sender doesn't
    /// spam). Sessions without a peer limit are unaffected.
    pub fn writeWebTransportStream(self: *Session, stream_id: u64, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        try self.gateWebTransportSendBytes(stream_id, bytes.len);
        try self.writeAll(stream_id, bytes);
        self.recordWebTransportSendBytes(stream_id, bytes.len);
    }

    fn gateWebTransportStreamOpen(
        self: *Session,
        session_id: u64,
        direction: WebTransportStreamKind,
    ) Error!void {
        // Distinguish three lifecycle states:
        //   * `.none`   — session never existed or has been torn down
        //                 (peer FIN/RESET of CONNECT, local close,
        //                 or `endWebTransportSession` ran). Opens
        //                 against this state are caller bugs — the
        //                 stream prefix would point at a session id
        //                 the peer has no context for, so surface
        //                 `UnknownWebTransportSession`.
        //   * `.pending` — session is in flight (CONNECT sent, 2xx
        //                  not yet observed). Flow state exists from
        //                  creation with SETTINGS-seeded credit, so the
        //                  peer-limit / drain gating below applies just
        //                  like for established sessions; bytes still
        //                  buffer server-side via `BufferedStreamPolicy`
        //                  until confirmation.
        //   * `.established` — flow state is present, fall through
        //                      to the limit / drain checks.
        switch (self.webTransportSessionState(session_id)) {
            .none => return Error.UnknownWebTransportSession,
            // Pending sessions are gated too: §9.2 SETTINGS credit is
            // seeded when the session is created, so opens before
            // confirmation count against the same limits. (They used to
            // bypass flow control entirely until the 2xx landed.)
            .pending, .established => {},
        }
        const flow = self.webTransportFlowMut(session_id) orelse return;
        // draft-ietf-webtrans-http3 §5.5: after receiving DRAIN,
        // an endpoint MUST NOT open new WebTransport streams. The
        // application gets a structured error so it can wind down
        // its outbound traffic gracefully.
        if (flow.received_drain) return Error.WebTransportSessionDraining;
        const limit = switch (direction) {
            .bidi => flow.peer_max_streams_bidi,
            .uni => flow.peer_max_streams_uni,
        } orelse return;
        const opened = switch (direction) {
            .bidi => flow.local_streams_opened_bidi,
            .uni => flow.local_streams_opened_uni,
        };
        if (opened >= limit) {
            try self.maybeEmitStreamsBlocked(flow, direction, limit);
            return Error.WebTransportStreamLimitExceeded;
        }
    }

    fn gateWebTransportSendBytes(self: *Session, stream_id: u64, byte_count: usize) Error!void {
        // A WT write primitive invoked on an unknown or non-WT stream is
        // caller misuse — surface it instead of letting the write proceed
        // unmetered. (A live substream whose session has already reached
        // `.none` still tolerates the race below: the flow state is gone,
        // there is nothing left to meter, and stream-level errors handle
        // the rest.)
        const state = self.streams.get(stream_id) orelse return Error.UnknownWebTransportSession;
        const session_id = state.wt_session_id orelse return Error.UnknownWebTransportSession;
        const flow = self.webTransportFlowMut(session_id) orelse return;
        const limit = flow.peer_max_data orelse return;
        const next = flow.local_data_sent + @as(u64, byte_count);
        if (next > limit) {
            try self.maybeEmitDataBlocked(flow, limit);
            return Error.WebTransportFlowControlExceeded;
        }
    }

    fn recordWebTransportSendBytes(self: *Session, stream_id: u64, byte_count: usize) void {
        const state = self.streams.get(stream_id) orelse return;
        const session_id = state.wt_session_id orelse return;
        if (self.webTransportFlowMut(session_id)) |flow| {
            flow.local_data_sent += @as(u64, byte_count);
        }
    }

    fn maybeEmitDataBlocked(self: *Session, flow: *WTSessionFlowState, limit: u64) Error!void {
        if (flow.sent_data_blocked_for) |last| {
            if (last == limit) return; // already advertised against this limit
        }
        var buf: [24]u8 = undefined;
        const n = try encodeFlowControlCapsule(&buf, webtransport_mod.CapsuleType.data_blocked, limit);
        try self.writeCapsulePayloadOnStream(flow.session_id, buf[0..n]);
        flow.sent_data_blocked_for = limit;
    }

    fn maybeEmitStreamsBlocked(
        self: *Session,
        flow: *WTSessionFlowState,
        direction: WebTransportStreamKind,
        limit: u64,
    ) Error!void {
        const last_ptr = switch (direction) {
            .bidi => &flow.sent_streams_blocked_bidi_for,
            .uni => &flow.sent_streams_blocked_uni_for,
        };
        if (last_ptr.*) |last| {
            if (last == limit) return;
        }
        var buf: [24]u8 = undefined;
        const capsule_type: u64 = switch (direction) {
            .bidi => webtransport_mod.CapsuleType.streams_blocked_bidi,
            .uni => webtransport_mod.CapsuleType.streams_blocked_uni,
        };
        const n = try encodeFlowControlCapsule(&buf, capsule_type, limit);
        try self.writeCapsulePayloadOnStream(flow.session_id, buf[0..n]);
        last_ptr.* = limit;
    }

    /// Sends a FIN on a WebTransport stream.
    pub fn finishWebTransportStream(self: *Session, stream_id: u64) Error!void {
        try self.quic.streamFinish(stream_id);
    }

    /// Resets a WebTransport stream with the application's 32-bit error code
    /// translated through the WebTransport-to-HTTP/3 mapping in
    /// draft-ietf-webtrans-http3 §4.6.
    pub fn resetWebTransportStream(
        self: *Session,
        stream_id: u64,
        app_error_code: u32,
    ) Error!void {
        try self.quic.streamReset(stream_id, webtransport_mod.appErrorToHttp3(app_error_code));
    }

    /// Resets a WebTransport stream with one of the reserved wire codes
    /// (`buffered_stream_rejected_code` / `session_gone_code`) without going
    /// through the application-code mapping.
    pub fn resetWebTransportStreamWithCode(
        self: *Session,
        stream_id: u64,
        wire_code: u64,
    ) Error!void {
        try self.quic.streamReset(stream_id, wire_code);
    }

    // ----------------------------------------------------------------------
    // WebTransport session registry
    //
    // The registry tracks two disjoint sets of CONNECT stream IDs: the
    // pending set (handshake in flight) and the established set
    // (response observed / sent). Membership in *either* set marks the
    // stream id as a known WebTransport Session ID for the purposes of
    // peer-opened-stream dispatch.
    //
    // The lifecycle hooks are:
    //   - markWebTransportSessionPending — called by Client.startWebTransport
    //     after `openRequest`, and by `processMessageState` on the server
    //     when a WT CONNECT request arrives.
    //   - confirmWebTransportSession — called by Server.acceptWebTransport
    //     after the 2xx response is sent, and by `processMessageState` on
    //     the client when a 2xx response arrives for a pending session.
    //   - endWebTransportSession — called when the CONNECT stream is
    //     finished or reset, or when a non-2xx response is observed.
    //     Internal-only — applications signal "this session is over"
    //     by sending CLOSE_WEBTRANSPORT_SESSION (draft-15 §5.4) via
    //     the protocol-level API, not by calling this directly.
    //
    // When a session transitions from pending → established or
    // established → closed the buffered-stream replay path is run so
    // that any held stream events are emitted (or dropped) on the next
    // drain.
    // ----------------------------------------------------------------------

    pub const WebTransportSessionState = enum { none, pending, established };

    /// Seeds draft §9.2 initial flow-control credit from the SETTINGS
    /// exchange into `flow`, filling only limits that are still null:
    /// the values we advertised become the receive-side limits we
    /// enforce on the peer; the values the peer advertised gate our own
    /// sends. Fill-if-null makes the helper safe to call twice — the
    /// server marks a session pending when the CONNECT arrives, which
    /// may legally precede the client's SETTINGS, so confirmation
    /// re-runs the seed to pick up late-arriving peer credit without
    /// clobbering anything a capsule already granted. When a side
    /// advertised nothing the limit stays null (no enforcement).
    fn seedWebTransportFlowCredit(self: *const Session, flow: *WTSessionFlowState) void {
        // Session-level flow control exists only in the modern era: on a
        // legacy-resolved connection every limit stays null, which the
        // gate sites already treat as "no enforcement" — a legacy
        // session can never block on credit Chrome will never grant,
        // and the auto-BLOCKED emission paths stay unreachable.
        if ((self.wt_negotiated_draft orelse .draft16) != .draft16) return;
        if (flow.local_max_data == null) flow.local_max_data = self.local_settings.wt_initial_max_data;
        if (flow.local_max_streams_uni == null) flow.local_max_streams_uni = self.local_settings.wt_initial_max_streams_uni;
        if (flow.local_max_streams_bidi == null) flow.local_max_streams_bidi = self.local_settings.wt_initial_max_streams_bidi;
        if (self.peer_settings) |ps| {
            if (flow.peer_max_data == null) flow.peer_max_data = ps.wt_initial_max_data;
            if (flow.peer_max_streams_uni == null) flow.peer_max_streams_uni = ps.wt_initial_max_streams_uni;
            if (flow.peer_max_streams_bidi == null) flow.peer_max_streams_bidi = ps.wt_initial_max_streams_bidi;
        }
    }

    fn createWebTransportSession(
        self: *Session,
        stream_id: u64,
        phase: @FieldType(WTSessionState, "phase"),
    ) Error!*WTSessionState {
        const sess = try self.allocator.create(WTSessionState);
        errdefer self.allocator.destroy(sess);
        sess.* = .{
            .phase = phase,
            .draft = self.wt_negotiated_draft orelse .draft16,
            .flow = .{ .session_id = stream_id },
        };
        // Bound a single reassembled capsule's declared value length by
        // the same knob that caps outbound capsule values; null keeps
        // the reassembler unbounded (dev default; production() caps it).
        sess.reassembler.max_capsule_value_len =
            if (self.config.max_capsule_value_size) |cap| @as(u64, cap) else null;
        self.seedWebTransportFlowCredit(&sess.flow);
        try self.wt_sessions.put(self.allocator, stream_id, sess);
        if (phase == .pending) self.wt_pending_count += 1;
        if (phase == .established) sess.established_event_pending = true;
        return sess;
    }

    pub fn markWebTransportSessionPending(self: *Session, stream_id: u64) Error!void {
        if (self.wt_sessions.contains(stream_id)) return;
        // Cap unconfirmed pending sessions so a peer can't open many WT
        // CONNECTs without completing them and grow the map up to
        // MAX_STREAMS_BIDI. Only a genuinely new stream id can grow it.
        if (self.config.max_pending_wt_sessions) |limit| {
            if (self.wt_pending_count >= limit) {
                return Error.ExcessivePendingWebTransportSessions;
            }
        }
        _ = try self.createWebTransportSession(stream_id, .pending);
    }

    pub fn confirmWebTransportSession(self: *Session, stream_id: u64) Error!void {
        // Reject confirmation if the underlying CONNECT stream has
        // already been finished or reset. Otherwise the server
        // commits to a session whose request stream is dead, the
        // application then opens new WT streams, and the peer
        // resets every one of them with `WEBTRANSPORT_SESSION_GONE`
        // because it has no session context to associate them
        // with. Surfacing the error here lets the application give
        // up cleanly.
        if (self.streams.get(stream_id)) |state| {
            if (state.recv_finished or state.recv_reset_seen) {
                if (self.wt_sessions.get(stream_id)) |sess| {
                    if (sess.phase == .pending) {
                        _ = self.wt_sessions.remove(stream_id);
                        self.wt_pending_count -= 1;
                        sess.deinit(self.allocator);
                        self.allocator.destroy(sess);
                    }
                }
                return Error.SessionClosed;
            }
        }

        if (self.wt_sessions.get(stream_id)) |sess| {
            if (sess.phase == .established) return;
            // Defensive re-check: `acceptWebTransport` gates BEFORE the
            // response; direct-confirm callers get the same policy.
            try self.checkWebTransportSessionCapacity();
            sess.phase = .established;
            sess.established_event_pending = true;
            self.wt_pending_count -= 1;
            // Late seed: the server may have marked this session pending
            // before the client's SETTINGS landed — fill any still-null
            // peer credit now (fill-if-null; capsule-granted values win).
            self.seedWebTransportFlowCredit(&sess.flow);
            return;
        }
        // Direct confirmation without a prior pending mark (primitive
        // users / unit fixtures) keeps working.
        try self.checkWebTransportSessionCapacity();
        _ = try self.createWebTransportSession(stream_id, .established);
    }

    fn endWebTransportSession(self: *Session, stream_id: u64) void {
        if (self.wt_sessions.fetchRemove(stream_id)) |entry| {
            if (entry.value.phase == .pending) self.wt_pending_count -= 1;
            entry.value.deinit(self.allocator);
            self.allocator.destroy(entry.value);
        }
        // Deferred GOAWAY hand-off: once the last established session is
        // gone, the transport-level graceful shutdown the H3 GOAWAY
        // deferred can finally engage (idempotent latch upstream).
        if (self.graceful_shutdown_deferred and self.webTransportEstablishedCount() == 0) {
            self.graceful_shutdown_deferred = false;
            self.quic.beginGracefulShutdown();
        }
    }

    /// Sweeps every live substream of a terminating session:
    /// STOP_SENDING plus a best-effort send-side RESET, both with
    /// `WEBTRANSPORT_SESSION_GONE` — the draft folds session-gone
    /// stream resets into session termination. The CONNECT stream
    /// itself is not touched (the caller decides its fate: echo-FIN,
    /// reset, or nothing). No per-stream events are emitted; the
    /// session-scoped `webtransport_session_closed` event covers the
    /// teardown.
    fn sweepWebTransportSubstreams(self: *Session, session_id: u64) void {
        var it = self.streams.valueIterator();
        while (it.next()) |state_ptr| {
            const state = state_ptr.*;
            if (state.id == session_id) continue;
            const sid = state.wt_session_id orelse continue;
            if (sid != session_id) continue;
            self.quic.streamStopSending(state.id, webtransport_mod.session_gone_code) catch {};
            // Unconditional best-effort: succeeds for halves we own
            // (local uni, either bidi direction), harmlessly refused
            // for peer-owned uni halves.
            self.quic.streamReset(state.id, webtransport_mod.session_gone_code) catch {};
            state.locally_rejected = true;
            state.recv_finished = true;
            state.rx.clearRetainingCapacity();
            state.wt_buffered = false;
            self.removeFromBufferedList(state.id);
        }
    }

    /// Ends `session_id` and emits the session-closed event: clones the
    /// reason FIRST (it may alias the session's own reassembler
    /// buffer), then sweeps substreams, drops registry state, and
    /// appends the event.
    fn closeWebTransportSessionWithEvent(
        self: *Session,
        session_id: u64,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
        how: WebTransportSessionClosedHow,
        code: ?u32,
        reason: []const u8,
        wire_error_code: ?u64,
    ) Error!void {
        try budget.reserve(reason.len);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        self.sweepWebTransportSubstreams(session_id);
        self.endWebTransportSession(session_id);
        try self.appendReservedEvent(events, .{
            .webtransport_session_closed = .{
                .session_id = session_id,
                .how = how,
                .code = code,
                .reason = owned_reason,
                .wire_error_code = wire_error_code,
            },
        });
    }

    /// Message-scoped failure of a WT CONNECT stream (malformed capsule
    /// framing, capsules after CLOSE, FIN mid-capsule): abort the
    /// CONNECT stream both directions with H3_MESSAGE_ERROR — a MESSAGE
    /// error, deliberately not a connection error — and end the session
    /// with a `.protocol_violation` close event if it still exists.
    /// Does NOT touch `state.rx`: the caller may still be iterating it
    /// (`processMessageState` returns without compacting on failure).
    fn failWebTransportConnectMessage(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        try self.terminateWebTransportSessionWithCode(
            state.id,
            protocol.ErrorCode.message_error,
            events,
            budget,
        );
    }

    /// Session error [draft-ietf-webtrans-http3 §5.6]: terminate the WT
    /// session for a protocol violation — abort the CONNECT stream both
    /// directions with `wire_code`, sweep substreams, drop registry
    /// state, and emit a `.protocol_violation` close event. The
    /// CONNECTION stays up; this is deliberately session-scoped.
    fn terminateWebTransportSessionWithCode(
        self: *Session,
        session_id: u64,
        wire_code: u64,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        self.quic.streamStopSending(session_id, wire_code) catch {};
        self.quic.streamReset(session_id, wire_code) catch {};
        if (self.streams.get(session_id)) |cstate| {
            cstate.locally_rejected = true;
            cstate.recv_finished = true;
            cstate.wt_close_observed = true;
        }
        if (self.wt_sessions.contains(session_id)) {
            try self.closeWebTransportSessionWithEvent(
                session_id,
                events,
                budget,
                .protocol_violation,
                null,
                "",
                wire_code,
            );
        }
    }

    /// True when `state`/`kind` name the body of a known WT CONNECT
    /// stream (or its post-CLOSE tombstone) in the direction the
    /// capsule protocol flows for our role.
    fn isWebTransportConnectBody(self: *const Session, state: *const StreamState, kind: message_mod.Kind) bool {
        const direction_ok = switch (self.role) {
            .server => kind == .request,
            .client => kind == .response,
        };
        if (!direction_ok) return false;
        return self.wt_sessions.contains(state.id) or state.wt_close_observed;
    }

    const WTIngestOutcome = enum { ok, stream_failed };

    /// Native ingestion entry: feeds one DATA event's worth of WT
    /// CONNECT-stream body bytes into the session's reassembler and
    /// folds complete capsules. `.stream_failed` tells the caller the
    /// CONNECT stream was message-error aborted (stop processing it).
    fn ingestWebTransportCapsuleBytes(
        self: *Session,
        state: *StreamState,
        bytes: []const u8,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!WTIngestOutcome {
        if (state.wt_close_observed) {
            // Capsules MUST NOT follow CLOSE_WEBTRANSPORT_SESSION.
            try self.failWebTransportConnectMessage(state, events, budget);
            return .stream_failed;
        }
        // Bytes racing a completed teardown are dropped (same tolerance
        // as the manual-observe path's `.none` rule).
        const sess = self.wt_sessions.get(state.id) orelse return .ok;
        try sess.reassembler.push(self.allocator, bytes);
        return self.drainWebTransportReassembler(sess, state, events, budget);
    }

    /// Conservative per-fold budget headroom: covers the largest
    /// session-scoped event payload with a bounded size (a CLOSE reason
    /// is at most 1024 bytes). Unknown-capsule values reserve their
    /// exact size and may still surface the normal oversized-payload
    /// budget errors, matching oversized `data` events.
    const wt_session_event_budget_headroom: usize = 1280;

    /// Streams limits cap at 2^60 [draft-ietf-webtrans-http3 §5.6].
    const webtransport_max_streams_ceiling: u64 = 1 << 60;

    fn drainBudgetHasRoom(budget: *const DrainBudget, owned_payload_bytes: usize) bool {
        if (budget.max_events) |max| {
            if (budget.events >= max) return false;
        }
        if (budget.max_payload_size) |max| {
            if (owned_payload_bytes > max) return false;
        }
        if (budget.max_payload_bytes) |max| {
            if (owned_payload_bytes > max or budget.payload_bytes > max - owned_payload_bytes) return false;
        }
        return true;
    }

    /// Folds complete capsules out of the session's reassembler under a
    /// conservative budget guard. Pauses (bytes stay buffered) when the
    /// budget cannot take another session event; the next drain resumes
    /// via `flushWebTransportSessionSignals`.
    fn drainWebTransportReassembler(
        self: *Session,
        sess: *WTSessionState,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!WTIngestOutcome {
        while (true) {
            if (!drainBudgetHasRoom(budget, wt_session_event_budget_headroom)) return .ok;
            const maybe = sess.reassembler.next() catch {
                // Undecodable capsule framing (bad varints, declared
                // value over the reassembly cap): the capsule stream is
                // unrecoverable — message error.
                try self.failWebTransportConnectMessage(state, events, budget);
                return .stream_failed;
            };
            const capsule = maybe orelse return .ok;
            switch (try self.foldWebTransportCapsuleNative(sess, state, capsule, events, budget)) {
                .continue_folding => {},
                // `sess` was destroyed with the session — do not touch
                // it (or its reassembler) again.
                .session_ended => return .ok,
                .stream_failed => return .stream_failed,
            }
        }
    }

    const WTFoldOutcome = enum { continue_folding, session_ended, stream_failed };

    /// The native fold: one complete capsule from the CONNECT stream
    /// into session state + typed events. The session is the sole
    /// consumer of the CONNECT stream's capsule protocol.
    fn foldWebTransportCapsuleNative(
        self: *Session,
        sess: *WTSessionState,
        state: *StreamState,
        capsule: capsule_mod.Capsule,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!WTFoldOutcome {
        const session_id = sess.flow.session_id;
        // Browser-era sessions predate session-level flow control: the
        // six WT_MAX_*/BLOCKED types are just unknown capsules to them
        // (CLOSE and DRAIN are era-stable — Chrome sends DRAIN even in
        // draft-02 mode). Routing them below keeps every modern-era
        // capsule MUST from firing against a legacy peer.
        const flow_capsules_active = sess.draft == .draft16;
        switch (capsule.capsule_type) {
            webtransport_mod.CapsuleType.close_session => {
                const close_info = webtransport_mod.decodeCloseSessionValue(capsule.value) catch {
                    // Malformed CLOSE (short value, oversized or
                    // invalid-UTF-8 reason) is a message error
                    // [draft-ietf-webtrans-http3 §5.4].
                    try self.failWebTransportConnectMessage(state, events, budget);
                    return .stream_failed;
                };
                if (sess.reassembler.buffered() > 0) {
                    // Capsules MUST NOT follow CLOSE — trailing bytes in
                    // the same flight are a message error.
                    try self.failWebTransportConnectMessage(state, events, budget);
                    return .stream_failed;
                }
                state.wt_close_observed = true;
                // Clean close: event first (the reason aliases the
                // reassembler owned by the session state we destroy),
                // then echo-FIN our send half — the draft's clean-close
                // shape is CLOSE, then FIN in both directions.
                try self.closeWebTransportSessionWithEvent(
                    session_id,
                    events,
                    budget,
                    .close_capsule,
                    close_info.code,
                    close_info.reason,
                    null,
                );
                self.finishStream(session_id) catch {};
                return .session_ended;
            },
            webtransport_mod.CapsuleType.drain_session => {
                if (capsule.value.len != 0) {
                    // Strictness unified with `classifyCapsule`: DRAIN's
                    // value MUST be empty [draft-ietf-webtrans-http3
                    // §5.5]; a non-empty one is a malformed capsule.
                    try self.failWebTransportConnectMessage(state, events, budget);
                    return .stream_failed;
                }
                if (!sess.flow.received_drain) {
                    sess.flow.received_drain = true;
                    try budget.reserve(0);
                    try self.appendReservedEvent(events, .{
                        .webtransport_session_draining = .{ .session_id = session_id },
                    });
                }
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.max_data => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeMaxDataValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                if (sess.flow.peer_max_data == null or value > sess.flow.peer_max_data.?) {
                    sess.flow.peer_max_data = value;
                    sess.flow.sent_data_blocked_for = null;
                    try budget.reserve(0);
                    try self.appendReservedEvent(events, .{
                        .webtransport_credit_granted = .{
                            .session_id = session_id,
                            .kind = .data,
                            .limit = value,
                        },
                    });
                }
                // Non-increasing values are NOT applied (monotonic fold)
                // and emit nothing — a peer cannot shrink our budget.
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.max_streams_bidi => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeMaxStreamsBidiValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                if (value > webtransport_max_streams_ceiling) {
                    // Streams limits cap at 2^60
                    // [draft-ietf-webtrans-http3 §5.6]: an oversized
                    // value closes the session with WT_FLOW_CONTROL_ERROR.
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                }
                if (sess.flow.peer_max_streams_bidi == null or value > sess.flow.peer_max_streams_bidi.?) {
                    sess.flow.peer_max_streams_bidi = value;
                    sess.flow.sent_streams_blocked_bidi_for = null;
                    try budget.reserve(0);
                    try self.appendReservedEvent(events, .{
                        .webtransport_credit_granted = .{
                            .session_id = session_id,
                            .kind = .streams_bidi,
                            .limit = value,
                        },
                    });
                }
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.max_streams_uni => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeMaxStreamsUniValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                if (value > webtransport_max_streams_ceiling) {
                    // Streams limits cap at 2^60
                    // [draft-ietf-webtrans-http3 §5.6]: an oversized
                    // value closes the session with WT_FLOW_CONTROL_ERROR.
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                }
                if (sess.flow.peer_max_streams_uni == null or value > sess.flow.peer_max_streams_uni.?) {
                    sess.flow.peer_max_streams_uni = value;
                    sess.flow.sent_streams_blocked_uni_for = null;
                    try budget.reserve(0);
                    try self.appendReservedEvent(events, .{
                        .webtransport_credit_granted = .{
                            .session_id = session_id,
                            .kind = .streams_uni,
                            .limit = value,
                        },
                    });
                }
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.data_blocked => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeDataBlockedValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                try budget.reserve(0);
                try self.appendReservedEvent(events, .{
                    .webtransport_peer_blocked = .{
                        .session_id = session_id,
                        .kind = .data,
                        .offered_limit = value,
                    },
                });
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.streams_blocked_bidi => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeStreamsBlockedBidiValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                if (value > webtransport_max_streams_ceiling) {
                    // Streams limits cap at 2^60
                    // [draft-ietf-webtrans-http3 §5.6]: an oversized
                    // value closes the session with WT_FLOW_CONTROL_ERROR.
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                }
                try budget.reserve(0);
                try self.appendReservedEvent(events, .{
                    .webtransport_peer_blocked = .{
                        .session_id = session_id,
                        .kind = .streams_bidi,
                        .offered_limit = value,
                    },
                });
                return .continue_folding;
            },
            webtransport_mod.CapsuleType.streams_blocked_uni => {
                if (!flow_capsules_active) return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget);
                const value = webtransport_mod.decodeStreamsBlockedUniValue(capsule.value) catch {
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                };
                if (value > webtransport_max_streams_ceiling) {
                    // Streams limits cap at 2^60
                    // [draft-ietf-webtrans-http3 §5.6]: an oversized
                    // value closes the session with WT_FLOW_CONTROL_ERROR.
                    try self.terminateWebTransportSessionWithCode(
                        session_id,
                        webtransport_mod.flow_control_error_code,
                        events,
                        budget,
                    );
                    return .session_ended;
                }
                try budget.reserve(0);
                try self.appendReservedEvent(events, .{
                    .webtransport_peer_blocked = .{
                        .session_id = session_id,
                        .kind = .streams_uni,
                        .offered_limit = value,
                    },
                });
                return .continue_folding;
            },
            else => return self.foldUnknownWebTransportCapsule(sess, state, capsule, events, budget),
        }
    }

    /// Unknown capsule types MUST be ignored (RFC 9297 §3.2) — surfaced
    /// byte-exact so intermediaries can forward. Also the destination
    /// for modern flow-control capsules arriving on a browser-era
    /// session, where those types are not defined.
    fn foldUnknownWebTransportCapsule(
        self: *Session,
        sess: *WTSessionState,
        state: *StreamState,
        capsule: capsule_mod.Capsule,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!WTFoldOutcome {
        _ = state;
        try budget.reserve(capsule.value.len);
        const owned = try self.allocator.dupe(u8, capsule.value);
        errdefer self.allocator.free(owned);
        try self.appendReservedEvent(events, .{
            .webtransport_unknown_capsule = .{
                .session_id = sess.flow.session_id,
                .capsule_type = capsule.capsule_type,
                .value = owned,
            },
        });
        return .continue_folding;
    }

    /// Drain-top pass: emits pending `webtransport_session_established`
    /// events (BEFORE buffered-stream replay, so establishment precedes
    /// replayed stream events) and resumes any budget-paused capsule
    /// folding.
    fn flushWebTransportSessionSignals(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        // Collect ids first — folding a CLOSE mutates the map mid-walk.
        var ids: std.ArrayList(u64) = .empty;
        defer ids.deinit(self.allocator);
        var it = self.wt_sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.established_event_pending or
                entry.value_ptr.*.reassembler.buffered() > 0)
            {
                try ids.append(self.allocator, entry.key_ptr.*);
            }
        }
        for (ids.items) |session_id| {
            const sess = self.wt_sessions.get(session_id) orelse continue;
            if (sess.established_event_pending) {
                if (!drainBudgetHasRoom(budget, 0)) return;
                sess.established_event_pending = false;
                try budget.reserve(0);
                try self.appendReservedEvent(events, .{
                    .webtransport_session_established = .{ .session_id = session_id },
                });
            }
            if (sess.reassembler.buffered() > 0) {
                const state = self.streams.get(session_id) orelse continue;
                _ = try self.drainWebTransportReassembler(sess, state, events, budget);
            }
        }
    }

    pub fn webTransportSessionState(self: *const Session, stream_id: u64) WebTransportSessionState {
        const sess = self.wt_sessions.get(stream_id) orelse return .none;
        return switch (sess.phase) {
            .pending => .pending,
            .established => .established,
        };
    }

    pub fn webTransportPendingCount(self: *const Session) usize {
        return self.wt_pending_count;
    }

    pub fn webTransportEstablishedCount(self: *const Session) usize {
        return self.wt_sessions.count() - self.wt_pending_count;
    }

    /// Accept-time capacity gate for `Config.max_wt_sessions`. Called by
    /// `Server.acceptWebTransport` BEFORE the 2xx goes on the wire (a
    /// confirm-time failure would be too late — the response is already
    /// sent); public so raw-Session embedders can gate the same way.
    pub fn checkWebTransportSessionCapacity(self: *const Session) Error!void {
        if (self.config.max_wt_sessions) |limit| {
            if (self.webTransportEstablishedCount() >= limit) {
                return Error.WebTransportSessionLimitReached;
            }
        }
    }

    /// The draft era WebTransport resolved to on this connection, or
    /// null before peer SETTINGS arrive / when no era intersects. Every
    /// session on the connection carries this era.
    pub fn webTransportNegotiatedDraft(self: *const Session) ?webtransport_mod.WtDraft {
        return self.wt_negotiated_draft;
    }

    pub fn webTransportBufferedByteCount(self: *const Session) usize {
        return self.bufferedWebTransportBytes();
    }

    /// True if `session_id` references a WebTransport CONNECT stream that
    /// the session knows about (pending or established). Used by the
    /// inbound-stream dispatch to decide whether to emit events,
    /// buffer, or reject.
    pub fn webTransportSessionExists(self: *const Session, session_id: u64) bool {
        return self.webTransportSessionState(session_id) != .none;
    }

    /// Returns the per-session flow-control snapshot for an established
    /// WebTransport session, or null if the session id is unknown or
    /// not yet confirmed. The snapshot is a value-typed copy and is
    /// safe to inspect outside any drain.
    pub fn webTransportFlowSnapshot(self: *const Session, session_id: u64) ?WTSessionFlowSnapshot {
        // Public contract unchanged: snapshots are for ESTABLISHED
        // sessions only (pending flow state is an internal gating
        // detail until it settles).
        const sess = self.wt_sessions.get(session_id) orelse return null;
        if (sess.phase != .established) return null;
        var snapshot = WTSessionFlowSnapshot.fromState(&sess.flow);
        snapshot.draft = sess.draft;
        return snapshot;
    }

    /// Mutable flow state for BOTH phases: pending sessions carry seeded
    /// §9.2 credit and are gated/counted exactly like established ones.
    fn webTransportFlowMut(self: *Session, session_id: u64) ?*WTSessionFlowState {
        const sess = self.wt_sessions.get(session_id) orelse return null;
        return &sess.flow;
    }

    /// Updates the locally-advertised `WT_MAX_DATA` limit and emits a
    /// matching capsule on the session's CONNECT stream. The capsule
    /// is sent as a reliable Capsule Protocol record on the response /
    /// request body — the peer's native capsule ingestion picks it up
    /// and updates its `peer_max_data`. Sending a non-increasing
    /// value is allowed (the peer ignores it per draft §5.6.4) but
    /// uncommon.
    pub fn sendWebTransportMaxData(self: *Session, session_id: u64, value: u64) Error!void {
        const sess = self.wt_sessions.get(session_id) orelse return Error.UnknownWebTransportSession;
        if (sess.draft != .draft16) return Error.WebTransportEraUnsupported;
        const flow = &sess.flow;
        var buf: [24]u8 = undefined;
        const n = try encodeFlowControlCapsule(&buf, webtransport_mod.CapsuleType.max_data, value);
        try self.writeCapsulePayloadOnStream(session_id, buf[0..n]);
        flow.local_max_data = value;
    }

    /// Updates the locally-advertised `WT_MAX_STREAMS_BIDI` (or _UNI)
    /// limit and emits the matching capsule.
    pub fn sendWebTransportMaxStreams(
        self: *Session,
        session_id: u64,
        direction: WebTransportStreamKind,
        value: u64,
    ) Error!void {
        const sess = self.wt_sessions.get(session_id) orelse return Error.UnknownWebTransportSession;
        // The flow-control capsules don't exist in the browser eras —
        // an intermediary must not emit modern capsules at a legacy
        // peer even though unknown-capsule tolerance would swallow them.
        if (sess.draft != .draft16) return Error.WebTransportEraUnsupported;
        const flow = &sess.flow;
        var buf: [24]u8 = undefined;
        const capsule_type: u64 = switch (direction) {
            .bidi => webtransport_mod.CapsuleType.max_streams_bidi,
            .uni => webtransport_mod.CapsuleType.max_streams_uni,
        };
        const n = try encodeFlowControlCapsule(&buf, capsule_type, value);
        try self.writeCapsulePayloadOnStream(session_id, buf[0..n]);
        switch (direction) {
            .bidi => flow.local_max_streams_bidi = value,
            .uni => flow.local_max_streams_uni = value,
        }
    }

    fn writeCapsulePayloadOnStream(self: *Session, stream_id: u64, payload: []const u8) Error!void {
        switch (self.role) {
            .client => try self.sendRequestData(stream_id, payload),
            .server => try self.sendResponseData(stream_id, payload),
        }
    }

    pub fn sendRequestData(self: *Session, stream_id: u64, data: []const u8) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        const state = try self.getState(stream_id);
        const encoder = try self.ensureEncoder(state, .request);
        try self.writeDataWithEncoder(stream_id, encoder, data);
    }

    pub fn sendRequestCapsule(self: *Session, stream_id: u64, capsule_type: u64, value: []const u8) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.sendCapsuleData(stream_id, .request, capsule_type, value);
    }

    pub fn sendRequestDatagramCapsule(self: *Session, stream_id: u64, payload: []const u8) Error!void {
        try self.validatePeerDatagramEnabled();
        try self.sendRequestCapsule(stream_id, capsule_mod.Type.datagram, payload);
    }

    pub fn sendRequestDatagramContextCapsule(
        self: *Session,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.validatePeerDatagramEnabled();
        const value_len = try contextPayloadEncodedLenChecked(context_id, payload.len);
        try self.validateCapsuleValueSize(value_len);
        const value = try self.allocator.alloc(u8, value_len);
        defer self.allocator.free(value);
        const n = try datagram_mod.encodeContextPayload(value, context_id, payload);
        try self.sendRequestDatagramCapsule(stream_id, value[0..n]);
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

    pub fn sendResponseCapsule(self: *Session, stream_id: u64, capsule_type: u64, value: []const u8) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.sendCapsuleData(stream_id, .response, capsule_type, value);
    }

    pub fn sendResponseDatagramCapsule(self: *Session, stream_id: u64, payload: []const u8) Error!void {
        try self.validatePeerDatagramEnabled();
        try self.sendResponseCapsule(stream_id, capsule_mod.Type.datagram, payload);
    }

    pub fn sendResponseDatagramContextCapsule(
        self: *Session,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.validatePeerDatagramEnabled();
        const value_len = try contextPayloadEncodedLenChecked(context_id, payload.len);
        try self.validateCapsuleValueSize(value_len);
        const value = try self.allocator.alloc(u8, value_len);
        defer self.allocator.free(value);
        const n = try datagram_mod.encodeContextPayload(value, context_id, payload);
        try self.sendResponseDatagramCapsule(stream_id, value[0..n]);
    }

    pub fn sendResponseTrailers(self: *Session, stream_id: u64, fields: []const qpack.FieldLine) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        const state = try self.ensureMessageState(stream_id, .request, .response);
        const encoder = try self.ensureEncoder(state, .response);
        try self.writeTrailersWithEncoder(stream_id, encoder, fields);
    }

    pub fn startPush(
        self: *Session,
        request_stream_id: u64,
        promise_fields: []const qpack.FieldLine,
        response_fields: []const qpack.FieldLine,
    ) Error!LocalPush {
        if (self.role != .server) return Error.InvalidRole;
        try self.start();
        if (!self.peerAllowsPush(self.next_push_id)) return Error.PushBlockedByGoaway;
        const push_id = try self.reservePushId();
        try self.writePushPromise(request_stream_id, push_id, promise_fields);
        const stream_id = try self.openPushStream(push_id, response_fields);
        return .{
            .request_stream_id = request_stream_id,
            .push_id = push_id,
            .stream_id = stream_id,
        };
    }

    pub fn sendPushData(self: *Session, stream_id: u64, data: []const u8) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        const state = try self.getState(stream_id);
        switch (state.uni_kind orelse return Error.WrongMessageKind) {
            .push => {},
            else => return Error.WrongMessageKind,
        }
        const encoder = try self.ensureEncoder(state, .push);
        try self.writeDataWithEncoder(stream_id, encoder, data);
    }

    pub fn sendPushTrailers(self: *Session, stream_id: u64, fields: []const qpack.FieldLine) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        const state = try self.getState(stream_id);
        switch (state.uni_kind orelse return Error.WrongMessageKind) {
            .push => {},
            else => return Error.WrongMessageKind,
        }
        const encoder = try self.ensureEncoder(state, .push);
        try self.writeTrailersWithEncoder(stream_id, encoder, fields);
    }

    pub fn cancelPush(self: *Session, push_id: u64) Error!void {
        try self.start();
        try self.validateLocalCancelPushId(push_id);
        try self.writeControlFrame(.{ .cancel_push = push_id });
        self.trace(.{
            .name = .cancel_push_sent,
            .role = self.role,
            .frame_type = protocol.FrameType.cancel_push,
            .value = push_id,
        });
        switch (self.role) {
            .client => self.stopReceivingPushIfOpen(push_id),
            .server => self.abortLocalPushIfOpen(push_id),
        }
    }

    pub fn sendPriorityUpdateForRequest(
        self: *Session,
        stream_id: u64,
        priority: priority_mod.Priority,
    ) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try validatePriorityRequestStreamId(stream_id);
        var priority_value_buf: [32]u8 = undefined;
        const priority_value_n = try priority.encode(&priority_value_buf);
        try self.sendPriorityUpdate(.{
            .priority_update_request = .{
                .prioritized_element_id = stream_id,
                .priority_field_value = priority_value_buf[0..priority_value_n],
            },
        });
        self.trace(.{
            .name = .priority_update_sent,
            .role = self.role,
            .stream_id = stream_id,
            .frame_type = protocol.FrameType.priority_update_request,
            .value = @as(u64, priority.urgency),
        });
    }

    pub fn sendPriorityUpdateForPush(
        self: *Session,
        push_id: u64,
        priority: priority_mod.Priority,
    ) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.validateLocalPriorityPushId(push_id);
        var priority_value_buf: [32]u8 = undefined;
        const priority_value_n = try priority.encode(&priority_value_buf);
        try self.sendPriorityUpdate(.{
            .priority_update_push = .{
                .prioritized_element_id = push_id,
                .priority_field_value = priority_value_buf[0..priority_value_n],
            },
        });
        self.trace(.{
            .name = .priority_update_sent,
            .role = self.role,
            .frame_type = protocol.FrameType.priority_update_push,
            .value = push_id,
        });
    }

    pub fn priorityForRequest(self: *const Session, stream_id: u64) ?priority_mod.Priority {
        return self.request_priorities.get(stream_id);
    }

    pub fn priorityForPush(self: *const Session, push_id: u64) ?priority_mod.Priority {
        return self.push_priorities.get(push_id);
    }

    // ----------------------------------------------------------------------
    // Stream lifecycle verbs
    //
    // The public surface uses three distinct mechanisms to terminate a
    // stream — they map to different QUIC frames, with different
    // semantics. Picking the wrong one corrupts the wire. The taxonomy:
    //
    //   * `finishStream` (clean half-close) — sends a QUIC FIN. No error
    //     code; bytes already sent are committed. Use after the last
    //     payload byte goes out.
    //
    //   * `resetStream` / `resetRequest` / `resetResponse` (outbound
    //     abort) — sends RESET_STREAM with an application error code.
    //     Drops in-flight outbound bytes; the peer sees the error code.
    //     Use when *we* want to stop sending (and don't care if the
    //     peer's already-sent bytes still arrive).
    //
    //   * `cancelRequest` / `rejectRequest` / `stopSending` (inbound
    //     abort) — sends QUIC STOP_SENDING. Asks the *peer* to stop
    //     sending us bytes; doesn't drop our own outbound. Use when we
    //     want to discard the response/request body but stay polite to
    //     our own send buffer.
    //
    // Convenience wrappers `Client.abort` / `Server.abort` issue a
    // RESET_STREAM with a role-appropriate default code (`request_cancelled`
    // on the client, `internal_error` on the server). For a *full* abort
    // (drop both directions), call `reset` followed by `cancel` (or vice
    // versa) — there is no single-call helper today.
    // ----------------------------------------------------------------------

    /// Sends a QUIC FIN on `stream_id` — clean half-close on the send
    /// side. Already-sent bytes are committed; no error code is exposed
    /// to the peer. Idempotent at the QUIC layer.
    ///
    /// If `stream_id` is the CONNECT control stream of a known WebTransport
    /// session, the local registry is also torn down — local FIN
    /// implicitly ends the session per draft-ietf-webtrans-http3 §5.4,
    /// mirroring what `observeFin` already does on the receive side. After
    /// this returns, peer-opened WT streams targeting this session id are
    /// routed through the buffered-stream policy instead of dispatched
    /// against a session we've already abandoned.
    pub fn finishStream(self: *Session, stream_id: u64) Error!void {
        if (self.shutdown_state == .closed) return Error.SessionClosed;
        try self.quic.streamFinish(stream_id);
        if (self.streams.get(stream_id)) |state| state.locally_finished = true;
        if (self.webTransportSessionExists(stream_id)) {
            // Local FIN ends the session: sweep live substreams with
            // SESSION_GONE (the draft folds those resets into session
            // termination). No event — the application initiated this.
            self.sweepWebTransportSubstreams(stream_id);
            self.endWebTransportSession(stream_id);
        }
    }

    pub fn sendDatagram(self: *Session, stream_id: u64, payload: []const u8) Error!void {
        _ = try self.sendDatagramTracked(stream_id, payload);
    }

    pub fn sendDatagramTracked(self: *Session, stream_id: u64, payload: []const u8) Error!u64 {
        if (self.shutdown_state == .closed) return Error.SessionClosed;
        try self.validateDatagramSend(stream_id, payload.len);

        const len = try datagram_mod.encodedLen(stream_id, payload.len);
        const encoded = try self.allocator.alloc(u8, len);
        defer self.allocator.free(encoded);
        const n = try datagram_mod.encode(encoded, stream_id, payload);
        const id = try self.quic.sendDatagramTracked(encoded[0..n]);
        self.trace(.{
            .name = .datagram_sent,
            .role = self.role,
            .stream_id = stream_id,
            .bytes = payload.len,
            .value = id,
        });
        return id;
    }

    pub fn sendDatagramWithContext(
        self: *Session,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) Error!void {
        _ = try self.sendDatagramWithContextTracked(stream_id, context_id, payload);
    }

    pub fn sendDatagramWithContextTracked(
        self: *Session,
        stream_id: u64,
        context_id: u64,
        payload: []const u8,
    ) Error!u64 {
        const payload_len = datagram_mod.contextPayloadEncodedLen(context_id, payload.len);
        try self.validateDatagramSend(stream_id, payload_len);

        const len = try datagram_mod.encodedLenWithContext(stream_id, context_id, payload.len);
        const encoded = try self.allocator.alloc(u8, len);
        defer self.allocator.free(encoded);
        const n = try datagram_mod.encodeWithContext(encoded, stream_id, context_id, payload);
        const id = try self.quic.sendDatagramTracked(encoded[0..n]);
        self.trace(.{
            .name = .datagram_sent,
            .role = self.role,
            .stream_id = stream_id,
            .bytes = payload.len,
            .value = id,
        });
        return id;
    }

    /// Outbound abort. Sends RESET_STREAM with `application_error_code`,
    /// dropping any buffered or in-flight outbound bytes. Cancels QPACK
    /// dynamic-table references owned by this stream. The peer sees the
    /// error code on its receive side. Use when we no longer want to send.
    ///
    /// If `stream_id` is the CONNECT control stream of a known WebTransport
    /// session, the local registry is also torn down — RESET implies
    /// abandonment, same as `finishStream`'s handling.
    pub fn resetStream(self: *Session, stream_id: u64, application_error_code: u64) Error!void {
        self.qpack_encoder_state.cancelStream(stream_id);
        try self.quic.streamReset(stream_id, application_error_code);
        if (self.streams.get(stream_id)) |state| state.locally_finished = true;
        self.trace(.{
            .name = .stream_reset_sent,
            .role = self.role,
            .stream_id = stream_id,
            .error_code = application_error_code,
        });
        if (self.webTransportSessionExists(stream_id)) {
            // RESET implies abandonment, same as `finishStream`.
            self.sweepWebTransportSubstreams(stream_id);
            self.endWebTransportSession(stream_id);
        }
    }

    /// Client-only convenience around `resetStream` — fails fast for a
    /// server-role caller.
    pub fn resetRequest(self: *Session, stream_id: u64, application_error_code: u64) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.resetStream(stream_id, application_error_code);
    }

    /// Server-only convenience around `resetStream` — fails fast for a
    /// client-role caller.
    pub fn resetResponse(self: *Session, stream_id: u64, application_error_code: u64) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.resetStream(stream_id, application_error_code);
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
        // Pair the H3-layer GOAWAY with quic-zig 0.4.0's transport-level
        // graceful shutdown: stop granting the peer MAX_STREAMS credit and
        // refuse new local stream opens (Error.ShuttingDown) so both sides
        // quiesce new-stream creation while in-flight streams drain. QUIC has
        // no GOAWAY frame — this is the intended transport building block a
        // higher layer pairs with its own GOAWAY signal. Existing stream-limit
        // credit is not revoked, so in-flight streams still complete.
        //
        // EXCEPT while WebTransport sessions are live — established OR
        // pending: draft-16 requires established sessions to survive
        // GOAWAY (including opening NEW substreams), and a pending
        // CONNECT admitted before the GOAWAY can still be accepted
        // afterward, at which point it needs fresh stream credit the
        // latched transport would never grant. The latch is deferred
        // until the last session ends (`endWebTransportSession` fires
        // it); the H3 request gates enforce GOAWAY on their own during
        // the window.
        // Long quiet drains are the embedder's keepalive problem:
        // max_idle_timeout keeps running, so drive
        // `Connection.requestPing()` (or WT-level traffic) if sessions
        // can go traffic-idle for minutes.
        if (self.webTransportEstablishedCount() > 0 or self.webTransportPendingCount() > 0) {
            self.graceful_shutdown_deferred = true;
        } else {
            self.quic.beginGracefulShutdown();
        }
        self.trace(.{
            .name = .goaway_sent,
            .role = self.role,
            .value = id,
            .frame_type = protocol.FrameType.goaway,
        });
    }

    /// Highest client-initiated bidirectional stream id observed from the
    /// peer — the stream that "was or might be processed" per RFC 9114
    /// §5.2, recorded before any per-stream rejection so auto-rejected
    /// streams count too. Extension streams sharing the client-bidi id
    /// space (WebTransport bidi, RFC 9114 §6.1 carve-outs) are included;
    /// they only raise the bound, which claims strictly less future work.
    /// Null on clients (servers do not initiate request streams) and on a
    /// server before the first client stream arrives. Feed into
    /// `gracefulGoawayId` — or use it directly — instead of hand-tracking
    /// stream ids from drained events.
    pub fn highestPeerRequestStreamId(self: *const Session) ?u64 {
        return self.highest_peer_request_stream_id;
    }

    /// The id to pass to `sendGoaway` for a graceful shutdown that admits
    /// everything already seen and nothing new (RFC 9114 §5.2). Server
    /// role: the next client bidi stream id after the highest observed
    /// (`highestPeerRequestStreamId() + 4`), or `0` when no request
    /// stream was ever observed — GOAWAY rejects ids >= the value, so `0`
    /// is the §5.2 "no requests were processed" form. Client role: the
    /// same shape over push ids (`highest + 1`, or `0` for "no pushes
    /// processed"). Clamped to a previously sent GOAWAY id — §5.2 forbids
    /// raising the bound, and streams observed after the first GOAWAY
    /// were auto-rejected, not processed — so the result is always valid
    /// for `sendGoaway`.
    pub fn gracefulGoawayId(self: *const Session) u64 {
        const next: u64 = switch (self.role) {
            .server => if (self.highest_peer_request_stream_id) |id| id + 4 else 0,
            .client => if (self.highest_peer_push_id) |id| id + 1 else 0,
        };
        const limit = self.sent_goaway_id orelse return next;
        return @min(next, limit);
    }

    /// Inbound abort. Sends QUIC STOP_SENDING with the given error code,
    /// asking the peer to stop sending us bytes on `stream_id`. Does NOT
    /// drop our own outbound bytes — pair with `resetStream` for a full
    /// bidirectional abort.
    pub fn stopSending(self: *Session, stream_id: u64, application_error_code: u64) Error!void {
        try self.quic.streamStopSending(stream_id, application_error_code);
    }

    /// Server-only inbound abort: STOP_SENDING with `request_rejected`.
    /// Use to refuse a request body while still allowing our response to
    /// flow (e.g. for a 4xx with a small error body).
    pub fn rejectRequest(self: *Session, stream_id: u64) Error!void {
        if (self.role != .server) return Error.InvalidRole;
        try self.stopSending(stream_id, protocol.ErrorCode.request_rejected);
    }

    /// Client-only inbound abort: STOP_SENDING with `request_cancelled`.
    /// Use to discard a server response we no longer care about. Does
    /// NOT cancel our own request send — for that, also call
    /// `resetRequest`.
    pub fn cancelRequest(self: *Session, stream_id: u64) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        try self.stopSending(stream_id, protocol.ErrorCode.request_cancelled);
    }

    pub fn shutdownState(self: *const Session) ShutdownState {
        return self.shutdown_state;
    }

    /// Number of in-flight request/response exchanges (see
    /// `isOpenRequestState` for the exact predicate: bidi request streams
    /// that are neither locally rejected nor fully closed, including
    /// not-yet-classified peer streams and WebTransport CONNECT streams).
    /// Pair with `shutdownState()` as the drain-complete condition after
    /// `sendGoaway`: once the state is `.draining` and this reaches zero,
    /// every request admitted before the GOAWAY has finished and the
    /// connection can be closed without cutting work short.
    pub fn openRequestStreamCount(self: *const Session) usize {
        var count: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (self.isOpenRequestState(entry.value_ptr.*)) count += 1;
        }
        return count;
    }

    /// True when `state` is an in-flight HTTP request/response exchange
    /// the application may still be working on — the predicate behind
    /// `openRequestStreamCount` / `openRequestStreams`. Bidi streams
    /// only; excludes streams the session locally rejected (the
    /// application never owned them) and fully-closed streams awaiting
    /// the per-drain GC. A peer bidi stream not yet classified by
    /// `processBidiState` counts — its first bytes are in flight and it
    /// might be a request; over-counting is the safe direction for a
    /// drain signal. An unclassified *locally*-initiated bidi counts only
    /// if this session opened it as a request (`openRequest` registers
    /// message state at open); raw QUIC streams opened behind the
    /// session's back are not the session's work. Note WebTransport
    /// CONNECT streams classify as `.request` (they are Extended CONNECT
    /// requests) and count until the WT session ends.
    fn isOpenRequestState(self: *const Session, state: *const StreamState) bool {
        if (stream_mod.isUnidirectional(state.id)) return false;
        if (state.locally_rejected) return false;
        if (state.isFullyClosed()) return false;
        if (state.bidi_kind) |kind| return kind == .request;
        if (self.isLocalInitiated(state.id)) {
            return state.message_decoder != null or state.message_encoder != null;
        }
        return true;
    }

    /// Iterates the in-flight request/response exchanges (same predicate
    /// as `openRequestStreamCount`) together with each stream's
    /// last-event time, for per-request deadline enforcement: walk the
    /// iterator, compare `last_event_us` against the loop's current
    /// `now_us`, and `rejectRequest` / `resetResponse` (server) or
    /// `cancelRequest` / `resetRequest` (client) the expired ones. The
    /// iterator borrows the session's stream table — do not interleave
    /// with calls that create or reclaim streams (`drain`, `openRequest`).
    pub fn openRequestStreams(self: *const Session) OpenRequestStreamIterator {
        return .{ .session = self, .inner = self.streams.iterator() };
    }

    pub fn lastCloseError(self: *const Session) ?errors_mod.ConnectionError {
        return self.last_close_error;
    }

    pub fn metrics(self: *const Session) observability_mod.Metrics {
        return self.metrics_counters;
    }

    pub fn setObservabilityHooks(self: *Session, hooks: observability_mod.Hooks) void {
        self.config.observability = hooks;
    }

    /// Install a QUIC qlog sink on the underlying connection
    /// (`Connection.setQlogCallback`). `quic.qlog.Writer.callback` is a
    /// compatible sink that serializes the stream to a `.sqlog` file
    /// (JSON-SEQ, loads in qvis). Since quic 0.12 the connection emits
    /// `connection_started` at install time — the first moment a sink
    /// exists — so the event is no longer silently dropped for wrapper
    /// users whose callback lands after connection setup.
    pub fn setQuicQlogCallback(
        self: *Session,
        callback: ?observability_mod.QuicQlogCallback,
        user_data: ?*anyopaque,
    ) void {
        self.quic.setQlogCallback(callback, user_data);
    }

    /// Enable or disable per-packet qlog events (`packet_sent`,
    /// `packet_received`, `packet_lost`) on the underlying connection
    /// (`Connection.setQlogPacketEvents`). Off by default; high-volume —
    /// keep off in production unless actively debugging. Pair with
    /// `setQuicQlogCallback`, which alone carries the lifecycle,
    /// recovery, and key-schedule events.
    pub fn setQlogPacketEvents(self: *Session, enabled: bool) void {
        self.quic.setQlogPacketEvents(enabled);
    }

    pub fn streamSendState(self: *const Session, stream_id: u64) Error!StreamSendState {
        const stream = self.quic.stream(stream_id) orelse return Error.MissingStream;
        const written = stream.send.writtenBytes();
        const acked = stream.send.ackedFloor();
        return .{
            .stream_id = stream_id,
            .written_bytes = written,
            .acked_bytes = acked,
            .buffered_bytes = written - acked,
            .has_pending = stream.send.hasPendingChunk(),
            .flow_blocked = self.streamFlowBlocked(stream_id),
        };
    }

    pub fn streamFlowBlocked(self: *const Session, stream_id: u64) ?FlowBlockedEvent {
        if (self.quic.localStreamDataBlockedAt(stream_id)) |limit| {
            return .{
                .source = .local,
                .kind = .stream_data,
                .limit = limit,
                .stream_id = stream_id,
            };
        }
        if (self.quic.localDataBlockedAt()) |limit| {
            return .{
                .source = .local,
                .kind = .data,
                .limit = limit,
            };
        }
        return null;
    }

    pub fn canBufferStreamBytes(self: *const Session, stream_id: u64, additional_bytes: usize) Error!bool {
        const max_buffered = self.config.max_stream_send_buffered orelse return true;
        const state = try self.streamSendState(stream_id);
        const max: u64 = @intCast(max_buffered);
        const additional: u64 = @intCast(additional_bytes);
        if (additional > max) return false;
        return state.buffered_bytes <= max - additional;
    }

    pub fn canSendData(self: *const Session, stream_id: u64, data_len: usize) Error!bool {
        return try self.canBufferStreamBytes(stream_id, self.dataFramesEncodedLen(data_len));
    }

    pub fn close(self: *Session, error_code: u64, reason: []const u8) void {
        self.shutdown_state = .closed;
        self.last_close_error = errors_mod.localConnectionCode(error_code);
        self.quic.close(false, error_code, reason);
        self.trace(.{
            .name = .connection_close_sent,
            .role = self.role,
            .bytes = reason.len,
            .error_code = error_code,
        });
    }

    pub fn drain(self: *Session, events: *std.ArrayList(Event)) Error!void {
        var budget = self.drainBudget();
        try self.drainConnectionEvents(events, &budget);
        try self.drainDatagrams(events, &budget);

        // Session-scoped WebTransport signals: pending `established`
        // events flush here — BEFORE the buffered-stream replay below,
        // so establishment always precedes the replayed stream events —
        // and budget-paused capsule folding resumes. Budget exhaustion
        // is non-fatal for the same reason as the replay path.
        self.flushWebTransportSessionSignals(events, &budget) catch |err| {
            if (!isLocalDrainBudgetError(err)) {
                self.closeForError(err);
                return err;
            }
        };

        // Replay WebTransport streams whose buffered prefix is now
        // unblocked because the corresponding session was confirmed (or
        // closed) since the previous drain. Budget exhaustion mid-replay
        // is non-fatal — the partially-replayed state survives to the
        // next drain via the wt_buffered / wt_buffered_fin flags. We
        // catch the budget errors here so a tight `max_events_per_drain`
        // setting doesn't tear the whole session down.
        self.replayBufferedWebTransportStreams(events, &budget) catch |err| {
            if (!isLocalDrainBudgetError(err)) {
                self.closeForError(err);
                return err;
            }
        };

        const read_chunk_size = if (self.config.read_chunk_size == 0) 4096 else self.config.read_chunk_size;
        const tmp = try self.ensureDrainScratch(&self.drain_read_scratch, read_chunk_size);

        var it = self.quic.streamIterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (self.shouldSkipStream(stream_id)) continue;

            // A stream quic-zig still yields but whose http3-side state
            // `gcClosedStreams` already reclaimed: `.data_recvd` /
            // `.data_read` are quic-zig's post-read FIN terminals (a
            // complete-but-unread stream is held in `.size_known`) and
            // `.reset_read` follows the reset path's `markRead`, so every
            // byte (or the reset) was already delivered through a prior
            // StreamState and all events for the stream have been surfaced.
            // Recreating state here would resurrect the finished exchange
            // as a permanently half-closed entry (its `locally_finished` is
            // unrecoverable) and emit a duplicate `stream_finished` from
            // the re-observed FIN. Skip it until quic-zig's own stream GC
            // reaps the entry. `.reset_recvd` (reset not yet surfaced) is
            // deliberately not skipped.
            if (self.streams.get(stream_id) == null and
                (entry.value_ptr.*.recv.state == .data_recvd or
                    entry.value_ptr.*.recv.state == .data_read or
                    entry.value_ptr.*.recv.state == .reset_read))
            {
                continue;
            }

            const state = self.ensureIncomingState(stream_id) catch |err| switch (err) {
                // PeerStreamLimitExceeded is a per-stream rejection,
                // not a fatal session error: ensureIncomingState
                // already sent STOP_SENDING. Skip this stream and let
                // the pump advance to the next one. Subsequent peer
                // bytes on the rejected stream are silently dropped
                // when QUIC's reset/ack flow eventually fires.
                Error.PeerStreamLimitExceeded => continue,
                else => {
                    self.closeForError(err);
                    return err;
                },
            };

            if (self.shouldRejectIncomingRequest(stream_id)) {
                try self.rejectIncomingRequest(state, tmp, events, &budget);
                continue;
            }

            if (entry.value_ptr.*.recv.reset) |reset| {
                try self.observeReset(state, reset.error_code, reset.final_size, events, &budget);
                entry.value_ptr.*.recv.markRead();
                continue;
            }

            while (true) {
                // streamReadFin (quic-zig 0.5.0) reports the peer's FIN inline
                // with the read that drains it — so end-of-stream is captured
                // even on the final read that makes the stream terminal (and
                // thus reapable), without reaching into the receive half.
                // Sticky into quic_recv_fin_seen so a stream we park below
                // (blocked_on_qpack) still surfaces its FIN when the
                // re-processing pass revisits it after quic-zig has reaped it
                // from streamIterator.
                const rr = try self.quic.streamReadFin(stream_id, tmp);
                if (rr.fin) state.quic_recv_fin_seen = true;
                if (rr.n == 0) break;
                // Enforce declared-length caps as soon as the frame header
                // is fully buffered, before the payload lands in rx — a
                // peer declaring a huge frame must not pin rx up to the
                // QUIC flow-control window (see checkIncomingFrameLength).
                self.checkIncomingFrameHeader(state, tmp[0..rr.n]) catch |err| {
                    if (errors_mod.classify(err).scope == .stream) {
                        if (self.messageStreamKind(state)) |kind| {
                            if (kind != .push) {
                                self.failMessageStream(state, kind, err, events, &budget);
                                return;
                            }
                        }
                    }
                    self.closeForError(err);
                    return err;
                };
                try state.rx.appendSlice(self.allocator, tmp[0..rr.n]);
            }

            self.processState(state, events, &budget) catch |err| {
                if (!isLocalDrainBudgetError(err)) self.closeForError(err);
                return err;
            };
            if (state.blocked_on_qpack) continue;
            self.observeFin(state, state.quic_recv_fin_seen, events, &budget) catch |err| {
                if (!isLocalDrainBudgetError(err)) self.closeForError(err);
                return err;
            };
        }

        // Re-process streams parked on a QPACK dynamic-table dependency,
        // independent of streamIterator (quic-zig 0.4.0 may have reaped them).
        // Runs after the main walk so any encoder-stream insert delivered this
        // drain has already advanced the decoder table.
        try self.drainQpackBlockedStreams(events, &budget);

        self.gcClosedStreams();
    }

    /// Re-process streams parked on a QPACK dynamic-table dependency.
    ///
    /// A HEADERS / PUSH_PROMISE block whose Required Insert Count exceeds the
    /// decoder's known-received count is parked (`blocked_on_qpack`) with its
    /// bytes retained in `state.rx`, awaiting the referenced insert on the
    /// peer's QPACK encoder stream. The main drain loop only revisits a stream
    /// that `streamIterator` still yields, but quic-zig 0.4.0 reaps a stream
    /// once its recv side is terminal (FIN + all bytes read) — which a
    /// fully-received-but-blocked request/response stream already is — so it
    /// vanishes from the iterator before unblocking, stranding the block. This
    /// pass re-runs `processState` for every blocked stream in the H3-side
    /// registry and, once a stream unblocks, surfaces its FIN from the sticky
    /// `quic_recv_fin_seen` captured while the stream was still live.
    fn drainQpackBlockedStreams(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        // Collect ids first so processState/observeFin never mutate a map we
        // are iterating (mirrors gcClosedStreams). Blocked streams are rare and
        // small; any surplus beyond the batch is retried on the next drain.
        var batch: [128]u64 = undefined;
        var n: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.*.blocked_on_qpack) continue;
            if (n == batch.len) break;
            batch[n] = entry.value_ptr.*.id;
            n += 1;
        }
        for (batch[0..n]) |stream_id| {
            const state = self.streams.get(stream_id) orelse continue;
            if (!state.blocked_on_qpack) continue;
            self.processState(state, events, budget) catch |err| {
                if (!isLocalDrainBudgetError(err)) self.closeForError(err);
                return err;
            };
            if (state.blocked_on_qpack) continue;
            self.observeFin(state, state.quic_recv_fin_seen, events, budget) catch |err| {
                if (!isLocalDrainBudgetError(err)) self.closeForError(err);
                return err;
            };
        }
    }

    /// Reclaims `Session.streams` entries whose lifecycle is fully
    /// closed (both directions terminated). Called at the tail of every
    /// `drain` so a long-lived session that opens many streams doesn't
    /// accumulate `StreamState` indefinitely.
    ///
    /// Decision is via `StreamState.isFullyClosed`, which combines the
    /// peer-side flags (`recv_finished` / `recv_reset_seen`, set by the
    /// observe paths) with the new local-side flag (`locally_finished`,
    /// set by `finishStream` / `resetStream`). The underlying quic-zig
    /// `Connection.streams` map is independent and out of scope here —
    /// quic-zig retains its entries through the QUIC connection's
    /// lifetime; this GC frees the http3-side state once we no longer
    /// need it (no further drains will surface events for this stream).
    ///
    /// Critical streams (control / QPACK encoder / QPACK decoder)
    /// stay alive because their `recv_finished` only flips on peer
    /// FIN of the critical stream, which itself is a connection-level
    /// error (RFC 9114 §6.2) — the session is closing anyway.
    ///
    /// Iteration safety: HashMap iteration invalidates on mutation, so
    /// we collect ids in a small fixed-size buffer per pass. If more
    /// than `batch.len` streams are reclaimable in one drain (rare),
    /// the surplus rolls to the next drain — still bounded, just not
    /// in one shot.
    fn gcClosedStreams(self: *Session) void {
        var batch: [128]u64 = undefined;
        var n: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (!state.isFullyClosed()) continue;
            if (n == batch.len) break;
            batch[n] = state.id;
            n += 1;
        }
        for (batch[0..n]) |stream_id| {
            const removed = self.streams.fetchRemove(stream_id) orelse continue;
            removed.value.deinit(self.allocator);
            self.allocator.destroy(removed.value);
            // Reclaim the cached RFC 9218 priority hint for this request
            // stream (keyed by stream id). It is no longer consultable once
            // the stream is reaped and would otherwise accumulate for the
            // connection's lifetime — a slow leak under normal traffic that
            // the `max_tracked_priorities` cap only bounds, never releases.
            _ = self.request_priorities.remove(stream_id);
        }
    }

    fn drainBudget(self: *const Session) DrainBudget {
        return .{
            .max_payload_size = self.config.max_event_payload_size,
            .max_payload_bytes = self.config.max_event_payload_bytes_per_drain,
            .max_events = self.config.max_events_per_drain,
        };
    }

    fn drainDatagrams(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        const max_payload = if (self.config.max_datagram_payload_size == 0)
            64 * 1024
        else
            self.config.max_datagram_payload_size;
        const scratch = try self.ensureDrainScratch(&self.drain_datagram_scratch, max_payload);

        while (self.quic.receiveDatagramInfo(scratch)) |info| {
            if (!self.local_settings.h3_datagram) {
                self.closeForError(Error.DatagramNotEnabled);
                return Error.DatagramNotEnabled;
            }
            const decoded = datagram_mod.decode(scratch[0..info.len]) catch |err| {
                self.close(protocol.ErrorCode.datagram_error, @errorName(err));
                return err;
            };
            // RFC 9297 §5 (Security Considerations): drop DATAGRAMs
            // targeting a stream that has already been closed — the
            // application has signalled it's done with the stream
            // and the peer's bytes would otherwise pile up as
            // events with no matching stream lifecycle. We do NOT
            // drop for unknown stream ids (a datagram may legitimately
            // arrive shortly before the stream-opening HEADERS land,
            // particularly for early-data flows); the receiver
            // queues it and the application can decide what to do
            // when the stream eventually opens.
            if (self.streams.get(decoded.stream_id)) |state| {
                if (state.recv_finished or state.recv_reset_seen) {
                    self.metrics_counters.datagrams_dropped_orphan += 1;
                    continue;
                }
            }
            // Budget headroom is checked BEFORE anything is consumed:
            // receiveDatagramInfo already popped the datagram, so an
            // EventQueueFull from reserve would silently lose it.
            // Exhausted budgets break instead — the remaining datagrams
            // stay queued for the next drain. A single oversized
            // datagram still surfaces EventPayloadTooLarge per the
            // documented budget contract (datagrams are unreliable; the
            // caller sees the explicit error rather than silent loss).
            if (budget.max_events != null and budget.events >= budget.max_events.?) break;
            if (budget.max_payload_bytes != null and
                decoded.payload.len > budget.max_payload_bytes.? -| budget.payload_bytes)
            {
                break;
            }
            try budget.reserve(decoded.payload.len);
            const payload = try self.allocator.dupe(u8, decoded.payload);
            errdefer self.allocator.free(payload);
            try self.appendReservedEvent(events, .{
                .datagram = .{
                    .stream_id = decoded.stream_id,
                    .payload = payload,
                    .arrived_in_early_data = info.arrived_in_early_data,
                },
            });
        }
    }

    fn drainConnectionEvents(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        while (self.quic.pollEvent()) |event| {
            switch (event) {
                .close => |close_event| try self.observeConnectionClose(close_event, events, budget),
                .datagram_acked => |acked| try self.appendEvent(events, budget, .{ .datagram_acked = acked }),
                .datagram_lost => |lost| try self.appendEvent(events, budget, .{ .datagram_lost = lost }),
                .flow_blocked => |blocked| try self.appendEvent(events, budget, .{ .flow_blocked = blocked }),
                .connection_ids_needed => |needed| try self.appendEvent(events, budget, .{ .connection_ids_needed = needed }),
                .early_data => |status| try self.observeEarlyDataOutcome(status, events, budget),
                // Transport-level ConnectionEvents the H3 layer does not
                // surface to its embedder — e.g. `alternative_server_address`,
                // a QUIC server-migration hint (draft-munizaga-quic-
                // alternative-server-address-00) added in quic-zig 0.4.0.
                // Per the ConnectionEvent forward-compatibility contract
                // (quic-zig docs/API_STABILITY.md), unknown variants are
                // handled with an `else` so additive variants don't break
                // compilation; H3 has no mapping for them, so drop them.
                else => {},
            }
        }
        self.syncShutdownState();
    }

    fn observeConnectionClose(
        self: *Session,
        close_event: quic.CloseEvent,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        const application = if (close_event.error_space == .application)
            errors_mod.applicationError(close_event.error_code)
        else
            null;
        try budget.reserve(close_event.reason.len);
        const reason = try self.allocator.dupe(u8, close_event.reason);
        errdefer self.allocator.free(reason);

        if (application) |app| {
            if (errorSourceFromCloseSource(close_event.source)) |source| {
                self.last_close_error = .{
                    .source = source,
                    .application = app,
                };
            }
        }

        self.syncShutdownState();
        try self.appendReservedEvent(events, .{
            .connection_closed = .{
                .source = close_event.source,
                .error_space = close_event.error_space,
                .error_code = close_event.error_code,
                .frame_type = close_event.frame_type,
                .reason = reason,
                .reason_truncated = close_event.reason_truncated,
                .at_us = close_event.at_us,
                .draining_deadline_us = close_event.draining_deadline_us,
                .application = application,
            },
        });
    }

    fn syncShutdownState(self: *Session) void {
        switch (self.quic.closeState()) {
            .open => {},
            .closing, .draining => if (self.shutdown_state != .closed) {
                self.shutdown_state = .draining;
            },
            .closed => self.shutdown_state = .closed,
        }
    }

    /// Deterministic GREASE picks (RFC 9114 §7.2.8). N is arbitrary but
    /// fixed: variety would need an RNG the session deliberately doesn't
    /// own, and a predictable reserved codepoint exercises peer tolerance
    /// just as well. 0x1f * 27 + 0x21 = 0x36a (setting), 0x1f * 41 + 0x21
    /// = 0x520 (stream type).
    const grease_setting_n: u64 = 27;
    const grease_stream_type_n: u64 = 41;

    fn openControlStream(self: *Session) Error!void {
        // openNextUni: monotonic per-type id, reap-safe (see openWebTransportUniStream).
        const id = (try self.quic.openNextUni()).id;
        try self.writeStreamType(id, protocol.StreamType.control);
        self.control_stream_id = id;
        errdefer self.control_stream_id = null;

        // Emission-only copy: `local_settings` stays clean for peer
        // validation and re-reads; GREASE exists solely on the wire.
        var advertised = self.local_settings;
        if (self.config.enable_grease) {
            advertised.grease = .{
                .id = protocol.greaseValue(grease_setting_n),
                .value = 0,
            };
        }
        try self.writeControlFrame(.{ .settings = advertised });
        self.trace(.{
            .name = .control_stream_opened,
            .role = self.role,
            .stream_id = id,
        });
        self.trace(.{
            .name = .settings_sent,
            .role = self.role,
            .stream_id = id,
            .frame_type = protocol.FrameType.settings,
        });
        if (self.role == .client) {
            if (self.config.max_push_id) |max_push_id| {
                try self.writeControlFrame(.{ .max_push_id = max_push_id });
            }
        }
        if (self.config.enable_grease) try self.openGreaseUniStream();
    }

    /// RFC 9114 §7.2.8 ¶2 + §6.2.3: open one stream of a reserved
    /// unidirectional type and FIN it immediately. Peers MUST either
    /// discard it or STOP_SENDING it (§6.2 ¶last); http3-zig's own receive
    /// path does the latter. Runs once per session, from
    /// `openControlStream` (guarded by `control_stream_id`).
    fn openGreaseUniStream(self: *Session) Error!void {
        const id = (try self.quic.openNextUni()).id;
        try self.writeStreamType(id, protocol.greaseValue(grease_stream_type_n));
        try self.quic.streamFinish(id);
    }

    fn openQpackStreams(self: *Session) Error!void {
        if (self.qpack_encoder_stream_id != null or self.qpack_decoder_stream_id != null) {
            return Error.QpackStreamsAlreadyOpen;
        }

        // openNextUni: monotonic per-type id, reap-safe (see openWebTransportUniStream).
        const enc_id = (try self.quic.openNextUni()).id;
        try self.writeStreamType(enc_id, protocol.StreamType.qpack_encoder);

        const dec_id = (try self.quic.openNextUni()).id;
        try self.writeStreamType(dec_id, protocol.StreamType.qpack_decoder);

        self.qpack_encoder_stream_id = enc_id;
        self.qpack_decoder_stream_id = dec_id;
        self.trace(.{
            .name = .qpack_streams_opened,
            .role = self.role,
            .stream_id = enc_id,
            .count = 2,
        });
    }

    fn processState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        if (stream_mod.isUnidirectional(state.id)) {
            try self.processUniState(state, events, budget);
        } else {
            try self.processBidiState(state, events, budget);
        }
    }

    fn processUniState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
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
            .control => try self.processControlState(state, events, budget),
            .qpack_encoder => try self.processQpackEncoderState(state),
            .qpack_decoder => try self.processQpackDecoderState(state),
            .unknown => state.rx.clearRetainingCapacity(),
            .push => try self.processPushState(state, events, budget),
            .webtransport_uni => try self.processWebTransportStreamState(state, .uni, events, budget),
        }
    }

    fn processBidiState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        // Streams that we've already rejected (e.g. via the
        // request-rejection path) keep receiving bytes until QUIC
        // delivers our STOP_SENDING / reset. Discard them rather than
        // feeding them through the message decoder, which would
        // otherwise mis-classify trailing frames as protocol errors.
        if (state.locally_rejected) {
            state.rx.clearRetainingCapacity();
            return;
        }
        if (state.bidi_kind == null) {
            // Peek (don't consume) the first varint to disambiguate between
            // a normal HTTP/3 request stream (first frame is HEADERS, type
            // 0x01) and a WebTransport bidirectional stream
            // (draft-ietf-webtrans-http3 §4.2: first byte is the
            // WT_STREAM frame-type marker 0x41 followed by the Session ID).
            const peek = varint.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };

            if (peek.value == protocol.FrameType.webtransport_bidi_stream) {
                state.bidi_kind = .webtransport;
                try compactRx(state, peek.bytes_read);
            } else {
                // Non-WT bidi: validate the role now and set up the
                // message decoder lazily. `ensureIncomingState` defers
                // these so server-initiated bidi can reach the WT
                // peek path; if the bytes aren't a WT marker, the
                // role check we deferred has to fire here.
                const decoder_kind = self.incomingMessageKind(state.id) catch |err| {
                    self.closeForError(err);
                    return err;
                };
                const encoder_kind: message_mod.Kind = switch (decoder_kind) {
                    .request => .response,
                    .response => .request,
                    .push => .response,
                };
                _ = self.ensureMessageState(state.id, decoder_kind, encoder_kind) catch |err| {
                    self.closeForError(err);
                    return err;
                };
                state.bidi_kind = .request;
            }
        }

        switch (state.bidi_kind.?) {
            .request => try self.processMessageState(state, events, budget),
            .webtransport => try self.processWebTransportStreamState(state, .bidi, events, budget),
        }
    }

    fn processWebTransportStreamState(
        self: *Session,
        state: *StreamState,
        kind: WebTransportStreamKind,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        if (state.locally_rejected) {
            // The buffered-stream policy already reset this stream; just
            // discard further bytes until QUIC confirms the close.
            state.rx.clearRetainingCapacity();
            return;
        }

        if (state.wt_session_id == null) {
            // The Session ID varint follows the stream marker we already
            // consumed (uni stream type 0x54 in `processUniState` or bidi
            // frame type 0x41 in `processBidiState`).
            const decoded = varint.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };
            // draft-ietf-webtrans-http3 §4.1 / §4.2: the Session ID
            // MUST equal the request stream id of the corresponding
            // CONNECT stream, which is by construction a
            // client-initiated bidirectional QUIC stream id (low two
            // bits = 0b00). A peer-supplied id with the wrong bits is
            // a protocol violation. We reset the offending stream
            // with `WEBTRANSPORT_SESSION_GONE` rather than closing
            // the whole connection — only this stream is malformed.
            if (stream_mod.isUnidirectional(decoded.value) or !stream_mod.isClientInitiated(decoded.value)) {
                // Per-stream rejection: STOP_SENDING (and RESET on
                // bidi where we own the send side too) signal the
                // peer; the offending stream is dropped silently
                // from our state machine. Do NOT propagate an
                // error up the drain loop — that would close the
                // whole connection for one malformed stream.
                self.quic.streamStopSending(state.id, webtransport_mod.session_gone_code) catch {};
                if (!stream_mod.isUnidirectional(state.id)) {
                    self.quic.streamReset(state.id, webtransport_mod.session_gone_code) catch {};
                }
                state.locally_rejected = true;
                state.recv_finished = true;
                state.rx.clearRetainingCapacity();
                return;
            }
            try compactRx(state, decoded.bytes_read);
            state.wt_session_id = decoded.value;
            self.trace(.{
                .name = .webtransport_stream_opened,
                .role = self.role,
                .stream_id = state.id,
                .frame_type = switch (kind) {
                    .uni => protocol.StreamType.webtransport_uni_stream,
                    .bidi => protocol.FrameType.webtransport_bidi_stream,
                },
                .value = decoded.value,
            });

            // Apply the buffered-stream policy. The header is only
            // dispatched (open event + subsequent data events) once the
            // session is known.
            switch (self.webTransportSessionState(decoded.value)) {
                .established => {
                    try self.emitWebTransportStreamOpened(state, kind, events, budget);
                },
                .pending, .none => switch (self.config.buffered_stream_policy) {
                    .pass_through => {
                        try self.emitWebTransportStreamOpened(state, kind, events, budget);
                    },
                    .reject => {
                        try self.rejectBufferedWebTransportStream(state);
                        return;
                    },
                    .buffer => {
                        state.wt_buffered = true;
                        try self.wt_buffered_streams.append(self.allocator, state.id);
                        if (try self.rejectIfBufferedWebTransportLimitExceeded(state)) return;
                        return;
                    },
                },
            }
        }

        if (state.wt_buffered) {
            // We've already parsed the prefix but the session still
            // isn't established. Hold incoming bytes in `state.rx`
            // until the replay path picks them up at the start of
            // the next drain after `confirmWebTransportSession`.
            //
            // Per-stream byte cap (draft-ietf-webtrans-http3 §4.5):
            // a hostile or malfunctioning peer can fill state.rx
            // before the application gets around to confirming the
            // session. Once we exceed the configured cap, drop the
            // stream the same way `BufferedStreamPolicy.reject`
            // would — STOP_SENDING with
            // `WEBTRANSPORT_BUFFERED_STREAM_REJECTED` — and remove
            // it from the buffered list so its bytes get freed.
            if (try self.rejectIfBufferedWebTransportLimitExceeded(state)) return;
            return;
        }

        if (state.rx.items.len == 0) return;

        // Receive-side flow-control enforcement
        // (draft-ietf-webtrans-http3 §5.6.4). If the application has
        // advertised `local_max_data`, peer bytes that would push the
        // running `peer_data_received` past that limit are a flow-
        // control violation: reset the offending stream with the
        // reserved `WEBTRANSPORT_SESSION_GONE` wire code. We don't
        // tear the whole session down here — surfacing the violation
        // via an explicit `webtransport_flow_violated` event lets the
        // application choose between retry, escalation, or reuse.
        if (self.webTransportFlowMut(state.wt_session_id.?)) |flow| {
            if (flow.local_max_data) |limit| {
                // Saturating addition: a peer-controlled `rx.items.len`
                // plus a long-running counter could in principle
                // overflow u64 on a long-lived flooded session. Saturate
                // to maxInt so the violation gate fires deterministically
                // rather than wrapping silently below the limit.
                const next = std.math.add(u64, flow.peer_data_received, @as(u64, state.rx.items.len)) catch std.math.maxInt(u64);
                if (next > limit) {
                    try self.handleWebTransportFlowViolation(state, flow, .data_overflow, events, budget);
                    return;
                }
            }
        }

        try budget.reserve(state.rx.items.len);
        const data = try self.allocator.dupe(u8, state.rx.items);
        errdefer self.allocator.free(data);
        const data_len = data.len;
        try self.appendReservedEvent(events, .{
            .webtransport_stream_data = .{
                .stream_id = state.id,
                .session_id = state.wt_session_id.?,
                .kind = kind,
                .data = data,
            },
        });
        state.rx.clearRetainingCapacity();

        // Bookkeeping: bump `peer_data_received` so the application
        // can decide when to advertise a higher `local_max_data` via
        // `sendMaxData`. The session is the sole bumper for this
        // counter; there is no public application-side hook (a
        // public hook would race the auto-bump and double-count).
        // Use saturating addition so a long-lived flooded session
        // can't wrap the counter and trip the receive-side gate
        // below; once we've reached u64 max the gate has long since
        // fired anyway.
        if (self.webTransportFlowMut(state.wt_session_id.?)) |flow| {
            flow.peer_data_received = std.math.add(u64, flow.peer_data_received, @as(u64, data_len)) catch std.math.maxInt(u64);
        }
    }

    fn emitWebTransportStreamOpened(
        self: *Session,
        state: *StreamState,
        kind: WebTransportStreamKind,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        // Receive-side stream-count enforcement. If the peer's open
        // would exceed our advertised `local_max_streams_*`, reset
        // the offending stream with `WEBTRANSPORT_SESSION_GONE`
        // (per draft-ietf-webtrans-http3 §5.6.2 the violation closes
        // the WT session; we surface it as an event so the
        // application can decide between session-close and per-
        // stream rejection).
        if (self.webTransportFlowMut(state.wt_session_id.?)) |flow| {
            const limit = switch (kind) {
                .bidi => flow.local_max_streams_bidi,
                .uni => flow.local_max_streams_uni,
            };
            const opened = switch (kind) {
                .bidi => flow.peer_streams_opened_bidi,
                .uni => flow.peer_streams_opened_uni,
            };
            if (limit) |l| {
                if (opened >= l) {
                    try self.handleWebTransportFlowViolation(
                        state,
                        flow,
                        switch (kind) {
                            .bidi => .streams_bidi_overflow,
                            .uni => .streams_uni_overflow,
                        },
                        events,
                        budget,
                    );
                    return;
                }
            }
        }

        // Reserve the event slot BEFORE bumping `peer_streams_opened_*`. The
        // buffered-stream replay path can retry this open across budget-limited
        // drains (see `wt_replay_opened`); incrementing only after a successful
        // reserve keeps a retried open from double-counting toward the peer
        // stream-count limit.
        try budget.reserve(0);
        if (self.webTransportFlowMut(state.wt_session_id.?)) |flow| {
            switch (kind) {
                .bidi => flow.peer_streams_opened_bidi += 1,
                .uni => flow.peer_streams_opened_uni += 1,
            }
        }
        try self.appendReservedEvent(events, .{
            .webtransport_stream_opened = .{
                .stream_id = state.id,
                .session_id = state.wt_session_id.?,
                .kind = kind,
            },
        });
    }

    /// Handles a peer flow-control violation (peer sent more bytes
    /// than our `local_max_data` allows, or opened more streams than
    /// our `local_max_streams_*` allows). Per draft-16 the violation is
    /// SESSION-fatal: after the `webtransport_flow_violated` event
    /// (kept for observability, still carrying the offending stream),
    /// the whole session is terminated with `WT_FLOW_CONTROL_ERROR` —
    /// CONNECT reset, substream sweep, `.protocol_violation` close
    /// event. The connection stays up.
    fn handleWebTransportFlowViolation(
        self: *Session,
        state: *StreamState,
        flow: *WTSessionFlowState,
        kind: WebTransportFlowViolationKind,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        const session_id = flow.session_id;
        const limit = switch (kind) {
            .data_overflow => flow.local_max_data orelse 0,
            .streams_bidi_overflow => flow.local_max_streams_bidi orelse 0,
            .streams_uni_overflow => flow.local_max_streams_uni orelse 0,
        };
        state.locally_rejected = true;
        state.recv_finished = true;
        state.rx.clearRetainingCapacity();

        try budget.reserve(0);
        try self.appendReservedEvent(events, .{
            .webtransport_flow_violated = .{
                .stream_id = state.id,
                .session_id = session_id,
                .kind = kind,
                .limit = limit,
            },
        });
        // `flow` is destroyed with the session — do not touch it after
        // this call.
        try self.terminateWebTransportSessionWithCode(
            session_id,
            webtransport_mod.flow_control_error_code,
            events,
            budget,
        );
    }

    /// Remove the given stream id from `wt_buffered_streams` if
    /// present. Used when a buffered stream is rejected after
    /// accumulation (e.g. byte cap exceeded). Idempotent.
    fn removeFromBufferedList(self: *Session, stream_id: u64) void {
        var i: usize = 0;
        while (i < self.wt_buffered_streams.items.len) : (i += 1) {
            if (self.wt_buffered_streams.items[i] == stream_id) {
                _ = self.wt_buffered_streams.orderedRemove(i);
                return;
            }
        }
    }

    fn bufferedWebTransportBytes(self: *const Session) usize {
        var total: usize = 0;
        for (self.wt_buffered_streams.items) |stream_id| {
            const state = self.streams.get(stream_id) orelse continue;
            if (state.wt_buffered) total += state.rx.items.len;
        }
        return total;
    }

    fn rejectBufferedWebTransportStreamFromBuffer(self: *Session, state: *StreamState) Error!void {
        try self.rejectBufferedWebTransportStream(state);
        state.wt_buffered = false;
        self.removeFromBufferedList(state.id);
        state.rx.clearRetainingCapacity();
    }

    fn rejectIfBufferedWebTransportLimitExceeded(self: *Session, state: *StreamState) Error!bool {
        if (self.config.wt_max_buffered_bytes_per_stream) |cap| {
            if (state.rx.items.len > cap) {
                try self.rejectBufferedWebTransportStreamFromBuffer(state);
                return true;
            }
        }
        if (self.config.wt_max_total_buffered_bytes) |cap| {
            if (self.bufferedWebTransportBytes() > cap) {
                try self.rejectBufferedWebTransportStreamFromBuffer(state);
                return true;
            }
        }
        return false;
    }

    fn rejectBufferedWebTransportStream(self: *Session, state: *StreamState) Error!void {
        // For peer-opened streams we own only the receive side
        // (unidirectional always; bidirectional only on send), so
        // STOP_SENDING is the universally-safe rejection signal.
        // draft-ietf-webtrans-http3 §4.5 explicitly allows either
        // STOP_SENDING or RESET_STREAM (or both) for buffered-stream
        // rejection; we go with STOP_SENDING because RESET_STREAM on a
        // peer-initiated uni stream would error at the QUIC layer.
        try self.quic.streamStopSending(state.id, webtransport_mod.buffered_stream_rejected_code);
        // Bidi streams also let us reset our own send side. Best
        // effort — failures are non-fatal because the peer will react
        // to the STOP_SENDING regardless.
        if (!stream_mod.isUnidirectional(state.id)) {
            self.quic.streamReset(state.id, webtransport_mod.buffered_stream_rejected_code) catch {};
        }
        state.locally_rejected = true;
        state.recv_finished = true;
        state.rx.clearRetainingCapacity();
    }

    /// Walks the buffered-stream list (in insertion order) and replays
    /// any WebTransport streams whose session is now established. Called
    /// at the start of every drain so that newly-confirmed sessions
    /// get their pending stream events surfaced without waiting for
    /// fresh bytes on the wire. Streams whose session has been closed
    /// are abandoned (STOP_SENDING-ed so the peer stops sending more
    /// bytes).
    ///
    /// Replay order matches the order the peer opened the streams —
    /// the `wt_buffered_streams` list is appended in
    /// `processWebTransportStreamState`, never re-ordered, so an
    /// in-order walk preserves the peer's ordering across the
    /// .buffer-policy delay.
    ///
    /// Each replayed stream emits, in order:
    ///   1. `webtransport_stream_opened`
    ///   2. zero or more `webtransport_stream_data` events for any
    ///      bytes that arrived while buffered
    ///   3. `webtransport_stream_finished` if a FIN landed during
    ///      buffering (`wt_buffered_fin`)
    fn replayBufferedWebTransportStreams(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        // Sort the buffered list by stream id so the replay surfaces
        // events in the order the peer opened the streams. Stream IDs
        // are monotonically increasing per (initiator, direction)
        // tuple per RFC 9000 §2.1, so for any single
        // peer/direction this is exactly the open order. We sort each
        // pass because new streams may have been appended in
        // hash-map-iteration order between drains; sorting again
        // re-establishes the invariant cheaply (the list is bounded
        // by `BufferedStreamPolicy.buffer`'s policy and is typically
        // small).
        std.sort.heap(u64, self.wt_buffered_streams.items, {}, std.sort.asc(u64));

        // Iterate by index because we may remove entries mid-loop.
        // Replayed/closed streams shrink the list from the front; pending
        // streams stay in place at the head.
        var i: usize = 0;
        while (i < self.wt_buffered_streams.items.len) {
            const stream_id = self.wt_buffered_streams.items[i];
            const state = self.streams.get(stream_id) orelse {
                _ = self.wt_buffered_streams.orderedRemove(i);
                continue;
            };
            // Keep streams that are still buffered OR mid-replay. A replay in
            // progress clears wt_buffered when it emits the open event but stays
            // in this list (tracked by wt_replay_opened) until data + FIN have
            // also committed, so a budget bail-out between those events resumes
            // here on the next drain instead of being pruned.
            if (!state.wt_buffered and !state.wt_replay_opened) {
                _ = self.wt_buffered_streams.orderedRemove(i);
                continue;
            }
            const kind = state.webTransportKind() orelse {
                state.wt_buffered = false;
                _ = self.wt_buffered_streams.orderedRemove(i);
                continue;
            };
            const session_id = state.wt_session_id orelse {
                state.wt_buffered = false;
                _ = self.wt_buffered_streams.orderedRemove(i);
                continue;
            };

            switch (self.webTransportSessionState(session_id)) {
                .established => {
                    // Self-contained replay: emit opened -> data -> finished
                    // entirely from H3-side buffers (`state.rx` and
                    // `state.wt_buffered_fin`), NOT the main streamIterator
                    // drain path. quic-zig 0.4.0 reaps a peer stream once its
                    // recv side is terminal (FIN + all bytes read), so by
                    // replay time the underlying QUIC stream is typically gone
                    // from streamIterator; relying on "the next drain's regular
                    // path" to surface data/FIN would strand them (data never
                    // arrives, so the stream never finishes).
                    //
                    // Each step commits its event under the drain budget or
                    // throws a budget error the caller filters into "retry next
                    // drain". The stream stays in `wt_buffered_streams` (with
                    // `wt_buffered = true`) until all three events have
                    // committed, so a mid-replay budget bail-out resumes
                    // cleanly on the next drain. `wt_replay_opened` dedupes the
                    // open across those retries; `processWebTransportStreamState`
                    // clears `rx` and the FIN block clears `wt_buffered_fin`, so
                    // data/FIN are each emitted exactly once.
                    if (!state.wt_replay_opened) {
                        try self.emitWebTransportStreamOpened(state, kind, events, budget);
                        state.wt_replay_opened = true;
                        // Clear wt_buffered now (only after the open committed)
                        // so processWebTransportStreamState emits the held
                        // payload — its `if (wt_buffered) { hold; return; }`
                        // guard would otherwise keep parking the bytes. The
                        // stream stays in wt_buffered_streams, keyed off
                        // wt_replay_opened, until data + FIN have both committed.
                        state.wt_buffered = false;
                    }
                    if (state.rx.items.len > 0) {
                        try self.processWebTransportStreamState(state, kind, events, budget);
                    }
                    if (state.wt_buffered_fin) {
                        try budget.reserve(0);
                        state.recv_finished = true;
                        state.wt_buffered_fin = false;
                        try self.appendReservedEvent(events, .{
                            .webtransport_stream_finished = .{
                                .stream_id = state.id,
                                .session_id = session_id,
                                .kind = kind,
                            },
                        });
                    }
                    // All three events committed: retire the replay entry.
                    // Do not advance `i` — orderedRemove shifts the tail down.
                    _ = self.wt_buffered_streams.orderedRemove(i);
                },
                .pending => {
                    // Keep buffering. Advance the cursor so we look at
                    // the next entry on this drain pass.
                    i += 1;
                },
                .none => {
                    // The CONNECT stream finished or reset before the
                    // handshake was confirmed; discard the buffered
                    // stream rather than holding bytes forever.
                    try self.rejectBufferedWebTransportStream(state);
                    _ = self.wt_buffered_streams.orderedRemove(i);
                },
            }
        }
    }

    /// Reject an incoming HTTP/3 frame on its DECLARED length before its
    /// payload is reassembled into `state.rx`. Without this, an oversized
    /// declared length buffers up to the QUIC stream flow-control window
    /// before the post-reassembly size check fires — a receive-buffer
    /// amplification DoS. DATA frames are intentionally exempt: legitimately
    /// large, and bounded by QUIC flow control plus the application body
    /// budget. Callers peek the header via `frame_mod.peekHeader` and call
    /// this before `frame_mod.decode`.
    /// The message kind for a stream that carries HTTP messages — either
    /// already classified or inferable from stream shape and role. Null
    /// for control, QPACK, WT, unknown, and pre-classification streams.
    fn messageStreamKind(self: *const Session, state: *const StreamState) ?message_mod.Kind {
        if (state.message_decoder) |decoder| return decoder.kind;
        if (stream_mod.isUnidirectional(state.id)) return null;
        if (state.bidi_kind == .webtransport) return null;
        if (state.control_validator != null) return null;
        if (!stream_mod.isClientInitiated(state.id)) return null;
        return switch (self.role) {
            .server => .request,
            .client => .response,
        };
    }

    /// Enforces the declared-length caps (checkIncomingFrameLength) as
    /// soon as a frame header is fully buffered — BEFORE its payload is
    /// appended to rx — so a peer cannot pin rx up to the QUIC
    /// flow-control window by declaring a huge frame. Skips streams whose
    /// leading bytes are not HTTP frames (WT marker/type, QPACK streams,
    /// unknown uni types) and waits out the leading varints (bounded to
    /// a few bytes). Once rx already holds 32 bytes, processState's own
    /// peekHeader path owns the check.
    fn checkIncomingFrameHeader(
        self: *const Session,
        state: *const StreamState,
        incoming: []const u8,
    ) Error!void {
        if (state.rx.items.len >= 32) return;

        var buf: [32]u8 = undefined;
        var n: usize = 0;
        const rx_take = @min(state.rx.items.len, buf.len);
        @memcpy(buf[0..rx_take], state.rx.items[0..rx_take]);
        n = rx_take;
        const in_take = @min(incoming.len, buf.len - n);
        @memcpy(buf[n..][0..in_take], incoming[0..in_take]);
        n += in_take;
        const src = buf[0..n];
        if (src.len == 0) return;

        var offset: usize = 0;
        if (stream_mod.isUnidirectional(state.id)) {
            const kind = if (state.uni_kind) |k| k else blk: {
                const d = varint.decode(src) catch return;
                break :blk stream_mod.kindFromType(d.value);
            };
            switch (kind) {
                .control => {
                    offset = if (state.uni_kind == null) (varint.decode(src) catch return).bytes_read else 0;
                },
                .push => {
                    if (state.uni_kind == null) {
                        const d = varint.decode(src) catch return;
                        const pid = varint.decode(src[d.bytes_read..]) catch return;
                        offset = d.bytes_read + pid.bytes_read;
                    } else if (state.push_id == null) {
                        const pid = varint.decode(src) catch return;
                        offset = pid.bytes_read;
                    }
                },
                .qpack_encoder, .qpack_decoder, .webtransport_uni, .unknown => return,
            }
        } else {
            // WT bidi streams begin with the 0x41 marker, not a frame
            // header; classify conservatively before processBidiState
            // has had a chance to set bidi_kind.
            if (state.bidi_kind == .webtransport) return;
            if (src[0] == protocol.FrameType.webtransport_bidi_stream) return;
        }

        if (offset > src.len) return;
        if (frame_mod.peekHeader(src[offset..])) |hdr| {
            try self.checkIncomingFrameLength(hdr.frame_type, hdr.length);
        }
    }

    fn checkIncomingFrameLength(self: *const Session, frame_type: u64, declared_len: u64) Error!void {
        if (frame_type == protocol.FrameType.data) return;

        // HEADERS / PUSH_PROMISE: the field section size limit applies
        // to the DECODED size (RFC 9114 §4.2.2: name + value + 32 bytes
        // per field), enforced exactly by the QPACK decode budget. The
        // declared-length check here is only a receive-buffer DoS
        // pre-gate, so it allows 2x slack: Huffman encoding can expand
        // a section to ~1.6x its decoded size.
        if (frame_type == protocol.FrameType.headers) {
            if (self.config.max_field_section_size) |max| {
                if (declared_len > max *| 2) return Error.HeaderSectionTooLarge;
            }
        } else if (frame_type == protocol.FrameType.push_promise) {
            if (self.config.max_field_section_size) |max| {
                // payload = push_id varint (<= 8 bytes) + field section.
                if (declared_len > max *| 2 +| 8) return Error.HeaderSectionTooLarge;
            }
        }

        // General non-DATA declared-length cap (control / unknown / GREASE,
        // and an upper bound over the header frames above).
        if (self.config.max_incoming_frame_length) |max| {
            if (declared_len > max) return Error.FrameTooLong;
        }
    }

    fn processControlState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        while (state.rx.items.len > 0) {
            if (frame_mod.peekHeader(state.rx.items)) |hdr| {
                self.checkIncomingFrameLength(hdr.frame_type, hdr.length) catch |err| {
                    self.closeForError(err);
                    return err;
                };
            } else return; // frame type/length varints not fully buffered yet
            const decoded = frame_mod.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };

            const frame_type = frame_mod.frameType(decoded.frame);
            const validator = state.control_validator.?;
            stream_mod.validateFrameType(.control, frame_type, !validator.seen_any, validator.settings_seen) catch |err| {
                self.closeForError(err);
                return err;
            };

            switch (decoded.frame) {
                .settings => |peer| {
                    try budget.reserve(0);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    if (self.remembered_peer_settings) |remembered| {
                        // §7.2.4.2 ¶5-¶7: an ACCEPTED 0-RTT attempt binds
                        // the server to remembered-compatible settings; a
                        // rejected (or unresolved) one just discards the
                        // remembered state and the new SETTINGS apply.
                        self.remembered_peer_settings = null;
                        if (self.quic.earlyDataStatus() == .accepted and
                            earlydata.validateRememberedSettings(remembered, peer) != null)
                        {
                            self.close(
                                protocol.ErrorCode.settings_error,
                                "SETTINGS incompatible with remembered 0-RTT settings",
                            );
                            return Error.RememberedSettingsViolated;
                        }
                    }
                    self.peer_settings = peer;
                    self.wt_negotiated_draft = webtransport_mod.resolveDraft(
                        webtransport_mod.localEras(self.local_settings),
                        peer,
                    );
                    self.qpack_encoder_state.max_blocked_streams = peer.qpack_blocked_streams;
                    try self.appendReservedEvent(events, .{ .peer_settings = peer });
                },
                .goaway => |id| {
                    try budget.reserve(0);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.observeGoaway(id);
                    try self.appendReservedEvent(events, .{ .goaway = id });
                },
                .max_push_id => |id| {
                    try budget.reserve(0);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.observeMaxPushId(id);
                },
                .cancel_push => |push_id| {
                    try budget.reserve(0);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.observeCancelPush(push_id);
                    try self.appendReservedEvent(events, .{ .cancel_push = .{ .push_id = push_id } });
                },
                .priority_update_request => |update| {
                    try budget.reserve(update.priority_field_value.len);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    const event = self.observePriorityUpdate(.{
                        .request_stream = update.prioritized_element_id,
                    }, update.priority_field_value) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.appendReservedEvent(events, .{ .priority_update = event });
                },
                .priority_update_push => |update| {
                    try budget.reserve(update.priority_field_value.len);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    const event = self.observePriorityUpdate(.{
                        .push = update.prioritized_element_id,
                    }, update.priority_field_value) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.appendReservedEvent(events, .{ .priority_update = event });
                },
                .unknown => |unknown| {
                    try budget.reserve(0);
                    state.control_validator.?.observe(frame_type) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.appendReservedEvent(events, .{
                        .ignored_unknown_frame = .{
                            .stream_id = state.id,
                            .frame_type = unknown.frame_type,
                        },
                    });
                },
                else => state.control_validator.?.observe(frame_type) catch |err| {
                    self.closeForError(err);
                    return err;
                },
            }

            try compactRx(state, decoded.bytes_read);
        }
    }

    fn processQpackEncoderState(self: *Session, state: *StreamState) Error!void {
        while (state.rx.items.len > 0) {
            const decoded = qpack.instructions.decodeEncoderInstruction(
                self.allocator,
                state.rx.items,
            ) catch |err| {
                if (err == error.InsufficientBytes) {
                    try self.flushQpackInsertCountIncrement();
                    return;
                }
                self.closeForError(err);
                return err;
            };
            defer qpack.instructions.freeDecodedEncoderInstruction(self.allocator, decoded);

            _ = try self.qpack_decoder_state.applyEncoderInstruction(
                &self.qpack_decoder_table,
                decoded.instruction,
            );
            self.trace(.{
                .name = .qpack_encoder_instruction_received,
                .role = self.role,
                .stream_id = state.id,
                .bytes = decoded.bytes_read,
            });
            try compactRx(state, decoded.bytes_read);
        }

        try self.flushQpackInsertCountIncrement();
    }

    fn flushQpackInsertCountIncrement(self: *Session) Error!void {
        if (self.qpack_decoder_state.takeInsertCountIncrement()) |instruction| {
            try self.writeQpackDecoderInstruction(instruction);
        }
    }

    fn processQpackDecoderState(self: *Session, state: *StreamState) Error!void {
        while (state.rx.items.len > 0) {
            const decoded = qpack.instructions.decodeDecoderInstruction(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };
            try self.qpack_encoder_state.receiveDecoderInstruction(decoded.instruction);
            self.trace(.{
                .name = .qpack_decoder_instruction_received,
                .role = self.role,
                .stream_id = state.id,
                .bytes = decoded.bytes_read,
            });
            try compactRx(state, decoded.bytes_read);
        }
    }

    fn processPushState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
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
            try self.validateReceivedPushId(decoded.value);
            if (self.pushIdInUse(decoded.value, state.id)) {
                self.closeForError(Error.InvalidPushId);
                return Error.InvalidPushId;
            }
            state.push_id = decoded.value;
            try compactRx(state, decoded.bytes_read);
            try budget.reserve(0);
            try self.appendReservedEvent(events, .{
                .push_stream = .{
                    .stream_id = state.id,
                    .push_id = decoded.value,
                },
            });
            if (state.message_decoder == null) {
                state.message_decoder = message_mod.Decoder.init(.push, .{
                    .max_field_section_size = self.config.max_field_section_size,
                    .enable_connect_protocol = false,
                });
            }
        }

        try self.processMessageState(state, events, budget);
    }

    fn processMessageState(
        self: *Session,
        state: *StreamState,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        const decoder = if (state.message_decoder) |*decoder| decoder else return Error.MissingStream;

        while (state.rx.items.len > 0) {
            if (frame_mod.peekHeader(state.rx.items)) |hdr| {
                self.checkIncomingFrameLength(hdr.frame_type, hdr.length) catch |err| {
                    if (errors_mod.classify(err).scope == .stream) {
                        if (self.messageStreamKind(state)) |kind| {
                            if (kind != .push) {
                                self.failMessageStream(state, kind, err, events, budget);
                                return;
                            }
                        }
                    }
                    self.closeForError(err);
                    return err;
                };
            } else return; // frame type/length varints not fully buffered yet
            const decoded = frame_mod.decode(state.rx.items) catch |err| {
                if (err == error.InsufficientBytes) return;
                self.closeForError(err);
                return err;
            };

            const maybe_event = switch (decoded.frame) {
                .headers => |block| blk: {
                    // Note: the size limit is enforced on the DECODED
                    // field section by the QPACK decode budget (RFC 9114
                    // §4.2.2) — the encoded `block.len` is not the right
                    // metric (Huffman can expand it ~1.6x) and is only
                    // bounded here by the read-loop declared-length
                    // pre-gate with 2x slack.
                    const decoded_fields = self.decodeFieldSectionForStream(state.id, block) catch |err| {
                        if (err == error.RequiredInsertCountNotReady) {
                            state.blocked_on_qpack = true;
                            return;
                        }
                        if (errors_mod.classify(err).scope == .stream and decoder.kind != .push) {
                            self.failMessageStream(state, decoder.kind, err, events, budget);
                            return;
                        }
                        self.closeForError(err);
                        return err;
                    };
                    var fields_to_free: ?[]qpack.FieldLine = decoded_fields.fields;
                    errdefer if (fields_to_free) |fields| qpack.freeFieldSection(self.allocator, fields);
                    decoder.validateOwnedFieldLines(decoded_fields.fields) catch |err| {
                        if (errors_mod.classify(err).scope == .stream and decoder.kind != .push) {
                            qpack.freeFieldSection(self.allocator, decoded_fields.fields);
                            self.failMessageStream(state, decoder.kind, err, events, budget);
                            return;
                        }
                        self.closeForError(err);
                        return err;
                    };
                    try budget.reserve(fieldsOwnedBytes(decoded_fields.fields));
                    const message_event = decoder.observeOwnedFieldLines(
                        self.allocator,
                        decoded_fields.fields,
                    ) catch |err| {
                        // observeOwnedFieldLines takes ownership and frees
                        // the section on error — do not double-free here.
                        fields_to_free = null;
                        if (errors_mod.classify(err).scope == .stream and decoder.kind != .push) {
                            self.failMessageStream(state, decoder.kind, err, events, budget);
                            return;
                        }
                        self.closeForError(err);
                        return err;
                    };
                    fields_to_free = null;
                    errdefer message_event.deinit(self.allocator);
                    try self.completeQpackFieldSection(state.id, decoded_fields.required_insert_count);
                    state.blocked_on_qpack = false;
                    break :blk message_event;
                },
                .push_promise => |promise| blk: {
                    if (self.config.max_field_section_size) |max| {
                        if (promise.field_section.len > max) {
                            self.closeForError(error.HeaderSectionTooLarge);
                            return error.HeaderSectionTooLarge;
                        }
                    }
                    decoder.validateFrame(decoded.frame) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    self.validateReceivedPushId(promise.push_id) catch |err| return err;

                    const decoded_fields = self.decodeFieldSectionForStream(state.id, promise.field_section) catch |err| {
                        if (err == error.RequiredInsertCountNotReady) {
                            state.blocked_on_qpack = true;
                            return;
                        }
                        self.closeForError(err);
                        return err;
                    };
                    defer qpack.freeFieldSection(self.allocator, decoded_fields.fields);

                    headers_mod.validateRequest(decoded_fields.fields) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    self.recordReceivedPushPromise(promise.push_id, decoded_fields.fields) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    try self.completeQpackFieldSection(state.id, decoded_fields.required_insert_count);
                    state.blocked_on_qpack = false;

                    try budget.reserve(promise.field_section.len + fieldsOwnedBytes(decoded_fields.fields));
                    const maybe_push_event = decoder.observe(self.allocator, decoded.frame) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    const message_event = maybe_push_event orelse break :blk null;
                    errdefer message_event.deinit(self.allocator);
                    try self.applyPushPolicy(promise.push_id);
                    break :blk message_event;
                },
                else => blk: {
                    decoder.validateFrame(decoded.frame) catch |err| {
                        self.closeForError(err);
                        return err;
                    };
                    const observed = decoder.observe(self.allocator, decoded.frame) catch |err| {
                        if (errors_mod.classify(err).scope == .stream and decoder.kind != .push) {
                            self.failMessageStream(state, decoder.kind, err, events, budget);
                            return;
                        }
                        self.closeForError(err);
                        return err;
                    };
                    // The WT CONNECT body path (capsule ingestion) reserves
                    // per emitted capsule event inside
                    // ingestWebTransportCapsuleBytes; reserving the raw DATA
                    // payload here would falsely trip max_event_payload_size
                    // on a large capsule batch. Oversized plain DATA is
                    // split into chunked events at emission, which reserves
                    // per chunk — reserving the whole payload here would
                    // re-throw EventPayloadTooLarge every drain and
                    // livelock the stream.
                    const wt_body = self.isWebTransportConnectBody(state, decoder.kind);
                    const oversize = budget.max_payload_size != null and
                        (messageFrameEventOwnedPayloadBytes(decoded.frame) orelse 0) > budget.max_payload_size.?;
                    if (!wt_body and !oversize) {
                        if (messageFrameEventOwnedPayloadBytes(decoded.frame)) |owned_payload_bytes| {
                            try budget.reserve(owned_payload_bytes);
                        }
                    }
                    break :blk observed;
                },
            };
            if (maybe_event) |message_event| {
                defer message_event.deinit(self.allocator);
                try self.observeWebTransportHeadersIfApplicable(state, decoder.kind, message_event);
                // Native WT capsule ingestion: a WT CONNECT stream's body
                // IS the capsule protocol, so the session consumes it —
                // the bytes feed the per-session reassembler and surface
                // only as typed `webtransport_*` events, never as raw
                // `Event.data` (BREAKING vs. the pre-native API).
                if (message_event == .data and self.isWebTransportConnectBody(state, decoder.kind)) {
                    switch (try self.ingestWebTransportCapsuleBytes(state, message_event.data, events, budget)) {
                        .ok => {},
                        // The CONNECT stream was message-error aborted:
                        // stop processing it (no compact — rx is dead).
                        .stream_failed => return,
                    }
                } else if (message_event == .data and
                    budget.max_payload_size != null and
                    message_event.data.len > budget.max_payload_size.?)
                {
                    // A single DATA frame larger than max_event_payload_size
                    // is split into chunked events so the stream makes
                    // progress instead of livelocking against the per-event
                    // cap (each drain would re-reserve and re-throw).
                    var pos: usize = 0;
                    while (pos < message_event.data.len) {
                        const chunk_len = @min(message_event.data.len - pos, budget.max_payload_size.?);
                        try budget.reserve(chunk_len);
                        try self.appendReservedMessageEvent(events, state.id, decoder.kind, .{
                            .data = message_event.data[pos .. pos + chunk_len],
                        });
                        pos += chunk_len;
                    }
                } else {
                    try self.appendReservedMessageEvent(events, state.id, decoder.kind, message_event);
                }
            }

            try compactRx(state, decoded.bytes_read);
        }
    }

    /// Watches the request/response HEADERS that flow through
    /// `processMessageState` and updates the WebTransport session
    /// registry as the handshake progresses.
    ///
    /// On the server, the first set of headers on a request stream that
    /// look like a WebTransport CONNECT request (`:method = CONNECT`,
    /// `:protocol` carrying either era's WebTransport token) marks the
    /// stream as a pending WT
    /// session. `Server.acceptWebTransport` later confirms it.
    ///
    /// On the client, headers received on a stream that's already in the
    /// pending set carry the response status. A 2xx confirms the
    /// session; any other status closes it.
    ///
    /// The modern draft has no SETTINGS-advertised session count
    /// (draft-15 replaced `SETTINGS_WT_MAX_SESSIONS` with the boolean
    /// `SETTINGS_WT_ENABLED`): the session-count policy lives in
    /// `Config.max_wt_sessions`, enforced at accept time
    /// (`checkWebTransportSessionCapacity`) with
    /// `Server.rejectWebTransport` as the wire answer — and on a
    /// draft-07 connection the same value is what SETTINGS advertises.
    fn observeWebTransportHeadersIfApplicable(
        self: *Session,
        state: *StreamState,
        kind: message_mod.Kind,
        event: message_mod.Event,
    ) Error!void {
        const fields = switch (event) {
            .headers => |f| f,
            else => return,
        };

        switch (self.role) {
            .server => {
                if (kind != .request) return;
                if (state.recv_finished) return;
                if (self.webTransportSessionExists(state.id)) return;
                // Look for `:method = CONNECT` and a `:protocol` carrying
                // either era's WebTransport token.
                // RFC 9114 §4.2 lower-cases all field names; pseudo-headers
                // sit at the front per §4.3.
                var has_connect = false;
                var has_wt = false;
                for (fields) |field| {
                    if (std.mem.eql(u8, field.name, ":method")) {
                        has_connect = std.mem.eql(u8, field.value, "CONNECT");
                    } else if (std.mem.eql(u8, field.name, ":protocol")) {
                        has_wt = webtransport_mod.isProtocolToken(field.value);
                    }
                }
                if (!(has_connect and has_wt)) return;
                try self.markWebTransportSessionPending(state.id);
            },
            .client => {
                if (kind != .response) return;
                const session_state = self.webTransportSessionState(state.id);
                if (session_state == .none) return;
                // Find `:status`; first response headers carry it.
                var status: ?[]const u8 = null;
                for (fields) |field| {
                    if (std.mem.eql(u8, field.name, ":status")) {
                        status = field.value;
                        break;
                    }
                }
                const value = status orelse return;
                // 1xx responses are informational and don't establish
                // the session — wait for the final response.
                if (value.len > 0 and value[0] == '1') return;
                if (webtransport_mod.isAcceptedStatus(value)) {
                    try self.confirmWebTransportSession(state.id);
                } else {
                    // Bootstrap rejected (non-2xx): no session-closed
                    // event — the application sees the response headers
                    // themselves. Substreams opened against the pending
                    // session are swept.
                    self.sweepWebTransportSubstreams(state.id);
                    self.endWebTransportSession(state.id);
                }
            },
        }
    }

    fn rejectIncomingRequest(
        self: *Session,
        state: *StreamState,
        scratch: []u8,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) Error!void {
        if (!state.locally_rejected) try budget.reserve(0);

        while (true) {
            const n = try self.quic.streamRead(state.id, scratch);
            if (n == 0) break;
        }

        state.rx.clearRetainingCapacity();
        if (state.locally_rejected) return;

        try self.rejectRequest(state.id);
        state.locally_rejected = true;
        state.recv_finished = true;
        try self.appendReservedEvent(events, .{
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
        budget: *DrainBudget,
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

        // Route WebTransport stream FINs to the dedicated lifecycle event so
        // applications can correlate them with the originating session
        // without re-deriving the kind from the stream id.
        if (state.webTransportKind()) |wt_kind| {
            // If the stream is currently buffered (waiting for the
            // session to be confirmed), park the FIN here. The replay
            // path will emit `webtransport_stream_finished` *after*
            // the deferred open + data events so the application sees
            // the lifecycle in the right order.
            if (state.wt_buffered) {
                state.wt_buffered_fin = true;
                return;
            }

            // Gate WT-flavored FIN events on the Session ID having been
            // parsed. A peer can FIN a uni stream after sending only the
            // type-byte 0x54 (or the bidi marker 0x41) but before the
            // Session ID varint lands. In that case
            // `processWebTransportStreamState` returned early with
            // `InsufficientBytes` and no `_opened` event was ever
            // emitted — emitting `_finished` now would synthesize a
            // phantom lifecycle event the application has no `_opened`
            // to pair against, with `session_id = 0` (the orelse
            // fallback) referring to nothing. Treat such streams as if
            // they had no application-visible existence: silently mark
            // them finished and move on.
            if (state.wt_session_id == null) {
                try budget.reserve(0);
                state.recv_finished = true;
                state.rx.clearRetainingCapacity();
                return;
            }

            // Make sure any unread bytes are surfaced before the FIN event;
            // otherwise the application would see "finished" with no data
            // event for the trailing bytes.
            if (state.rx.items.len > 0) {
                try self.processWebTransportStreamState(state, wt_kind, events, budget);
            }
            try budget.reserve(0);
            state.recv_finished = true;
            try self.appendReservedEvent(events, .{
                .webtransport_stream_finished = .{
                    .stream_id = state.id,
                    .session_id = state.wt_session_id.?,
                    .kind = wt_kind,
                },
            });
            return;
        }

        // RFC 9114 §7.1: a cleanly terminated stream whose last frame is
        // truncated is a connection error of type H3_FRAME_ERROR.
        // processState consumes every complete frame, so rx residue at
        // FIN is a partial frame (or, on push streams, a partial
        // push-id varint).
        if (state.message_decoder != null and state.rx.items.len > 0) {
            self.closeForError(error.InsufficientBytes);
            return error.InsufficientBytes;
        }

        const message_kind = if (state.message_decoder) |*decoder| blk: {
            decoder.finish() catch |err| {
                // RFC 9114 §4.1 ¶14: a request that terminates without
                // a complete message aborts its response stream with
                // H3_REQUEST_INCOMPLETE (MissingHeaders / under-length
                // body at FIN), not H3_MESSAGE_ERROR.
                if (self.role == .server and decoder.kind == .request and
                    (err == error.MissingHeaders or err == error.ContentLengthMismatch))
                {
                    self.failMessageStream(state, decoder.kind, error.RequestIncomplete, events, budget);
                    return;
                }
                if (errors_mod.classify(err).scope == .stream and decoder.kind != .push) {
                    self.failMessageStream(state, decoder.kind, err, events, budget);
                    return;
                }
                self.closeForError(err);
                return err;
            };
            break :blk decoder.kind;
        } else null;

        try budget.reserve(0);
        state.recv_finished = true;
        // If this stream was the CONNECT stream of a WebTransport
        // session, peer FIN ends the session [draft-ietf-webtrans-http3
        // §5.4]. A FIN landing with a partial capsule still buffered is
        // a malformed message; otherwise it's a clean fin-close with a
        // session-closed event. Either way the registry is cleared so
        // subsequent peer-opened WT streams aren't dispatched against a
        // dead session.
        if (self.wt_sessions.get(state.id)) |sess| {
            if (sess.reassembler.buffered() > 0) {
                try self.failWebTransportConnectMessage(state, events, budget);
            } else {
                try self.closeWebTransportSessionWithEvent(
                    state.id,
                    events,
                    budget,
                    .fin,
                    null,
                    "",
                    null,
                );
            }
        }
        try self.appendReservedEvent(events, .{
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
        budget: *DrainBudget,
    ) Error!void {
        if (state.recv_reset_seen) return;
        // Reserve the terminal event slot BEFORE mutating recv state: if
        // the budget throws here the next drain retries cleanly, whereas
        // the old mutate-then-reserve ordering dropped the reset event
        // forever on EventQueueFull (recv_reset_seen short-circuited the
        // retry).
        try budget.reserve(0);
        try self.cancelQpackDecodeForStream(state.id);
        state.rx.clearRetainingCapacity();
        state.recv_reset_seen = true;
        state.recv_finished = true;

        // A peer RESET of the CONNECT stream tears the session down the
        // same way a FIN does — reset-close event with the wire code
        // preserved [draft-ietf-webtrans-http3 §4.6]. The helper
        // reserves before mutating, so a budget error here loses only
        // the session-close event; the reset event below must still
        // surface, so budget errors are swallowed and non-budget errors
        // propagate.
        if (self.wt_sessions.contains(state.id)) {
            self.closeWebTransportSessionWithEvent(
                state.id,
                events,
                budget,
                .reset,
                null,
                "",
                error_code,
            ) catch |err| {
                if (!isLocalDrainBudgetError(err)) return err;
            };
        }

        // If we locally rejected this stream (e.g. via the
        // buffered-stream `.reject` policy), the peer's matching RESET is
        // just acknowledgement of our STOP_SENDING — we must not surface
        // it as a fresh `webtransport_stream_reset` event because no
        // `webtransport_stream_opened` was ever emitted to pair with it.
        if (state.locally_rejected) return;

        // RESETs on a WebTransport stream carry application error codes
        // mapped through the §4.6 algorithm. Surface both the wire code and
        // the recovered 32-bit application code so callers can pick whichever
        // form matters for their error handling.
        if (state.webTransportKind()) |wt_kind| {
            try self.appendReservedEvent(events, .{
                .webtransport_stream_reset = .{
                    .stream_id = state.id,
                    .session_id = state.wt_session_id orelse 0,
                    .kind = wt_kind,
                    .error_code = error_code,
                    .application_error_code = webtransport_mod.http3ToAppError(error_code),
                    .final_size = final_size,
                },
            });
            return;
        }

        const kind: ?message_mod.Kind = if (state.message_decoder) |decoder|
            decoder.kind
        else if (!stream_mod.isUnidirectional(state.id))
            self.incomingMessageKind(state.id) catch null
        else
            null;

        try self.appendReservedEvent(events, .{
            .stream_reset = .{
                .stream_id = state.id,
                .kind = kind,
                .error_code = error_code,
                .final_size = final_size,
            },
        });

        // Opt-in eager reclaim (`Config.reclaim_peer_reset_streams`): a peer
        // RESET of a plain bidirectional stream leaves it half-closed, so it
        // would otherwise linger until the local side closes. Tear the local
        // send side down now — the peer has abandoned the exchange — so
        // `isFullyClosed` holds and `gcClosedStreams` reclaims it at the end
        // of this drain. The `streamReset` may fail if quic-zig has already
        // reaped its own entry (recv terminal); that is fine, we still mark
        // the local side closed so the http3-zig registry reclaims. Uni
        // streams already reap on `recv_done`; the WebTransport branch
        // returned above, so this only touches request/response streams.
        if (self.config.reclaim_peer_reset_streams and
            !state.locally_finished and
            !stream_mod.isUnidirectional(state.id))
        {
            self.quic.streamReset(state.id, protocol.ErrorCode.request_cancelled) catch {};
            state.locally_finished = true;
        }
    }

    /// Datagram-gate view of peer settings: the real SETTINGS once they
    /// arrive, else the remembered ones (RFC 9297 §2.1.1 blesses
    /// remembered-settings datagrams in early data). Deliberately NOT
    /// consulted by the QPACK-dynamic or extended-CONNECT gates — see
    /// `rememberPeerSettings` for the v1 replay-safety rationale.
    fn effectivePeerSettings(self: *const Session) ?settings_mod.Settings {
        return self.peer_settings orelse self.remembered_peer_settings;
    }

    fn validateDatagramSend(self: *Session, stream_id: u64, payload_len: usize) Error!void {
        try datagram_mod.validateStreamId(stream_id);

        // RFC 9297 §2.1.1: a QUIC DATAGRAM MUST NOT be sent until
        // SETTINGS_H3_DATAGRAM has been both SENT and received with
        // value 1 — gate on our own advertised setting too, not just
        // the peer's.
        if (!self.local_settings.h3_datagram) return Error.DatagramNotEnabled;
        const peer = self.effectivePeerSettings() orelse return Error.MissingSettings;
        if (!peer.h3_datagram) return Error.DatagramNotEnabled;

        const encoded_len = try datagram_mod.encodedLen(stream_id, payload_len);
        const peer_transport = try self.quic.peerTransportParams();
        const params = peer_transport orelse return Error.DatagramNotEnabled;
        if (params.max_datagram_frame_size == 0) return Error.DatagramNotEnabled;
        if (encoded_len > params.max_datagram_frame_size) return Error.DatagramTooLarge;
    }

    /// Mirrors the peer-settings half of `validateDatagramSend` for the
    /// capsule-based DATAGRAM path (RFC 9297 §3.4): both transports require
    /// `SETTINGS_H3_DATAGRAM = 1` from the peer. Capsule path doesn't go
    /// through QUIC datagram framing so it skips the transport-param checks.
    fn validatePeerDatagramEnabled(self: *const Session) Error!void {
        const peer = self.effectivePeerSettings() orelse return Error.MissingSettings;
        if (!peer.h3_datagram) return Error.DatagramNotEnabled;
    }

    fn cancelQpackDecodeForStream(self: *Session, stream_id: u64) Error!void {
        if (!self.qpack_decoder_state.isStreamBlocked(stream_id)) return;

        const instruction = self.qpack_decoder_state.cancelStream(stream_id);
        if (self.qpack_decoder_stream_id != null) {
            try self.writeQpackDecoderInstruction(instruction);
        }
    }

    fn appendReservedMessageEvent(
        self: *Session,
        events: *std.ArrayList(Event),
        stream_id: u64,
        kind: message_mod.Kind,
        event: message_mod.Event,
    ) Error!void {
        const out: Event = switch (event) {
            .headers => |fields| blk: {
                var in_early_data = false;
                if (self.role == .server and kind == .request) {
                    self.applyRequestPriorityOnHeaders(stream_id, fields);
                    in_early_data = self.quic.streamArrivedInEarlyData(stream_id) orelse false;
                }
                break :blk .{ .headers = .{
                    .stream_id = stream_id,
                    .kind = kind,
                    .fields = try cloneFields(self.allocator, fields),
                    .arrived_in_early_data = in_early_data,
                } };
            },
            .interim_headers => |fields| .{ .interim_headers = .{
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
            .push_promise => |promise| blk: {
                try self.validateReceivedPushId(promise.push_id);
                const fields = self.received_push_promises.get(promise.push_id) orelse return Error.InvalidPushId;
                const field_section = try self.allocator.dupe(u8, promise.field_section);
                errdefer self.allocator.free(field_section);
                const fields_copy = try cloneFields(self.allocator, fields);
                break :blk .{ .push_promise = .{
                    .stream_id = stream_id,
                    .push_id = promise.push_id,
                    .field_section = field_section,
                    .fields = fields_copy,
                } };
            },
            .ignored_unknown => |frame_type| .{ .ignored_unknown_frame = .{
                .stream_id = stream_id,
                .frame_type = frame_type,
            } },
        };
        try self.appendReservedEvent(events, out);
    }

    fn appendEvent(
        self: *Session,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
        event: Event,
    ) Error!void {
        try budget.reserve(eventOwnedPayloadBytes(event));
        try self.appendReservedEvent(events, event);
    }

    fn appendReservedEvent(
        self: *Session,
        events: *std.ArrayList(Event),
        event: Event,
    ) Error!void {
        // Every emitted event funnels through here, so this is the single
        // choke point that keeps `StreamState.last_event_us` honest for
        // `openRequestStreams`-based deadline enforcement. The stream may
        // already be reclaimed (or the event stream-less) — both no-ops.
        if (eventStreamId(event)) |stream_id| {
            if (self.streams.get(stream_id)) |state| {
                state.last_event_us = self.quic.last_activity_us;
            }
        }
        try appendRawEvent(self.allocator, events, event);
        self.traceEmittedEvent(event);
    }

    const DecodedFieldSection = struct {
        fields: []qpack.FieldLine,
        required_insert_count: u64,
    };

    fn decodeFieldSectionForStream(
        self: *Session,
        stream_id: u64,
        block: []const u8,
    ) Error!DecodedFieldSection {
        if (!self.receivesDynamicQpack()) {
            return .{
                .fields = try qpack.decodeFieldSectionWithOptions(
                    self.allocator,
                    block,
                    self.qpackDecodeOptions(),
                ),
                .required_insert_count = 0,
            };
        }

        const decoded_prefix = try qpack.state.decodeFieldSectionPrefix(
            block,
            self.local_settings.qpack_max_table_capacity,
            self.qpack_decoder_table.insert_count,
        );
        switch (try self.qpack_decoder_state.beginFieldSection(
            stream_id,
            decoded_prefix.prefix.required_insert_count,
        )) {
            .ready => {},
            .blocked => return error.RequiredInsertCountNotReady,
        }

        return .{
            .fields = try qpack.decodeDynamicFieldSectionWithOptions(
                self.allocator,
                &self.qpack_decoder_table,
                self.local_settings.qpack_max_table_capacity,
                block,
                self.qpackDecodeOptions(),
            ),
            .required_insert_count = decoded_prefix.prefix.required_insert_count,
        };
    }

    fn qpackDecodeOptions(self: *const Session) qpack.FieldSectionDecodeOptions {
        // RFC 9114 §4.2.2: SETTINGS_MAX_FIELD_SECTION_SIZE limits the
        // DECODED size (name + value + 32 bytes per field), so the
        // decode budget is driven by max_field_section_size whenever it
        // is set; max_decoded_field_section_bytes remains the fallback
        // for callers that left the settings-facing knob unset.
        const max_decoded: ?usize = if (self.config.max_field_section_size) |max|
            std.math.cast(usize, max)
        else
            self.config.max_decoded_field_section_bytes;
        return .{
            .max_field_lines = self.config.max_field_lines,
            .max_decoded_bytes = max_decoded,
        };
    }

    fn completeQpackFieldSection(
        self: *Session,
        stream_id: u64,
        required_insert_count: u64,
    ) Error!void {
        const instruction = try self.qpack_decoder_state.completeFieldSection(
            stream_id,
            required_insert_count,
        ) orelse return;
        try self.writeQpackDecoderInstruction(instruction);
    }

    fn ensureIncomingState(self: *Session, stream_id: u64) Error!*StreamState {
        // Record the RFC 9114 §5.2 GOAWAY bound before any per-stream
        // rejection below: a stream we observe at all "was or might [have
        // been] processed", so the graceful GOAWAY id must cover it even
        // when the per-stream limit (or the post-GOAWAY auto-reject path)
        // refuses it. Client-initiated bidi only — that is the id space a
        // server GOAWAY covers; extension streams sharing it (WebTransport
        // bidi, RFC 9114 §6.1 carve-outs) only ever push the bound higher,
        // which is safe: a larger id claims strictly less future work.
        if (self.role == .server and
            !stream_mod.isUnidirectional(stream_id) and
            stream_mod.isClientInitiated(stream_id))
        {
            if (self.highest_peer_request_stream_id == null or
                stream_id > self.highest_peer_request_stream_id.?)
            {
                self.highest_peer_request_stream_id = stream_id;
            }
        }

        if (self.streams.get(stream_id)) |state| return state;

        // Defense-in-depth: bound the size of `self.streams` against a
        // peer that opens streams and never finishes them. QUIC's
        // MAX_STREAMS already provides per-direction caps, but those
        // are typically generous; this knob lets the application keep
        // session-level state proportional. STOP_SENDING + a structured
        // error give the peer a clear signal and the application a
        // surfaced event (`request_rejected` for bidi via the existing
        // path; uni rejections fail the call).
        if (self.config.max_concurrent_peer_streams) |limit| {
            if (self.streams.count() >= limit) {
                self.quic.streamStopSending(stream_id, protocol.ErrorCode.request_rejected) catch {};
                return Error.PeerStreamLimitExceeded;
            }
        }

        if (stream_mod.isUnidirectional(stream_id)) {
            return try self.createState(stream_id);
        }

        // RFC 9114 §6.1 ¶3: a client receiving a server-initiated
        // bidi stream MUST close with H3_STREAM_CREATION_ERROR
        // unless an extension has been negotiated.
        // draft-ietf-webtrans-http3 §4.2 is exactly such an extension.
        // Defer the role check to `processBidiState` (where we peek
        // for the `0x41` WT marker) only when we have a WebTransport
        // session in flight — otherwise fire the error eagerly so
        // peers don't have to send extra bytes to learn we rejected.
        if (self.isExtensionDirectionBidi(stream_id) and !self.webTransportEndpointActive()) {
            return Error.UnexpectedStream;
        }
        return try self.createState(stream_id);
    }

    /// True if `stream_id` is a bidi stream id that's in the
    /// role-mismatched direction (server-initiated arriving at a
    /// client, per RFC 9114 §6.1 ¶3). The server side never sees this
    /// case for incoming streams: it only ever opens server-initiated
    /// bidis itself, and those are pre-registered in
    /// `openWebTransportBidiStream`.
    fn isExtensionDirectionBidi(self: *const Session, stream_id: u64) bool {
        if (stream_mod.isUnidirectional(stream_id)) return false;
        return self.role == .client and !stream_mod.isClientInitiated(stream_id);
    }

    /// True if any WebTransport session is currently pending or
    /// established. Used to decide whether peer-initiated bidi streams
    /// in the otherwise-forbidden direction (per RFC 9114 §6.1 ¶3) get
    /// the WebTransport carve-out treatment in `processBidiState`.
    fn webTransportEndpointActive(self: *const Session) bool {
        return self.wt_sessions.count() > 0;
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
            state.message_decoder = message_mod.Decoder.init(decoder_kind, self.messageDecodeOptions(decoder_kind));
        }

        _ = try self.ensureEncoder(state, encoder_kind);
        return state;
    }

    fn ensureEncoder(self: *Session, state: *StreamState, kind: message_mod.Kind) Error!*message_mod.Encoder {
        if (state.message_encoder) |*encoder| {
            if (encoder.kind != kind) return Error.WrongMessageKind;
            return encoder;
        }

        state.message_encoder = message_mod.Encoder.init(kind, self.messageEncodeOptions(kind));
        if (state.message_encoder) |*encoder| return encoder;
        unreachable;
    }

    fn messageEncodeOptions(self: *const Session, kind: message_mod.Kind) message_mod.EncodeOptions {
        return .{
            .max_field_section_size = self.config.max_field_section_size,
            .enable_connect_protocol = kind == .request and
                self.peer_settings != null and
                self.peer_settings.?.enable_connect_protocol,
        };
    }

    fn messageDecodeOptions(self: *const Session, kind: message_mod.Kind) message_mod.DecodeOptions {
        return .{
            .max_field_section_size = self.config.max_field_section_size,
            .enable_connect_protocol = kind == .request and self.local_settings.enable_connect_protocol,
        };
    }

    fn ensureExtendedConnectAllowed(self: *const Session, fields: []const qpack.FieldLine) Error!void {
        if (headers_mod.requestProtocol(fields) == null) return;
        const peer = self.peer_settings orelse return Error.MissingSettings;
        if (!peer.enable_connect_protocol) return Error.ExtendedConnectNotEnabled;
    }

    fn getState(self: *Session, stream_id: u64) Error!*StreamState {
        return self.streams.get(stream_id) orelse Error.MissingStream;
    }

    fn createState(self: *Session, stream_id: u64) Error!*StreamState {
        const state = try self.allocator.create(StreamState);
        errdefer self.allocator.destroy(state);
        state.* = .{
            .id = stream_id,
            // Baseline for request-deadline enforcement: a stream that
            // opens and then never produces an event still ages from
            // its creation time rather than sitting at 0 forever.
            .last_event_us = self.quic.last_activity_us,
        };
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
            .webtransport_uni => {
                // No critical-stream uniqueness check: WebTransport uni
                // streams are application traffic, multiple peer-opened
                // streams are normal. The Session ID is parsed in
                // `processWebTransportStreamState` once enough bytes arrive.
            },
            .unknown => {},
        }
    }

    fn validateReceivedPushId(self: *Session, push_id: u64) Error!void {
        const max_push_id = self.config.max_push_id orelse {
            self.closeForError(Error.InvalidPushId);
            return Error.InvalidPushId;
        };
        if (push_id > max_push_id) {
            self.closeForError(Error.InvalidPushId);
            return Error.InvalidPushId;
        }
        // All received-push-id observation points (push stream prefix,
        // PUSH_PROMISE, client-side CANCEL_PUSH) funnel through here, so
        // this is the choke point for the client-side GOAWAY bound
        // (RFC 9114 §5.2: a client GOAWAY carries a push id).
        if (self.highest_peer_push_id == null or push_id > self.highest_peer_push_id.?) {
            self.highest_peer_push_id = push_id;
        }
    }

    fn recordReceivedPushPromise(
        self: *Session,
        push_id: u64,
        fields: []const qpack.FieldLine,
    ) Error!void {
        if (self.role != .client) return;
        if (self.received_push_promises.get(push_id)) |existing| {
            if (!fieldSectionsEqual(existing, fields)) return Error.InconsistentPushPromise;
            return;
        }

        // Defense-in-depth beyond the client-advertised MAX_PUSH_ID: cap the
        // distinct push promises tracked so a server can't flood the map.
        if (self.config.max_tracked_push_promises) |limit| {
            if (self.received_push_promises.count() >= limit) return Error.ExcessivePushPromises;
        }

        const copy = try cloneFields(self.allocator, fields);
        errdefer freeFields(self.allocator, copy);
        try self.received_push_promises.put(self.allocator, push_id, copy);
    }

    fn applyPushPolicy(self: *Session, push_id: u64) Error!void {
        if (self.role != .client) return;
        switch (self.config.push_policy) {
            .accept => {},
            .cancel_promises => try self.cancelPush(push_id),
        }
    }

    fn validateLocalCancelPushId(self: *const Session, push_id: u64) Error!void {
        switch (self.role) {
            .client => {
                const max_push_id = self.config.max_push_id orelse return Error.PushNotEnabled;
                if (push_id > max_push_id) return Error.InvalidPushId;
            },
            .server => {
                const max_push_id = self.peer_max_push_id orelse return Error.PushNotEnabled;
                if (push_id > max_push_id or push_id >= self.next_push_id) {
                    return Error.InvalidPushId;
                }
            },
        }
    }

    fn validateLocalPriorityPushId(self: *const Session, push_id: u64) Error!void {
        if (self.role != .client) return Error.InvalidRole;
        const max_push_id = self.config.max_push_id orelse return Error.PushNotEnabled;
        if (push_id > max_push_id) return Error.InvalidPriorityTarget;
        if (self.received_push_promises.get(push_id) == null) return Error.InvalidPriorityTarget;
    }

    fn pushIdInUse(self: *const Session, push_id: u64, except_stream_id: u64) bool {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.id == except_stream_id) continue;
            if (state.push_id != null and state.push_id.? == push_id) return true;
        }
        return false;
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

    fn peerAllowsPush(self: *const Session, push_id: u64) bool {
        // RFC 9114 §5.2 ¶3: "Endpoints MUST NOT initiate new requests or
        // promise new pushes on the connection after receipt of a GOAWAY
        // frame from the peer." A client GOAWAY carries a push id (§7.2.6
        // ¶1); pushes with id ≥ the limit are rejected by the sender of
        // the GOAWAY (§5.2 ¶7), so the server MUST refuse new promises at
        // or above the threshold.
        const limit = self.peer_goaway_id orelse return true;
        return push_id < limit;
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

    fn sendPriorityUpdate(self: *Session, frame: frame_mod.Frame) Error!void {
        try self.start();
        try self.writeControlFrame(frame);
    }

    fn reservePushId(self: *Session) Error!u64 {
        const max_push_id = self.peer_max_push_id orelse return Error.PushNotEnabled;
        if (self.next_push_id > max_push_id) return Error.PushLimitExceeded;
        const push_id = self.next_push_id;
        self.next_push_id += 1;
        return push_id;
    }

    fn writePushPromise(
        self: *Session,
        request_stream_id: u64,
        push_id: u64,
        fields: []const qpack.FieldLine,
    ) Error!void {
        if (stream_mod.isUnidirectional(request_stream_id) or !stream_mod.isClientInitiated(request_stream_id)) {
            return Error.UnexpectedStream;
        }
        try headers_mod.validateRequest(fields);

        // PUSH_PROMISE field sections ride the same dynamic-capable path
        // as HEADERS (see writeDynamicFieldSectionWithEncoder). Under the
        // default static_only posture the dynamic path declines and the
        // static fallback below produces byte-identical output to the
        // pre-dynamic implementation.
        if (try self.writeDynamicPushPromise(request_stream_id, push_id, fields)) return;

        const field_section_len = qpack.fieldSectionEncodedLen(fields);
        if (self.config.max_field_section_size) |max| {
            if (field_section_len > max) return Error.HeaderSectionTooLarge;
        }
        const field_section = try self.allocator.alloc(u8, field_section_len);
        defer self.allocator.free(field_section);
        const field_section_n = try qpack.encodeFieldSection(field_section, fields);
        std.debug.assert(field_section_n == field_section.len);
        try self.writePushPromiseFrame(request_stream_id, push_id, field_section);
    }

    /// Dynamic-QPACK PUSH_PROMISE path. Mirrors
    /// `writeDynamicFieldSectionWithEncoder`: emits any encoder-stream
    /// instructions first, then encodes the field section against the
    /// dynamic table, tracking it against the request stream — the
    /// decoder acknowledges PUSH_PROMISE sections under the stream that
    /// carried the frame (RFC 9204 §4.4.1), which is the request stream.
    /// Returns false (no bytes written) when dynamic QPACK is not in
    /// play or the peer's SETTINGS_QPACK_BLOCKED_STREAMS budget is
    /// saturated, so the caller falls back to the static/literal path.
    fn writeDynamicPushPromise(
        self: *Session,
        request_stream_id: u64,
        push_id: u64,
        fields: []const qpack.FieldLine,
    ) Error!bool {
        if (!(try self.prepareDynamicQpackEncoder(fields))) return false;

        const options = self.dynamicQpackEncodeOptions(request_stream_id);
        const field_section_len = qpack.dynamicFieldSectionEncodedLenWithOptions(
            &self.qpack_encoder_table,
            fields,
            options,
        ) catch |err| switch (err) {
            error.BlockedStreamLimitExceeded => return false,
            else => return err,
        };
        if (self.config.max_field_section_size) |max| {
            if (field_section_len > max) return Error.HeaderSectionTooLarge;
        }
        const field_section = try self.allocator.alloc(u8, field_section_len);
        defer self.allocator.free(field_section);
        const field_section_n = qpack.encodeDynamicFieldSectionWithOptions(
            field_section,
            &self.qpack_encoder_table,
            fields,
            options,
        ) catch |err| switch (err) {
            error.BlockedStreamLimitExceeded => return false,
            else => return err,
        };
        try self.writePushPromiseFrame(request_stream_id, push_id, field_section[0..field_section_n]);
        return true;
    }

    fn writePushPromiseFrame(
        self: *Session,
        request_stream_id: u64,
        push_id: u64,
        field_section: []const u8,
    ) Error!void {
        const frame: frame_mod.Frame = .{ .push_promise = .{
            .push_id = push_id,
            .field_section = field_section,
        } };
        const buf = try self.allocator.alloc(u8, frame_mod.encodedLen(frame));
        defer self.allocator.free(buf);
        const n = try frame_mod.encode(buf, frame);
        try self.writeAll(request_stream_id, buf[0..n]);
        self.trace(.{
            .name = .headers_sent,
            .role = self.role,
            .stream_id = request_stream_id,
            .frame_type = protocol.FrameType.push_promise,
            .bytes = field_section.len,
            .value = push_id,
        });
    }

    fn openPushStream(
        self: *Session,
        push_id: u64,
        response_fields: []const qpack.FieldLine,
    ) Error!u64 {
        // openNextUni: monotonic per-type id, reap-safe (see openWebTransportUniStream).
        const stream_id = (try self.quic.openNextUni()).id;
        errdefer self.quic.streamReset(stream_id, protocol.ErrorCode.internal_error) catch {};
        const state = try self.createState(stream_id);
        state.uni_kind = .push;
        state.push_id = push_id;
        errdefer {
            _ = self.streams.remove(stream_id);
            state.deinit(self.allocator);
            self.allocator.destroy(state);
        }

        // Apply any RFC 9218 priority buffered for this push id (from an
        // earlier PRIORITY_UPDATE, keyed by push id before the push stream
        // existed) to quic-zig's send scheduler, mirroring the request path.
        if (self.push_priorities.get(push_id)) |p| {
            self.quic.streamSetPriority(stream_id, .{
                .urgency = p.urgency,
                .incremental = p.incremental,
            }) catch {};
        }

        try self.writeStreamType(stream_id, protocol.StreamType.push);
        try self.writePushId(stream_id, push_id);
        const encoder = try self.ensureEncoder(state, .push);
        try self.writeHeadersWithEncoder(stream_id, encoder, response_fields);
        return stream_id;
    }

    fn writePushId(self: *Session, stream_id: u64, push_id: u64) Error!void {
        var buf: [8]u8 = undefined;
        const n = try varint.encode(&buf, push_id);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeHeadersWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        try self.writeFieldSectionWithEncoder(.headers, stream_id, encoder, fields);
    }

    fn writeDataWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        data: []const u8,
    ) Error!void {
        try self.ensureStreamSendCapacity(stream_id, self.dataFramesEncodedLen(data.len));

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
            self.trace(.{
                .name = .data_sent,
                .role = self.role,
                .stream_id = stream_id,
                .frame_type = protocol.FrameType.data,
                .bytes = chunk.len,
            });
            offset = end;
        }
    }

    fn dataFramesEncodedLen(self: *const Session, data_len: usize) usize {
        if (data_len == 0) return 0;
        const chunk_size = if (self.config.max_data_frame_payload == 0)
            data_len
        else
            self.config.max_data_frame_payload;

        var total: usize = 0;
        var offset: usize = 0;
        while (offset < data_len) {
            const end = @min(data_len, offset + chunk_size);
            const chunk_len = end - offset;
            total += varint.encodedLen(protocol.FrameType.data) +
                varint.encodedLen(chunk_len) +
                chunk_len;
            offset = end;
        }
        return total;
    }

    fn sendCapsuleData(
        self: *Session,
        stream_id: u64,
        kind: message_mod.Kind,
        capsule_type: u64,
        value: []const u8,
    ) Error!void {
        try self.validateCapsuleValueSize(value.len);
        const state = switch (kind) {
            .request => try self.getState(stream_id),
            .response => try self.ensureMessageState(stream_id, .request, .response),
            .push => return Error.InvalidRole,
        };
        const encoded_len = try capsuleEncodedLenChecked(capsule_type, value.len);
        const encoder = try self.ensureEncoder(state, kind);
        try self.ensureStreamSendCapacity(stream_id, self.dataFramesEncodedLen(encoded_len));
        const encoded = try self.allocator.alloc(u8, encoded_len);
        defer self.allocator.free(encoded);
        const n = try capsule_mod.encode(encoded, capsule_type, value);
        try self.writeDataWithEncoder(stream_id, encoder, encoded[0..n]);
        self.trace(.{
            .name = .capsule_sent,
            .role = self.role,
            .stream_id = stream_id,
            .bytes = value.len,
            .value = capsule_type,
        });
    }

    fn validateCapsuleValueSize(self: *const Session, value_len: usize) Error!void {
        const max = self.config.max_capsule_value_size orelse return;
        if (value_len > max) return Error.CapsuleTooLarge;
    }

    fn writeTrailersWithEncoder(
        self: *Session,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        try self.writeFieldSectionWithEncoder(.trailers, stream_id, encoder, fields);
    }

    const FieldSectionKind = enum {
        headers,
        trailers,
    };

    fn writeFieldSectionWithEncoder(
        self: *Session,
        section_kind: FieldSectionKind,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        if (try self.writeDynamicFieldSectionWithEncoder(section_kind, stream_id, encoder, fields)) {
            return;
        }

        const payload_len = qpack.fieldSectionEncodedLen(fields);
        const len = varint.encodedLen(protocol.FrameType.headers) + varint.encodedLen(payload_len) + payload_len;
        const buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = switch (section_kind) {
            .headers => try encoder.encodeHeaders(buf, fields),
            .trailers => try encoder.encodeTrailers(buf, fields),
        };
        try self.writeAll(stream_id, buf[0..n]);
        self.traceFieldSectionSent(section_kind, stream_id, payload_len, fields.len);
    }

    fn writeDynamicFieldSectionWithEncoder(
        self: *Session,
        section_kind: FieldSectionKind,
        stream_id: u64,
        encoder: *message_mod.Encoder,
        fields: []const qpack.FieldLine,
    ) Error!bool {
        if (!(try self.prepareDynamicQpackEncoder(fields))) return false;

        // Best-effort dynamic encoding: if the peer's
        // SETTINGS_QPACK_BLOCKED_STREAMS budget is saturated,
        // gracefully fall back to the literal/static-only path
        // rather than aborting the request. Per RFC 9204 §2.1.2,
        // an encoder MUST NOT cause more streams to be blocked
        // than the peer allows; falling back to literals means
        // the outgoing field section can be decoded without any
        // dynamic-table reference.
        const options = self.dynamicQpackEncodeOptions(stream_id);
        const field_section_len = qpack.dynamicFieldSectionEncodedLenWithOptions(
            &self.qpack_encoder_table,
            fields,
            options,
        ) catch |err| switch (err) {
            error.BlockedStreamLimitExceeded => return false,
            else => return err,
        };
        const field_section = try self.allocator.alloc(u8, field_section_len);
        defer self.allocator.free(field_section);
        const field_section_n = qpack.encodeDynamicFieldSectionWithOptions(
            field_section,
            &self.qpack_encoder_table,
            fields,
            options,
        ) catch |err| switch (err) {
            error.BlockedStreamLimitExceeded => return false,
            else => return err,
        };

        const len = varint.encodedLen(protocol.FrameType.headers) +
            varint.encodedLen(field_section_n) +
            field_section_n;
        const buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = switch (section_kind) {
            .headers => try encoder.encodeHeadersBlock(buf, fields, field_section[0..field_section_n]),
            .trailers => try encoder.encodeTrailersBlock(buf, fields, field_section[0..field_section_n]),
        };
        try self.writeAll(stream_id, buf[0..n]);
        self.traceFieldSectionSent(section_kind, stream_id, field_section_n, fields.len);
        return true;
    }

    fn prepareDynamicQpackEncoder(self: *Session, fields: []const qpack.FieldLine) Error!bool {
        if (!self.canUseDynamicQpackEncoder()) return false;
        if (!(try self.syncQpackEncoderCapacity())) return false;

        const max_instruction_len = qpackEncoderInstructionsMaxLen(
            fields,
            self.config.enable_qpack_huffman,
            self.qpack_encoder_table.len(),
        );
        if (max_instruction_len == 0) return true;

        const instruction_buf = try self.allocator.alloc(u8, max_instruction_len);
        defer self.allocator.free(instruction_buf);
        const n = try qpack.encodeFieldSectionEncoderInstructions(
            instruction_buf,
            &self.qpack_encoder_table,
            fields,
            self.dynamicQpackEncodeOptions(0),
        );
        if (n > 0) try self.writeQpackEncoderBytes(instruction_buf[0..n]);
        return true;
    }

    fn syncQpackEncoderCapacity(self: *Session) Error!bool {
        const peer = self.peer_settings orelse return false;
        const peer_capacity = std.math.cast(usize, peer.qpack_max_table_capacity) orelse
            std.math.maxInt(usize);
        const desired = @min(self.config.qpack_encoder_table_capacity, peer_capacity);
        if (desired == 0) return false;
        if (desired == self.qpack_encoder_capacity) return true;

        const instruction: qpack.EncoderInstruction = .{ .set_capacity = desired };
        var buf: [16]u8 = undefined;
        const n = try qpack.instructions.encodeEncoderInstruction(&buf, instruction);
        try self.writeQpackEncoderBytes(buf[0..n]);
        _ = try qpack.instructions.applyEncoderInstruction(&self.qpack_encoder_table, instruction);
        self.qpack_encoder_capacity = desired;
        return true;
    }

    fn dynamicQpackEncodeOptions(
        self: *Session,
        stream_id: u64,
    ) qpack.DynamicFieldSectionEncodeOptions {
        return .{
            .huffman = self.config.enable_qpack_huffman,
            .tracker = .{
                .encoder_state = &self.qpack_encoder_state,
                .stream_id = stream_id,
            },
            .indexing = self.config.qpack_indexing,
        };
    }

    fn canUseDynamicQpackEncoder(self: *const Session) bool {
        if (!self.hasDynamicQpackIndexing()) return false;
        if (self.qpack_encoder_stream_id == null) return false;
        if (self.config.qpack_encoder_table_capacity == 0) return false;
        const peer = self.peer_settings orelse return false;
        return peer.qpack_max_table_capacity > 0;
    }

    fn hasDynamicQpackIndexing(self: *const Session) bool {
        return self.config.qpack_indexing.dynamic_references != .none or
            self.config.qpack_indexing.dynamic_inserts != .never;
    }

    fn receivesDynamicQpack(self: *const Session) bool {
        return self.local_settings.qpack_max_table_capacity > 0;
    }

    fn usesQpackStreams(self: *const Session) bool {
        return self.config.enable_qpack_streams or
            self.receivesDynamicQpack() or
            self.config.qpack_encoder_table_capacity > 0 or
            self.hasDynamicQpackIndexing();
    }

    fn writeQpackEncoderBytes(self: *Session, bytes: []const u8) Error!void {
        const stream_id = self.qpack_encoder_stream_id orelse return Error.MissingStream;
        try self.writeAll(stream_id, bytes);
        self.trace(.{
            .name = .qpack_encoder_bytes_sent,
            .role = self.role,
            .stream_id = stream_id,
            .bytes = bytes.len,
        });
    }

    fn writeQpackDecoderInstruction(
        self: *Session,
        instruction: qpack.DecoderInstruction,
    ) Error!void {
        const stream_id = self.qpack_decoder_stream_id orelse return Error.MissingStream;
        var buf: [16]u8 = undefined;
        const n = try qpack.instructions.encodeDecoderInstruction(&buf, instruction);
        try self.writeAll(stream_id, buf[0..n]);
        self.trace(.{
            .name = .qpack_decoder_instruction_sent,
            .role = self.role,
            .stream_id = stream_id,
            .bytes = n,
        });
    }

    fn writeStreamType(self: *Session, stream_id: u64, stream_type: u64) Error!void {
        var buf: [8]u8 = undefined;
        const n = try varint.encode(&buf, stream_type);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeAll(self: *Session, stream_id: u64, bytes: []const u8) Error!void {
        try self.ensureStreamSendCapacity(stream_id, bytes.len);

        var rest = bytes;
        while (rest.len > 0) {
            const n = try self.quic.streamWrite(stream_id, rest);
            if (n == 0) return Error.WriteStalled;
            rest = rest[n..];
        }
    }

    fn ensureStreamSendCapacity(self: *const Session, stream_id: u64, additional_bytes: usize) Error!void {
        if (try self.canBufferStreamBytes(stream_id, additional_bytes)) return;
        return Error.SendBufferFull;
    }

    fn observeGoaway(self: *Session, id: u64) Error!void {
        try self.validatePeerGoawayId(id);
        if (self.peer_goaway_id) |previous| {
            if (id > previous) return Error.InvalidGoawayId;
        }
        self.peer_goaway_id = id;
        self.enterDraining();
    }

    fn observeMaxPushId(self: *Session, id: u64) Error!void {
        if (self.role != .server) {
            self.closeForError(Error.FrameUnexpected);
            return Error.FrameUnexpected;
        }
        if (self.peer_max_push_id) |previous| {
            if (id < previous) {
                self.closeForError(Error.InvalidPushId);
                return Error.InvalidPushId;
            }
        }
        self.peer_max_push_id = id;
    }

    fn observeCancelPush(self: *Session, push_id: u64) Error!void {
        switch (self.role) {
            .client => {
                try self.validateReceivedPushId(push_id);
                // RFC 9114 §7.2.3 ¶? : "If a client receives a
                // CANCEL_PUSH frame, it discards any pushed
                // response associated with the indicated push ID."
                // Stop reading from any matching push stream so we
                // don't keep accumulating pushed bytes the server
                // has already abandoned. `stopReceivingPushIfOpen`
                // is a no-op for unknown / not-yet-open push ids.
                self.stopReceivingPushIfOpen(push_id);
            },
            .server => {
                const max_push_id = self.peer_max_push_id orelse {
                    self.closeForError(Error.InvalidPushId);
                    return Error.InvalidPushId;
                };
                if (push_id > max_push_id or push_id >= self.next_push_id) {
                    self.closeForError(Error.InvalidPushId);
                    return Error.InvalidPushId;
                }
                self.abortLocalPushIfOpen(push_id);
            },
        }
    }

    /// True if `map` can accept `key` without exceeding
    /// `Config.max_tracked_priorities` — no cap set, the key is already
    /// present (an overwrite that doesn't grow the map), or the map is
    /// below the cap.
    fn priorityMapHasRoom(
        self: *const Session,
        map: *const std.AutoHashMapUnmanaged(u64, priority_mod.Priority),
        key: u64,
    ) bool {
        const limit = self.config.max_tracked_priorities orelse return true;
        return map.contains(key) or map.count() < limit;
    }

    fn observePriorityUpdate(
        self: *Session,
        target: PriorityTarget,
        priority_field_value: []const u8,
    ) Error!PriorityUpdateEvent {
        if (self.role != .server) return Error.FrameUnexpected;

        switch (target) {
            .request_stream => |stream_id| try validatePriorityRequestStreamId(stream_id),
            .push => |push_id| try self.validatePriorityPushId(push_id),
        }

        const priority = try priority_mod.Priority.parse(priority_field_value);
        const owned = try self.allocator.dupe(u8, priority_field_value);
        errdefer self.allocator.free(owned);

        switch (target) {
            .request_stream => |stream_id| {
                // Priorities are advisory (RFC 9218 §7): under a flood of
                // distinct stream ids, drop the cached hint for a new id
                // beyond the cap rather than growing the map unboundedly.
                // The scheduler still receives the hint below regardless.
                if (self.priorityMapHasRoom(&self.request_priorities, stream_id)) {
                    try self.request_priorities.put(self.allocator, stream_id, priority);
                }
                // Feed the RFC 9218 hint to quic-zig 0.6.0's send scheduler so
                // the server's response bytes on this request stream are
                // emitted in urgency order. Best-effort: a PRIORITY_UPDATE for
                // an already-completed (reaped) request has nothing to
                // schedule (streamSetPriority returns StreamNotFound).
                self.quic.streamSetPriority(stream_id, .{
                    .urgency = priority.urgency,
                    .incremental = priority.incremental,
                }) catch {};
            },
            .push => |push_id| {
                if (self.priorityMapHasRoom(&self.push_priorities, push_id)) {
                    try self.push_priorities.put(self.allocator, push_id, priority);
                }
            },
        }

        return .{
            .target = target,
            .priority = priority,
            .priority_field_value = owned,
        };
    }

    /// RFC 9218 §5: the `priority` request header is the client's
    /// request-time urgency signal; feed it to the transport send scheduler
    /// exactly like the PRIORITY_UPDATE path does. Runs when a request's
    /// header section completes server-side — the first moment the stream
    /// exists on the transport, so it also applies a PRIORITY_UPDATE that
    /// arrived (and was buffered in `request_priorities`) before the stream
    /// opened; that buffered frame supersedes the header (RFC 9218 §7: the
    /// frame is the later signal by construction). Best-effort and advisory:
    /// an unparseable Priority field is treated as absent (§4 ¶7) and a
    /// reaped stream has nothing to schedule.
    fn applyRequestPriorityOnHeaders(
        self: *Session,
        stream_id: u64,
        fields: []const qpack.FieldLine,
    ) void {
        const effective: priority_mod.Priority =
            self.request_priorities.get(stream_id) orelse blk: {
                const parsed = priority_mod.fromFieldLines(fields) catch return;
                break :blk parsed orelse return;
            };
        self.quic.streamSetPriority(stream_id, .{
            .urgency = effective.urgency,
            .incremental = effective.incremental,
        }) catch {};
    }

    fn validatePriorityPushId(self: *const Session, push_id: u64) Error!void {
        const max_push_id = self.peer_max_push_id orelse return Error.InvalidPriorityTarget;
        if (push_id > max_push_id) return Error.InvalidPriorityTarget;
        // RFC 9218 §7.2: a PRIORITY_UPDATE (0xF0701) MUST reference a
        // promised push stream — a push id greater than the maximum or
        // one that has not yet been promised is a connection error of
        // type H3_ID_ERROR. (`push_priorities` still buffers hints for
        // ids that ARE promised but whose push stream has not opened.)
        if (push_id >= self.next_push_id) return Error.InvalidPriorityTarget;
    }

    fn stopReceivingPushIfOpen(self: *Session, push_id: u64) void {
        const stream_id = self.findPushStream(push_id) orelse return;
        self.stopSending(stream_id, protocol.ErrorCode.request_cancelled) catch {};
    }

    fn abortLocalPushIfOpen(self: *Session, push_id: u64) void {
        const stream_id = self.findPushStream(push_id) orelse return;
        self.resetStream(stream_id, protocol.ErrorCode.request_cancelled) catch {};
    }

    fn findPushStream(self: *const Session, push_id: u64) ?u64 {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.uni_kind) |kind| {
                switch (kind) {
                    .push => if (state.push_id != null and state.push_id.? == push_id) {
                        return state.id;
                    },
                    else => {},
                }
            }
        }
        return null;
    }

    fn enterDraining(self: *Session) void {
        if (self.shutdown_state == .active) self.shutdown_state = .draining;
    }

    fn trace(self: *Session, event: observability_mod.TraceEvent) void {
        self.metrics_counters.observe(event);
        self.config.observability.emit(event);
    }

    fn traceFieldSectionSent(
        self: *Session,
        section_kind: FieldSectionKind,
        stream_id: u64,
        payload_len: usize,
        field_count: usize,
    ) void {
        self.trace(.{
            .name = switch (section_kind) {
                .headers => .headers_sent,
                .trailers => .trailers_sent,
            },
            .role = self.role,
            .stream_id = stream_id,
            .frame_type = protocol.FrameType.headers,
            .bytes = payload_len,
            .count = field_count,
        });
    }

    fn traceEmittedEvent(self: *Session, event: Event) void {
        switch (event) {
            // Connection-level 0-RTT disposition; no per-frame trace
            // mapping (observability counters may follow separately).
            .early_data => {},
            .peer_settings => self.trace(.{
                .name = .settings_received,
                .role = self.role,
                .frame_type = protocol.FrameType.settings,
            }),
            .headers => |headers| self.trace(.{
                .name = .headers_received,
                .role = self.role,
                .stream_id = headers.stream_id,
                .frame_type = protocol.FrameType.headers,
                .bytes = fieldsOwnedBytes(headers.fields),
                .count = headers.fields.len,
                .early_data = headers.arrived_in_early_data,
            }),
            .interim_headers => |headers| self.trace(.{
                .name = .headers_received,
                .role = self.role,
                .stream_id = headers.stream_id,
                .frame_type = protocol.FrameType.headers,
                .bytes = fieldsOwnedBytes(headers.fields),
                .count = headers.fields.len,
            }),
            .trailers => |trailers| self.trace(.{
                .name = .trailers_received,
                .role = self.role,
                .stream_id = trailers.stream_id,
                .frame_type = protocol.FrameType.headers,
                .bytes = fieldsOwnedBytes(trailers.fields),
                .count = trailers.fields.len,
            }),
            .data => |data| self.trace(.{
                .name = .data_received,
                .role = self.role,
                .stream_id = data.stream_id,
                .frame_type = protocol.FrameType.data,
                .bytes = data.data.len,
            }),
            .datagram => |datagram| self.trace(.{
                .name = .datagram_received,
                .role = self.role,
                .stream_id = datagram.stream_id,
                .bytes = datagram.payload.len,
                .early_data = datagram.arrived_in_early_data,
            }),
            .datagram_acked => |acked| self.trace(.{
                .name = .datagram_acked,
                .role = self.role,
                .bytes = acked.len,
                .value = acked.id,
                .early_data = acked.arrived_in_early_data,
            }),
            .datagram_lost => |lost| self.trace(.{
                .name = .datagram_lost,
                .role = self.role,
                .bytes = lost.len,
                .value = lost.id,
                .early_data = lost.arrived_in_early_data,
            }),
            .flow_blocked => |blocked| self.trace(.{
                .name = .flow_blocked,
                .role = self.role,
                .stream_id = blocked.stream_id,
                .value = blocked.limit,
            }),
            .connection_ids_needed => |needed| self.trace(.{
                .name = .connection_ids_needed,
                .role = self.role,
                .count = needed.issue_budget,
                .value = needed.next_sequence_number,
            }),
            .push_promise => |promise| self.trace(.{
                .name = .headers_received,
                .role = self.role,
                .stream_id = promise.stream_id,
                .frame_type = protocol.FrameType.push_promise,
                .bytes = promise.field_section.len,
                .value = promise.push_id,
            }),
            .push_stream => |push| self.trace(.{
                .name = .push_stream_received,
                .role = self.role,
                .stream_id = push.stream_id,
                .frame_type = protocol.StreamType.push,
                .value = push.push_id,
            }),
            .cancel_push => |cancel| self.trace(.{
                .name = .cancel_push_received,
                .role = self.role,
                .frame_type = protocol.FrameType.cancel_push,
                .value = cancel.push_id,
            }),
            .priority_update => |update| self.trace(.{
                .name = .priority_update_received,
                .role = self.role,
                .stream_id = switch (update.target) {
                    .request_stream => |stream_id| @as(?u64, stream_id),
                    .push => null,
                },
                .frame_type = switch (update.target) {
                    .request_stream => protocol.FrameType.priority_update_request,
                    .push => protocol.FrameType.priority_update_push,
                },
                .bytes = update.priority_field_value.len,
                .value = switch (update.target) {
                    .request_stream => @as(u64, update.priority.urgency),
                    .push => |push_id| push_id,
                },
            }),
            .goaway => |id| self.trace(.{
                .name = .goaway_received,
                .role = self.role,
                .frame_type = protocol.FrameType.goaway,
                .value = id,
            }),
            .stream_finished => |finished| self.trace(.{
                .name = .stream_finished,
                .role = self.role,
                .stream_id = finished.stream_id,
            }),
            .stream_reset => |reset| self.trace(.{
                .name = .stream_reset_received,
                .role = self.role,
                .stream_id = reset.stream_id,
                .error_code = reset.error_code,
                .value = reset.final_size,
            }),
            .request_rejected => |rejected| self.trace(.{
                .name = .request_rejected,
                .role = self.role,
                .stream_id = rejected.stream_id,
                .error_code = rejected.error_code,
            }),
            .connection_closed => |closed| self.trace(.{
                .name = .connection_closed,
                .role = self.role,
                .bytes = closed.reason.len,
                .error_code = closed.error_code,
            }),
            .ignored_unknown_frame => |unknown| self.trace(.{
                .name = .ignored_unknown_frame,
                .role = self.role,
                .stream_id = unknown.stream_id,
                .frame_type = unknown.frame_type,
            }),
            .webtransport_stream_opened => |opened| self.trace(.{
                .name = .webtransport_stream_opened,
                .role = self.role,
                .stream_id = opened.stream_id,
                .frame_type = switch (opened.kind) {
                    .uni => protocol.StreamType.webtransport_uni_stream,
                    .bidi => protocol.FrameType.webtransport_bidi_stream,
                },
                .value = opened.session_id,
            }),
            .webtransport_stream_data => |data| self.trace(.{
                .name = .webtransport_stream_data_received,
                .role = self.role,
                .stream_id = data.stream_id,
                .frame_type = switch (data.kind) {
                    .uni => protocol.StreamType.webtransport_uni_stream,
                    .bidi => protocol.FrameType.webtransport_bidi_stream,
                },
                .bytes = data.data.len,
                .value = data.session_id,
            }),
            .webtransport_stream_finished => |finished| self.trace(.{
                .name = .webtransport_stream_finished,
                .role = self.role,
                .stream_id = finished.stream_id,
                .value = finished.session_id,
            }),
            .webtransport_stream_reset => |reset| self.trace(.{
                .name = .webtransport_stream_reset_received,
                .role = self.role,
                .stream_id = reset.stream_id,
                .error_code = reset.error_code,
                .value = reset.final_size,
            }),
            .webtransport_flow_violated => |violation| self.trace(.{
                .name = .webtransport_stream_reset_received,
                .role = self.role,
                .stream_id = violation.stream_id,
                .error_code = webtransport_mod.session_gone_code,
                .value = violation.limit,
            }),
            .webtransport_session_established => |established| self.trace(.{
                .name = .webtransport_session_established,
                .role = self.role,
                .stream_id = established.session_id,
            }),
            .webtransport_session_closed => |closed| self.trace(.{
                .name = .webtransport_session_closed,
                .role = self.role,
                .stream_id = closed.session_id,
                .error_code = closed.wire_error_code orelse 0,
                .bytes = closed.reason.len,
            }),
            .webtransport_session_draining => |draining| self.trace(.{
                .name = .webtransport_session_drain_received,
                .role = self.role,
                .stream_id = draining.session_id,
            }),
            .webtransport_peer_blocked => |blocked| switch (blocked.kind) {
                .data => self.trace(.{
                    .name = .webtransport_peer_data_blocked,
                    .role = self.role,
                    .stream_id = blocked.session_id,
                    .value = blocked.offered_limit,
                }),
                .streams_bidi => self.trace(.{
                    .name = .webtransport_peer_streams_blocked,
                    .role = self.role,
                    .stream_id = blocked.session_id,
                    .frame_type = webtransport_mod.CapsuleType.streams_blocked_bidi,
                    .value = blocked.offered_limit,
                }),
                .streams_uni => self.trace(.{
                    .name = .webtransport_peer_streams_blocked,
                    .role = self.role,
                    .stream_id = blocked.session_id,
                    .frame_type = webtransport_mod.CapsuleType.streams_blocked_uni,
                    .value = blocked.offered_limit,
                }),
            },
            .webtransport_credit_granted => |credit| self.trace(.{
                .name = .webtransport_credit_granted,
                .role = self.role,
                .stream_id = credit.session_id,
                .value = credit.limit,
            }),
            .webtransport_unknown_capsule => |unknown| self.trace(.{
                .name = .webtransport_unknown_capsule_received,
                .role = self.role,
                .stream_id = unknown.session_id,
                .frame_type = unknown.capsule_type,
                .bytes = unknown.value.len,
            }),
        }
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

    /// RFC 9114 §4.1.2: a malformed request or response is a STREAM error
    /// of type H3_MESSAGE_ERROR — reset the offending stream and keep the
    /// connection alive. Push-stream message errors keep connection scope
    /// (callers dispatch on `decoder.kind`). Emits `request_rejected`
    /// (server role) or `stream_reset` (client role) so the refusal is
    /// never silent. The reset itself is durable; only the notification
    /// event may be lost to drain-budget exhaustion.
    fn failMessageStream(
        self: *Session,
        state: *StreamState,
        kind: message_mod.Kind,
        err: anyerror,
        events: *std.ArrayList(Event),
        budget: *DrainBudget,
    ) void {
        const code = errors_mod.codeForError(err);
        self.resetStream(state.id, code) catch {};
        state.recv_finished = true;
        state.locally_rejected = true;
        state.rx.clearRetainingCapacity();

        budget.reserve(0) catch return;
        switch (self.role) {
            .server => self.appendReservedEvent(events, .{
                .request_rejected = .{
                    .stream_id = state.id,
                    .error_code = code,
                },
            }) catch {},
            .client => self.appendReservedEvent(events, .{
                .stream_reset = .{
                    .stream_id = state.id,
                    .kind = kind,
                    .error_code = code,
                    .final_size = 0,
                    .source = .local,
                },
            }) catch {},
        }
    }

    fn closeForError(self: *Session, err: anyerror) void {
        const close_error = errors_mod.localConnectionError(err);
        self.shutdown_state = .closed;
        self.last_close_error = close_error;
        self.quic.close(false, close_error.application.code, close_error.reason());
        self.trace(.{
            .name = .connection_close_sent,
            .role = self.role,
            .bytes = close_error.reason().len,
            .error_code = close_error.application.code,
        });
    }
};

fn errorSourceFromCloseSource(source: quic.CloseSource) ?errors_mod.Source {
    return switch (source) {
        .local => .local,
        .peer => .peer,
        else => null,
    };
}

fn appendRawEvent(allocator: std.mem.Allocator, events: *std.ArrayList(Event), event: Event) Error!void {
    events.append(allocator, event) catch |err| {
        event.deinit(allocator);
        return err;
    };
}

fn isLocalDrainBudgetError(err: anyerror) bool {
    return switch (err) {
        error.EventPayloadTooLarge,
        error.EventQueueFull,
        => true,
        else => false,
    };
}

/// The stream id an event is about, for per-stream activity stamping in
/// `appendReservedEvent`. Null for connection-scoped variants (settings,
/// goaway, cancel_push, connection lifecycle) and for `priority_update`,
/// whose target may be a push id rather than a stream id.
fn eventStreamId(event: Event) ?u64 {
    return switch (event) {
        .headers => |e| e.stream_id,
        .interim_headers => |e| e.stream_id,
        .data => |e| e.stream_id,
        .trailers => |e| e.stream_id,
        .datagram => |e| e.stream_id,
        .push_promise => |e| e.stream_id,
        .push_stream => |e| e.stream_id,
        .stream_finished => |e| e.stream_id,
        .stream_reset => |e| e.stream_id,
        .request_rejected => |e| e.stream_id,
        .ignored_unknown_frame => |e| e.stream_id,
        .flow_blocked => |e| e.stream_id,
        .webtransport_stream_opened => |e| e.stream_id,
        .webtransport_stream_data => |e| e.stream_id,
        .webtransport_stream_finished => |e| e.stream_id,
        .webtransport_stream_reset => |e| e.stream_id,
        .webtransport_flow_violated => |e| e.stream_id,
        .webtransport_session_established => |e| e.session_id,
        .webtransport_session_closed => |e| e.session_id,
        .webtransport_session_draining => |e| e.session_id,
        .webtransport_peer_blocked => |e| e.session_id,
        .webtransport_credit_granted => |e| e.session_id,
        .webtransport_unknown_capsule => |e| e.session_id,
        else => null,
    };
}

fn eventOwnedPayloadBytes(event: Event) usize {
    return switch (event) {
        .headers => |field_event| fieldsOwnedBytes(field_event.fields),
        .trailers => |field_event| fieldsOwnedBytes(field_event.fields),
        .data => |data| data.data.len,
        .datagram => |datagram| datagram.payload.len,
        .push_promise => |promise| promise.field_section.len + fieldsOwnedBytes(promise.fields),
        .priority_update => |update| update.priority_field_value.len,
        .connection_closed => |closed| closed.reason.len,
        .webtransport_stream_data => |data| data.data.len,
        .webtransport_session_closed => |closed| closed.reason.len,
        .webtransport_unknown_capsule => |unknown| unknown.value.len,
        else => 0,
    };
}

fn messageFrameEventOwnedPayloadBytes(frame: frame_mod.Frame) ?usize {
    return switch (frame) {
        .data => |bytes| bytes.len,
        .push_promise => |promise| promise.field_section.len,
        .unknown => 0,
        else => null,
    };
}

fn fieldsOwnedBytes(fields: []const qpack.FieldLine) usize {
    var total = @sizeOf(qpack.FieldLine) * fields.len;
    for (fields) |field| total += field.name.len + field.value.len;
    return total;
}

fn fieldSectionsEqual(a: []const qpack.FieldLine, b: []const qpack.FieldLine) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!std.mem.eql(u8, left.name, right.name)) return false;
        if (!std.mem.eql(u8, left.value, right.value)) return false;
    }
    return true;
}

fn contextPayloadEncodedLenChecked(context_id: u64, payload_len: usize) Error!usize {
    const context_len = try varintEncodedLenChecked(context_id);
    return std.math.add(usize, context_len, payload_len) catch Error.ValueTooLarge;
}

/// Encodes a single-varint WebTransport flow-control capsule (e.g.
/// `WT_MAX_DATA`, `WT_DATA_BLOCKED`, `WT_MAX_STREAMS_BIDI`, …) directly
/// into `dst`. Equivalent to `webtransport.encodeMaxData` / friends but
/// returns `Error` (the session's narrower error set) instead of the
/// wider `webtransport.Error`, so the call sites here don't have to
/// thread a wider error union through every public method.
fn encodeFlowControlCapsule(dst: []u8, capsule_type: u64, value: u64) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], capsule_type);
    const value_len = varint.encodedLen(value);
    pos += try varint.encode(dst[pos..], @as(u64, @intCast(value_len)));
    pos += try varint.encode(dst[pos..], value);
    return pos;
}

fn capsuleEncodedLenChecked(capsule_type: u64, value_len: usize) Error!usize {
    const type_len = try varintEncodedLenChecked(capsule_type);
    const value_len_u64 = std.math.cast(u64, value_len) orelse return Error.ValueTooLarge;
    const length_len = try varintEncodedLenChecked(value_len_u64);
    const prefix_len = std.math.add(usize, type_len, length_len) catch return Error.ValueTooLarge;
    return std.math.add(usize, prefix_len, value_len) catch Error.ValueTooLarge;
}

fn varintEncodedLenChecked(value: u64) Error!usize {
    const len = varint.encodedLen(value);
    if (len == 0) return Error.ValueTooLarge;
    return len;
}

fn validateClientBidiStreamId(id: u64) Error!void {
    if (stream_mod.isUnidirectional(id) or !stream_mod.isClientInitiated(id)) {
        return Error.InvalidGoawayId;
    }
}

fn validatePriorityRequestStreamId(id: u64) Error!void {
    if (stream_mod.isUnidirectional(id) or !stream_mod.isClientInitiated(id)) {
        return Error.InvalidPriorityTarget;
    }
}

fn compactRx(state: *StreamState, consumed: usize) Error!void {
    if (consumed == 0) return;
    if (consumed > state.rx.items.len) return Error.InvalidFramePayload;
    const remaining = state.rx.items.len - consumed;
    std.mem.copyForwards(u8, state.rx.items[0..remaining], state.rx.items[consumed..]);
    state.rx.shrinkRetainingCapacity(remaining);
}

fn qpackEncoderInstructionsMaxLen(
    fields: []const qpack.FieldLine,
    huffman: bool,
    table_entry_count: usize,
) usize {
    var n: usize = 0;
    const string_options: qpack.StringOptions = .{ .huffman = huffman };
    // A Duplicate instruction is a 5-bit-prefix integer holding an
    // encoder-relative index, which is always < the current entry count.
    const duplicate_max_len = qpack.integer.encodedLen(5, table_entry_count);
    for (fields) |field| {
        const literal_len = qpack.stringLiteralEncodedLen(5, field.name, string_options) +
            qpack.stringLiteralEncodedLen(7, field.value, string_options);
        n += @max(literal_len, duplicate_max_len);
    }
    return n;
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
    var client_quic: quic.Connection = undefined;

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

    var budget = session.drainBudget();
    try session.processMessageState(state, &events, &budget);
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

test "session event batch helpers release payloads and clear lists" {
    const allocator = std.testing.allocator;
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(allocator);

    try events.append(allocator, .{
        .data = .{
            .stream_id = 0,
            .kind = .response,
            .data = try allocator.dupe(u8, "owned body"),
        },
    });
    try events.append(allocator, .{ .goaway = 4 });

    clearEvents(allocator, &events);
    try std.testing.expectEqual(@as(usize, 0), events.items.len);

    try events.append(allocator, .{
        .data = .{
            .stream_id = 4,
            .kind = .response,
            .data = try allocator.dupe(u8, "owned again"),
        },
    });
    deinitEvents(allocator, events.items);
    events.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0), events.items.len);
}

const TraceRecorder = struct {
    events: [16]observability_mod.TraceEvent = undefined,
    count: usize = 0,

    fn callback(user_data: ?*anyopaque, event: observability_mod.TraceEvent) void {
        const self: *TraceRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count < self.events.len) {
            self.events[self.count] = event;
            self.count += 1;
        }
    }

    fn contains(self: *const TraceRecorder, name: observability_mod.TraceEventName) bool {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return true;
        }
        return false;
    }
};

test "session observability hooks record emitted events and metrics" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;
    var recorder: TraceRecorder = .{};

    var session = Session.init(allocator, .client, &client_quic, .{
        .observability = .{
            .callback = TraceRecorder.callback,
            .user_data = &recorder,
        },
    });
    defer session.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = ":status", .value = "200" },
    };

    const state = try session.ensureMessageState(0, .response, .request);
    var enc = message_mod.Encoder.init(.response, .{});
    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &fields);
    pos += try enc.encodeData(buf[pos..], "hello");
    try state.rx.appendSlice(allocator, buf[0..pos]);

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    var budget = session.drainBudget();
    try session.processMessageState(state, &events, &budget);

    const snapshot = session.metrics();
    try std.testing.expectEqual(@as(u64, 2), snapshot.frames_received);
    try std.testing.expectEqual(@as(u64, 1), snapshot.headers_received);
    try std.testing.expectEqual(@as(u64, 1), snapshot.data_frames_received);
    try std.testing.expectEqual(@as(u64, 5), snapshot.data_bytes_received);
    try std.testing.expect(recorder.contains(.headers_received));
    try std.testing.expect(recorder.contains(.data_received));
}

test "session event budget resumes pending trailers" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{
        .max_events_per_drain = 1,
    });
    defer session.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    const trailers = [_]qpack.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    const state = try session.ensureMessageState(0, .response, .request);
    var enc = message_mod.Encoder.init(.response, .{});
    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &fields);
    pos += try enc.encodeTrailers(buf[pos..], &trailers);
    try state.rx.appendSlice(allocator, buf[0..pos]);

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    var first_budget = session.drainBudget();
    try std.testing.expectError(
        Error.EventQueueFull,
        session.processMessageState(state, &events, &first_budget),
    );
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    switch (events.items[0]) {
        .headers => |event| try std.testing.expectEqualStrings("200", event.fields[0].value),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expect(state.rx.items.len > 0);

    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();

    var second_budget = session.drainBudget();
    try session.processMessageState(state, &events, &second_budget);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    switch (events.items[0]) {
        .trailers => |event| try std.testing.expectEqualStrings("ok", event.fields[0].value),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(usize, 0), state.rx.items.len);
}

test "session DATAGRAM capsule path gates on peer h3_datagram (RFC 9297 §3.4)" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;

    // Peer hasn't sent SETTINGS yet — every datagram-capsule entry point
    // must surface MissingSettings rather than emit a stream-bound capsule
    // the peer can't interpret.
    {
        var session = Session.init(allocator, .client, &client_quic, .{});
        defer session.deinit();
        _ = try session.ensureMessageState(0, .response, .request);

        try std.testing.expectError(Error.MissingSettings, session.sendRequestDatagramCapsule(0, "x"));
        try std.testing.expectError(Error.MissingSettings, session.sendRequestDatagramContextCapsule(0, 0, "x"));
    }

    // Peer SETTINGS arrived but `h3_datagram=0` — we must refuse to send.
    {
        var session = Session.init(allocator, .client, &client_quic, .{});
        defer session.deinit();
        session.peer_settings = .{ .h3_datagram = false };
        _ = try session.ensureMessageState(0, .response, .request);

        try std.testing.expectError(Error.DatagramNotEnabled, session.sendRequestDatagramCapsule(0, "x"));
        try std.testing.expectError(Error.DatagramNotEnabled, session.sendRequestDatagramContextCapsule(0, 0, "x"));
    }

    // Server-side parity: `sendResponseDatagramCapsule` /
    // `sendResponseDatagramContextCapsule` enforce the same gate.
    {
        var server_quic: quic.Connection = undefined;
        var session = Session.init(allocator, .server, &server_quic, .{});
        defer session.deinit();
        _ = try session.ensureMessageState(0, .request, .response);

        try std.testing.expectError(Error.MissingSettings, session.sendResponseDatagramCapsule(0, "x"));
        try std.testing.expectError(Error.MissingSettings, session.sendResponseDatagramContextCapsule(0, 0, "x"));

        session.peer_settings = .{ .h3_datagram = false };
        try std.testing.expectError(Error.DatagramNotEnabled, session.sendResponseDatagramCapsule(0, "x"));
        try std.testing.expectError(Error.DatagramNotEnabled, session.sendResponseDatagramContextCapsule(0, 0, "x"));
    }
}

test "session caps outgoing capsule values before allocation" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{
        .max_capsule_value_size = 1,
    });
    defer session.deinit();

    // The DATAGRAM-capsule path (RFC 9297 §3.4) requires the peer to have
    // advertised `SETTINGS_H3_DATAGRAM = 1`. Inject a peer-settings record
    // so this size-cap test reaches the `CapsuleTooLarge` check rather than
    // bouncing on `MissingSettings`.
    session.peer_settings = .{ .h3_datagram = true };

    _ = try session.ensureMessageState(0, .response, .request);

    try std.testing.expectError(
        Error.CapsuleTooLarge,
        session.sendRequestCapsule(0, capsule_mod.Type.datagram, "xx"),
    );
    try std.testing.expectError(
        Error.CapsuleTooLarge,
        session.sendRequestDatagramContextCapsule(0, 0, "x"),
    );
}

test "production config applies bounded defaults and feature opt-ins" {
    const config = Config.production(.{});
    try std.testing.expectEqual(@as(u64, 4096), config.settings.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 16), config.settings.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), config.settings.max_field_section_size);
    try std.testing.expect(!config.settings.enable_connect_protocol);
    try std.testing.expect(!config.settings.h3_datagram);
    try std.testing.expectEqual(@as(?usize, 128), config.max_field_lines);
    try std.testing.expectEqual(@as(?usize, 128 * 1024), config.max_decoded_field_section_bytes);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), config.max_field_section_size);
    try std.testing.expectEqual(@as(usize, 16 * 1024), config.max_data_frame_payload);
    try std.testing.expectEqual(@as(usize, 16 * 1024), config.max_datagram_payload_size);
    try std.testing.expectEqual(@as(?usize, 64 * 1024), config.max_capsule_value_size);
    try std.testing.expectEqual(@as(?usize, 1 * 1024 * 1024), config.max_stream_send_buffered);
    try std.testing.expectEqual(@as(?usize, 64 * 1024), config.wt_max_buffered_bytes_per_stream);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), config.wt_max_total_buffered_bytes);
    try std.testing.expectEqual(@as(?usize, 1 * 1024 * 1024), config.max_event_payload_size);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), config.max_event_payload_bytes_per_drain);
    try std.testing.expectEqual(@as(?usize, 512), config.max_events_per_drain);

    const datagram_config = Config.production(.{
        .enable_connect_protocol = true,
        .enable_datagram = true,
        .max_push_id = 4,
        .push_policy = .cancel_promises,
    });
    try std.testing.expect(datagram_config.settings.enable_connect_protocol);
    try std.testing.expect(datagram_config.settings.h3_datagram);
    try std.testing.expectEqual(@as(?u64, 4), datagram_config.max_push_id);
    try std.testing.expectEqual(PushPolicy.cancel_promises, datagram_config.push_policy);
}

test "session validates GOAWAY stream ids by role" {
    var conn: quic.Connection = undefined;
    var server_session = Session.init(std.testing.allocator, .server, &conn, .{});
    try server_session.validateLocalGoawayId(0);
    try server_session.validateLocalGoawayId(4);
    try std.testing.expectError(Error.InvalidGoawayId, server_session.validateLocalGoawayId(1));
    try std.testing.expectError(Error.InvalidGoawayId, server_session.validateLocalGoawayId(2));

    var client_session = Session.init(std.testing.allocator, .client, &conn, .{});
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

test "session derives the graceful GOAWAY id from observed peer streams" {
    const allocator = std.testing.allocator;
    var conn: quic.Connection = undefined;
    conn.last_activity_us = 0;

    var server_session = Session.init(allocator, .server, &conn, .{});
    defer server_session.deinit();

    // No request stream observed yet: RFC 9114 §5.2's "no requests were
    // processed" form — GOAWAY rejects ids >= the value, so 0 covers all.
    try std.testing.expectEqual(@as(?u64, null), server_session.highestPeerRequestStreamId());
    try std.testing.expectEqual(@as(u64, 0), server_session.gracefulGoawayId());

    // Streams can be observed out of order; the bound is the maximum.
    _ = try server_session.ensureIncomingState(0);
    _ = try server_session.ensureIncomingState(8);
    _ = try server_session.ensureIncomingState(4);
    try std.testing.expectEqual(@as(?u64, 8), server_session.highestPeerRequestStreamId());
    try std.testing.expectEqual(@as(u64, 12), server_session.gracefulGoawayId());

    // Peer uni streams and re-observation leave the bound alone.
    _ = try server_session.ensureIncomingState(2);
    _ = try server_session.ensureIncomingState(8);
    try std.testing.expectEqual(@as(?u64, 8), server_session.highestPeerRequestStreamId());

    // Streams observed after a GOAWAY was sent are auto-rejected, not
    // processed — the graceful id clamps to what was already advertised
    // (§5.2 forbids raising it).
    server_session.sent_goaway_id = 4;
    _ = try server_session.ensureIncomingState(16);
    try std.testing.expectEqual(@as(?u64, 16), server_session.highestPeerRequestStreamId());
    try std.testing.expectEqual(@as(u64, 4), server_session.gracefulGoawayId());

    // Client role: the id space is push ids (§5.2 ¶1), the increment 1.
    var client_session = Session.init(allocator, .client, &conn, .{ .max_push_id = 8 });
    defer client_session.deinit();
    try std.testing.expectEqual(@as(?u64, null), client_session.highestPeerRequestStreamId());
    try std.testing.expectEqual(@as(u64, 0), client_session.gracefulGoawayId());
    try client_session.validateReceivedPushId(3);
    try std.testing.expectEqual(@as(u64, 4), client_session.gracefulGoawayId());
}

test "session counts open request streams and stamps last-event activity" {
    const allocator = std.testing.allocator;
    var conn: quic.Connection = undefined;
    conn.last_activity_us = 111;

    var session = Session.init(allocator, .server, &conn, .{});
    defer session.deinit();

    try std.testing.expectEqual(@as(usize, 0), session.openRequestStreamCount());

    // An unclassified peer bidi stream counts — it may become a request —
    // and the creation stamp seeds its deadline clock.
    const pending = try session.ensureIncomingState(0);
    try std.testing.expectEqual(@as(usize, 1), session.openRequestStreamCount());
    try std.testing.expectEqual(@as(u64, 111), pending.last_event_us);

    // Emitting an event through the single choke point refreshes the stamp.
    conn.last_activity_us = 222;
    const state = try session.ensureMessageState(4, .request, .response);
    state.bidi_kind = .request;
    var events: std.ArrayList(Event) = .empty;
    defer {
        session.clearEvents(&events);
        events.deinit(allocator);
    }
    conn.last_activity_us = 333;
    try session.appendReservedEvent(&events, .{
        .stream_finished = .{ .stream_id = 4, .kind = .request },
    });
    // Only the event's own stream is restamped; stream 0 keeps its
    // creation-time stamp.
    try std.testing.expectEqual(@as(u64, 111), pending.last_event_us);
    try std.testing.expectEqual(@as(u64, 333), state.last_event_us);

    // Peer uni, WT-classified bidi, locally-rejected, and fully-closed
    // streams are all excluded from the open-request view.
    _ = try session.ensureIncomingState(2);
    const wt = try session.ensureIncomingState(8);
    wt.bidi_kind = .webtransport;
    const rejected = try session.ensureIncomingState(12);
    rejected.locally_rejected = true;
    const closed = try session.ensureIncomingState(16);
    closed.bidi_kind = .request;
    closed.recv_finished = true;
    closed.locally_finished = true;
    try std.testing.expectEqual(@as(usize, 2), session.openRequestStreamCount());

    var seen_pending = false;
    var seen_request = false;
    var rows: usize = 0;
    var it = session.openRequestStreams();
    while (it.next()) |open| : (rows += 1) {
        switch (open.stream_id) {
            0 => {
                seen_pending = true;
                try std.testing.expectEqual(@as(u64, 111), open.last_event_us);
            },
            4 => {
                seen_request = true;
                try std.testing.expectEqual(@as(u64, 333), open.last_event_us);
            },
            else => return error.TestExpectedEqual,
        }
    }
    try std.testing.expectEqual(@as(usize, 2), rows);
    try std.testing.expect(seen_pending);
    try std.testing.expect(seen_request);
}

test "session emits stream reset once" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{});
    defer session.deinit();

    const state = try session.ensureMessageState(0, .response, .request);

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    var budget = session.drainBudget();
    try session.observeReset(state, protocol.ErrorCode.request_cancelled, 42, &events, &budget);
    try session.observeReset(state, protocol.ErrorCode.request_cancelled, 42, &events, &budget);

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

test "session clears blocked QPACK state when a stream resets" {
    const allocator = std.testing.allocator;
    var client_quic: quic.Connection = undefined;

    var session = Session.init(allocator, .client, &client_quic, .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 1,
        },
    });
    defer session.deinit();

    const state = try session.ensureMessageState(0, .response, .request);
    try std.testing.expectEqual(
        qpack.state.FieldSectionStatus.blocked,
        try session.qpack_decoder_state.beginFieldSection(0, 1),
    );
    try std.testing.expect(session.qpack_decoder_state.isStreamBlocked(0));

    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    var budget = session.drainBudget();
    try session.observeReset(state, protocol.ErrorCode.request_cancelled, 0, &events, &budget);

    try std.testing.expect(!session.qpack_decoder_state.isStreamBlocked(0));
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    switch (events.items[0]) {
        .stream_reset => |event| {
            try std.testing.expectEqual(@as(u64, 0), event.stream_id);
            try std.testing.expectEqual(protocol.ErrorCode.request_cancelled, event.error_code);
        },
        else => return error.TestExpectedEqual,
    }
}

test "remembered peer settings feed the datagram gates until real SETTINGS arrive" {
    const allocator = std.testing.allocator;
    var conn: quic.Connection = undefined;

    // Role gate: remembered settings are a client concept.
    {
        var session = Session.init(allocator, .server, &conn, .{});
        defer session.deinit();
        try std.testing.expectError(Error.InvalidRole, session.rememberPeerSettings(.{}));
    }

    // Remembered settings are the effective peer settings pre-SETTINGS;
    // the real frame shadows them on arrival, and late installs refuse.
    {
        var session = Session.init(allocator, .client, &conn, .{});
        defer session.deinit();
        try session.rememberPeerSettings(.{ .h3_datagram = true });
        try std.testing.expect(session.effectivePeerSettings().?.h3_datagram);
        session.peer_settings = .{ .h3_datagram = false };
        try std.testing.expect(!session.effectivePeerSettings().?.h3_datagram);
        try std.testing.expectError(
            Error.RememberedSettingsTooLate,
            session.rememberPeerSettings(.{}),
        );
    }

    // A remembered h3_datagram=0 refuses the capsule path exactly like
    // the real-settings gate (RFC 9297 §2.1.1).
    {
        var session = Session.init(allocator, .client, &conn, .{});
        defer session.deinit();
        try session.rememberPeerSettings(.{ .h3_datagram = false });
        _ = try session.ensureMessageState(0, .response, .request);
        try std.testing.expectError(Error.DatagramNotEnabled, session.sendRequestDatagramCapsule(0, "x"));
    }

    // v1 replay safety: extended CONNECT stays gated on REAL SETTINGS —
    // remembered enable_connect_protocol does not unlock it, so a request
    // staged in 0-RTT can never carry a CONNECT the post-rejection server
    // might not accept (quic replays verbatim; see rememberPeerSettings).
    {
        var session = Session.init(allocator, .client, &conn, .{});
        defer session.deinit();
        try session.rememberPeerSettings(.{ .enable_connect_protocol = true });
        const fields = [_]qpack.FieldLine{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "connect-udp" },
        };
        try std.testing.expectError(
            Error.MissingSettings,
            session.ensureExtendedConnectAllowed(&fields),
        );
    }
}
