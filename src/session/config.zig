//! Session configuration: the `Config` surface, its production
//! preset, and the policy enums. Split from session.zig (pure move);
//! `session.Config` / `session.BufferedStreamPolicy` etc. remain the
//! public paths via re-export aliases.

const std = @import("std");
const quic = @import("quic");
const qpack = @import("../qpack/root.zig");
const observability_mod = @import("../observability.zig");
const settings_mod = @import("../settings.zig");
const webtransport_mod = @import("../webtransport.zig");
const earlydata = @import("../earlydata.zig");

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
