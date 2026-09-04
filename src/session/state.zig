//! Per-stream and per-WebTransport-session state, plus the drain
//! budget. Split from session.zig (pure move); `WTSessionFlowSnapshot`
//! remains public via a re-export alias, the rest stays internal to the
//! session engine.

const std = @import("std");
const quic = @import("quic");
const message_mod = @import("../message.zig");
const stream_mod = @import("../stream.zig");
const capsule_mod = @import("../capsule.zig");
const webtransport_mod = @import("../webtransport.zig");

const WebTransportStreamKind = webtransport_mod.StreamKind;

pub const BidiKind = enum {
    /// HTTP/3 request/response stream (the normal case).
    request,
    /// WebTransport bidirectional stream
    /// (draft-ietf-webtrans-http3 §4.2). The first varint on the wire is
    /// the WebTransport bidi-stream marker `0x41`, followed by the Session
    /// ID varint, followed by raw application bytes.
    webtransport,
};

pub const StreamState = struct {
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

    pub fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.rx.deinit(allocator);
    }

    /// True when no further events will surface for this stream — the
    /// receive side is closed (FIN observed or RESET seen) AND the
    /// local send side is closed (or the stream is unidirectional with
    /// only one applicable direction). Used by `Session.gcClosedStreams`.
    pub fn isFullyClosed(self: *const StreamState) bool {
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
    pub fn webTransportKind(self: *const StreamState) ?WebTransportStreamKind {
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

pub const DrainBudget = struct {
    max_payload_size: ?usize,
    max_payload_bytes: ?usize,
    max_events: ?usize,
    payload_bytes: usize = 0,
    events: usize = 0,

    /// Local error set (both are members of the session's `Error`); the
    /// session engine's `try` call sites coerce into its wider set.
    const BudgetError = error{ EventQueueFull, EventPayloadTooLarge };

    pub fn reserve(self: *DrainBudget, owned_payload_bytes: usize) BudgetError!void {
        if (self.max_events) |max| {
            if (self.events >= max) return error.EventQueueFull;
        }
        if (self.max_payload_size) |max| {
            if (owned_payload_bytes > max) return error.EventPayloadTooLarge;
        }
        if (self.max_payload_bytes) |max| {
            if (owned_payload_bytes > max or self.payload_bytes > max - owned_payload_bytes) {
                return error.EventQueueFull;
            }
        }
        self.events += 1;
        self.payload_bytes += owned_payload_bytes;
    }
};

/// An owned HTTP/3 DATAGRAM popped from the transport but not yet
/// emitted as an event (see `Session.pending_datagram`).
pub const PendingDatagram = struct {
    stream_id: u64,
    payload: []u8,
    arrived_in_early_data: bool,
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
pub const WTSessionState = struct {
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

    pub fn deinit(self: *WTSessionState, allocator: std.mem.Allocator) void {
        self.reassembler.deinit(allocator);
    }
};

pub const WTSessionFlowState = struct {
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
