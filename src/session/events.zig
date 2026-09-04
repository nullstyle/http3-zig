//! The session event model: the `Event` tagged union `drain` yields,
//! every event payload type, and the batch helpers. Split from
//! session.zig (pure move); `session.Event` etc. remain the public
//! paths via re-export aliases. Ownership contract: events own deep
//! copies of their payloads; `Event.deinit` / `deinitEvents` /
//! `clearEvents` release them.

const std = @import("std");
const quic = @import("quic");
const errors_mod = @import("../errors.zig");
const qpack = @import("../qpack/root.zig");
const webtransport_mod = @import("../webtransport.zig");
const message_mod = @import("../message.zig");
const settings_mod = @import("../settings.zig");
const priority_mod = @import("../priority.zig");

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
/// `Session.openRequestStreams`. A SNAPSHOT taken at construction
/// time: iteration never touches the live stream table, so
/// interleaving `drain` / `openRequest` cannot invalidate it (the
/// named streams may close mid-iteration; callers already tolerate
/// that). Up to `capacity` streams are captured; beyond that
/// `truncated` is set and the surplus remains for the next call —
/// deadline sweeps converge over successive drains.
pub const OpenRequestStreamIterator = struct {
    pub const capacity = 128;

    streams: [capacity]OpenRequestStream = undefined,
    len: usize = 0,
    pos: usize = 0,
    /// True when more open request streams existed than `capacity`
    /// could capture — call `openRequestStreams` again after acting
    /// on this batch.
    truncated: bool = false,

    pub fn next(self: *OpenRequestStreamIterator) ?OpenRequestStream {
        if (self.pos >= self.len) return null;
        defer self.pos += 1;
        return self.streams[self.pos];
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
            .headers => |event| qpack.freeFieldSection(allocator, event.fields),
            .interim_headers => |event| qpack.freeFieldSection(allocator, event.fields),
            .trailers => |event| qpack.freeFieldSection(allocator, event.fields),
            .data => |event| allocator.free(event.data),
            .datagram => |event| allocator.free(event.payload),
            .push_promise => |event| {
                allocator.free(event.field_section);
                qpack.freeFieldSection(allocator, event.fields);
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
