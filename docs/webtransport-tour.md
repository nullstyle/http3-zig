# WebTransport Tour

A walkthrough of `http3-zig`'s WebTransport-over-HTTP/3 surface for application
authors. The library tracks
[`draft-ietf-webtrans-http3`](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/16/)
(revision -16), pinned in [`README.md`](../README.md). The CONNECT request
sends `:protocol = webtransport-h3` (draft-16 §3.2); the browser-era legacy
token `webtransport` is accepted on receive. Datagrams use RFC 9297 HTTP/3
Datagrams; capsules use the RFC 9297 Capsule Protocol — and the session
consumes the CONNECT stream's capsule protocol natively, surfacing typed
`webtransport_*` events instead of raw body bytes.

This tour assumes you already know what WebTransport is conceptually
(Extended CONNECT, datagrams, peer-initiated streams) and want to wire up a
client + server today. For deeper transport background see
[`quic-zig`](https://github.com/nullstyle/quic-zig). For the broader HTTP/3
session model see [`README.md` § Design Shape](../README.md#design-shape) and
the doc comment at the top of [`src/root.zig`](../src/root.zig).

---

## Quickstart

A complete in-process loopback ships at
[`examples/loopback_wt.zig`](../examples/loopback_wt.zig); the snippets below
distill its public-API moves.

### Client side

```zig
const std = @import("std");
const http3_zig = @import("http3_zig");

// Settings MUST advertise WebTransport, HTTP/3 Datagrams, and Extended CONNECT
// (draft-16 §9.2). All three are required on both peers.
const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

var client_h3 = http3_zig.Session.init(
    allocator, .client, &client_quic, .{ .settings = wt_settings },
);
defer client_h3.deinit();
try client_h3.start();

// ... pump until both sides have seen each other's SETTINGS ...

var client = http3_zig.Client.init(&client_h3);
var client_wt = try client.startWebTransport(allocator, .{
    .authority = "localhost",
    .path = "/wt",
});
// `client_wt` is now in the "pending" state. It becomes "established"
// when the 2xx response on the CONNECT stream arrives — the drain that
// observes it emits a `webtransport_session_established` event (and
// `ResponseReader.webTransportAccepted()` reports it on the response).
```

### Server side

```zig
var server_h3 = http3_zig.Session.init(
    allocator, .server, &server_quic, .{ .settings = wt_settings },
);
defer server_h3.deinit();
try server_h3.start();

var server = http3_zig.Server.init(&server_h3);

// In your event loop, when a `request_updated` / `request_complete`
// observation arrives:
const request = request_state.reader();
if (request.isWebTransport()) {
    var accepted = try server.acceptWebTransport(allocator, request, .{});
    // `accepted` is now established server-side. Send datagrams,
    // open WT streams, observe peer-opened streams via
    // `webtransport_stream_opened` events.
}
```

The full pump loop, certificate setup, and `TransportLoopback` glue live in
[`examples/loopback_wt.zig`](../examples/loopback_wt.zig). For a real network
peer the loop is the same; only the packet driver changes.

---

## Establishing a session

### Settings exchange

`startWebTransport` and `acceptWebTransport` both gate on the peer's SETTINGS
having arrived AND advertising all three of `SETTINGS_WT_ENABLED`,
`SETTINGS_H3_DATAGRAM`, and `SETTINGS_ENABLE_CONNECT_PROTOCOL`. The library
enforces this eagerly so the application never commits to a session the peer
can't drive:

```zig
// From tests/integration/webtransport.zig
try std.testing.expectError(
    error.PeerSettingsNotReceived,
    h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    }),
);
```

If the peer's SETTINGS lack any of the three required keys, the call returns
`error.PeerDidNotEnableWebTransport` instead. Pump the session loop until
`Session.peer_settings != null`, then check `webtransport.peerEnabled(...)` if
you want to surface a friendlier error before calling the helper.

### Client: `startWebTransport`

```zig
pub fn startWebTransport(
    self: *Client,
    allocator: std.mem.Allocator,
    options: WebTransportConnectOptions,
) (session.Error || webtransport.Error)!WebTransportClientStream;
```

`WebTransportConnectOptions` mirrors the WebTransport CONNECT request:

```zig
pub const ConnectOptions = struct {
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    headers: []const qpack.FieldLine = &.{},
    /// Comma-separated list of WebTransport subprotocols (draft §3.4).
    /// Tokens follow the HTTP token grammar — validated automatically.
    subprotocols: []const []const u8 = &.{},
};
```

After `startWebTransport` returns, the CONNECT request is on the wire and the
session is registered as **pending** in `Session`. Pending sessions are
flow-controlled from the moment they exist: per-session flow state is created
at pending time, seeded from the peer's `SETTINGS_WT_INITIAL_MAX_*` credit
(see [Flow control](#flow-control)), so opens and sends before the 2xx count
against the same limits as afterwards.

The session transitions to **established** when the client observes a 2xx
response on the CONNECT stream. The drain that observes it emits
`webtransport_session_established` — guaranteed to precede any replayed
`webtransport_stream_*` events for streams that were buffered against the
session — and `ResponseReader.webTransportAccepted()` reports it on the
response:

```zig
.webtransport_session_established => |established| {
    // established.session_id == the CONNECT stream id.
    // Now safe to open WT streams and send datagrams.
},
```

### Subprotocol negotiation

Pass `subprotocols` on the client side; the request gains a
`wt-available-protocols` header. The server reads it via
`RequestReader.webTransportSubprotocols(allocator)`, picks one, and passes it
in `AcceptOptions.subprotocol`. The library validates that the chosen token
was actually offered (returns `error.SubprotocolNotOffered` otherwise):

```zig
const offered = [_][]const u8{ "echo-v1", "echo-v2", "telemetry-v3" };
var client_wt = try h3_client.startWebTransport(allocator, .{
    .authority = "localhost",
    .path = "/wt",
    .subprotocols = &offered,
});

// On the server:
var parsed = try request.webTransportSubprotocols(allocator);
defer parsed.deinit(allocator);
// parsed.tokens is &[_][]const u8{ "echo-v1", "echo-v2", "telemetry-v3" }.
server_wt = try h3_server.acceptWebTransport(allocator, request, .{
    .subprotocol = "echo-v2",
});

// Back on the client:
const selected = response.webTransportSubprotocol() orelse
    return error.MissingSubprotocol;
// selected == "echo-v2"
```

### Server: `acceptWebTransport`

```zig
pub fn acceptWebTransport(
    self: *Server,
    allocator: std.mem.Allocator,
    request: RequestReader,
    options: WebTransportAcceptOptions,
) (session.Error || webtransport.Error)!WebTransportServerStream;
```

The helper checks `request.isWebTransport()` (returns `error.NotWebTransport`
if the CONNECT didn't carry `:protocol = webtransport-h3` — or the legacy
`webtransport` token, which browsers still send), then sends the response and
confirms the session in the underlying `Session`. Status codes outside `2xx`
are rejected with `error.InvalidAcceptStatus`.

To refuse a pending session with a wire-visible signal instead of accepting
it, use `Server.rejectWebTransport`:

```zig
try server.rejectWebTransport(request, .alpn_failed);          // WT_ALPN_ERROR
try server.rejectWebTransport(request, .requirements_not_met); // WT_REQUIREMENTS_NOT_MET
try server.rejectWebTransport(request, .{ .wire_code = code });
```

It aborts the CONNECT stream in both directions with the mapped `WT_*` code
(draft §9.5) and clears the pending registry state; the peer observes a
`webtransport_session_closed` event with `how == .reset` carrying the code.
`acceptWebTransport`'s validation errors (like `SubprotocolNotOffered`)
deliberately do NOT auto-reject — the application chooses the signal.

`WebTransportAcceptOptions`:

```zig
pub const AcceptOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    subprotocol: ?[]const u8 = null,
};
```

After `acceptWebTransport` returns, peer-opened streams that arrived earlier
referencing this Session ID are dispatched (or replayed if held under the
`.buffer` policy — see [Streams](#streams) below).

---

## Streams

WebTransport streams are layered over QUIC streams with a small framing
prefix the library writes for you. Two flavors:

| Kind | QUIC parity | Wire prefix |
|---|---|---|
| `.uni` | unidirectional | type `0x54` + Session ID varint |
| `.bidi` | bidirectional | frame type `0x41` + Session ID varint |

Both peers can open both kinds. Server-initiated bidi streams are normally
forbidden in HTTP/3 — WebTransport carves them out (draft §4.2).

### Opening locally

`openUniStream` / `openBidiStream` return a typed `WebTransportStream`
handle — a plain copyable value carrying `{ session, session_id, stream_id,
kind }` — and the substream verbs live on it:

```zig
// From the WebTransportClientStream / WebTransportServerStream:
const uni = try wt.openUniStream();
try uni.write("hello");
try uni.finish();

const bidi = try wt.openBidiStream();
try bidi.write("ping");
// ... peer can write back; observe via webtransport_stream_data ...
try bidi.finish();

// Reset with a 32-bit application error code (mapped to the HTTP/3 wire
// code per draft §4.6):
try uni.reset(0xabad1dea);
// Or bypass the mapping with a raw wire code:
try uni.resetWithCode(0x52e4a40fa8db);
```

The handle's `stream_id` field is public so you can correlate it with the
`webtransport_stream_*` events, and the handle needs no deinit — store it in
application maps freely. Every verb delegates to the raw-u64 `Session`
primitives (`Session.writeWebTransportStream`,
`Session.finishWebTransportStream`, …), which stay public as an escape
hatch for code that only holds a bare stream id.

### Observing peer-opened streams

Peer-opened WebTransport streams surface as four event variants on
`session.Event`. They are also classified by the high-level `Client` /
`Server` facades (`ResponseEvent.webtransport_stream_*` / `RequestEvent.*`),
but the raw `session.Event` shapes are usually easiest in a runner-driven
loop:

```zig
.webtransport_stream_opened => |opened| {
    // opened: { stream_id, session_id, kind }; kind ∈ { .uni, .bidi }
    // Adopt the peer-opened stream as a typed handle; the same verbs
    // (write / finish / reset / resetWithCode) now target it:
    const handle = wt.streamHandle(opened.stream_id, opened.kind);
    if (opened.kind == .bidi) try handle.write("pong");
},
.webtransport_stream_data => |data| {
    // data: { stream_id, session_id, kind, data: []u8 }
    // `data.data` is owned by the caller after drain — release it with
    // session.clearEvents(&events) or http3_zig.clearEvents(...).
    try buf.appendSlice(allocator, data.data);
},
.webtransport_stream_finished => |finished| {
    // finished: { stream_id, session_id, kind }
    // Peer FIN'd the stream cleanly.
},
.webtransport_stream_reset => |reset| {
    // reset: { stream_id, session_id, kind, error_code, application_error_code, final_size }
    // .error_code is the raw QUIC wire code.
    // .application_error_code is the recovered 32-bit WT app code,
    //   null if the wire code lands on a reserved stride.
    // .final_size is the QUIC final-size at reset time.
},
```

`streamHandle(stream_id, kind)` works for any substream of the session —
peer-opened ids straight out of `webtransport_stream_opened` event data, or
raw ids you stored earlier. It is unchecked: the caller vouches that the id
actually belongs to this WebTransport session.

### Buffered-stream policy

A peer can open a WebTransport stream **before** the session has been
confirmed — for example, the client opens a uni stream the same packet round
as the CONNECT request, before the server has called `acceptWebTransport`.
The session needs a policy for those bytes; pick one via
`SessionConfig.buffered_stream_policy`:

| Policy | Behavior |
|---|---|
| `.pass_through` | (default) Surface the stream events even before the session is confirmed. The application is responsible for correlating. |
| `.reject` | Reset the stream with the reserved `WEBTRANSPORT_BUFFERED_STREAM_REJECTED` (`0x3994bd84`) wire code. No stream events fire for the held bytes. |
| `.buffer` | Hold the bytes (capped per stream by `wt_max_buffered_bytes_per_stream`, default 64 KiB in `production()`, and across the session by `wt_max_total_buffered_bytes`, default 4 MiB). When the session confirms, replay `_opened` + `_data` + `_finished` in client-open order. |

The `.buffer` policy is the closest match to the spec's recommendation
(draft §4.5). Streams whose session is never confirmed are abandoned. Streams
that exceed the per-stream buffer cap, or would push the session over the
aggregate buffer cap, are reset with the `WEBTRANSPORT_BUFFERED_STREAM_REJECTED`
code.

For server-initiated bidi streams (the WebTransport carve-out from RFC 9114
§6.1 ¶3), the server calls `accepted.openBidiStream()` and the client
receives them via the same `webtransport_stream_*` event family — see the
`WebTransport server-initiated bidirectional stream` test in
[`tests/integration/webtransport.zig`](../tests/integration/webtransport.zig)
for the full shape, including the `stream_id & 0b11 == 0b01` parity check.

---

## Datagrams

WebTransport datagrams ride on RFC 9297 HTTP/3 Datagrams using the CONNECT
stream's quarter-stream-id as the addressing key. The QUIC-DATAGRAM path is
the WT datagram path — the draft mandates it, and the old capsule fallback
no longer round-trips as a datagram for WT sessions (see below).

### Unreliable: `sendDatagram`

```zig
try client_wt.sendDatagram("ping");

// Optional tracked variant returns a send-id you can correlate with
// .datagram_acked / .datagram_lost events later:
const send_id = try client_wt.sendDatagramTracked("priority-ping");
```

`sendDatagram` translates to a QUIC DATAGRAM frame; if the QUIC peer didn't
advertise `max_datagram_frame_size > 0` you'll get
`error.DatagramNotEnabled`. Payload size is bounded by
`max_datagram_frame_size`; oversized writes return `error.DatagramTooLarge`.

### Receiving datagrams

```zig
.datagram => |datagram| {
    // datagram.stream_id IS the WebTransport Session ID: the wire
    // carries a quarter-stream-id (RFC 9297 §2) and the decoder
    // multiplies it back out to the CONNECT stream id, which is the
    // Session ID (draft §2.3). Route on it directly.
    // datagram.payload is owned by the caller after drain.
    if (datagram.stream_id == session_id) {
        process(datagram.payload);
    }
},
```

Datagrams remain legal after a DRAIN and after an H3 GOAWAY (draft-16) —
only new stream opens are gated. See [GOAWAY and
WebTransport](#goaway-and-webtransport).

### The capsule escape hatch is not a WT datagram path

`underlyingWriter().datagramCapsule(...)` still exists on the CONNECT
writer, but for WebTransport it is out-of-spec **and no longer round-trips
as a datagram**: the draft mandates the QUIC-DATAGRAM path, and since the
session now consumes the CONNECT stream's capsule protocol natively, a
`DATAGRAM` capsule arriving on a WT CONNECT stream surfaces on a WT-aware
peer as `webtransport_unknown_capsule` (capsule_type `0x00`), not as a
`.datagram` event. That's why the path is only reachable through
`underlyingWriter()`: the typed `WebTransportStream` substream handle
deliberately carries no capsule or datagram surface. Use `sendDatagram` /
`sendDatagramTracked` for WT datagrams, and reserve the capsule paths for
non-WT RFC 9297 / MASQUE contexts. See README § Datagram sends for the full
comparison.

---

## Flow control

WebTransport adds session-scoped flow-control limits on top of QUIC's
stream-scoped limits, advertised via three capsule families
(draft §5.6):

| Capsule | What it limits |
|---|---|
| `WT_MAX_DATA` | Total bytes peer is willing to receive across all WT streams in this session. |
| `WT_MAX_STREAMS_BIDI` | Cumulative bidi WT streams peer is willing to accept. |
| `WT_MAX_STREAMS_UNI` | Cumulative uni WT streams peer is willing to accept. |

Three matching `WT_*_BLOCKED` capsules signal "I want to send more but I'm
stuck at this limit." The library auto-emits them when a local send hits the
peer's advertised cap, and dedupes against `sent_*_blocked_for` so a
steadily-blocked sender doesn't spam.

A limit that was never advertised is not enforced: a `null` peer limit means
your sends are ungated in that dimension, and a `null` local limit means the
peer's traffic is not policed in that dimension.

### Initial credit via SETTINGS

The `SETTINGS_WT_INITIAL_MAX_DATA` / `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` /
`SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` settings (draft §9.2, the
`wt_initial_max_*` fields on `http3_zig.Settings`) advertise a starting
limit that applies to every session, saving the bootstrap round-trip a
`WT_MAX_DATA` capsule would cost. The credit is seeded into each session's
flow state at **pending** time, so it gates traffic before the 2xx lands
too. `null` (the default — including in `SessionConfig.production`) means
"nothing advertised": the peer starts with no credit from SETTINGS, and
your receive side enforces nothing until you advertise a limit explicitly.

### Advertising limits to the peer

```zig
try wt.sendMaxData(64 * 1024);            // 64 KiB across all WT streams
try wt.sendMaxStreamsBidi(8);
try wt.sendMaxStreamsUni(32);
```

Each of these is encoded as a single capsule on the CONNECT stream body and
also updates the local snapshot's `local_*` counter so the receive-side
enforcement uses the new limit immediately.

### Session events: the capsule protocol, typed

You never see — and never parse — the CONNECT stream's body. The session
consumes it as the capsule protocol natively (a per-session reassembler
handles capsules that legally span DATA frames) and folds every capsule
into session state, surfacing six typed session-scoped events. `Event.data`
is **not** emitted for WT CONNECT bodies. A drain-loop `switch` handling
all six:

```zig
.webtransport_session_established => |established| {
    // Pending → established (client: 2xx observed; server: accept
    // completed). Always precedes replayed buffered-stream events.
    _ = established.session_id;
},
.webtransport_session_closed => |closed| {
    // The session is GONE by the time you see this: registry state
    // dropped, live substreams swept with WEBTRANSPORT_SESSION_GONE.
    // closed.how ∈ { .close_capsule, .fin, .reset, .protocol_violation }
    // closed.code / closed.reason — the CLOSE capsule payload
    //   (code non-null only for .close_capsule; reason is owned UTF-8).
    // closed.wire_error_code — the RESET code (.reset) or the code we
    //   sent (.protocol_violation).
},
.webtransport_session_draining => |draining| {
    // Peer sent DRAIN_WEBTRANSPORT_SESSION: stop opening new streams;
    // in-flight streams and datagrams keep flowing.
    _ = draining.session_id;
},
.webtransport_peer_blocked => |blocked| {
    // Peer reports being stuck at one of OUR advertised limits.
    // blocked.kind ∈ { .data, .streams_bidi, .streams_uni };
    // blocked.offered_limit is the limit it is stuck at. Granting more
    // credit (sendMaxData / sendMaxStreams*) is application policy.
},
.webtransport_credit_granted => |credit| {
    // Peer strictly raised a limit gating OUR sends — the wakeup a
    // sender blocked on WebTransportFlowControlExceeded /
    // WebTransportStreamLimitExceeded waits for. Non-increasing
    // capsules are ignored and emit nothing (monotonic fold).
    // credit.kind / credit.limit describe the new budget.
},
.webtransport_unknown_capsule => |unknown| {
    // Capsule outside the WT family, byte-exact (owned value bytes).
    // Applications normally ignore it (RFC 9297 §3.2); intermediaries
    // forward it.
},
```

Flow-control state is also folded into the snapshot (`flowState()`, below)
before the events are delivered, so reading the snapshot from an event
handler always sees the post-fold values.

### Forwarding session events (intermediaries)

Intermediaries re-emit session-scoped events onto the other leg of a proxy
with `forwardSessionEventTo` (on both `WebTransportClientStream` and
`WebTransportServerStream`):

```zig
.webtransport_credit_granted,
.webtransport_peer_blocked,
.webtransport_session_draining,
.webtransport_session_closed,
.webtransport_unknown_capsule,
=> {
    _ = try downstream_wt.forwardSessionEventTo(event, &upstream_wt);
},
```

`forwardSessionEventTo(event, other)` returns `true` when the event belonged
to this session and was forwarded, `false` otherwise (other sessions'
events, non-session-scoped variants). The re-emission is byte-equivalent on
the wire, with per-variant semantics:

- `webtransport_credit_granted` re-grants through `other`'s send verbs
  (`sendMaxData` / `sendMaxStreams*`), keeping `other`'s `local_*`
  bookkeeping in sync with the wire.
- `webtransport_peer_blocked` re-encodes the matching `WT_*_BLOCKED`
  capsule as a pure signal, touching neither leg's limits.
- `webtransport_session_draining` calls `other.sendDrain()`.
- `webtransport_session_closed` forwards only `how == .close_capsule`
  (as `other.close(code, reason)`, which also FINs `other`'s CONNECT);
  FIN/reset/local-violation propagation is application policy and returns
  `false`.
- `webtransport_unknown_capsule` re-emits byte-exact so extensions survive
  the intermediary.

The raw escape hatch is `underlyingWriter().capsule(capsule_type, value)`
for emitting an arbitrary capsule on a CONNECT stream. Stream-copy,
datagram, FIN, and reset policy stay application-owned — see
[`examples/webtransport_proxy.zig`](../examples/webtransport_proxy.zig),
which models downstream client ↔ proxy ↔ upstream server with two
in-process H3 pairs, forwarding session events with `forwardSessionEventTo`
and forwarding DATAGRAMs, WT substream bytes, FIN, and reset through
explicit application-owned maps.

### The flow snapshot

```zig
const snap = wt.flowState() orelse return error.SessionGone;
// Peer-advertised limits (gate our sends):
snap.peer_max_data;          // ?u64
snap.peer_max_streams_bidi;  // ?u64
snap.peer_max_streams_uni;   // ?u64
// Locally-advertised limits (we sent these to the peer):
snap.local_max_data;         // ?u64
// ... etc
// Counters:
snap.local_data_sent;        // u64 — bytes we've written on WT streams
snap.peer_data_received;     // u64 — bytes we've surfaced as _data events
snap.local_streams_opened_uni;
snap.peer_streams_opened_uni;
// Drain bit:
snap.received_drain;         // bool
```

`flowState()` returns `null` once the session has ended (peer FIN'd,
explicit close, etc.). Use the absence as a clean signal that the session
is gone.

### Backpressure

The write gate is all-or-nothing. When a write would push `local_data_sent`
past the peer's `WT_MAX_DATA`, the library:

1. Writes nothing (the whole write is refused, not split).
2. Auto-emits a `WT_DATA_BLOCKED` capsule (deduped against the same limit).
3. Returns `error.WebTransportFlowControlExceeded`.

```zig
// Server has advertised peer_max_data = 16:
const stream = try client_wt.openUniStream();
try stream.write("0123456789ABCDEF"); // 16 bytes — ok
try std.testing.expectError(
    error.WebTransportFlowControlExceeded,
    stream.write("x"), // 1 byte over — refused, WT_DATA_BLOCKED emitted
);
```

Same shape for stream-count limits — `openUniStream` / `openBidiStream`
return `error.WebTransportStreamLimitExceeded` when the peer's
`WT_MAX_STREAMS_*` is at or below the local count, and auto-emit the
matching `WT_STREAMS_BLOCKED_*` capsule.

To resume, wait for the `webtransport_credit_granted` event — the typed
wakeup a blocked sender gets when the peer strictly raises the limit — and
retry the write or open. The fold is monotonic: a peer cannot shrink your
budget, and non-increasing `WT_MAX_*` capsules are ignored without an
event.

For the QUIC-side view of the same substream, `WebTransportStream.writable()`
(Unstable tier) reports the transport send-window headroom — the bytes a
`write` could hand to the transport as new data right now, or `null` when
the transport doesn't know the stream. It complements `canBuffer` (H3-side
buffering cap) and `flowState()` (the WT session-level budget).

### Receive-side enforcement

The reverse direction is enforced automatically — and a violation is
**session-fatal** (draft-16 §5.6). If the peer overflows your advertised
`local_max_data` or `local_max_streams_*`, sends a malformed flow-capsule
value, or advertises a streams limit above 2^60, the library terminates the
WebTransport session with `WT_FLOW_CONTROL_ERROR` (`0x045d4487`): the
CONNECT stream is reset with that code, every live substream is swept with
`WEBTRANSPORT_SESSION_GONE`, and a `webtransport_session_closed` event with
`how == .protocol_violation` is emitted. The connection deliberately
survives — the blast radius of a misbehaving peer session is that session,
never the H3 connection.

For observability, a limit overflow also emits `webtransport_flow_violated`
(immediately before the session-closed event), still carrying the offending
stream:

```zig
.webtransport_flow_violated => |v| {
    // v.kind ∈ { .data_overflow, .streams_bidi_overflow, .streams_uni_overflow }
    // v.limit is the value the peer overflowed (your advertised cap).
    // v.session_id, v.stream_id identify which session/stream tripped it.
},
```

---

## Closing

There are three ways to end a session locally. On the receive side they all
funnel into the same typed event — `webtransport_session_closed` — whose
`how` field tells you which one the peer used. By the time the event is
delivered the session is already gone: registry state dropped, every live
substream swept with `WEBTRANSPORT_SESSION_GONE` (STOP_SENDING + best-effort
RESET), `flowState()` returning `null`.

### 1. Explicit close: `close(code, reason)`

```zig
try client_wt.close(0xdeadbeef, "shutdown");
```

Sender side (draft §5.4 obligations, enforced by the facade):

1. The reason must be valid UTF-8 — garbage is refused outright with
   `error.InvalidCloseReason` (shipping it would hand the receiver an
   `H3_MESSAGE_ERROR`).
2. An oversized reason (> 1024 bytes) is truncated at a UTF-8 codepoint
   boundary (`webtransport.truncateCloseReasonUtf8`) — never mid-sequence.
3. The `CLOSE_WEBTRANSPORT_SESSION` capsule (32-bit application code +
   reason) is written to the CONNECT stream body, and the CONNECT stream is
   FIN'd.

Receive side: the session ends **the moment the CLOSE capsule arrives** —
not at the subsequent FIN. The library sweeps the substreams, echo-FINs its
own send half of the CONNECT stream (the draft's clean-close shape is
CLOSE, then FIN in both directions), and emits:

```zig
.webtransport_session_closed => |closed| {
    if (closed.how == .close_capsule) {
        std.debug.print("peer closed: code=0x{x} reason=\"{s}\"\n", .{
            closed.code.?, closed.reason,
        });
    }
},
```

Strictness on the receive side (all message-scoped, draft §5.4/§5.5): a
malformed CLOSE payload, any capsule after CLOSE, a non-empty DRAIN value,
or a FIN landing mid-capsule aborts the CONNECT stream with
`H3_MESSAGE_ERROR` — a message error, never a connection error — and
surfaces as `webtransport_session_closed` with `how == .protocol_violation`.

### 2. Implicit close: `finish()`

```zig
try server_wt.finish();
```

FINs the CONNECT stream **without** a `CLOSE_WEBTRANSPORT_SESSION` capsule
(draft §5.4 explicitly allows this). Local-side registry state is torn down
as part of the finish; the peer observes `webtransport_session_closed` with
`how == .fin` and `code == null` — a clean close with no code/reason.

### 3. Reset: `reset(error_code)` / `abort()` / `bidiAbort(error_code)`

```zig
try wt.reset(0x42);      // RESET_STREAM with the given app code
try wt.abort();          // RESET_STREAM with H3_REQUEST_CANCELLED
try wt.bidiAbort(0x42);  // RESET_STREAM + STOP_SENDING (client side)
```

`reset` aborts the CONNECT stream from the send side with the given
application error code. Outbound bytes that haven't been sent are dropped;
the peer sees `webtransport_session_closed` with `how == .reset` and the
RESET's code preserved in `wire_error_code` — not a clean WT close. Use
this for catastrophic local errors, not for normal shutdowns.

For refusing a session that was never accepted, the server-side
`rejectWebTransport(request, .alpn_failed | .requirements_not_met |
.{ .wire_code = … })` is the wire-correct spelling of this shape — it
aborts the pending CONNECT both directions with the reserved draft §9.5
code (see [Server: `acceptWebTransport`](#server-acceptwebtransport)).

Reset alone leaves the peer free to keep streaming the other direction, so
a real-world abort usually needs both halves. On the client,
`WebTransportClientStream.bidiAbort(code)` (mirroring
`RequestWriter.bidiAbort`) does `reset(code)` on the send half plus
`cancel()` (STOP_SENDING) on the receive half in one call. It is
session-scope and abrupt — it tears the WebTransport session down (draft
§5.4); prefer the `close(code, reason)` capsule path for graceful shutdown.

Note that the session facade's `reset` and a substream handle's `reset` are
different operations on different *types* — the former tears down the whole
session via the CONNECT stream; the latter resets a single application
stream within a still-live session. See the pitfalls section below.

---

## Draining

`DRAIN_WEBTRANSPORT_SESSION` (draft §5.5) is a "no new streams, please" signal
that doesn't tear the session down. Existing streams keep flowing; new opens
are forbidden.

### Sending a drain

```zig
try wt.sendDrain();
```

Encodes the empty `DRAIN_WEBTRANSPORT_SESSION` capsule (type `0x78ae`) and
writes it on the CONNECT stream body.

### Observing a drain

The peer's DRAIN surfaces as a typed event (first DRAIN only — repeats are
folded silently):

```zig
.webtransport_session_draining => |draining| {
    // Peer is draining session `draining.session_id`. Finish in-flight
    // streams; don't open new ones.
},
```

The `received_drain` bit on `flowState()` flips at the same moment, for
code that prefers polling the snapshot.

After the drain arrives, locally-initiated `openUniStream` /
`openBidiStream` calls return `error.WebTransportSessionDraining`. Existing
streams (already opened in either direction) continue to flow normally; the
spec leaves it to the peer to decide when to follow up with
`CLOSE_WEBTRANSPORT_SESSION`. Datagrams continue to flow as well — after
DRAIN *and* after an H3 GOAWAY (draft-16).

### The wind-down recipe

A server retiring an endpoint gracefully:

1. **Per-session DRAIN** — `sendDrain()` on every live session, so peers
   stop opening new WT streams but finish in-flight work.
2. **GOAWAY** — `Session.sendGoaway(session.gracefulGoawayId())`, refusing
   new WT CONNECT bootstraps while established sessions keep running (see
   [GOAWAY and WebTransport](#goaway-and-webtransport)).
3. **Wait** — pump until sessions retire (each peer's `close()` / FIN, or
   your own per-session deadline). If the drain window is long and the
   sessions go traffic-idle, keep the connection alive with
   `Connection.requestPing()` — `max_idle_timeout` keeps running during
   the drain.
4. **Close** — `close(code, reason)` any stragglers, then let the
   connection shut down.

---

## GOAWAY and WebTransport

Established WebTransport sessions **survive** an H3 GOAWAY (draft-16
requires it) — including opening new substreams on them — while new WT
CONNECT bootstraps are refused. The library implements this by deferring
quic-zig's transport-level graceful shutdown: `sendGoaway` defers the
transport latch while established WT sessions exist, and the last session's
end engages it. During the deferral window the H3-layer gates enforce
GOAWAY (new requests are auto-rejected); the transport keeps granting the
peer stream credit until the latch drops.

Semantics worth pinning:

- **Datagrams stay legal** after both DRAIN and GOAWAY.
- **Idle timeout keeps running** during the deferral window. A long, quiet
  drain needs keepalive: drive `Connection.requestPing()` (or WT-level
  traffic) if your sessions can go traffic-idle — upstream-confirmed
  semantics.
- New `startWebTransport` CONNECTs after GOAWAY are refused; established
  sessions are untouched until they end by their own lifecycle.

The full behavior is pinned by
[`tests/integration/webtransport_goaway.zig`](../tests/integration/webtransport_goaway.zig).

---

## Error handling

The error union for `startWebTransport` / `acceptWebTransport` and the
streaming methods is `session.Error || webtransport.Error`. The variants
you'll actually hit in normal application flow:

| Error | Source | Cause |
|---|---|---|
| `error.PeerSettingsNotReceived` | `webtransport.Error` | Tried to bootstrap before peer SETTINGS arrived. Pump the loop. |
| `error.PeerDidNotEnableWebTransport` | `webtransport.Error` | Peer SETTINGS lack one of `wt_enabled` / `h3_datagram` / `enable_connect_protocol`. |
| `error.NotWebTransport` | `webtransport.Error` | `acceptWebTransport` called on a non-WT request. |
| `error.InvalidAcceptStatus` | `webtransport.Error` | `AcceptOptions.status` isn't 2xx. |
| `error.SubprotocolNotOffered` | `webtransport.Error` | Server picked a token the client didn't list. |
| `error.WebTransportFlowControlExceeded` | `session.Error` | Local write would exceed peer's `WT_MAX_DATA`. |
| `error.WebTransportStreamLimitExceeded` | `session.Error` | Local open would exceed peer's `WT_MAX_STREAMS_*`. |
| `error.WebTransportSessionDraining` | `session.Error` | Local open after peer sent `DRAIN_WEBTRANSPORT_SESSION`. |
| `error.UnknownWebTransportSession` | `session.Error` | WT primitive invoked for a session id the registry no longer knows (never existed, or already torn down). |
| `error.SessionClosed` | `session.Error` | Send-side method called after `Session.close()` ran. |
| `error.InvalidCloseReason` | `webtransport.Error` | `close()` reason is not valid UTF-8. (Oversized reasons no longer error — the facade truncates at a codepoint boundary.) |

For receive-side flow violations the library doesn't return an error to the
caller — those are session-fatal: a `webtransport_flow_violated` event (with
a `WebTransportFlowViolationKind` describing what overflowed) followed by a
`webtransport_session_closed` event with `how == .protocol_violation` after
the session is terminated with `WT_FLOW_CONTROL_ERROR`. The connection
survives.

---

## Common pitfalls

1. **Calling `startWebTransport` before peer SETTINGS arrived.** Returns
   `error.PeerSettingsNotReceived`. The bootstrap is gated on having seen
   the peer's SETTINGS frame so the eager `peerEnabled` check can run. Pump
   the session until `Session.peer_settings != null`, then retry.

2. **Confusing session-scope with substream-scope teardown.** These are now
   different *types*, not just different method names. `wt.finish()` /
   `wt.reset(code)` on a `WebTransportClientStream` /
   `WebTransportServerStream` act on the *CONNECT* stream — i.e. close or
   tear down the whole session. `handle.finish()` / `handle.reset(code)` on
   a `WebTransportStream` handle (from `openUniStream` / `openBidiStream` /
   `streamHandle`) FIN or reset a single WT substream within a still-live
   session. Likewise, `wt.abort()` and `wt.bidiAbort(code)` abort the
   session, not a stream. Because the substream verbs live on the handle
   rather than taking a bare `u64` id, the compiler enforces the scope
   distinction — there is no id parameter to hand to the wrong method. The
   32-bit application code on `handle.reset` round-trips through the
   WebTransport error-code mapping (draft §4.6) and surfaces on the peer as
   `webtransport_stream_reset.application_error_code`. One caveat: the
   raw-u64 `Session` primitives (`Session.writeWebTransportStream`,
   `finishWebTransportStream`, `resetWebTransportStream`, …) remain public
   as an escape hatch, and code that goes through them gets no such
   type-level protection — keep the scope distinction in mind there.

3. **Forgetting to free drained events before `Session.deinit`.** The session retains
   ownership of any events queued internally, but **events already yielded
   by `drain()`** belong to the caller. Call `session.clearEvents(&events)`,
   `http3_zig.clearEvents(session_allocator, &events)`, or per-event
   `event.deinit(session_allocator)` before `Session.deinit` — see
   [`src/root.zig`](../src/root.zig) for the full allocator contract.

4. **Using the wrong allocator for event cleanup.** Events deep-clone their
   payloads (`data`, `payload`, `field_section`, etc.) out of the
   **session's** allocator. The `ArrayList` you pass to `drain()` can use a
   per-drain arena, but event payload cleanup must use the session's
   allocator. Typical patterns:

   ```zig
   defer session.clearEvents(&events);
   // or: defer http3_zig.clearEvents(session_allocator, &events);
   defer events.deinit(events_arena);
   ```

5. **Backing the session with a per-drain arena.** The doc comment on
   `Session.init` calls this out: per-stream rx buffers, QPACK dynamic
   tables, and per-WT-session flow state persist across drains. An arena
   reset between drains corrupts them. Use a long-lived
   `GeneralPurposeAllocator` (or wrapping arena) for the session itself.

6. **Sending `WT_MAX_DATA` from the wrong side.** `sendMaxData` advertises
   *your* receive limit (i.e. how much you're willing to receive). It
   updates `local_max_data` on your snapshot, not `peer_max_data`. The
   peer's session folds the capsule automatically, and — if the value is a
   strict increase — *its* `peer_max_data` reflects the new value and a
   `webtransport_credit_granted` event fires there. Read the snapshot field
   names carefully when debugging — `peer_*` always means "what the peer
   told us"; `local_*` always means "what we told the peer."

7. **Parsing the CONNECT stream body yourself.** Don't — there are no more
   `data` events for a WT CONNECT stream's body. The session consumes it as
   the capsule protocol natively (including capsules split across DATA
   frames) and everything it carries reaches you as typed events:
   flow-control folds as `webtransport_credit_granted` /
   `webtransport_peer_blocked`, DRAIN as `webtransport_session_draining`,
   CLOSE as `webtransport_session_closed`, and anything unrecognized as
   `webtransport_unknown_capsule` (byte-exact, for forwarding). Code that
   waited for CONNECT-body `data` events to feed `capsule.iter` /
   `observeCapsule` is obsolete — the manual-observe surface no longer
   exists.

---

## See also

- [`examples/loopback_wt.zig`](../examples/loopback_wt.zig) — runnable
  in-process loopback demonstrating the full bootstrap → exchange → close
  flow. Run via `just example-loopback-wt`.
- [`examples/webtransport_proxy.zig`](../examples/webtransport_proxy.zig) —
  runnable two-hop intermediary example showing session-event forwarding
  (`forwardSessionEventTo`) plus the caller-owned datagram, WT stream, FIN,
  and reset forwarding datapath. Run via `just example-webtransport-proxy`.
- [`tests/integration/webtransport.zig`](../tests/integration/webtransport.zig)
  — exhaustive integration tests covering streams, datagrams, flow control,
  drain, close, buffered policies, subprotocol negotiation, and reset
  propagation.
- [`tests/integration/webtransport_goaway.zig`](../tests/integration/webtransport_goaway.zig)
  — GOAWAY × WebTransport lifecycle: session survival, datagrams after
  DRAIN + GOAWAY, the deferred transport latch, and `requestPing`
  keepalive.
- [`tests/integration/webtransport_forwarding.zig`](../tests/integration/webtransport_forwarding.zig)
  — two-hop session-event forwarding, including credit, BLOCKED, DRAIN,
  unknown-capsule, and CLOSE behavior.
- [`src/webtransport.zig`](../src/webtransport.zig) — protocol primitives:
  capsule codecs, error-code mapping, settings predicates, subprotocol
  parsing.
- [`src/session.zig`](../src/session.zig) — `Event` union with full
  `webtransport_*` family, `WTSessionFlowSnapshot`, buffered-stream policy.
- [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/16/)
  — the spec this library tracks.
