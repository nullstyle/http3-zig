# WebTransport Tour

A walkthrough of `http3-zig`'s WebTransport-over-HTTP/3 surface for application
authors. The library tracks
[`draft-ietf-webtrans-http3-15`](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/15/)
(July 2025), pinned in [`README.md`](../README.md). Datagrams use RFC 9297
HTTP/3 Datagrams; capsules use the RFC 9297 Capsule Protocol.

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
// (draft-15 §9.2). All three are required on both peers.
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
// when the 2xx response on the CONNECT stream arrives — observe it via
// `ResponseReader.webTransportAccepted()` in the drain loop.
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
session is registered as **pending** in `Session`. It transitions to
**established** when the client observes a 2xx response on the CONNECT stream
— surface that via `ResponseReader.webTransportAccepted()`:

```zig
.response_updated, .response_complete => |response_state| {
    const response = response_state.reader();
    if (!client_saw_response and response.headers().len > 0) {
        try std.testing.expect(response.webTransportAccepted());
        try std.testing.expectEqualStrings("200", response.status().?);
        client_saw_response = true;
        // Now safe to open WT streams and send datagrams.
    }
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
if the CONNECT didn't carry `:protocol = webtransport`), then sends the
response and confirms the session in the underlying `Session`. Status codes
outside `2xx` are rejected with `error.InvalidAcceptStatus`.

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

```zig
// From the WebTransportClientStream / WebTransportServerStream:
const uni_id = try wt.openUniStream();
try wt.writeStream(uni_id, "hello");
try wt.finishStream(uni_id);

const bidi_id = try wt.openBidiStream();
try wt.writeStream(bidi_id, "ping");
// ... peer can write back; observe via webtransport_stream_data ...
try wt.finishStream(bidi_id);

// Reset with an application error code (mapped to HTTP/3 wire code):
try wt.resetStream(uni_id, 0xabad1dea);
// Or use the raw wire code:
try wt.resetStreamWithCode(uni_id, 0x52e4a40fa8db);
```

### Observing peer-opened streams

Peer-opened WebTransport streams surface as four event variants on
`session.Event`. They are also classified by the high-level `Client` /
`Server` facades (`ResponseEvent.webtransport_stream_*` / `RequestEvent.*`),
but the raw `session.Event` shapes are usually easiest in a runner-driven
loop:

```zig
.webtransport_stream_opened => |opened| {
    // opened: { stream_id, session_id, kind }; kind ∈ { .uni, .bidi }
},
.webtransport_stream_data => |data| {
    // data: { stream_id, session_id, kind, data: []u8 }
    // `data.data` is owned by the caller after drain — free with
    // event.deinit(session.allocator) per the allocator contract.
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
stream's quarter-stream-id as the addressing key. The library exposes both
the unreliable QUIC-DATAGRAM path and a reliable Capsule Protocol path.

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

Both reliable-mode and unreliable-mode datagrams surface as the same event:

```zig
.datagram => |datagram| {
    // datagram.stream_id is the WebTransport Session ID.
    // datagram.payload is owned by the caller after drain.
    if (datagram.stream_id == session_id) {
        process(datagram.payload);
    }
},
```

### Reliable: capsule path

For situations where you need delivery (the QUIC peer didn't enable
DATAGRAMs, or the payload is too large for a single frame), use
`datagramCapsule` on the underlying writer:

```zig
// WebTransport*Stream.requestWriter() / .responseWriter() returns the
// underlying *RequestWriter / *ResponseWriter:
try wt.requestWriter().datagramCapsule("reliable-payload");
```

This packages the bytes in a `DATAGRAM` capsule on the CONNECT stream body.
The peer decodes it via `capsule.iter(body())` and the same
`.datagram` event fires. Use the unreliable path by default; switch to
capsule mode only when you've verified the peer doesn't support QUIC
DATAGRAMs (`session.peer_settings.?.h3_datagram == false`) or you actually
need ordering / delivery guarantees.

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

### Advertising limits to the peer

```zig
try wt.sendMaxData(64 * 1024);            // 64 KiB across all WT streams
try wt.sendMaxStreamsBidi(8);
try wt.sendMaxStreamsUni(32);
```

Each of these is encoded as a single capsule on the CONNECT stream body and
also updates the local snapshot's `local_*` counter so the receive-side
enforcement uses the new limit immediately.

### Observing inbound capsules

The peer's flow-control capsules ride on the CONNECT stream body. Iterate
them and feed each one to `observeCapsule`:

```zig
.response_updated, .response_complete => |response_state| {
    const response = response_state.reader();
    if (response.body().len > 0) {
        var it = http3_zig.capsule.iter(response.body());
        while (try it.next()) |decoded| {
            try client_wt.observeCapsule(decoded.capsule);
        }
    }
},
```

`observeCapsule` ignores capsules outside the WebTransport family (so it's
safe to feed the whole stream). It updates the per-session flow snapshot.

### Forwarding WT capsules

Intermediaries can forward WebTransport control / extension capsules without
becoming the owner of the full stream or datagram datapath:

```zig
var it = http3_zig.capsule.iter(connect_body);
while (try it.next()) |decoded| {
    try downstream_wt.forwardCapsuleTo(decoded.capsule, &upstream_wt);
}
```

`forwardCapsuleTo` first calls `observeCapsule` on the receiving handle, then
writes the same capsule with `sendCapsule` on the paired outbound handle.
Unknown capsules are forwarded unchanged. `CLOSE_WEBTRANSPORT_SESSION` is not
special-cased: forwarding the capsule does not finish or reset either CONNECT
stream, so applications still own FIN/reset and stream-copy policy.

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

When a local write would exceed the peer's `WT_MAX_DATA`, the library:

1. Writes everything that fits up to the limit.
2. Auto-emits a `WT_DATA_BLOCKED` capsule (deduped against the same limit).
3. Returns `error.WebTransportFlowControlExceeded`.

```zig
// Server has advertised peer_max_data = 16:
try client_wt.writeStream(stream_id, "0123456789ABCDEF"); // 16 bytes — ok
try std.testing.expectError(
    error.WebTransportFlowControlExceeded,
    client_wt.writeStream(stream_id, "x"), // 1 byte over — blocked
);
```

Same shape for stream-count limits — `openUniStream` / `openBidiStream`
return `error.WebTransportStreamLimitExceeded` when the peer's
`WT_MAX_STREAMS_*` is at or below the local count, and auto-emit the
matching `WT_STREAMS_BLOCKED_*` capsule. To resume, wait for the peer to
send a higher `WT_MAX_DATA` / `WT_MAX_STREAMS_*` and feed it via
`observeCapsule`; the next write will succeed.

### Receive-side enforcement

The reverse direction is enforced automatically. If the peer overflows your
advertised `local_max_data` or `local_max_streams_*`, the library resets the
offending stream and emits a `webtransport_flow_violated` event:

```zig
.webtransport_flow_violated => |v| {
    // v.kind ∈ { .data_overflow, .streams_bidi_overflow, .streams_uni_overflow }
    // v.limit is the value the peer overflowed (your advertised cap).
    // v.session_id, v.stream_id identify which session/stream tripped it.
},
```

---

## Closing

There are three ways a session can end. They differ in what shows up on the
peer.

### 1. Explicit close: `close(code, reason)`

```zig
try client_wt.close(0xdeadbeef, "shutdown");
```

This:

1. Encodes a `CLOSE_WEBTRANSPORT_SESSION` capsule with the application code
   (32-bit) and reason phrase (UTF-8, ≤ 1024 bytes — `error.CloseReasonTooLarge`
   otherwise).
2. Writes it to the CONNECT stream body.
3. FINs the CONNECT stream.

The peer observes the capsule on the CONNECT body, then the FIN. Iterate the
body and call `webtransport.classifyCapsule` to extract the code and reason:

```zig
var it = http3_zig.capsule.iter(request.body());
while (try it.next()) |decoded| {
    const wt_event = try http3_zig.webtransport.classifyCapsule(decoded.capsule);
    switch (wt_event) {
        .close_session => |close| {
            std.debug.print("peer closed: code=0x{x} reason=\"{s}\"\n", .{
                close.code, close.reason,
            });
        },
        else => {},
    }
}
```

### 2. Implicit close: `finish()`

```zig
try server_wt.finish();
```

FINs the CONNECT stream **without** a `CLOSE_WEBTRANSPORT_SESSION` capsule
(draft §5.4 explicitly allows this). The peer treats it as a clean close
with no code/reason. Local-side flow state disappears immediately
(`flowState()` returns `null`); the peer observes the FIN and runs its own
cleanup.

No protocol-level error code is surfaced — there's nothing to classify on
the receive side beyond the stream-finished signal.

### 3. Reset: `reset(error_code)` / `abort()`

```zig
try wt.reset(0x42);   // RESET_STREAM with the given app code
try wt.abort();       // RESET_STREAM with H3_REQUEST_CANCELLED
```

`reset` aborts the CONNECT stream from the send side with the given
application error code. Outbound bytes that haven't been sent are dropped;
the peer sees a `connection_closed` / stream-reset event rather than a
clean WT close. Use this for catastrophic local errors, not for normal
shutdowns.

`reset` and the per-WT-stream `resetStream` are different operations — the
former tears down the whole session via the CONNECT stream; the latter
resets a single application stream within a still-live session.

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
writes it on the CONNECT stream body. The peer's local snapshot's
`received_drain` bit flips on its next `observeCapsule` call.

### Observing a drain

Iterate inbound capsules on the CONNECT body and feed them to
`observeCapsule`. Watch the snapshot:

```zig
var it = http3_zig.capsule.iter(response.body());
while (try it.next()) |decoded| {
    try client_wt.observeCapsule(decoded.capsule);
}
if (client_wt.flowState()) |snap| {
    if (snap.received_drain) {
        // Peer is draining. Finish in-flight streams; don't open new ones.
    }
}
```

After `received_drain` flips, locally-initiated `openUniStream` /
`openBidiStream` calls return `error.WebTransportSessionDraining`. Existing
streams (already opened in either direction) continue to flow normally; the
spec leaves it to the peer to decide when to follow up with
`CLOSE_WEBTRANSPORT_SESSION`. Datagrams continue to flow as well.

A typical pattern: peer drains, you finish your in-flight uni/bidi streams,
then either side calls `close()` to retire the session.

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
| `error.UnknownWebTransportSession` | `session.Error` | Capsule observed for a session not in the established set. |
| `error.SessionClosed` | `session.Error` | Send-side method called after `Session.close()` ran. |
| `error.CloseReasonTooLarge` | `webtransport.Error` | `close()` reason exceeds 1024 bytes. |

For receive-side flow violations the library doesn't return an error to the
caller — those bubble up as `webtransport_flow_violated` events instead, with
a `WebTransportFlowViolationKind` describing what overflowed.

---

## Common pitfalls

1. **Calling `startWebTransport` before peer SETTINGS arrived.** Returns
   `error.PeerSettingsNotReceived`. The bootstrap is gated on having seen
   the peer's SETTINGS frame so the eager `peerEnabled` check can run. Pump
   the session until `Session.peer_settings != null`, then retry.

2. **Confusing `reset` with `resetStream`.** `wt.reset(code)` aborts the
   *CONNECT* stream — i.e. tears down the whole session. `wt.resetStream(id,
   code)` resets a single peer/local WT stream within a still-live session.
   Likewise, `wt.abort()` aborts the session, not a stream. The 32-bit
   application code on `resetStream` round-trips through the WebTransport
   error-code mapping (draft §4.6) and surfaces on the peer as
   `webtransport_stream_reset.application_error_code`.

3. **Forgetting to drain before `Session.deinit`.** The session retains
   ownership of any events queued internally, but **events already yielded
   by `drain()`** belong to the caller. You must call
   `event.deinit(session.allocator)` on each one before
   `Session.deinit` — see [`src/root.zig`](../src/root.zig) for the full
   allocator contract.

4. **Using the wrong allocator on `event.deinit`.** Events deep-clone their
   payloads (`data`, `payload`, `field_section`, etc.) out of the
   **session's** allocator. The `ArrayList` you pass to `drain()` can use a
   per-drain arena, but `event.deinit` MUST receive the session's allocator.
   A typical pattern:

   ```zig
   defer for (events.items) |ev| ev.deinit(session.allocator);
   defer events.deinit(events_arena);
   ```

5. **Backing the session with a per-drain arena.** The doc comment on
   `Session.init` calls this out: per-stream rx buffers, QPACK dynamic
   tables, and per-WT-session flow state persist across drains. An arena
   reset between drains corrupts them. Use a long-lived
   `GeneralPurposeAllocator` (or wrapping arena) for the session itself.

6. **Sending `WT_MAX_DATA` from the wrong side.** `sendMaxData` advertises
   *your* receive limit (i.e. how much you're willing to receive). It
   updates `local_max_data` on your snapshot, not `peer_max_data`. The peer
   sees the capsule, calls `observeCapsule`, and *its* `peer_max_data`
   reflects the new value. Read the snapshot field names carefully when
   debugging — `peer_*` always means "what the peer told us"; `local_*`
   always means "what we told the peer."

7. **Treating QUIC-DATAGRAM and capsule-mode datagrams as different
   events.** Both surface as `.datagram` with the same Session ID. The
   sender chooses (via `sendDatagram` vs `datagramCapsule`); the receiver
   doesn't have to branch.

---

## See also

- [`examples/loopback_wt.zig`](../examples/loopback_wt.zig) — runnable
  in-process loopback demonstrating the full bootstrap → exchange → close
  flow. Run via `just example-loopback-wt` (if defined) or directly.
- [`tests/integration/webtransport.zig`](../tests/integration/webtransport.zig)
  — exhaustive integration tests covering streams, datagrams, flow control,
  drain, close, buffered policies, subprotocol negotiation, and reset
  propagation.
- [`src/webtransport.zig`](../src/webtransport.zig) — protocol primitives:
  capsule codecs, error-code mapping, settings predicates, subprotocol
  parsing.
- [`src/session.zig`](../src/session.zig) — `Event` union with full
  `webtransport_*` family, `WTSessionFlowSnapshot`, buffered-stream policy.
- [draft-ietf-webtrans-http3-15](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/15/)
  — the spec this library tracks.
