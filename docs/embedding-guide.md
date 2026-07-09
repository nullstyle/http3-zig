# Embedding Guide

http3-zig is designed to sit inside an application-owned event loop. It owns
HTTP/3 session state, typed events, QPACK, capsules, WebTransport helpers, and
the client/server facades. Your application still owns sockets, timers,
connection tables, routing policy, body storage, and worker scheduling.

## Consuming From Your Own Project

Add http3-zig as a `build.zig.zon` dependency and import three modules —
`http3_zig` plus the `quic_zig`/`boringssl` instances it exports. The
embedding API below is quic_zig-typed (your app constructs and owns the
`*quic_zig.Connection`), and the TLS helpers traffic in
`boringssl.tls.Context`, so both sibling modules are load-bearing. Never
declare your own quic-zig or boringssl-zig dependency next to http3-zig:
that creates second module instances whose types do not unify with
http3-zig's (`expected quic_zig.Connection, found quic_zig.Connection`).

```zig
const http3_dep = b.dependency("http3_zig", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("http3_zig", http3_dep.module("http3_zig"));
exe.root_module.addImport("quic_zig", http3_dep.module("quic_zig"));
exe.root_module.addImport("boringssl", http3_dep.module("boringssl"));
```

If you prefer a single import, the same instances are re-exported as
`http3_zig.quic_zig` and `http3_zig.boringssl`. A complete out-of-tree
consumer (CI-checked) lives in
[`tools/consumer-smoke/`](../tools/consumer-smoke/).

## One Connection Shape

For each accepted or dialed QUIC connection, keep these objects together:

```zig
var quic = try quic_zig.Connection.initServer(allocator, tls);
defer quic.deinit();

var h3 = http3_zig.Session.init(
    allocator,
    .server,
    &quic,
    http3_zig.SessionConfig.production(.{}),
);
defer h3.deinit();

var server = http3_zig.Server.init(&h3);

var events: std.ArrayList(http3_zig.Event) = .empty;
defer events.deinit(allocator);
```

`Session` borrows the `quic_zig.Connection`; it does not own or free it.
Pin the `Session` to one thread or shard. Public operations mutate state
directly and do not lock internally.

## Pump Order

In a socket-backed event loop, each ready connection normally follows this
order:

1. Read UDP datagrams from your socket and pass each one to `quic.handle`.
2. Advance QUIC timers with `quic.tick(now_us)`.
3. Poll outgoing QUIC datagrams with `quic.poll` until it returns `null`, then
   send those bytes through your socket.
4. Start the HTTP/3 session once the QUIC connection is usable. `Session.start`
   is idempotent, and `TransportEndpoint.drainSession` calls it automatically.
5. Drain HTTP/3 events with `h3.drain(&events)`.
6. Process events and call back into `Client`, `Server`, writer handles, or
   `Session` as your application policy requires.
7. Free drained events with `h3.clearEvents(&events)`, then reuse or deinit
   the event list according to your loop's allocation policy. The
   session-bound call is the recommended form: event payloads are cloned out
   of the *session's* allocator, and this binding supplies it implicitly.
   (`http3_zig.clearEvents(allocator, &events)` exists for contexts without
   a session pointer; handing it any other allocator — e.g. the events
   list's — is silent memory corruption.)

The small `http3_zig.TransportEndpoint` helper keeps the repeated QUIC/H3 order
in one place without owning sockets or clocks:

```zig
var endpoint = http3_zig.TransportEndpoint.withSession(&quic, &h3, &events);

try endpoint.tick(now_us);

while (try udpRecv(socket, packet_buf[0..])) |packet| {
    try endpoint.handle(packet.bytes, packet.from, now_us);
}

while (try endpoint.poll(packet_buf[0..], now_us)) |n| {
    try udpSend(socket, peer_addr, packet_buf[0..n]);
}

_ = try endpoint.drainSession();
for (events.items) |event| {
    // Classify, route, and respond here.
}
_ = endpoint.clearEvents();
```

`TransportLoopback` is just the in-process version of this pattern for examples
and tests. Production code usually keeps `TransportEndpoint` or open-codes the
same order around its own socket API. `examples/manual_pump_get.zig` shows the
open-coded version without `TransportLoopback`.

`TransportLoopback.step` returns `TransportStepStats`; use
`stats.madeProgress()` in tests or harnesses that want to pump until an
in-process exchange goes idle without taking socket ownership into the library.
Use `total.accumulate(stats)` when a harness wants aggregate packet/event
counts across many explicit steps.
When a `TransportEndpoint` owns the `(Session, events)` pairing, use
`endpoint.clearEvents()` after processing a drained batch to release payloads
through the session allocator and retain the event list for the next step.

## Choosing Event Surfaces

Use the raw event classifiers when your application wants streaming ownership:

```zig
const request_event = http3_zig.RequestEvent.from(event) orelse return;
switch (request_event) {
    .data => |data| try body_sink.write(data.bytes),
    .finished => |done| try respond(server, done.stream_id),
    else => {},
}
```

Use `ClientRunner` and `ServerRunner` when you want owned request/response
lifecycle state that outlives the current drain. Runners accumulate headers,
body bytes, trailers, and terminal state, and their body growth can be capped
with tracker configs. Raw events are better for large uploads/downloads,
proxies, or tools that stream directly into an application buffer.
`observeBatch` returns `RunnerBatchStats`; use `stats.madeProgress()` and
`total.accumulate(stats)` when a harness wants to detect or aggregate runner
activity across many drain batches.

Runnable examples:

- Run the full cookbook with `zig build run-examples` or `just run-examples`.
- `examples/loopback_get.zig`: facade runners and complete response tracking.
- `examples/manual_pump_get.zig`: the same GET while manually driving QUIC
  `tick` / `poll` / `handle` and HTTP/3 `drain`.
- `examples/observability_metrics.zig`: trace callbacks plus metrics snapshots
  around a real request/response loop.
- `examples/request_reset.zig`: client request reset and server-side
  `stream_reset` classification.
- `examples/tracked_datagram.zig`: tracked HTTP/3 DATAGRAM send IDs and
  ACK-event correlation.
- `examples/bounded_body_sink.zig`: raw response events into caller-owned
  bounded storage.
- `examples/streaming_upload.zig`: client upload pacing with
  `RequestWriter.canWrite` and server-side raw request DATA budgeting.
- `examples/graceful_shutdown.zig`: server-initiated GOAWAY drain where the
  accepted request completes and the client's next request is blocked.
- `examples/webtransport_proxy.zig`: explicit intermediary policy for WT
  capsules, datagrams, substreams, FIN, and reset forwarding.

## Backpressure

There are three independent backpressure signals to handle:

- `RequestWriter.canWrite`, `ResponseWriter.canWrite`, and
  `StreamSendState` describe send-side bytes buffered below HTTP/3.
- `EventPayloadTooLarge` and `EventQueueFull` from `Session.drain` mean the
  event batch hit local drain limits. Use `Session.clearEvents` (or its
  `TransportEndpoint.clearEvents` wrapper), then drain again.
- Raw body events are storage-neutral. If you use raw `.data` events, your
  application must decide whether to append, stream to disk, pass to another
  service, reset the stream, or close the connection when its own budget is hit.

The production preset enables bounded defaults for frame sizes, decoded field
storage, event batches, send buffers, datagrams, capsules, and WebTransport
pre-confirmation buffering. See
[`production-limits.md`](production-limits.md) for the current inventory.

## Shutdown

For graceful HTTP/3 shutdown, call
`Session.sendGoaway(session.gracefulGoawayId())` — or use the facade-level
close/reset helpers according to your application policy — then keep pumping
the QUIC connection until pending events and outgoing packets are drained. A
connection close appears as a typed `connection_closed` event; inspect its
structured HTTP/3 error metadata before removing the connection from your
tables.

`Session.gracefulGoawayId` returns the RFC 9114 §5.2 "covers nothing new" id:
the next client request stream id after the highest the session has observed
(`Session.highestPeerRequestStreamId`), or `0` when no request was ever seen —
so no server needs to hand-track stream ids from events to shut down
correctly. The drain-complete condition is equally session-derived: once
`shutdownState()` is `.draining` and `openRequestStreamCount()` reaches zero,
every request admitted before the GOAWAY has finished and the connection can
be closed without cutting work short.

`examples/graceful_shutdown.zig` shows the common server-side shape: accept
request stream `0`, send `GOAWAY` at `gracefulGoawayId()` (which is `4` after
one request) so the next client request stream is covered by the advertised
limit, finish the already-accepted response, pump until
`openRequestStreamCount() == 0`, and let the client observe
`RequestBlockedByGoaway` when it tries to open another request.

Before `Session.deinit`, free all events that were yielded by prior drains —
preferably with the session-bound `Session.clearEvents`, which binds the
correct allocator implicitly (`http3_zig.clearEvents` and per-event
`event.deinit` require the session's allocator). `Session.deinit` only
releases state still owned by the session; drained event payloads belong to
the caller.

## Request Deadlines

`Session.openRequestStreams` iterates the in-flight request/response
exchanges together with each stream's last-activity time, so per-request
timeouts need no application-side stream map either. `last_event_us` is in
the same clock domain as the `now_us` your loop feeds
`quic.handle`/`tick`/`poll`: it is stamped when the stream is created and
every time the session surfaces an event for it, so a request that opened and
went silent still ages. Collect expired ids first, then act — acting is safe
mid-iteration today, but collect-then-act stays correct if stream teardown
ever reshapes the table:

```zig
var expired: std.ArrayList(u64) = .empty;
defer expired.deinit(allocator);
var open = h3.openRequestStreams();
while (open.next()) |req| {
    if (now_us - req.last_event_us > request_deadline_us) {
        try expired.append(allocator, req.stream_id);
    }
}
for (expired.items) |stream_id| {
    // Server-side: refuse the rest of the request body and drop the
    // response; the client sees H3_REQUEST_REJECTED.
    try h3.rejectRequest(stream_id);
    try h3.resetResponse(stream_id, http3_zig.protocol.ErrorCode.request_rejected);
}
```

Client-side enforcement is symmetric with `cancelRequest` (stop receiving the
response) plus `resetRequest` (abort the request send). Note WebTransport
CONNECT streams appear in the iterator for the lifetime of their session —
exempt them (`RequestReader.isWebTransport`, or your own routing table) from
request deadlines.

## Certificate Rotation

http3-zig adds nothing TLS-specific on top of quic-zig here; rotation is a
transport-layer concern with one load-bearing BoringSSL property. For the
raw-`Connection` embedding shape this guide uses, build a **new** boringssl
context (`server.initTlsContext`) when certificates rotate and hand it to
*new* connections only. Existing connections finish on the old context:
BoringSSL up-refs the `SSL_CTX` on `SSL_new`, so each connection's TLS state
keeps the context it was created against alive until that connection is torn
down — deinit the old context after its last connection closes (or refcount
it the way quic-zig's own wrapper does).

If you embed via quic-zig's multi-connection `quic_zig.Server` wrapper
instead, use `Server.replaceTlsContext` (`Server.TlsReload`): it swaps the
context for future accepts, drains the old one behind a per-slot refcount,
and documents the resumption caveat (session tickets minted under the old
context cannot be decrypted under the new one — bridge ticket keys yourself
if 0-RTT must survive rotation).
