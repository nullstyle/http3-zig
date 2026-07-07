# Embedding Guide

http3-zig is designed to sit inside an application-owned event loop. It owns
HTTP/3 session state, typed events, QPACK, capsules, WebTransport helpers, and
the client/server facades. Your application still owns sockets, timers,
connection tables, routing policy, body storage, and worker scheduling.

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
7. Free drained events with `h3.clearEvents(&events)` or
   `http3_zig.clearEvents(allocator, &events)`, then reuse or deinit the event
   list according to your loop's allocation policy.

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
h3.clearEvents(&events);
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

## Choosing Event Surfaces

Use the raw event classifiers when your application wants streaming ownership:

```zig
const request_event = http3_zig.server.RequestEvent.from(event) orelse return;
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
  event batch hit local drain limits. Free the events already emitted, clear the
  list, and drain again.
- Raw body events are storage-neutral. If you use raw `.data` events, your
  application must decide whether to append, stream to disk, pass to another
  service, reset the stream, or close the connection when its own budget is hit.

The production preset enables bounded defaults for frame sizes, decoded field
storage, event batches, send buffers, datagrams, capsules, and WebTransport
pre-confirmation buffering. See
[`production-limits.md`](production-limits.md) for the current inventory.

## Shutdown

For graceful HTTP/3 shutdown, call `Session.sendGoaway` or use facade-level
close/reset helpers according to your application policy, then keep pumping the
QUIC connection until pending events and outgoing packets are drained. A
connection close appears as a typed `connection_closed` event; inspect its
structured HTTP/3 error metadata before removing the connection from your
tables.

`examples/graceful_shutdown.zig` shows the common server-side shape: accept
request stream `0`, send `GOAWAY(4)` so the next client request stream is
covered by the advertised limit, finish the already-accepted response, and let
the client observe `RequestBlockedByGoaway` when it tries to open another
request.

Before `Session.deinit`, free all events that were yielded by prior drains with
`Session.clearEvents`, `http3_zig.clearEvents`, or per-event `event.deinit`.
`Session.deinit` only releases state still owned by the session; drained event
payloads belong to the caller.
