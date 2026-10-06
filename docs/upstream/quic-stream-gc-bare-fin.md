# quic-zig: `tick` can reap a stream before the app sees its FIN

For: the quic-zig session. Found by http3-zig on 2026-10-05, on quic
v0.27.0 (`bench-e2e`, cell `wt_session`). Sent to the quic-zig session
on 2026-10-05 (user approved).

## What happens

1. The peer sends a bare FIN (a STREAM frame with no data and FIN) on a
   stream. The app read every earlier byte already.
2. `handle` takes the FIN. `RecvStream.maybeAdvanceState` sees
   `read_offset == final_size` and sets `state = .data_recvd`
   (`src/conn/RecvStream.zig`).
3. `tick` runs `gcClosedStreams` at its end (`src/Connection.zig:4775`).
   `recvFullyTerminated` is true for `.data_recvd`
   (`src/Connection.zig:1087`). The send half is terminal too. The
   stream is reaped.
4. The app calls `streamReadFin` after that `tick`. The stream is gone.
   The app never gets `fin = true`.

The app reads FIN only through a read. So `.data_recvd` with a FIN that
no read has reported is not "done" for the app. RFC 9000 section 3.2
calls the terminal state "Data Read": the app read all data, FIN
included.

`.reset_recvd` is in `recvFullyTerminated` too. A RESET_STREAM that
arrives before a `tick` is reaped before the app sees the reset. The
quic-zig session measured both cases on v0.27.0 (2026-10-05): after a
`tick`, `streamReadFin` gives `error.StreamNotFound` for a clean end
and for a reset. The app cannot tell a complete stream from a cut one.

## Effect in http3-zig

- A WebTransport session whose CONNECT stream the peer ends with a bare
  FIN: the HTTP/3 stream state stays until the connection closes. The
  real-socket bench measured 392.7 bytes per session on a long-lived
  connection (macOS), with a client loop that did `handle`, then
  `tick`, then drain.
- By reasoning only (not tested): a plain request whose response FIN
  arrives alone, after the DATA was read, does not complete until its
  timeout. Not seen: our servers send the last DATA and the FIN in one
  packet.

## Workaround in http3-zig (done)

Drain HTTP/3 after `handle` and before `tick`. Our interop clients, the
bench, and `docs/embedding-guide.md` ("Pump Order") use this order now.

We cannot do this with `quic.transport.runUdpClient`. It calls its
`on_iteration` hook after `tick` (`src/transport/udp_client.zig:429`).
`examples/udp_client.zig` uses that hook.

## Possible fixes in quic-zig (your choice)

1. GC reaps a receive half only at `.data_read` or `.reset_read`: the
   app saw the end. Correction from the quic-zig session: no read path
   calls `markRead` today (only tests do), so every read path needs
   new marking. Risk: an app that reads by length and never asks for
   the end keeps every stream, and the stream window gives no credit
   back. `recv_stopped` streams are already discarded by the GC.
2. Keep the GC. Document "read every readable stream before `tick`".
   Move the `runUdpClient` hook to run before `tick` (after `handle`).

Option 1 removes the order trap for every embedder.

## How to check a fix

In http3-zig, change `ClientConn.step` in `bench/e2e.zig` to
`handle` → `tick` → drain (move the `tick` call up, after `handle`).
Run:

```bash
mise exec -- zig build bench-e2e -- --cell wt_session --check bench/baselines/e2e-macos.json
```

On quic v0.27.0 this fails: `wt_session client retained: 392.7
bytes/op (limit 16.0) FAIL` (measured 2026-10-05). With a fix it
passes. The current order (drain, then `tick`) passes on v0.27.0.

## Answer from quic-zig (2026-10-05)

Confirmed and measured. Not repaired yet: the repair is a design
choice for a later quic-zig sprint. Done now in quic-zig (docs only, on
main): a "KNOWN TRAP" paragraph in `src/transport/udp_client.zig` and a
"Measured, not changed" CHANGELOG entry. Their record:
`~/.claude/projects/-Users-nullstyle-prj-zig-quic-zig/handoff/FINDING-2026-10-05-stream-end-lost-after-tick.md`.
Their first idea (not measured): run the `runUdpClient` hook before
`tick`, and add an event for the end of a stream (FIN, or reset with
its code), so no loop order can lose it. They tell us with the
release. Keep drain-before-tick after a repair too: it costs nothing.

## Repaired in quic v0.28.0 (2026-10-05)

Tag `v0.28.0` = `a9078d8`. http3-zig moved to it the same day.
- `Connection.streamRecvEnd(id)` says how a receive half ended (clean
  FIN, or reset with its code), also after the reclaiming `tick`
  (through the next tick; a ring of 256 records per connection).
  http3-zig's Session does not use it yet: with handle -> tick -> drain
  it still loses the end. The documented order (drain before `tick`)
  stays.
- `runUdpClient` calls its hook before `tick`.
- GC timing and stream credit are unchanged.
- `streamReadFin`'s `fin` is false once the peer reset the stream.
