# quic-zig: `tick` can reap a stream before the app sees its FIN

For: the quic-zig session. Found by http3-zig on 2026-10-05, on quic
v0.27.0 (`bench-e2e`, cell `wt_session`). Not sent yet.

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

By reading the code only (not tested): `.reset_recvd` is in
`recvFullyTerminated` too. A RESET_STREAM that arrives before a `tick`
can be reaped before the app sees the reset.

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
   app saw the end. `streamReadFin` already calls `markRead` when it
   reports `fin`. An app that never reads a stream keeps it (as for
   any unread stream); `recv_stopped` streams are already discarded by
   the GC.
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
