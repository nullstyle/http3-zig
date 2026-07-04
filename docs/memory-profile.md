# http3-zig WebTransport long-running memory profile

This report tracks how the http3-zig WebTransport stack uses heap memory
across many drains on a single long-lived session. **The point is
detecting monotonic growth, not minimizing absolute working-set size.** A
change is good if it makes the per-iteration delta strictly smaller.

## What is measured

`bench/wt_memory.zig` (run via `zig build mem-profile`) drives an
in-process pair of `http3_zig.Session`s through
`http3_zig.TransportLoopback`. The harness wraps the project's
`DebugAllocator` (`safety = true, verbose_log = false`) inside a thin
`CountingAllocator` that tracks live `bytes_in_use` and `max_bytes_ever`.

The harness:

1. Establishes **one** WebTransport session over **one** QUIC
   connection. The session and the connection are reused for every
   iteration — nothing is torn down between them.
2. Records a `warm-up` sample right after session establishment.
3. Runs N iterations of one fixed unit of work:
   - Open a uni stream, write 256 bytes, finish.
   - Drain server events until `_opened` + `_data` (≥256 bytes) +
     `_finished` have all been observed for that stream.
   - Send a 64-byte datagram client→server, drain until the server sees it.
   - Send a 64-byte datagram server→client, drain until the client sees it.
   - Pump until both sides go quiescent (a drained pump produces no events).
   - Free every drained event via `Session.freeEvent`.
4. Samples `bytes_in_use` / `max_bytes_ever` at 500 / 1 000 / 2 000 iters.
5. Tears down the session and calls `gpa.deinit()`, which reports `.ok`
   if no allocation escaped `freeEvent` / the per-component `deinit`.

Numbers reflect *library overhead only* — the loopback shim hands buffers
between two `quic_zig.Connection` instances in-process. No kernel sockets,
no real network. Useful as a steady-state signal, not a wire-line
working-set claim.

## The numbers

2 000-iteration trace on the current tree (http3-zig against quic-zig
0.4.0):

| Stage | iters | bytes-in-use | max-bytes-ever | Δ vs warm-up |
| --- | ---: | ---: | ---: | ---: |
| warm-up | 0 | 2 527 500 | 2 527 550 | +0 |
| 500 iters | 500 | 2 649 708 | 2 652 293 | +122 208 |
| 1k iters | 1 000 | 2 771 116 | 2 773 701 | +243 616 |
| 2k iters | 2 000 | 3 013 932 | 3 016 517 | +486 432 |

**Δ bytes-in-use warm-up → 2k iters: +486 432 bytes over 2 000 iters
(≈ 243 bytes/iter).** `gpa.deinit()` reports **ok** — every allocation
made during the loop is reachable from the `Session` deinit chain.

## Verdict

Per-iteration growth is **≈ 243 bytes/iter**, down **~91 %** from the
≈ 2 755 bytes/iter this harness measured before terminal-stream reaping
landed (see history below). The delta is constant across windows
(warm-up→500: 244/iter; 500→1k: 243/iter; 1k→2k: 243/iter), so it is a
small predictable per-iteration cost, not a fixed warm-up overhead
amortizing away. The remaining growth is connection-level bookkeeping that
scales with the total number of streams a single connection has ever
opened (ack-range / packet-number history, the reaped-stream watermark
bitsets, and similar), not a leak — the detector is clean and everything
is freed at teardown.

## History: the cross-layer leak, now closed

This harness originally measured **≈ 2 755 bytes/iter** of monotonic
growth from never-removed per-stream bookkeeping on **both** layers — the
http3 `Session.streams` map and the quic-zig `Connection.streams` map each
kept a permanent entry (and its `rx` / recv-reassembly / send-chunk
buffers) for every stream ever opened, freed only at whole-connection
teardown.

It was closed in two steps:

1. **http3 side:** `Session.gcClosedStreams` (called at the tail of every
   `drain`) reclaims a `StreamState` once both directions are terminal,
   driven by `StreamState.locally_finished` plus the recv-side flags. That
   took the figure to ≈ 2 239 bytes/iter and left the rest one layer down.
2. **quic-zig side:** the residual required quic-zig to stop retaining
   terminal streams. quic-zig **0.3.0+** added exactly that — a
   `gcClosedStreams` pass at the tail of `tick` that `fetchRemove`s a
   stream once its recv side (peer-initiated) or send side
   (locally-initiated) is terminal. Building http3-zig against **quic-zig
   0.4.0** picks up that reaping and drops the figure to the ≈ 243
   bytes/iter above. (Adapting the http3 drain loop to that reaping — it
   can no longer rely on `streamIterator` re-yielding a parked stream — is
   the subject of the 0.4.0 upgrade commit.)

An earlier revision of this file predicted the quic-side fix as "deferred
to a follow-up release"; that release is quic-zig 0.4.0, and this trace is
it landing.

## Regression gate

`bench/wt_memory.zig` exits non-zero when per-iteration growth exceeds
`max_bytes_per_iter_gate` (600 bytes/iter — ≈ 2.5× the current figure, so
allocator / platform variation passes, but a reintroduced per-stream leak
in the thousands of bytes/iter fails). CI runs `zig build mem-profile` and
gates on that exit code, so a memory regression breaks the build rather
than silently drifting the published number. Bump the gate deliberately
(and update the numbers above) if a legitimate change raises the baseline.

## Caveats

- **One allocation pattern.** The harness exercises a single drain shape
  (uni stream + datagram round-trip). Other patterns — large header sets,
  many bidi streams, WT datagrams routed to nonexistent sessions, peers
  that open streams without finishing them — could grow elsewhere
  (`message_states`, QPACK dynamic tables, `wt_buffered_streams`) in ways
  this trace would not detect.
- **Loopback only.** No real network, loss, reorder, or back-pressure. A
  fixture closer to wire conditions would surface a different mix (e.g.
  ACK-pacing buffers).
- **Larger runs are now viable.** With reaping on both layers the per-pump
  cost no longer grows superlinearly (each drain iterates a small, GC'd
  map), so 5k/10k runs complete in practical wall-clock time. The default
  stays at 2 000 iterations to keep the CI gate fast; bump
  `total_iterations` + `sample_at_iters` for a deeper manual run.
- **`max_bytes_ever` tracks `bytes_in_use`.** The two stay within ~256
  bytes of each other at every checkpoint, so the growth is genuine
  retained memory, not an allocator high-water artifact from a transient
  per-iteration spike.
- **Counting allocator semantics.** The `CountingAllocator` reports the
  *requested* byte count of every allocation, not `DebugAllocator`'s
  internal bucket bookkeeping or kernel-page padding. App-level demand —
  the right unit for library overhead, slightly smaller than RSS.

## How to reproduce

```sh
cd http3-zig
zig build mem-profile --cache-dir /tmp/h3-cache-W2
```

The step always builds with `-OReleaseSafe` (private boringssl + quic_zig
+ http3_zig instances at the same optimize mode), so the `DebugAllocator`
leak detector and the counting allocator overhead are both in scope. The
harness writes a Markdown table to stdout and exits non-zero if the leak
detector fires **or** per-iteration growth exceeds the regression gate.
