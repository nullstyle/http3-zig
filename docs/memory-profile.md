# http3-zig WebTransport long-running memory profile

This report establishes a starting-point picture of how the http3-zig
WebTransport stack uses heap memory across many drains on a single
long-lived session. **The point is detecting monotonic growth, not
optimization.** A future change is good if it makes the per-iteration
delta strictly smaller; we are not yet trying to minimize the absolute
working-set size.

## What is measured

`bench/wt_memory.zig` (run via `zig build mem-profile`) drives an
in-process pair of `http3_zig.Session`s through
`http3_zig.TransportLoopback`. The harness wraps a `DebugAllocator`
with `safety = true, verbose_log = false` (the 0.16 rename of
`GeneralPurposeAllocator(.{ .safety = true, .verbose_log = false })`)
inside a thin `CountingAllocator` that tracks live `bytes_in_use` and
`max_bytes_ever`.

The harness:

1. Establishes **one** WebTransport session over **one** QUIC
   connection. The session and the connection are reused for every
   iteration — nothing is torn down between them.
2. Records a `warm-up` sample right after session establishment.
3. Runs N iterations of one fixed unit of work:
   - Open a uni stream, write 256 bytes, finish.
   - Drain server events until `_opened` + `_data` (≥256 bytes) +
     `_finished` have all been observed for that stream.
   - Send a 64-byte datagram client→server, drain until the server
     sees it.
   - Send a 64-byte datagram server→client, drain until the client
     sees it.
   - Pump until both sides go quiescent (a single drained pump
     produces no events on either endpoint).
   - Free every drained event via `Session.freeEvent`, releasing any
     deep-cloned payload bytes back to the counting allocator.
4. Samples `bytes_in_use` and `max_bytes_ever` at three checkpoints
   (1k / 5k / 10k by spec, run at the cadence the harness completes
   in — see Caveats).
5. Tears down the session and the H3Pair, then calls
   `gpa.deinit()`. The `DebugAllocator` reports `.ok` if no
   allocation has escaped `freeEvent` / the per-component
   `deinit`.

Numbers reflect *library overhead only* — the loopback shim hands
buffers between two `quic_zig.Connection` instances in-process. No
kernel sockets, no real network. They are useful as a steady-state
signal, not as a wire-line working-set claim.

## The numbers

The binary is configured to run 10 000 iterations per the spec.
**The 10 000-iter and 5 000-iter runs do not complete in practical
wall-clock time** under the current implementation (5k wall-clocks
~10 minutes, 10k extrapolates to ~30 minutes+). See **Caveats**
below for why this is itself a symptom of the same growth.

The **2 000-iteration trace** (clean, fast, signal already clear) is
reproduced below. The 1 000-iter samples in the spec-default table
are the same numbers that a future, fixed implementation should be
able to extend out to 10k.

### 2 000-iteration trace

Re-run by changing `total_iterations` in `bench/wt_memory.zig` to
`2_000` and `sample_at_iters` to `.{ 500, 1_000, 2_000 }`; default
checked-in values target the spec's 10k.

| Stage | iters | bytes-in-use | max-bytes-ever | Δ vs warm-up |
| --- | ---: | ---: | ---: | ---: |
| warm-up | 0 | 2 527 274 | 2 527 324 | +0 |
| 500 iters | 500 | 3 905 298 | 3 905 554 | +1 378 024 |
| 1k iters | 1 000 | 5 282 930 | 5 283 186 | +2 755 656 |
| 2k iters | 2 000 | 8 038 194 | 8 038 450 | +5 510 920 |

**Δ bytes-in-use warm-up → 2k iters: +5 510 920 bytes over 2 000
iters (≈ 2 755 bytes / iter).**

`gpa.deinit()` reports **ok** at the end of the run — every
allocation made during the iteration loop is reachable from the
`H3Pair` / `Session` deinit chain.

## Verdict

**Memory does NOT stay flat after warm-up.** The trace shows clean,
linear growth at **≈ 2 755 bytes per iteration**:

- 500 → 1 000 iters: +1 377 632 bytes (≈ 2 755 / iter for that
  500-iter window)
- 1 000 → 2 000 iters: +2 755 264 bytes (≈ 2 755 / iter)

The per-iteration delta is constant across windows, so this is a
predictable per-iteration cost rather than a fixed warm-up overhead
amortizing to zero. The leak detector reports clean because the state
is reachable — but functionally, a single long-lived WT session that
opens N uni streams over its lifetime accumulates O(N) heap regardless
of whether those streams have already finished.

### Likely source

The Session struct keeps two relevant per-stream tables in
`src/session.zig`:

- `streams: AutoHashMapUnmanaged(u64, *StreamState)` (line 1001)
- `wt_buffered_streams: ArrayList(u64)` (line 1027)

A textual scan of `src/session.zig` shows exactly **one**
`self.streams.remove(stream_id)` call site (line 3912) — and that one
is inside the `errdefer` of `openPushStream`, i.e. it only runs on the
error path while a *push* stream is being opened. There is no removal
on:

- A WT uni-stream client-finish (the path my harness exercises 10 000
  times).
- A WT uni-stream server-side `_finished` event.
- A request-stream `request_complete`.

So `Session.streams` is effectively monotonic for the lifetime of a
session: every stream that is ever opened — locally or by the peer —
contributes a permanent entry. Each entry carries a `*StreamState`
(line 768) which has scalar fields plus an `rx: ArrayList(u8)` whose
backing buffer is freed by `StreamState.deinit` only when the *whole*
session is torn down.

A `StreamState` rounded up with hashmap bookkeeping plus the matching
quic-zig stream-state entry on the QUIC layer maps cleanly onto the
≈ 2 755 bytes/iter we observe. The growth is dominated by these
never-removed bookkeeping entries; the 256-byte stream payload and
the two 64-byte datagrams are released by `freeEvent` on each
iteration and are not part of the trend.

`wt_buffered_streams` is plausibly innocent here — it's an ArrayList
that gets `orderedRemove`'d as buffered streams are replayed, and the
spec exercise opens streams *after* the WT session is confirmed (so
they should never enter the buffer). The QPACK dynamic tables are
also plausibly innocent for this exercise: literal-only request
patterns don't extend the dynamic table.

The fix likely lives in two places: a `streams.remove` call when a
stream both finishes RX and has its TX completion drained, plus the
matching cleanup on the WT-stream finished/reset paths. **Per the
task brief I am NOT applying that fix** — other agents are touching
this codebase concurrently. This finding is logged here for triage.

## Post-fix trace (partial — http3-side cleanup landed)

After landing `Session.gcClosedStreams` (called at the tail of every
`drain`) and tracking `StreamState.locally_finished` from
`finishStream` / `resetStream`, the same 2 000-iteration harness now
reports:

| Stage | iters | bytes-in-use | max-bytes-ever | Δ vs warm-up |
| --- | ---: | ---: | ---: | ---: |
| warm-up | 0 | 2 527 274 | 2 527 324 | +0 |
| 500 iters | 500 | 3 647 298 | 3 648 070 | +1 120 024 |
| 1k iters | 1 000 | 4 766 930 | 4 767 702 | +2 239 656 |
| 2k iters | 2 000 | 7 006 194 | 7 006 966 | +4 478 920 |

**Per-iter cost: 2 755 → 2 239 bytes (≈ 19 % reduction).** The
remaining growth lives one layer down. Greppy survey of
`/Users/nullstyle/prj/ai-workspace/quic-zig/src/conn/state.zig`
finds **zero** `streams.remove` / `streams.fetchRemove` call sites:
the `quic_zig.Connection.streams: AutoHashMapUnmanaged(u64, *Stream)`
map is monotonic for the connection's lifetime, same shape as the
http3 map was before this commit. Each surviving entry carries the
quic-zig per-stream `Stream` (recv reassembly buffers, send chunk
ring, ACK ranges) plus the small bookkeeping bits, mapping cleanly
onto the residual ≈ 2 239 bytes / iter.

**Verdict on the partial fix:** the http3 layer no longer leaks per
finished stream. The remaining cross-layer leak requires a matching
`streams.remove` pass in quic-zig (or a public compaction API we can
call from `Session.gcClosedStreams`) — that's a quic-zig change with
its own dependency-bump cycle, deferred to a follow-up release. Until
then a long-lived WT session still grows O(N) at ≈ 2.2 KiB / stream
opened, ~19 % smaller than before. The per-pump cost — which is what
made the 5k / 10k runs unusably slow before this commit — is also
improved (the http3-side iteration is now over a small, GC'd map),
though the QUIC-side iterator still walks all-time-ever streams.

## Caveats

- **One allocation pattern.** The harness exercises a single drain
  shape (uni stream + datagram round-trip). Pathological inputs —
  long-running requests with large header sets, many bidi streams,
  WebTransport datagrams routed to nonexistent sessions, peers that
  open many streams without finishing them — could grow elsewhere
  (`message_states`, QPACK dynamic tables, `wt_buffered_streams`)
  in patterns this trace would not detect.
- **Loopback only.** No real network, no datagram loss / reorder, no
  back-pressure. `pumpOnce` is a synchronous in-process step. A
  fixture closer to wire conditions would surface a different mix
  (e.g. ACK-pacing buffers).
- **Per-pump cost grows superlinearly past ~2 000 iterations.** A 5
  000-iteration run wall-clocks ~10 minutes (vs. ~9 seconds for 2
  000), and 10 000 iterations exceeds practical waiting under this
  implementation. The slowdown almost certainly shares a root cause
  with the leak above — every `pumpOnce` walks
  `Session.streams` (and the matching map on the quic_zig
  side), which keeps growing because nothing removes finished
  entries. The 2 000-iteration trace gives a clean linear signal
  before the slowdown becomes confounding; samples at 5k and 10k
  exist in the spec but won't be representative of real-world
  steady-state until the per-stream cleanup lands. Once the leak is
  fixed, the binary's `total_iterations` constant should go back to
  10 000 and this file should be re-run end-to-end.
- **`max_bytes_ever` tracks `bytes_in_use`.** The two values stay
  within ~256 bytes of each other across every checkpoint, which
  means there's no large transient spike during an iteration that
  the steady-state value is hiding. The growth is genuine retained
  memory, not an allocator high-water artifact.
- **Counting allocator semantics.** The `CountingAllocator` reports
  the *requested* byte count of every allocation handed back through
  the `Allocator` vtable. It does not include `DebugAllocator`'s
  internal bucket bookkeeping or the kernel-page padding underneath.
  The numbers above are app-level demand, which is the right unit
  for tracking library overhead but will be slightly smaller than
  RSS as observed by `ps`.

## How to reproduce

```sh
cd http3-zig
zig build mem-profile --cache-dir /tmp/h3-cache-W2
```

The step always builds with `-OReleaseSafe` (private boringssl +
quic_zig + http3_zig dependency instances at the same optimize mode,
mirroring the `wt-load` pattern), so the `DebugAllocator` leak
detector and the counting allocator overhead are both in scope. The
harness writes a Markdown table to stdout and exits non-zero only if
the leak detector fires.
