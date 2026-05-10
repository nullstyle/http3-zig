# WebTransport concurrent-session load baseline

This file records the published numbers from `zig build wt-load` —
the 100-concurrent-session WebTransport load test added in
`bench/wt_load.zig`. The intent is a baseline for spotting scaling
cliffs (sudden allocator jumps, drain-budget firing repeatedly,
mis-attribution under pressure), not a optimization target.

V1 of the multiplexing tests — `tests/integration/webtransport_multiplexing.zig`
— covered correctness for 5 sessions. This load test scales the same
per-session bookkeeping pattern to 100 sessions and exercises uni
streams, bidirectional datagrams, per-session `WT_MAX_DATA` capsule
emits, and explicit client-side `close(code, reason)` capsules.

## In-process disclaimer

The harness is **in-process**: `http3_zig.TransportLoopback` shuttles
QUIC packets between two `quic_zig.Connection` instances inside a
single Zig process. There are no kernel sockets, no real network, no
real loss / pacing / RTT. Wall-clock numbers reflect *library
overhead only* and are useful as a regression signal — not as a
wire-line throughput claim. Loss, when it shows up here, comes from
the QUIC datagram queue being smaller than the application's burst,
not from a real network layer.

## Workload

| Knob | Value |
| --- | ---: |
| Concurrent WebTransport sessions on one QUIC connection | **100** |
| Uni streams per session (client→server) | 5 |
| Stream payload | 1024 B (`session-{idx}-stream-{n}-…` prefix + ramp) |
| Datagrams per session | 10 (5 client→server + 5 server→client, alternating) |
| Datagram payload | 64 B (`{c2s\|s2c}-s{idx}-d{n}-…` prefix + ramp) |
| `sendMaxData` capsules emitted server-side | 100 (one per session, distinct value) |
| Client-side `close(0, "ok")` capsules | 100 (one per session) |
| **Totals** | 100 sessions, 500 uni streams, 1000 datagrams |

Transport-params tuning relative to the integration fixture:

- `initial_max_streams_bidi = 256` (vs fixture 16) — covers 100 CONNECT streams + slack.
- `initial_max_streams_uni  = 1024` (vs fixture 16) — covers 500 client-initiated WT uni streams + the 3 H3 control / QPACK uni streams + slack.
- `initial_max_data = 16 MiB` — the QUIC layer's `max_initial_connection_receive_window` ceiling.
- Loopback driver `max_datagrams_per_direction = 64` (vs `1` in `bench/wt_bench.zig`) so the in-process pump drains the workload in a reasonable iteration count.

## Hardware + Zig

- Apple M5 Max (`Mac17,6`), 18 cores, 128 GiB RAM.
- macOS Darwin 25.4.0 arm64.
- Zig `0.17.0-dev.256+04481c76c`.
- Built with `-Doptimize=ReleaseFast` (the build step pins this regardless of the top-level optimize so the numbers below are comparable across runs).

## Results (5-run sample)

| Run | Wall-clock (ms) | Pump iterations | C→S dgrams recv/sent | S→C dgrams recv/sent | Sessions closed |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 7.884 | 14 | 500/500 | 500/500 | 100/100 |
| 2 | 7.888 | 14 | 500/500 | 500/500 | 100/100 |
| 3 | 7.939 | 14 | 500/500 | 500/500 | 100/100 |
| 4 | 7.921 | 14 | 500/500 | 500/500 | 100/100 |
| 5 | 7.874 | 14 | 500/500 | 500/500 | 100/100 |

Median ≈ **7.89 ms**, range **7.87–7.94 ms** (variance < 1%).

### Per-op throughput (median run)

- Sessions/sec ≈ **12 650**
- Streams/sec ≈ **63 200** (1 KiB payload each, 5 per session)
- Datagrams/sec ≈ **126 400** (64 B payload each, 10 per session)

### App-level byte rate

- Total app payload: 500 × 1 KiB streams + 1000 × 64 B datagrams ≈ **564 KB**.
- Wall-clock ≈ 7.89 ms.
- App-payload throughput ≈ **71 MiB/s** (in-process, no kernel).

### Invariants observed

All five runs satisfied:

- `lastCloseError() == null` on both peers (no protocol-level CONNECTION_CLOSE).
- 100/100 sessions transitioned to `webTransportSessionState == .none` cleanly on both client and server.
- 500/500 `webtransport_stream_finished` events fired on the server side (all uni streams cleanly FIN'd).
- 500/500 client→server datagrams arrived attributed to the right session (verified via the `{dir}-s{idx}-d{n}-` self-attestation prefix encoded in each payload).
- 500/500 server→client datagrams ditto.
- Every per-session `sendMaxData(64 KiB + idx*1 KiB)` capsule was emitted with a distinct value (catching any aliasing in the per-session `WTSessionFlowState`).
- No errors other than the harmless retry path (`DatagramQueueFull` returned on first attempt for some datagrams under burst — the harness retries the same `dg_idx` next pump).
- No `WebTransportSessionDraining` / `WebTransportFlowControlExceeded` surfaced (no DRAIN was sent).

## Cliff observations

Nothing alarming surfaced at this workload. Detail observations below
are offered as a baseline against future runs:

1. **Pump count is small (14 iterations).** The loopback driver's `max_datagrams_per_direction = 64` lets a single step move ~96 KB worth of QUIC packets per direction. With ~564 KB of total application payload, 14 iterations cover the workload comfortably. If a future change inflates per-stream overhead or adds chatty capsules, this number is the early warning — a 2× jump for the same workload would say something has gotten talkier.

2. **Zero datagram loss observed in-process.** With `max_datagrams_per_direction = 64` and the harness retrying on `DatagramQueueFull`, the 1000 datagrams all delivered. An earlier draft of the harness (with `max_datagrams_per_direction = 4`) saw ~52% c2s and ~64% s2c delivery before timeout — every dropped datagram came from queue-full at the QUIC layer, not from the loss detector. **This is a sharp cliff:** if a future test hits the queue limit, dropped datagrams will silently stall the workload unless the harness counts `datagram_lost` events toward "drained" (which it now does).

3. **Per-session bookkeeping scales linearly.** Memory characteristics weren't profiled here (see `docs/memory-profile.md` for the long-running per-session leak detector); but the workload completes in ~7.9 ms with no observable per-iteration slowdown, so the per-session `WTSessionFlowState` allocator pattern (one `*WTSessionFlowState` heap allocation per session, kept in a hashmap keyed by session id) is fine at 100×.

4. **All 500 uni streams open in a single pump iteration.** No `WebTransportStreamLimitExceeded` retries fired — the WT layer's per-session `peer_max_streams_uni` is `null` (unlimited) when neither peer sends a `WT_MAX_STREAMS_UNI` capsule, so all 500 opens succeed before the first round-trip. This is the expected v0.1 behavior, but worth noting: under a future workload that explicitly advertises a tighter `WT_MAX_STREAMS_UNI`, the fast path here would degrade into a multi-pump retry loop.

5. **Session establishment is the long pole at this size.** ~7.9 ms wall-clock for 100 fresh CONNECT requests + 500 uni streams + 1000 datagrams + 100 closes works out to roughly 79 µs per session including its share of streams + datagrams + close. The single-session bench/wt_bench.zig session-establishment number is on the order of 10s of µs (see `docs/perf-baseline.md`), so most of this load test's wall-clock is spent on the establishment path multiplied by 100 — not on streams or datagrams.

## How to reproduce

```sh
zig build wt-load --cache-dir /tmp/h3-cache-W3
```

The build step pins the load test to ReleaseFast regardless of the
top-level `-Doptimize` flag. Invariants are checked on every step
(the harness returns explicit error tags rather than relying on
`assert`), so a regression that misses cross-session attribution will
surface as a failed `zig build wt-load`.

## Notes for future tightening

This is a baseline — we are deliberately not optimizing. Things
worth measuring next:

- Allocator high-water mark — wire a tracking allocator under the
  100-session run and report peak / per-session bytes.
- Per-event allocation counts — `webtransport_stream_data` clones the
  payload into the event union; at 1 KiB × 500 streams that's ~500 KiB
  of transient allocation. Cheap to amortize, possibly cheap to remove.
- Scaling beyond 100 sessions — at what session count does the QUIC
  stream id space, the WT registry hash map, or the datagram queue
  start producing visible cliffs? This baseline is the comparison
  point.
