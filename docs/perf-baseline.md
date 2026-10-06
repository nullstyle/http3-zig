# http3-zig WebTransport baseline performance

These numbers establish a starting point for tracking
performance regressions and improvements in the WebTransport stack.
**They are baseline measurements, not optimization targets.** A future
change is good if it doesn't make these slower; we are not yet trying
to make them faster.

## What is measured

`bench/wt_bench.zig` (run via
`zig build bench -Doptimize=ReleaseFast`) drives an
in-process pair of `http3_zig.Session`s through
`http3_zig.TransportLoopback`. Each iteration is timed with
`std.Io.Clock.awake.now(io)` (monotonic). 10 warmup iterations are
discarded; 1000 measured iterations feed into p50/p99/mean/max.

Three operations:

1. **Session establish** — fresh QUIC handshake (TLS 1.3 +
   transport-parameter exchange) → SETTINGS exchange → Extended
   CONNECT (`startWebTransport` → server `acceptWebTransport`) →
   client observes a 200 status. Includes all per-iteration setup
   and teardown of QUIC + H3 + TLS state.
2. **Datagram RT (64 B)** — on a persistent, already-established
   session: `client.sendDatagram(64 bytes)` → server receives →
   `server.sendDatagram(64 bytes)` → client receives.
3. **Uni stream RT (1 KiB)** — on the same persistent session:
   `client.openUniStream()`, then `write(1 KiB)` + `finish()` on the
   returned `WebTransportStream` handle → server observes the
   `webtransport_stream_finished` event.

## Important caveat: in-process loopback, not network

The benchmark harness **does not use real sockets.** Both
`quic.Connection`s share an in-process buffer shim (the same one
the integration tests use). The timer therefore measures **library
CPU overhead only** — encoding, decoding, frame parsing, QPACK,
session bookkeeping. There is no kernel context switch, no NIC, no
RTT.

So:

- Session establish numbers reflect handshake CPU cost (BoringSSL
  handshake, QUIC packet processing, SETTINGS parsing, CONNECT
  framing). On a real WAN this would be dominated by RTT.
- Datagram RT measures QUIC datagram encode + decode + H3 datagram
  prefix.
- Stream RT measures QUIC stream frame encode + decode + WT framing.

For real-network numbers, see the WebTransport interop matrix
(`zig build wt-interop-matrix`).

## Hardware / build

| Field | Value |
| --- | --- |
| Host | Apple M5 Max, 18 cores |
| OS | macOS (Darwin 27.0.0), arm64 |
| Zig | 0.17.0 |
| quic-zig | 0.25.0 |
| Build mode | `ReleaseFast` (http3-zig; quic and BoringSSL are ReleaseSafe since 2026-10-06) |
| Cache dirs | project defaults (`.zig-cache`, `.zig-global-cache`) |
| Date | 2026-10-04 (Zig 0.17.0 + quic v0.25.0 pin move) |
| Iterations | 10 warmup + 1000 measured |

Reproduce with:

```bash
mise exec -- zig build bench -Doptimize=ReleaseFast
```

## Numbers

```
| Operation | p50 | p99 | mean | max |
| --- | ---: | ---: | ---: | ---: |
| Session establish | 128.79 µs | 164.75 µs | 130.63 µs | 198.83 µs |
| Datagram RT (64B) | 4.33 µs | 6.83 µs | 4.36 µs | 14.17 µs |
| Uni stream RT (1KiB) | 4.71 µs | 8.17 µs | 4.70 µs | 22.71 µs |
```

Raw nanoseconds (the format the bench prints — useful for diffing
against future runs):

```
| Operation | p50 ns | p99 ns | mean ns | max ns |
| --- | ---: | ---: | ---: | ---: |
| Session establish | 128792 | 164750 | 130628 | 198833 |
| Datagram RT (64B) | 4333 | 6833 | 4363 | 14166 |
| Uni stream RT (1KiB) | 4708 | 8167 | 4703 | 22708 |

The 2026-10-04 pin move (Zig 0.17.0-dev.1978 → 0.17.0, quic v0.19.0 →
v0.25.0), measured same-machine with both trees built ReleaseFast and
three alternating runs each (lowest p50 of each side; the table above
is one later run, verbatim): establish 128.7 →
127.8 µs (flat), datagram RT 5.96 → 4.08 µs (−32%), uni-stream RT
5.42 → 4.71 µs (−13%). The gain is in the transport; http3-zig's
code on these paths did not change. The previous published p50s were
122.29 / 5.67 / 5.25 µs (2026-09-03, Darwin 25.6.0, quic v0.19.0); the
establish row reads higher today on both pins, so compare same-day runs
only.

The 2026-09-03 allocation pass (zero-copy DATA/capsule stream writes,
reused datagram send scratch, static-table borrows in QPACK decode,
O(1) dynamic-table eviction, comptime static-table lookup buckets,
pre-sized Huffman output) moved the same-machine p50s from ≈126/6.0/5.75
to the numbers above (−3% establish, −5% datagram RT, −9% uni-stream
RT); first post-rebuild runs read ~5-8% hot and are discarded per the
lowest-of-runs convention below.
```

## Real-socket tier (`zig build bench-e2e`)

The numbers above are in-process. `bench/e2e.zig` runs a `quic.Server`
loop on a background thread and real QUIC clients over loopback UDP
(ReleaseSafe), so the packet path, the server's connection-ID demux,
and the kernel are in the loop. Recorded 2026-10-05 on quic v0.28.1 in
`bench/baselines/` (Linux: the CI run of `3c2f4c8`); allocation rows
updated for quic v0.29.0 (2026-10-06):

| Cell | macOS arm64 (M5 Max) | Linux x86_64 (CI runner) |
| --- | --- | --- |
| `h3_connect` (handshake, SETTINGS, GET, close) | 388/s, p50 2.9 ms | 901/s, p50 1.1 ms |
| `h3_get` (one connection) | 18,213/s, p50 51 us | 24,300/s, p50 40 us |
| `wt_session` (open + close on one connection) | 9,043/s, p50 109 us | 11,625/s, p50 84 us |
| `wt_datagram` (echo round trip) | 22,742/s, p50 41 us | 29,352/s, p50 34 us |
| `wt_uni` (uni-stream echo round trip) | 22,226/s, p50 43 us | 25,393/s, p50 40 us |
| allocations per connection (client / server) | 80 / 94 | 80 / 94 |
| allocations per GET (client / server) | 17 / 22 | 17 / 22 |
| allocations per WT session / datagram / uni stream (client) | 16 / 3 / 11.1 | 16 / 3 / 11.1 |
| client packets per connection (sent / received) | 8.0 / 7.0 | 8.0 / 7.0 |
| client bytes per connection (sent / received) | 1,540 / 2,592 | 1,540 / 2,592 |
| client bytes per GET (sent / received) | 55 / 48 | 55 / 48 |

History: the GET rows fell from 2 packets per GET (and, on macOS,
~123 us p50) when the bench client began to read before `tick` (its
ACK now rides on the next request). quic v0.28.0 added one allocation
per connection on each side (74/88 before): the ring that remembers how
reclaimed streams ended (`streamRecvEnd`, about 10 KiB, made on the
first stream reclaim). quic v0.29.0 added five more (75/89 -> 80/94): its
sent-packet tracker and CRYPTO buffers now grow on demand, and a
connection holds about 0.8 MB less (the in-process profile's
two-connection warm-up: 2.03 MB -> 0.41 MB).

What CI gates (`bench/baselines/README.md`): the allocation counts
(identical on both systems; one new allocation per operation fails),
packets and bytes (25%), retained bytes per request, and the memory
soak. Not the times: the macOS loop waits on a 1 ms receive timer more
often, so its times are mostly a measure of that timer, and on a
shared runner they move with nothing changed.

## Notes on variance

p50 was stable across re-runs (within ~5%). p99 / max jitter is
larger and partly driven by macOS scheduler noise on a non-quiesced
host — taking the lowest of three runs is a reasonable cleanup
strategy for regression comparisons. Comparable medians, not
worst-case tails, are the meaningful regression signal.

The Debug-mode run is tens of times slower than ReleaseFast (for
example, session establishment is roughly 7.3 ms rather than
~0.15 ms) — never publish Debug numbers, they are misleading.

## What to do with these numbers

- **CI regression check.** A future commit that bumps p50 by more
  than ~20% on this hardware is worth investigating.
- **Rough cost model.** If you're sketching a feature that involves
  N WT datagrams, multiply by ~4-5 µs per RT for an order-of-magnitude
  CPU estimate.
- **Do not** treat these as latency commitments to consumers. Real
  network paths are dominated by RTT, not by these CPU costs.
