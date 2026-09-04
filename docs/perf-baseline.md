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
| OS | macOS (Darwin 25.6.0), arm64 |
| Zig | 0.17.0-dev.1978+c961124d9 |
| quic-zig | 0.19.0 |
| Build mode | `ReleaseFast` |
| Cache dirs | project defaults (`.zig-cache`, `.zig-global-cache`) |
| Date | 2026-09-03 |
| Iterations | 10 warmup + 1000 measured |

Reproduce with:

```bash
mise exec -- zig build bench -Doptimize=ReleaseFast
```

## Numbers

```
| Operation | p50 | p99 | mean | max |
| --- | ---: | ---: | ---: | ---: |
| Session establish | 153.25 µs | 242.54 µs | 159.90 µs | 292.79 µs |
| Datagram RT (64B) | 6.21 µs | 9.96 µs | 6.28 µs | 31.04 µs |
| Uni stream RT (1KiB) | 6.54 µs | 11.13 µs | 6.64 µs | 67.29 µs |
```

Raw nanoseconds (the format the bench prints — useful for diffing
against future runs):

```
| Operation | p50 ns | p99 ns | mean ns | max ns |
| --- | ---: | ---: | ---: | ---: |
| Session establish | 153250 | 242541 | 159898 | 292792 |
| Datagram RT (64B) | 6208 | 9959 | 6280 | 31041 |
| Uni stream RT (1KiB) | 6542 | 11125 | 6643 | 67291 |
```

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
  N WT datagrams, multiply by ~6 µs per RT for an order-of-magnitude
  CPU estimate.
- **Do not** treat these as latency commitments to consumers. Real
  network paths are dominated by RTT, not by these CPU costs.
