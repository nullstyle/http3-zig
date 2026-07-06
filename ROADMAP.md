# http3-zig Roadmap

http3-zig is a pre-1.0 HTTP/3 stack over `quic-zig` and `boringssl-zig`. The
normative core — RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 9218 (Extensible
Priorities), RFC 9220 (extended CONNECT), and RFC 9297 (HTTP Datagrams /
capsules) — is implemented, along with WebTransport
(draft-ietf-webtrans-http3-15), WebSocket-over-HTTP/3 (RFC 6455 framing over
the RFC 9220 extended-CONNECT bootstrap), and CONNECT-UDP / MASQUE helpers.

See the [README](README.md) for the current capability surface and the
[CHANGELOG](CHANGELOG.md) for release history.

## Planned

- **Third-party interop.** The in-tree self-tests — HTTP/3 and WebTransport,
  http3-zig client ↔ http3-zig server over a real UDP socket — gate every
  push. WebTransport advisory CI brings up pinned webtransport-go and
  pywebtransport peers. HTTP/3 advisory CI now brings up a pinned
  quic-go/http3 server and a pinned aioquic server, then drives both with the
  public external-H3 client. Both foreign-peer matrices remain advisory while
  third-party setup is still treated as flake-prone; expanding H3 coverage to
  ngtcp2, lsquic, and curl/Chromium remains future scope.

- **QPACK dynamic-table cross-implementation coverage.** The dynamic-table
  fixture corpus (RFC 9204 Appendix B exact bytes) is pinned in-tree and now
  exported as `interop/qpack_dynamic/fixtures.json` for implementation-neutral
  peer harnesses; `zig build qpack-dynamic-interop` checks that the committed
  JSON stays byte-for-byte in sync with the Zig vectors. Binding the corpus to
  a second implementation remains blocked on `quic-go/qpack` dynamic-table
  support or an agreed alternate peer.

- **WebTransport intermediary forwarding.** WT control-capsule forwarding
  helpers are in place for intermediaries that already own both CONNECT
  streams, and `examples/webtransport_proxy.zig` now shows the application
  datapath for stream-copy loops, DATAGRAM routing, and CONNECT FIN/reset
  policy across two in-process H3 pairs. A reusable full proxy remains out of
  scope unless a future release chooses an explicit policy layer.

- **Embedding cookbook.** [`docs/embedding-guide.md`](docs/embedding-guide.md)
  now documents the application-owned event-loop shape, session/event
  ownership rules, raw-event vs runner tradeoffs, and the backpressure signals
  embedders need to wire into custom servers, clients, proxies, and test
  harnesses. The guide points at runnable facade, streaming-body, and
  WebTransport proxy examples. Remaining: add a focused graceful GOAWAY /
  shutdown example, and consider a socket-backed skeleton if quic-zig grows a
  stable public listener/dialer helper for examples.

- **Memory-budget enforcement polish.** Opt-in caps cover send buffers,
  outgoing capsules, session event queues, tracker bodies, decoded QPACK
  field sections, concurrent peer streams, adversarial-reachable session maps
  (tracked priorities, received push promises, pending WebTransport sessions),
  and both per-stream and aggregate pre-confirmation WebTransport buffering.
  See [`docs/production-limits.md`](docs/production-limits.md). The
  `examples/bounded_body_sink.zig` and `examples/streaming_upload.zig`
  raw-event examples now demonstrate caller-owned streaming body storage plus
  send-side `canWrite` checks in both response and request directions.
  Remaining: consider higher-level helpers where they do not hide application
  semantics.
