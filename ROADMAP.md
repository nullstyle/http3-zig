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
  push. Interop against foreign servers (quic-go, ngtcp2, lsquic, aioquic,
  and Chromium/curl) has skip-friendly harnesses under [`interop/`](interop/)
  but is not yet green in CI: standing up the real servers is open work, and
  third-party WebTransport currently stalls at the QUIC handshake (see
  [`docs/wt-third-party-interop.md`](docs/wt-third-party-interop.md)).

- **QPACK dynamic-table cross-implementation coverage.** The dynamic-table
  fixture corpus (RFC 9204 Appendix B exact bytes) is pinned in-tree; binding
  it to a second implementation is blocked on `quic-go/qpack` dynamic-table
  support or an agreed alternate peer.

- **WebTransport intermediary forwarding.** Endpoint-side flow-control capsule
  enforcement is in place; intermediary forwarding of `WT_MAX_DATA` /
  `WT_*_BLOCKED` capsules is not yet implemented.

- **Automated long-running fuzzing.** The per-push smoke corpus and
  coverage-guided `zig build test --fuzz` are wired; sustained long-running
  fuzz campaigns against a larger seeded corpus are not yet automated in CI.

- **Memory-budget enforcement polish.** Opt-in caps cover send buffers,
  outgoing capsules, session event queues, tracker bodies, decoded QPACK
  field sections, and the production preset; remaining per-buffer budgets are
  being extended toward a fully-bounded default posture.
