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
  push. The WebTransport foreign-peer matrix now brings up pinned
  webtransport-go and pywebtransport peers in CI and is green on the v0.4.8
  line, but it remains advisory while third-party peer setup is still treated
  as flake-prone. HTTP/3 foreign-server coverage (quic-go, ngtcp2, lsquic,
  aioquic, Chromium/curl) has skip-friendly harnesses under
  [`interop/`](interop/) and remains future scope.

- **QPACK dynamic-table cross-implementation coverage.** The dynamic-table
  fixture corpus (RFC 9204 Appendix B exact bytes) is pinned in-tree; binding
  it to a second implementation is blocked on `quic-go/qpack` dynamic-table
  support or an agreed alternate peer.

- **WebTransport intermediary forwarding.** Endpoint-side flow-control capsule
  enforcement is in place; intermediary forwarding of `WT_MAX_DATA` /
  `WT_*_BLOCKED` capsules is not yet implemented.

- **Memory-budget enforcement polish.** Opt-in caps cover send buffers,
  outgoing capsules, session event queues, tracker bodies, decoded QPACK
  field sections, concurrent peer streams, and the adversarial-reachable
  session maps (tracked priorities, received push promises, pending
  WebTransport sessions) — all wired into the production preset, with
  per-request priority entries reclaimed when streams close. Remaining:
  continue extending per-buffer budgets toward a fully-bounded default
  posture.
