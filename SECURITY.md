# Security policy

http3-zig is a network-protocol library that parses untrusted bytes
from peers (HTTP/3 frames, QPACK field sections, capsules, datagrams,
WebTransport stream prefixes) over QUIC. We treat memory-safety
issues, panics on adversarial inputs, and resource-exhaustion vectors
as security-relevant.

## Reporting a vulnerability

**Do not file public GitHub issues for vulnerabilities.** Send a
private report to `nullstyle+http3-zig-security@gmail.com` with:

- A clear description of the issue.
- Steps to reproduce (a minimal hand-crafted byte sequence is ideal).
- The affected revision (commit SHA or tag).
- Optionally, your suggested mitigation.

I'll acknowledge receipt within 7 days. The intended disclosure
timeline is **90 days** from acknowledgement to coordinated public
disclosure. If a fix lands earlier, public disclosure follows.

## Scope

In scope:
- Memory-safety bugs (use-after-free, out-of-bounds, double-free,
  data races) reachable from peer-controlled input.
- Panics or unreachable-reached on adversarial wire-format inputs.
- Algorithmic complexity attacks (e.g. quadratic blowup on a
  malicious header set).
- Unbounded resource consumption (memory, allocator pressure,
  internal state map growth) attributable to peer-controlled input
  beyond the documented `Config` caps.
- TLS / QUIC handshake oversights specific to this library
  (note: anything in sister project [`quic-zig`](https://github.com/nullstyle/quic-zig)
  or [`boringssl-zig`](https://github.com/nullstyle/boringssl-zig)
  belongs in those repos).

Out of scope:
- Issues reachable only with a misconfigured `Config` that disables
  one of the `production()` defaults.
- Issues that depend on a malicious / modified Zig compiler or
  build environment.
- Issues in third-party WebTransport peer implementations
  (`webtransport-go`, `pywebtransport`, ...) used in interop
  testing — please file those upstream.
