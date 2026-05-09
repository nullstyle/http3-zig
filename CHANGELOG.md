# Changelog

All notable changes to http3-zig are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

### Added

- **`SECURITY.md`** with private-disclosure address and 90-day SLA.
- **`CONTRIBUTING.md`** with build / test / interop instructions.
- **`LICENSE`** (Apache 2.0, matching sister project quic-zig).

### Changed (BREAKING)

- **WebTransport wire-format pin: draft-13 → draft-15.**
  http3-zig now tracks `draft-ietf-webtrans-http3-15` (July 2025
  revision). The visible knob: SETTINGS bootstrap moved from the
  numeric `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29` (draft-13) to the
  boolean `SETTINGS_WT_ENABLED = 0x2c7cf000` (draft-15).
  - `Settings.wt_max_sessions: ?u64` → `Settings.wt_enabled: bool`.
  - `ProductionOptions.wt_max_sessions` removed; the numeric
    session-count limit is no longer in the spec.
  - Server-side N+1 session-rejection enforcement removed
    (applications can still bound concurrent sessions in
    `Server.acceptWebTransport`).
  - Dual-peer interop in CI: webtransport-go (master pseudo-version
    pending a tagged release post-PR #254) + pywebtransport v0.17.1
    (the only Python facade currently shipping draft-15).

- **Removed `recordPeerDataReceived` from the public WT API.** The
  session auto-bumps `peer_data_received` as it surfaces
  `webtransport_stream_data` events; calling the legacy public
  helper double-counted and synthesized spurious
  `webtransport_flow_violated` events. Affected:
  `WebTransportClientStream.recordPeerDataReceived`,
  `WebTransportServerStream.recordPeerDataReceived`,
  `Session.webTransportRecordDataReceived`.

- **`buildRequestFields` now omits `:scheme` and `:path` for classic
  CONNECT** (`:method = "CONNECT"`, no `:protocol`) per
  RFC 9114 §4.4 ¶3. Extended CONNECT (with `:protocol`) is
  unchanged. Migration: callers that were passing `:scheme = "https"`
  + `:path = "/"` for classic CONNECT no longer need to clear them
  manually.

### Added (correctness)

- **HTTP/3 message validation hardening** (RFC 9114 §4 + RFC 9110 §6.5):
  - `content-length` is parsed and cross-checked against decoded
    body length; mismatched / duplicate / non-decimal values are
    rejected as `H3_MESSAGE_ERROR`. Closes a header-smuggling
    surface.
  - Empty `:authority` is now rejected (`MalformedAuthority`).
  - Classic CONNECT (`:method = "CONNECT"` without `:protocol`) is
    validated per spec: `:scheme` and `:path` MUST be omitted, and
    `:authority` MUST be present and non-empty.
  - Trailers reject `content-length`, `host`, `te`, plus the
    request-modifier set (`cache-control`, `expect`,
    `max-forwards`, `pragma`, `range`, auth-related).

- **WebTransport session-state hardening:**
  - `observeFin` no longer emits a phantom
    `webtransport_stream_finished` event for a stream whose
    `_opened` event was never produced (peer FINs after sending
    only the type byte but before the Session ID lands).
  - Per-session `received_drain` flag is set when the peer's
    `DRAIN_WEBTRANSPORT_SESSION` capsule arrives; further
    `openWebTransportUniStream` / `openWebTransportBidiStream`
    calls return the new `error.WebTransportSessionDraining`
    (draft-15 §5.5).
  - `Client.startWebTransport` and `Server.acceptWebTransport`
    eagerly check that the peer advertised `SETTINGS_WT_ENABLED`
    + `H3_DATAGRAM` + `ENABLE_CONNECT_PROTOCOL`; missing settings
    surface as `error.PeerDidNotEnableWebTransport` /
    `error.PeerSettingsNotReceived` before the request goes on
    the wire (draft-15 §9.2).

- **Resource-exhaustion caps (defense-in-depth):**
  - `Config.max_concurrent_peer_streams` (production default 1024)
    bounds the size of `Session.streams`. Peer-opened streams past
    the cap are rejected with `STOP_SENDING(H3_REQUEST_REJECTED)`
    and the new `error.PeerStreamLimitExceeded`. QUIC's MAX_STREAMS
    already provides per-direction caps; this is a session-layer
    knob covering the case where MAX_STREAMS is generous but
    HTTP/3 state shouldn't grow proportionally.
  - `Config.wt_max_buffered_bytes_per_stream` (production default
    64 KiB) bounds bytes a single peer-opened WebTransport stream
    holds in `state.rx` while waiting for its session to be
    confirmed under `BufferedStreamPolicy.buffer`. Streams that
    overflow get reset with
    `WEBTRANSPORT_BUFFERED_STREAM_REJECTED`.
  - `peer_data_received` accumulation now uses saturating addition
    so a long-lived flooded session can't wrap u64 and silently
    pass the receive-side flow-control gate.

### Fixed

- **Test fixtures invoke `markPathValidated` on the synthetic
  handshake.** `tests/integration/_fixtures.zig` and
  `tests/conformance/_h3_fixture.zig` shuttle TLS data through an
  in-process outbox→inbox shim instead of real datagrams; that
  bypasses RFC 9000 §8.1's anti-amplification budget validation.
  Fixture now flips the bit explicitly so `Session.close` can flush
  CONNECTION_CLOSE in the server-initiates-close case (was failing
  the `lifecycle_close` integration test).

### Tooling / infra

- **Dual-peer WebTransport interop** in
  [`.github/workflows/wt-interop.yml`](.github/workflows/wt-interop.yml):
  webtransport-go + pywebtransport, both pinned, both brought up on
  every scheduled run.
- **In-tree WT echo server** at
  [`interop/external_wt/server.zig`](interop/external_wt/server.zig)
  + per-push real-socket gate in
  [`.github/workflows/wt-interop-self-test.yml`](.github/workflows/wt-interop-self-test.yml).
- **Seeded fuzz corpus** at
  [`fuzz/corpus/`](fuzz/corpus/) (105 hand-curated inputs across 16
  codec targets); regenerated via `zig build seed-fuzz-corpus`,
  walked per-push by the [`fuzz`](.github/workflows/fuzz.yml)
  workflow.
