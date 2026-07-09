# Changelog

All notable changes to http3-zig are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

### Added

- Added `examples/udp_server.zig` — the production HTTP/3 server skeleton:
  real UDP socket, multi-connection accept via `quic_zig.Server` +
  `transport.runUdpServer`, one `Session` (production preset) + facade +
  `ServerRunner` + `TransportEndpoint` per connection hung off
  `Slot.user_data` (created on first sight in the `on_iteration` hook),
  ordered teardown in `on_connection_will_close` (the hook runs inside
  `reap` while `slot.conn` is still valid — the pattern that makes reap
  safe for a borrowing `Session`), and a two-phase SIGINT shutdown
  (per-session `sendGoaway(gracefulGoawayId())`, pump until
  `openRequestStreamCount() == 0` or a drain deadline, then hand off to
  the loop's CONNECTION_CLOSE grace window).
- Added `examples/udp_client.zig` — the real-socket HTTP/3 client:
  `quic_zig.Client.connect` (system trust store by default, `--insecure`
  for self-signed demos), `transport.runUdpClient`, the request gated on
  `handshakeDone()`, response assembly via `ClientRunner`, and a clean
  H3_NO_ERROR close. Interops with `examples/udp_server.zig`.
- Added `examples/udp_smoke.zig` + `zig build run-udp-smoke` — one-process
  real-loopback proof of the pair (server loop on a background thread,
  client GET / against an ephemeral port, non-zero exit unless a 200 with
  the exact expected body round-trips); wired into CI on the Ubuntu Debug
  leg after `run-examples`.
- Added `TransportEndpoint.advance` (delegates to `Connection.advance`):
  the client bootstrap step real-network embedders need to emit the first
  ClientHello — `quic_zig.Client.connect` defers it for 0-RTT staging, and
  loopback tests use the in-process peer shim instead. Documented as pump
  order step 0 in the embedding guide and pinned in the public-API smoke.
- Added embedding-guide sections for multi-connection accept ("Accepting
  Connections": `quic_zig.Server` owns accept/demux/Retry/rate limits;
  init per-slot sessions in the `on_iteration` hook, deinit in
  `on_connection_will_close` before reap destroys the connection),
  clocks and wakeups (one monotonic `now_us` domain owned by the
  `runUdp*` loops; open-coded loops size poll timeouts with
  `nextTimerDeadline`, never wall-clock), and a 0-RTT status note
  (transport-level 0-RTT is end-to-end in quic-zig 0.9.0, but http3-zig
  has no blessed 0-RTT request path yet — HTTP/3 early data is
  unsupported/untested and requests before `handshakeDone()` are
  undefined; tracked as future work).
- Stated the config posture prominently in the README and embedding
  guide: `SessionConfig.production(.{})` is the deployment posture; the
  bare `.{}` defaults are a compatibility posture with unbounded buffers.
- Added `Session.highestPeerRequestStreamId` and `Session.gracefulGoawayId`
  so a server can send the RFC 9114 §5.2 "covers nothing new" GOAWAY id
  (highest observed client request stream + 4, or 0 when none was seen;
  clamped to a previously sent GOAWAY) without hand-tracking stream ids
  from drained events. The client role gets the symmetric push-id form.
  `examples/graceful_shutdown.zig` now derives its GOAWAY id from the
  accessor instead of hardcoding `4`.
- Added `Session.openRequestStreamCount` and `Session.openRequestStreams`
  (yielding `OpenRequestStream { stream_id, last_event_us }`) so shutdown
  orchestration can poll `shutdownState() == .draining` plus a zero open
  count as the drain-complete condition, and request-deadline enforcement
  can walk in-flight exchanges without mirroring stream lifecycle in an
  application map. Per-stream `last_event_us` is stamped at stream
  creation and at the single event-emission choke point, in the same
  clock domain as the `now_us` the embedder feeds the transport.
- Added an optional `alpn` field to the client/server `TlsOptions` so
  WebTransport-only or multi-protocol deployments can override the
  default `"h3"` ALPN without dropping to a raw boringssl context;
  existing callers compile unchanged.
- Added embedding-guide sections for the session-derived shutdown shape,
  request deadlines, and certificate rotation (new boringssl context for
  new connections — BoringSSL up-refs `SSL_CTX` per `SSL_new`, so live
  connections finish on the old one — with
  `quic_zig.Server.replaceTlsContext` as the integrated wrapper path).

### Changed

- Blessed the session-bound `Session.clearEvents` as the recommended
  event-cleanup call (it binds the session allocator implicitly, closing
  the mismatched-allocator trap in the free-standing helpers) and
  standardized every example and the docs on it; the free-standing
  `http3_zig.clearEvents` / `deinitEvents` forms now document the trap
  and remain for contexts without a session pointer.

### Fixed

- Fixed the drain loop resurrecting streams that `gcClosedStreams` had
  already reclaimed: quic-zig keeps yielding a finished stream until its
  own stream GC reaps it, and the recreated blank `StreamState` emitted a
  duplicate `stream_finished` event and then lingered as a permanently
  half-closed entry (its `locally_finished` flag is unrecoverable after
  the reclaim). The drain loop now skips iterator entries with no
  http3-side state whose transport recv half is in a post-read terminal
  state (`data_recvd` / `data_read` / `reset_read`) — everything for such
  a stream was already surfaced through the reclaimed state.

## [0.4.9] - 2026-07-09

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19.

### Changed

- Exported the shared `quic_zig` and `boringssl` module instances from
  build.zig — consumers can now `dep.module("quic_zig")` /
  `dep.module("boringssl")` — and re-exported them in the root as
  `http3_zig.quic_zig` / `http3_zig.boringssl`. The embedding API is
  quic_zig-typed (`Session.init` takes a `*quic_zig.Connection`), and
  previously no supported path existed for an out-of-tree consumer to name
  those types with the correct module identity.
- Added an out-of-tree consumer smoke package (`tools/consumer-smoke/`)
  that depends on http3-zig like a real application and compile-asserts
  the exported-module type identity; runs in CI.
- Fixed the cosmetic quic_zig `build_options` version handed to the
  recreated module (was a stale "0.6.0"; now matches the pinned v0.7.5
  tag) and extended `tools/check-boringssl-pin.sh` to lint it against the
  build.zig.zon pin so it cannot drift again.
- Corrected the README Zig-version claim (0.16.0 → 0.17.0-dev master with
  the verified floor in `build.zig.zon`), replaced the inaccurate
  "no extra wiring is required" install note with real module-wiring
  guidance, and added a "Consuming From Your Own Project" section to the
  embedding guide.
- Added WebTransport control-capsule forwarding helpers on client/server WT
  stream handles, with two-hop intermediary coverage for MAX_DATA, BLOCKED,
  DRAIN, unknown, and CLOSE capsule behavior.
- Added a runnable WebTransport proxy datapath example that forwards WT
  capsules, DATAGRAMs, substream data, FIN, and resets across two in-process
  HTTP/3 pairs while keeping proxy policy application-owned.
- Added advisory HTTP/3 foreign-peer coverage against pinned `quic-go/http3`
  and aioquic servers, with local peer scripts, CI jobs, and status docs.
- Added a committed JSON manifest and exporter for the RFC 9204 Appendix B
  dynamic QPACK fixture corpus, with the in-tree runner checking for drift
  between the neutral manifest and the Zig vectors.
- Added a bounded body sink loopback example showing raw
  `RequestEvent` / `ResponseEvent` consumption with caller-owned response-body
  storage and send-side `ResponseWriter.canWrite` checks.
- Added a manual pump GET example showing the QUIC `tick` / `poll` /
  `handle` plus HTTP/3 `drain` order without `TransportLoopback`.
- Added an observability metrics example showing `ObservabilityHooks` and
  `Metrics` snapshots around a real request/response loop.
- Added a request reset lifecycle example showing a client `RequestWriter`
  reset surfacing as a typed server-side peer reset event.
- Added a tracked HTTP/3 DATAGRAM example showing bidirectional send IDs and
  ACK-event correlation over a CONNECT stream.
- Added a streaming upload loopback example showing client-side
  `RequestWriter.canWrite` checks and server-side raw request-body budgeting.
- Added an embedding guide documenting event-loop integration, event ownership,
  raw-event vs runner tradeoffs, backpressure signals, and shutdown shape.
- Added a graceful GOAWAY shutdown loopback example showing an accepted request
  completing while the client's next request is rejected by the peer GOAWAY
  limit.
- Added aggregate `examples` / `run-examples` build steps and a CI gate that
  runs the in-process embedding cookbook on Ubuntu.
- Added public API smoke coverage for the documented stable embedding surface,
  including the transport-driver helpers, a standalone `zig build check-api`
  audit target, and a named CI gate.
- Added `TransportStepStats.madeProgress()` for in-process examples and test
  harnesses that pump until a transport loop goes idle.
- Updated the loopback GET example to use `TransportStepStats.madeProgress()`
  as an explicit stuck-loop guard.
- Fixed `TransportLoopback.step` stats so `handled_datagrams` matches the
  datagrams relayed to the peer during the step.
- Added `TransportStepStats.accumulate()` so explicit test harness loops can
  collect aggregate packet/event counts without duplicating counter math.
- Added `deinitEvents` / `clearEvents` helpers, plus session-bound
  `freeEvents` / `clearEvents` methods, so embedders can release drained event
  batches without hand-rolled cleanup loops.
- Added `TransportEndpoint.clearEvents()` so endpoint-based event loops can
  release the attached session event batch through the same helper that drained
  it.
- Added root `RequestEvent` / `ResponseEvent` aliases and refreshed embedding
  docs/examples to use the current event cleanup helpers.
- Added `RunnerBatchStats.madeProgress()` and `accumulate()` so runner-based
  harnesses can detect and aggregate application event activity without
  duplicating counter math.
- Added `wt_max_total_buffered_bytes` to cap aggregate pre-confirmation
  WebTransport buffering under `BufferedStreamPolicy.buffer`; production
  presets default it to 4 MiB and tests cover the aggregate cap.

## [0.4.8] - 2026-07-05

### Fixed

- Raised the per-push `h3-interop-self-test` timeout so fresh CI runners can
  finish compiling the in-tree HTTP/3 interop binaries instead of cancelling
  during the build step.

## [0.4.7] - 2026-07-05

### Fixed

- Updated the boringssl pin checker to understand the quic-zig `git+https`
  tag pin used for v0.7.5, keeping CI's pre-build dependency alignment check
  green.

## [0.4.6] - 2026-07-05

### Changed

- Repointed to `quic-zig` v0.7.5, carrying the pinned quic-go interop
  output fix and Windows CI test-harness cleanup while keeping the
  `boringssl-zig` v0.6.4 pin aligned.

## [0.4.5] - 2026-07-05

### Fixed

- Fixed the in-tree WebTransport self-test completion race. The harness now
  treats a post-close datagram echo as proof that the exchange flushed, keeps
  the server-side session handle through same-batch close/data ordering, and
  gives the server a short post-completion drain window before exit.

## [0.4.4] - 2026-07-05

### Fixed

- Raised the per-push `wt-interop-self-test` timeout so current CI runners
  can finish compiling the WebTransport self-test binaries instead of
  cancelling during install.

## [0.4.3] - 2026-07-05

### Changed

- Repointed to `quic-zig` v0.7.2 and `boringssl-zig` v0.6.4. This keeps
  the 0.7.x hardening line while carrying the Windows QNS build fixes,
  BoringSSL Windows macro hygiene/no-asm fallback, and Winsock linking.

## [0.4.2] - 2026-07-05

### Changed

- Repointed to `quic-zig` v0.7.1 and `boringssl-zig` v0.6.2. This keeps
  the 0.7.0 transport hardening while avoiding CI failures from the
  BoringSSL googlesource tarball endpoint and the stale boringssl-zig
  consumer example build API.

## [0.4.1] - 2026-07-05

### Added

- **Opt-in eager reclaim of peer-RESET streams.** New
  `Config.reclaim_peer_reset_streams` (default `false`). A peer RESET leaves a
  bidirectional request/response stream half-closed — receive side terminal,
  local send side still open — so its `StreamState` lingers in the `streams`
  map (bounded by `max_concurrent_peer_streams`, but never released) until the
  local side closes. When enabled, a peer RESET tears the local side down
  immediately and the per-drain GC reclaims the entry the same pass the
  `stream_reset` event is surfaced. Deliberately narrow: peer FIN is *not*
  reclaimed (a server legitimately keeps responding after the client's request
  FIN), and referencing the stream id after its `stream_reset` event with this
  on is a use-after-reclaim.
- **WebTransport initial flow-control SETTINGS (draft-ietf-webtrans-http3-15
  §9.2).** `SETTINGS_WT_INITIAL_MAX_DATA` / `_STREAMS_UNI` / `_STREAMS_BIDI`
  are now emitted, parsed, and wired into per-session flow control end to
  end — previously they existed only as unused constants. Set
  `ProductionOptions.wt_initial_max_data` / `wt_initial_max_streams_uni` /
  `wt_initial_max_streams_bidi` (or the corresponding `Settings` fields) to
  grant peers initial per-session credit, so a WebTransport session opens
  with limits already in force instead of waiting for the first
  `WT_MAX_DATA` / `WT_MAX_STREAMS` capsule. Each side's advertised values
  become the receive-side limits it enforces; the peer's advertised values
  gate its sends. Unset (`null`, the default) advertises nothing and
  preserves the prior capsule-only behavior — no new enforcement unless you
  opt in.

### Changed

- Repointed the transport dependency to the tagged `quic-zig` v0.7.0
  hardening release and the `boringssl-zig` v0.6.1 tag, keeping the
  cross-repo BoringSSL pin byte-for-byte identical while pulling in the
  strict persisted 0-RTT formats, sanitizer propagation, and pinned
  quic-go CI scaffolding.

### Fixed

- **Real-network WebTransport interop client now drives the QUIC
  handshake.** `interop/external_wt/client.zig`'s pump loop was
  missing an explicit `quic_zig.Connection.advance()` call, so the
  TLS state machine never produced a ClientHello and `poll()` had
  nothing to emit. Symptom: `wt-interop-self-test` and the third-party
  `wt-interop` matrix both timed out at phase 1 with
  `SettingsExchangeTimedOut`. After this fix the self-test progresses
  cleanly through phase 1 (SETTINGS), phase 2 (CONNECT), and phase 3
  (datagram + uni stream + CLOSE_WT). With the quic-zig v0.6.1 transport
  fix, the full WebTransport flow now completes against webtransport-go;
  the remaining issue is a post-success harness clean-shutdown timeout.
  See [`docs/wt-third-party-interop.md`](docs/wt-third-party-interop.md).
  The third-party matrix step is `continue-on-error: true` so it doesn't
  block merges.

- **Real-network HTTP/3 interop client now drives the QUIC handshake.**
  `interop/external_h3/client.zig` had the same gap as the WebTransport
  client: its pump loop never called `quic_zig.Connection.advance()` (so
  no ClientHello was ever emitted) or `h3.start()` (so the control stream
  and SETTINGS were never opened). Both interop clients also still used
  `Allocator.dupeZ`, renamed to `dupeSentinel` in the tracked Zig
  toolchain. Fixed all three; the client now completes a full HTTP/3
  request/response against the in-tree `curl-h3` server over loopback.

### Security (hardening)

- **Capped four adversarial-reachable session maps** a hostile peer could
  grow without bound: `received_push_promises`, `request_priorities`,
  `push_priorities`, and `wt_pending_sessions`. New `Config` caps
  (`max_tracked_priorities`, `max_tracked_push_promises`,
  `max_pending_wt_sessions`) are wired into the production presets
  (1024/256/256). Priority floods drop the excess update (advisory,
  RFC 9218 §7); push-promise and WebTransport-session floods close with
  H3_EXCESSIVE_LOAD.

### Changed (BREAKING)

- **`Config` naming + type consistency (pre-1.0 cleanup).**
  - `qpack_huffman` → `enable_qpack_huffman` and `open_qpack_streams` →
    `enable_qpack_streams`, aligning on/off toggles under the `enable_`
    prefix used by `enable_connect_protocol` / `enable_datagram` /
    `enable_webtransport`.
  - `Config.max_field_section_size` (and the `Client.Config` /
    `Server.Config` / message-codec mirrors) is now `?u64` instead of
    `?usize`, matching the wire type in `Settings`. On 64-bit targets this
    is source-compatible for integer-literal callers.

### Removed (BREAKING — post-deprecation cleanup)

- **`finishSend` removed from six wrapper types.** The v0.3
  deprecation cycle is complete. Affected types — each kept its
  canonical `finish` method:
  - `WebTransportClientStream`, `WebSocketClientStream`,
    `ConnectUdpClientStream`
  - `WebTransportServerStream`, `WebSocketServerStream`,
    `ConnectUdpServerStream`

  Migration: one-character rename in callers (`finishSend()` →
  `finish()`).

- **`WTStreamDirection` removed.** v0.3 made it an alias for
  `webtransport.StreamKind`; v0.4 deletes the alias entirely. The
  canonical type is `webtransport.StreamKind` (re-exported as
  `WebTransportStreamKind`). Internal session-machine signatures
  migrated to the canonical name.

### Added (test infrastructure)

- **30 new property-fuzz corpus seeds** at
  `fuzz/corpus/wt-interleaved/21-..50-..` (corpus is now 50 seeds,
  was 20). Categories: multi-stream interleaving (5),
  datagram bursts including pre-SETTINGS / post-CLOSE_WT (5), capsule
  races (`WT_MAX_DATA` / `WT_MAX_STREAMS` / `WT_DATA_BLOCKED`
  arriving close together) (5), DRAIN-then-activity (3), aborted
  sequences (RESET at 5 lifecycle points) (5), extreme sizes (3),
  borderline UTF-8 (2), plus 2 long mixed-op sequences. Zero crashes
  in the harness sweep.

- **CI workflow:** `.github/workflows/wt-interop.yml` matrix step now
  carries `continue-on-error: true`. The per-push real-socket gate
  (`wt-interop-self-test.yml`) remains hard-gating; third-party
  interop is advisory until the gap doc's investigation lands.

- **HTTP/3 interop self-test** (`.github/workflows/h3-interop-self-test.yml`
  + `interop/external_h3/self_test.sh`): the HTTP/3 counterpart to the
  WebTransport self-test. Brings up the in-tree `curl-h3` server on a real
  UDP socket and drives it with the in-tree `external-h3` client — a full
  handshake plus request/response using only http3-zig binaries (GET
  `/hello` and POST `/echo`), gating the real-socket pump path the
  in-process tests don't reach.

### Performance / correctness (memory)

- **`Session.streams` is now garbage-collected at the tail of every
  `drain`.** Previously the per-stream `StreamState` map was effectively
  monotonic — a long-lived session that opens many streams accumulated
  O(N) heap whether or not those streams had finished. New mechanism:
  `StreamState.locally_finished` flips when `finishStream` /
  `resetStream` runs, paired with the existing `recv_finished` /
  `recv_reset_seen` flags. `Session.gcClosedStreams` removes any
  StreamState whose `isFullyClosed()` returns true (peer-uni: receive
  side closed; local-uni: locally_finished; bidi: both). Iteration
  safety via fixed-size 128-id batch buffer; surplus rolls to the next
  drain. Per-iteration cost in the long-running profile dropped from
  ≈ 2 755 → ≈ 2 239 bytes (≈ 19 % reduction).
  - **Caveat (v0.4 follow-up):** the residual ~2 239 B/iter lives in
    the underlying `quic_zig.Connection.streams` map which has no
    cleanup of its own. A matching pass in quic-zig (or a public
    compaction API we can call from here) is the cross-repo follow-up.
    Documented in [`docs/memory-profile.md`](docs/memory-profile.md).

### Added (test infrastructure)

- **`bench/wt_memory.zig` + `zig build mem-profile`** — long-running
  WebTransport session profiler that runs N iterations of a fixed
  unit of work (open uni stream + 256 B + finish + datagram round-trip
  + drain to quiescence) and reports `bytes_in_use` / `max_bytes_ever`
  at three checkpoints. Wraps a 0.16 `DebugAllocator` with a custom
  `CountingAllocator`. ReleaseSafe build keeps allocator safety on for
  leak detection. See [`docs/memory-profile.md`](docs/memory-profile.md).

- **`bench/wt_load.zig` + `zig build wt-load`** — concurrent-session
  load test exercising N parallel WebTransport sessions on one QUIC
  connection. Establishes the dispatch routing is correct and surfaces
  any hidden cross-session contention. See
  [`docs/load-baseline.md`](docs/load-baseline.md) for the baseline
  numbers (M5 Max, ReleaseFast, 100 sessions: 7.89 ms median,
  ≈ 12.6 k sessions/sec).

- **`fuzz/wt_interleaved.zig` + `fuzz/wt_interleaved_main.zig`** —
  property-based fuzz harness that interprets random bytes as a
  sequence of WebTransport operations (open / write / finish / reset /
  datagram / capsule) and runs them on an H3Pair. 20 hand-written
  corpus seeds at `fuzz/corpus/wt-interleaved/`. Wired into `build.zig`
  with the standard fuzz-target pattern. Zero panics surfaced on the
  initial sweep — but the harness is the actual deliverable; the seeds
  are the floor, not the ceiling.

### Documentation

- **README:** new `## Datagram sends` and `## Stream lifecycle` index
  sections (per V7 narrowing rec #2 and #3). Each is a short
  decision-tree pointing at the canonical methods.

- **Doc comments** on `WebTransportClientStream.requestWriter()` /
  `WebTransportServerStream.responseWriter()` warning that
  `datagramCapsule` / `datagramContextCapsule` invoked through the
  underlying writer are NOT valid WebTransport sends (per V7 rec #6).

- **Tracker doc clarification** that `ResponseTracker` /
  `RequestTracker` / `PushedResponseTracker` cover the CONNECT-message
  body only — they do not accumulate WebTransport substream data,
  which surfaces via `webtransport_stream_data` events (per V7 rec #4).

### Added (correctness)

- **`Session.observeWebTransportCapsule` is now tolerant of just-torn-down
  sessions.** A capsule that arrived on the wire BEFORE a close
  (CLOSE_WEBTRANSPORT_SESSION or implicit FIN of CONNECT) often surfaces
  to the application AFTER the session's local state has been
  destroyed — a single drain pass emits the body bytes and the close
  event together. Calling `observeCapsule` for a `.none` session now
  returns silently rather than `Error.UnknownWebTransportSession`. The
  capsule's value is lost (no flow state to fold it into) but the
  application's drain loop doesn't crash mid-close. Regression:
  `WebTransport: CLOSE_WT capsule interleaved with WT_MAX_DATA`.

- **`gateWebTransportStreamOpen` distinguishes `.none` from `.pending`.**
  Previously a null lookup in `webTransportFlowMut` was treated as a
  silent no-op (allowing opens to silently succeed against a dead
  session id). The gate now explicitly switches:
  - `.none` → `Error.UnknownWebTransportSession` (caller bug — session
    never existed or was torn down)
  - `.pending` → allow, gating not applicable yet (bootstrap race —
    application is opening streams before the session is confirmed)
  - `.established` → apply per-session limit / drain checks.
  Regression:
  `WebTransport: peer FIN of CONNECT while local mid-send on three streams`.

### Added (interop / wire format)

- **Six previously-missing WebTransport wire constants** from the
  draft-15 audit (no behavioral change — applications now have names
  for spec-defined values they may need to inspect):
  - `protocol.SettingId.wt_initial_max_data` = `0x2b61` (re-exported as
    `webtransport.SettingId.wt_initial_max_data`).
  - `protocol.SettingId.wt_initial_max_streams_uni` = `0x2b64`.
  - `protocol.SettingId.wt_initial_max_streams_bidi` = `0x2b65`.
  - `webtransport.flow_control_error_code` = `0x045d4487`.
  - `webtransport.alpn_error_code` = `0x0817b3dd`.
  - `webtransport.requirements_not_met_code` = `0x212c0d48`.
  Audit doc: [`design/error-code-audit-v0.2.md`](design/error-code-audit-v0.2.md).

### Added (test coverage)

- **WebTransport multiplexing tests** at
  [`tests/integration/webtransport_multiplexing.zig`](tests/integration/webtransport_multiplexing.zig).
  Four scenarios verify N concurrent WT sessions on one QUIC connection
  route correctly: 5 sessions × 10 uni streams (no cross-session bleed),
  3 sessions where one DRAINs while others stay active, 3 sessions
  with independent datagram delivery, per-session
  `WT_MAX_STREAMS_UNI` enforcement.

- **WebTransport race / interleaving tests** at
  [`tests/integration/webtransport_races.zig`](tests/integration/webtransport_races.zig).
  Four scenarios cover ordering corner cases: DRAIN in the same drain
  batch as 50 peer-opened streams; CLOSE_WT interleaved with WT_MAX_DATA
  (regression for the tolerance fix above); peer FIN of CONNECT during
  local mid-send on three streams (regression for the gate fix above);
  peer RESET of CONNECT while buffered streams are pending under the
  `.buffer` policy.

- **Eleven adversarial WebTransport fuzz seeds** added under
  [`fuzz/corpus/webtransport/`](fuzz/corpus/webtransport/) and
  [`fuzz/corpus/webtransport-session/`](fuzz/corpus/webtransport-session/).
  Multi-frame sequences (CLOSE-then-MAX_DATA, DRAIN-twice, MAX_DATA
  regression, BLOCKED-then-grant) plus single-frame malformed inputs
  (oversized close reason, truncated reason, overlong varint, invalid
  UTF-8 reason, u62-max bidi/uni limits). Zero panics surfaced.

### Documentation

- **[`docs/webtransport-tour.md`](docs/webtransport-tour.md)** —
  application-author walkthrough (683 lines) covering session
  establishment, streams, datagrams, flow control, closing, draining,
  error handling, and seven common pitfalls. Pulls real code from the
  integration tests.

- **[`docs/perf-baseline.md`](docs/perf-baseline.md)** — three
  performance numbers measured in-process (loopback shim, no sockets):
  WT session establishment, datagram round-trip, 1 KiB stream
  round-trip. Apple M5 Max, ReleaseFast, Zig 0.16.0. Published as a
  baseline for regression tracking, not optimization targets.
  Run via `zig build bench -Doptimize=ReleaseFast`.

- **[`design/error-code-audit-v0.2.md`](design/error-code-audit-v0.2.md)** —
  exhaustive comparison of our wire constants vs.
  draft-ietf-webtrans-http3-15 §9. 17 items audited; 6 drift items
  (now closed by the additions above); zero codepoint mismatches on
  the values we emit.

- **[`design/api-narrowing-proposal.md`](design/api-narrowing-proposal.md)** —
  audit of duplicate / redundant API paths with v0.3 / v0.4
  recommendations. Identifies five clusters (datagram sends, lifecycle
  verbs, stream-open paths, trackers vs raw events, re-exports).

### Deprecated

- **`finishSend` on `WebTransportClientStream`,
  `WebTransportServerStream`, `WebSocketClientStream`,
  `WebSocketServerStream`, `ConnectUdpClientStream`,
  `ConnectUdpServerStream` is deprecated.** Each type now has a
  canonical `finish` method with identical wire effect; `finishSend`
  remains as an alias and will be removed in v0.4. Migration is a
  one-character rename. Rationale:
  [`design/api-narrowing-proposal.md`](design/api-narrowing-proposal.md).

- **`WTStreamDirection` is deprecated, now an alias for
  `webtransport.StreamKind`.** Will be removed in v0.4. Migration:
  use `webtransport.StreamKind` (re-exported as
  `WebTransportStreamKind`) directly. Note: `StreamKind`'s order is
  `{ uni, bidi }`, reversed from the deprecated alias's
  `{ bidi, uni }`. No call site in this repo serialized the enum via
  `@intFromEnum`, so the rename is source-compatible at the switch /
  constant-construction level.

### Performance

- **`zig build bench` step** runs the new in-process WebTransport
  benchmark and prints per-operation p50 / p99 / mean / max.

## [0.2.0]

Tagged at commit `2ce728f`. This section covers the 0.1.0 and 0.2.0
releases together; see `git log v0.1.0..v0.2.0` for precise per-tag
attribution.

### Added

- **`SECURITY.md`** with private-disclosure address and 90-day SLA.
- **`CONTRIBUTING.md`** with build / test / interop instructions.
- **`LICENSE`** (Apache 2.0, matching sister project quic-zig).

### Changed (BREAKING)

- **`closeWebTransportSession` is no longer public.** The function only
  ever tore down local registry state — it never sent
  `CLOSE_WEBTRANSPORT_SESSION` on the wire — so exposing it as a public
  verb invited misuse. Renamed to private `endWebTransportSession`.
  Application close path is unchanged: call
  `WebTransportClientStream.close(code, reason)` /
  `WebTransportServerStream.close(code, reason)` to send the capsule, or
  `finishSend()` for an implicit close (now also tears down local
  registry state — see "Fixed" below).

- **`WTSessionFlowState` is no longer exported from `http3_zig.*`.** The
  mutable per-session flow-accounting struct is an implementation
  detail; applications already observe a read-only snapshot via
  `WebTransportClientStream.flowState()` /
  `WebTransportServerStream.flowState()` returning
  `?WTSessionFlowSnapshot`. The snapshot remains exported.

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
  - Dual-peer interop in CI: webtransport-go (draft-15 via master) +
    pywebtransport v0.17.1 (a Python facade shipping draft-15).

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

- **HTTP Datagram capsule path (RFC 9297 §3.4) now gates on peer
  `SETTINGS_H3_DATAGRAM`.** Previously
  `sendRequestDatagramCapsule` / `sendResponseDatagramCapsule` (and the
  context variants) would emit a DATAGRAM-typed capsule even if the peer
  hadn't advertised h3_datagram; the QUIC-DATAGRAM path
  (`sendDatagram`) was already gated. Both paths now share the same
  `MissingSettings` / `DatagramNotEnabled` semantics.

- **`Client.Config.production` / `Server.Config.production` presets** —
  one-line opt-in to bounded resource caps (max_concurrent_peer_streams = 256,
  max_field_section_size = 16 KiB, wt_max_buffered_bytes_per_stream = 16 KiB,
  buffered_stream_policy = .reject, max_event_payload_bytes_per_drain = 4 MiB,
  max_events_per_drain = 512). Defaults are unchanged; the preset is a
  snapshot, not a new field.

### Fixed

- **Test fixtures invoke `markPathValidated` on the synthetic
  handshake.** `tests/integration/_fixtures.zig` and
  `tests/conformance/_h3_fixture.zig` shuttle TLS data through an
  in-process outbox→inbox shim instead of real datagrams; that
  bypasses RFC 9000 §8.1's anti-amplification budget validation.
  Fixture now flips the bit explicitly so `Session.close` can flush
  CONNECTION_CLOSE in the server-initiates-close case (was failing
  the `lifecycle_close` integration test).

- **Local FIN / RESET of a WT CONNECT stream now tears down the local
  session registry** (draft-ietf-webtrans-http3-15 §5.4). Previously
  `Session.finishStream` / `Session.resetStream` only sent the QUIC
  frame; the local-side `wt_established_sessions` entry leaked. The
  receive side (`observeFin`, `observeReset`) already tore down the
  peer's view; this restores symmetry. Covered by the new test
  `WebTransport: peer FINs CONNECT control stream without CLOSE_WEBTRANSPORT_SESSION cleanly closes session`.

- **PRIORITY_UPDATE-Push for an unpromised push id now buffers**
  instead of closing the connection (RFC 9218 §7.2 — receiver SHOULD
  buffer the priority signal and apply it when the push is later
  promised). Previously `validatePriorityPushId` rejected
  `push_id >= next_push_id` with `H3_ID_ERROR`. The peer's
  `MAX_PUSH_ID` bound is still enforced — only the timing race is
  relaxed. Companion to the existing buffering for unopened request
  streams. New test:
  `PRIORITY_UPDATE for unpromised push id is buffered, not rejected [RFC9218 §7.2]`.

### Performance

- **Drain scratch buffers reused across `Session.drain` calls.** The
  per-drain `read_chunk_size` and `max_datagram_payload_size`
  scratch allocations are now stored on the session and grown
  monotonically; previously each drain paid alloc + free.
  Released in `Session.deinit`.

- **`Session.freeEvent(event)` helper** binds the right allocator for
  drained events implicitly. Equivalent to `event.deinit(session.allocator)`,
  but the caller no longer has to remember which allocator pairs with
  the event bytes (cloned out of the session's allocator, not the
  events list's allocator).

### Documentation

- **Allocator contract** documented at the top of
  [`src/root.zig`](src/root.zig). Six-bullet section explaining
  `Session.init` allocator lifetime, `Client/Server.init` facade
  semantics, Event byte ownership transfer on drain, the arena-with-reset
  warning for QPACK tables and rx buffers, `Session.deinit` invariants,
  and the independent allocator held by trackers.

- **Event-variant role audit.** Each variant of `Session.Event` now
  carries a `Role: client | server | both` doc tag, plus a 30-line
  summary block listing the role split (3 client-only, 2 server-only,
  20 shared). Makes a future `ClientEvent` / `ServerEvent` API split a
  mechanical refactor.

- **Stream lifecycle verbs documented** in
  [`src/session.zig`](src/session.zig). `finishStream` (clean FIN,
  no error code), `resetStream` / `resetRequest` / `resetResponse`
  (outbound abort, RESET_STREAM with an error code), `cancelRequest` /
  `rejectRequest` / `stopSending` (inbound abort, STOP_SENDING) — each
  has a doc comment explaining the QUIC frame it sends and when to use
  it. Same documentation cascaded to the `Client` / `Server` top-level
  wrappers.

- **`Session.Error` variants documented.** The 28 session-specific
  error variants now each carry a doc comment explaining when they
  fire and (where applicable) the spec section that defines the
  underlying behaviour.

### Observability

- **QPACK trace events.** Four new
  `observability.TraceEventName` variants emitted through the existing
  `Hooks` infrastructure:
  - `qpack_dynamic_insert` — fires after a successful dynamic-table
    append in `DynamicTable.insertOwned`.
  - `qpack_dynamic_evict` — fires per evicted entry inside
    `DynamicTable.evictToCapacity`.
  - `qpack_section_blocked` — fires in `DecoderState.beginFieldSection`
    when a header section is held pending dynamic-table insertions.
  - `qpack_section_unblocked` — fires when a previously-blocked
    section's required insert count is satisfied.
  Each event carries `stream_id` / `value` / `bytes` / `count` as
  appropriate; matching `Metrics` counters increment on emit.

### Tooling / infra

- **CI hardening:** `timeout-minutes` set on every job in
  [`.github/workflows/test.yml`](.github/workflows/test.yml) and
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml). The test
  matrix now covers `Debug` × `ReleaseSafe` × `{ubuntu-latest,
  ubuntu-24.04-arm, macos-latest}`. The fuzz workflow uploads crash
  artifacts on failure and runs on macOS as well as Linux.

- **`.github/workflows/release.yml`** triggers on `v*.*.*` tag pushes,
  validates the tag matches `build.zig.zon`'s `.version`, runs the
  full test suite, and publishes a GitHub release with autogenerated
  notes plus `CHANGELOG.md` body.

- **`.github/workflows/fuzz-nightly.yml`** runs the corpus walker for
  30 minutes nightly + on demand, uploading crashes on failure.

- **WebTransport interop runs on every push** — both Go
  (`webtransport-go`) and Python (`pywebtransport`) peers, with
  `continue-on-error: true` removed so peer failures gate merges.

- **New conformance test** `SETTINGS frame with zero settings is
  accepted [RFC9114 §7.2.4 ¶3]` (peer-sends-empty-SETTINGS).

- **Stricter Priority field-value parsing** (RFC 8941 §3.1.2 +
  RFC 9218 §4): dictionary keys outside the lowercase-token grammar
  and internal whitespace inside member-values now produce
  `Error.InvalidParameter` rather than slipping through as
  silently-ignored unknowns. Two new tests under `tests/conformance/rfc9218_priority.zig`.

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
