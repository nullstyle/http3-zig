# http3-zig Roadmap

Target: a production-ready HTTP/3 stack over `quic-zig` and `boringssl-zig`.
Normative core: RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 9218
(Extensible Priorities), RFC 9220 (extended CONNECT), RFC 9297 (HTTP
Datagrams / capsules), and the QUIC RFCs already tracked by `quic-zig`.

## Phase 0: Scaffold and Codecs

- Package metadata, tests, and docs.
- HTTP/3 frame and SETTINGS codecs.
- QPACK integer/string primitives, full static table, and non-blocking
  static/literal field sections.
- Header validation and pseudo-header ordering checks.
- RFC 9218 priority parameter parser.
- HTTP/3 stream-context frame validation.
- Transport-free message encoder/decoder for request/response HEADERS, DATA,
  and trailers.
- `quic-zig.Connection` adapter for control stream and optional QPACK streams.

## Phase 1: HTTP/3 State Machine

- Done: per-connection control stream validation and duplicate critical stream
  checks in `session.Session`.
- Done: SETTINGS exchange, peer capability storage, and connection-error mapping
  for decoded HTTP/3/QPACK/message errors.
- Done: request/response stream parser and writer for HEADERS/DATA/trailers,
  including deep-owned application events.
- Done: in-process `quic-zig` integration test with `h3` ALPN, request body,
  response body, stream FIN validation, and GOAWAY delivery.
- Done: incoming RESET_STREAM observability via session reset events, plus
  STOP_SENDING helpers for request rejection/cancellation.
- Done: graceful-drain state, client-side GOAWAY request blocking, and
  server-side rejection/discard of non-compliant request streams above a local
  GOAWAY limit.
- Done: opt-in dynamic QPACK encoder/decoder stream processing in
  `session.Session`, including dynamic response field-section references and
  decoder feedback over the in-process `quic-zig` exchange.
- Done: send-side RESET_STREAM convenience over `quic-zig.streamReset`, including
  client request aborts, server response aborts, and QPACK blocked-stream
  cancellation cleanup.
- Done: `quic-zig` connection-close events are surfaced through the typed
  session/client/server event model with copied reasons and HTTP/3 application
  error metadata when available.
- Done: `quic-zig` flow-control blocked events are surfaced through the typed
  session/client/server event model and runner batch summaries.
- Done: `quic-zig` connection-ID replenishment events are surfaced through the
  typed session/client/server event model and runner batch summaries.
- Done: higher-level client/server event runners over session events and
  lifecycle trackers.
- Done: Extended CONNECT foundation with `SETTINGS_ENABLE_CONNECT_PROTOCOL`,
  `:protocol` validation, client request construction, server request metadata,
  and in-process negotiation coverage.

## Phase 2: QPACK Complete

- Done: full static table and RFC 7541 Huffman codec for string literals.
- Done: dynamic table core with capacity, insertion/eviction, duplication,
  absolute indexing, encoder-stream relative indexing, and field-section
  relative/post-base lookup helpers.
- Done: encoder/decoder stream instruction codecs, including dynamic-table
  application of encoder stream instructions.
- Done: transport-free QPACK state synchronization for Required Insert Count
  wrapping, field-section prefix base handling, blocked stream accounting,
  Known Received Count, acknowledgments, cancellations, and insert-count
  increments.
- Done: dynamic-aware field-section codecs for indexed field lines, literal
  field lines with dynamic name references, post-base references, and
  encoder-side outstanding reference tracking.
- Done: configurable indexing policy with safe defaults for sensitive fields,
  non-blocking or tracked dynamic references, and opt-in dynamic insertions.
- Done: RFC 9204 Appendix B exact-byte fixture coverage for literal field
  sections, dynamic table inserts, acknowledgments, duplicates, stream
  cancellations, and eviction.
- Done: quic-go/qpack cross-implementation fixture coverage for the shared
  static/literal/Huffman profile.
- Done: dynamic-table QPACK interop fixture corpus and Zig runner for exact
  RFC 9204 Appendix B encoder stream, field-section, table-snapshot, and
  decoder-feedback bytes, plus negative vectors for malformed dynamic inputs.
- Parked: binding that dynamic-table corpus to a second implementation,
  pending quic-go/qpack dynamic-table support or an agreed alternate peer.

## Phase 3: Client and Server APIs

- Done: thin `client.Client` and `server.Server` facades over `Session` for
  request/response operations and typed event classification.
- Done: `client.RequestOptions` / `Client.request` for pseudo-header assembly
  and simple body/trailer sends.
- Done: `server.ResponseOptions` / `Server.respond` for common responses.
- Done: streaming request/response writer handles
  (`Client.startRequest` / `RequestWriter`, `Server.startResponse` /
  `ResponseWriter`) for incremental body, trailer, and finish sends.
- Done: `server.RequestTracker` for owned request lifecycle state assembled
  from session events.
- Done: structured error model for HTTP/3/QPACK application codes, local causes,
  connection-close state, and stream reset/rejection events.
- Done: reader-side response/request convenience handles via
  `client.ResponseTracker` / `ResponseReader` and
  `server.RequestTracker` / `RequestReader`.
- Done: `ClientRunner` and `ServerRunner` compose session-event
  classification, owned lifecycle tracking, and batch completion summaries for
  applications and interop harnesses.
- Done: optional curl HTTP/3 interop harness with localhost UDP server
  coverage for GET, request metadata, status/header checks, POST echo, large
  upload echo, multi-request connection reuse, large response, client-side
  cancellation, response reset, connection-close-after-response, and GOAWAY.
- Done: reusable transport driver helpers shared by the in-process tests and
  curl interop server, while keeping socket and clock ownership outside the
  library.
- Done: compact in-process loopback example layered on the public
  client/server, runner, and transport driver APIs.
- Done: opt-in per-stream send-buffer backpressure caps plus send-state
  introspection for written, acknowledged, buffered, pending, and flow-blocked
  state.
- Done: request/response tracker body-budget caps for applications that use the
  owned lifecycle assemblers.
- Done: session drain event-count and owned-payload budgets, covering transient
  DATA, DATAGRAM, capsule DATA, push-promise, and close-reason event copies.
- Done: QPACK field-section decode budgets for decoded field-line count and
  decoded owned field storage, distinct from encoded HEADERS size limits.
- Done: outgoing reliable capsule value budgets, including context-aware
  DATAGRAM capsules before their encoded DATA-frame payload allocation.
- Done: `SessionConfig.production(.{})` preset for conservative field-section,
  decoded-QPACK, event-queue, capsule, datagram, and send-buffer limits without
  changing compatibility defaults.
- Done: first external HTTP/3 client interop harness over ordinary
  `quic-zig.Connection` APIs, using the public `Client`, `ClientRunner`, and
  transport driver endpoint helpers against IP-literal UDP peers.
- Done: optional external-peer matrix runner for quic-go, ngtcp2, lsquic, and
  aioquic style servers, with skip-friendly peer wrappers and caller-provided
  server commands.
- Next: wire concrete peer command recipes into local/CI jobs as those
  dependencies are installed, keep curl-as-client coverage current, and add
  more examples layered on the shared driver.

## Phase 4: Production Extensions

- Done: RFC 9218 Priority header helpers and HTTP/3 PRIORITY_UPDATE
  scheduling hooks, including client request/push send APIs, server receive
  events, latest-priority state, runner observations, metrics, and invalid
  target/value hardening. Remaining application policy: use that state to
  order queued response writes once quic-zig exposes the right scheduling knobs.
- Done: first server push API slice with client `MAX_PUSH_ID` opt-in,
  server-side `PUSH_PROMISE` emission, server-initiated push streams, typed
  pushed response events, and in-process coverage.
- Done: server push cancellation and abuse-hardening slice with
  `CANCEL_PUSH` send/receive APIs, typed cancellation events, push stream
  cancellation behavior, push-ID limit checks, invalid frame placement checks,
  and duplicate push stream ID rejection.
- Done: server push policy/consistency slice with decoded duplicate
  `PUSH_PROMISE` field comparison, `H3_MESSAGE_ERROR` on inconsistent
  duplicates, and `PushPolicy.cancel_promises` for app-level auto-cancel.
- Done: server push completion polish with same-origin/cacheable promise
  helpers, request-derived push convenience APIs, `PushedResponseTracker`, and
  `ClientRunner` pushed-response lifecycle observations.
- Done: HTTP/3 DATAGRAM groundwork over `quic-zig` DATAGRAM frames, including
  RFC 9297 quarter-stream-id payload codec, SETTINGS/transport negotiation
  checks, typed session/client/server datagram events, tracked send outcome
  propagation, and bidirectional in-process coverage.
- Done: Extended CONNECT foundation with negotiated `:protocol` support.
- Done: Capsule Protocol and context-aware DATAGRAM helpers, including
  DATAGRAM capsule codecs, Context ID payload helpers, request/response writer
  send paths, and in-process coverage over both QUIC DATAGRAM frames and
  reliable DATA-frame capsules.
- Done: observability hooks for TLS keylog callback configuration, QUIC qlog
  callback passthrough, typed HTTP/3 trace events, and session/client/server
  metrics snapshots.
- Done: WebSocket-over-H3 foundation with negotiated Extended CONNECT helpers,
  typed request/accept wrappers, and bidirectional byte-flow coverage.
- Done: RFC 6455 WebSocket frame codec with masking, close-code validation,
  control-frame abuse checks, incremental fragmentation tracking, stream
  writer helpers, and fuzz smoke coverage.
- Done: higher-level WebSocket message assembly with owned text/binary events,
  text/close UTF-8 validation, interleaved ping/pong/close handling,
  message-size caps, stream writer helpers, integration coverage, and fuzz
  smoke coverage.
- Done: CONNECT-UDP helper foundation layered on Extended CONNECT, capsules,
  and context-aware datagrams, including target path construction/parsing,
  Context ID 0 UDP payload helpers, typed client/server tunnel wrappers,
  checked context registry helpers, reusable per-tunnel receive classification
  for DATAGRAM frames and DATAGRAM capsules, drop/buffer/abort receive
  disposition, UDP payload length guards, integration coverage, and fuzz smoke
  coverage.
- Done: deeper MASQUE receive state, including endpoint Context ID allocation
  checks, bounded unknown-context datagram buffering, and explicit
  drain/drop helpers for extension registration policy.
- Done: capsule-aware MASQUE pending-buffer helpers with sustained
  unknown-context DATAGRAM capsule pressure coverage and exact byte-accounting
  checks across fill, reject, drain, and drop cycles.
- Done: extension-specific capsule type registration semantics with DATAGRAM
  and GREASE registration rejection, bounded per-receiver capacity, receiver
  routing, pending-buffer non-retention, and structured CONNECT error
  classification.
- Done: WebTransport-over-HTTP/3 (draft-ietf-webtrans-http3-15) handshake slice
  with `:protocol = webtransport` request/response classification,
  `SETTINGS_WT_ENABLED` (codepoint `0x2c7cf000`) advertisement,
  `WebTransportClientStream` / `WebTransportServerStream` facades layered
  on the existing CONNECT, HTTP/3 Datagram, and Capsule plumbing, plus
  session-level helpers that open locally-initiated unidirectional and
  bidirectional WebTransport streams with the `0x54` / `0x41` prefix
  written automatically.
- Done: WebTransport stream-error code mapping (the
  `f(n) = 0x52e4a40fa8db + n + (n / 30)` translation between the
  application's 32-bit code and the QUIC stream error code), reserved
  `WEBTRANSPORT_BUFFERED_STREAM_REJECTED` / `WEBTRANSPORT_SESSION_GONE`
  codes, and `CLOSE_WEBTRANSPORT_SESSION` (0x2843) +
  `DRAIN_WEBTRANSPORT_SESSION` (0x78ae) capsule encoders/decoders with
  UTF-8 reason validation and 1024-byte length cap, exercised by the
  draft-ietf-webtrans-http3 conformance suite and the codec fuzz target.
- Done: inbound WebTransport stream dispatch — peer-opened
  unidirectional streams (type `0x54`) and client-initiated
  bidirectional streams (frame type `0x41`) are now recognized in the
  session state machine, the Session ID prefix is parsed, and bytes
  flow through new typed events
  (`webtransport_stream_opened` / `webtransport_stream_data` /
  `webtransport_stream_finished` / `webtransport_stream_reset`). Stream
  RESETs reverse-map the QUIC error code back to the 32-bit
  WebTransport application code via the §4.6 algorithm and surface
  both the wire and application codes to the application.
- Done: WebTransport session registry tracking pending and
  established CONNECT streams, fed by hooks in
  `Client.startWebTransport`, `Server.acceptWebTransport`, and the
  HEADERS observer in `processMessageState`. Session lifecycle is
  closed automatically on FIN / RESET of the CONNECT stream.
- Removed: server-side `SETTINGS_WT_MAX_SESSIONS` enforcement.
  draft-ietf-webtrans-http3-15 §9.2 collapsed the numeric
  `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29` codepoint into the boolean
  `SETTINGS_WT_ENABLED = 0x2c7cf000`, so there is no longer a
  SETTINGS-advertised session-count limit to enforce. Applications
  that want to bound concurrent sessions can decline
  `Server.acceptWebTransport` based on their own counters
  (`Session.webTransportPendingCount` /
  `webTransportEstablishedCount` are still public for that purpose).
- Done: buffered-stream policy (`SessionConfig.buffered_stream_policy`).
  Three modes — `.pass_through` (legacy), `.reject` (sends
  STOP_SENDING with `WEBTRANSPORT_BUFFERED_STREAM_REJECTED`), and
  `.buffer` (holds bytes until the corresponding session is confirmed
  and replays the dispatch on the next drain). The replay path runs
  at the start of every drain and abandons buffered streams whose
  session never establishes (CONNECT FIN/RESET observed before
  acceptance).
- Done: WebTransport subprotocol negotiation
  (`wt-available-protocols` / `wt-protocol`). `Client.startWebTransport`
  takes a list of offered tokens; `Server.acceptWebTransport`
  validates the chosen token against that list. Helpers parse the
  RFC 8941 sf-list value with whitespace trimming, validate against
  the HTTP token grammar (RFC 9110 §5.6.2), and bound the offered
  list to `max_subprotocol_count`.
- Done: `SessionConfig.production` WebTransport preset fields
  (`enable_webtransport`, `buffered_stream_policy`). Enabling
  WebTransport in the preset auto-enables the prerequisite settings
  (`enable_connect_protocol`, `h3_datagram`) and emits
  `SETTINGS_WT_ENABLED` (draft-ietf-webtrans-http3-15 §9.2).
- Done: WebTransport flow-control capsule codecs pinned to
  draft-ietf-webtrans-http3-15 (capsule values verified against the
  IANA "Capsule Types" registry table, §9.6 and §5.6.{2..5}; values
  unchanged since draft-13). `WT_MAX_DATA` (0x190b4d3d),
  `WT_DATA_BLOCKED` (0x190b4d41), `WT_MAX_STREAMS_BIDI` (0x190b4d3f),
  `WT_MAX_STREAMS_UNI` (0x190b4d40), `WT_STREAMS_BLOCKED_BIDI`
  (0x190b4d43), `WT_STREAMS_BLOCKED_UNI` (0x190b4d44). Each carries a
  single QUIC varint and rides through the existing
  `webtransport.classifyCapsule` dispatch as a typed `CapsuleEvent`
  variant. Codec only — session-level enforcement (consuming
  `WT_MAX_DATA` to gate sends, emitting `WT_DATA_BLOCKED` on
  backpressure, intermediary forwarding) is still pending.
- Done: WebTransport-specific trace event names
  (`webtransport_stream_opened` / `_data_received` / `_finished` /
  `_reset_received`) plus matching counters in `observability.Metrics`,
  so qlog consumers can distinguish WebTransport streams from generic
  HTTP/3 streams without inspecting the per-event `frame_type` field.
- Done: in-process WebTransport loopback example
  (`examples/loopback_wt.zig`, build target
  `run-example-loopback-wt`). Walks through QUIC handshake, SETTINGS
  exchange, `startWebTransport` / `acceptWebTransport`, datagram
  exchange, unidirectional WT stream send, and
  `CLOSE_WEBTRANSPORT_SESSION` capsule, with progress prints for each
  step.
- Done: sustained-pressure integration tests for WebTransport — 16
  concurrent uni streams, 256 KiB single-stream payload across
  multiple writes, 64 concurrent datagrams, scoped buffered-stream
  replay (8 streams under `.buffer` policy), and per-stream
  send-buffer backpressure. Surfaced two known nuances of the
  `.buffer` policy (FIN delivery before replay, hash-map
  iteration order vs. open order) — see "Next" below.
- Done: server-initiated bidirectional WebTransport streams
  (draft-ietf-webtrans-http3 §4.2 carve-out of RFC 9114 §6.1 ¶3).
  quic-zig already supported server-initiated bidi at the QUIC
  layer (`tests/conformance/rfc9000_streams_flow.zig` pre-existing
  KAT) — the actual block was in http3-zig: `ensureIncomingState`
  rejected server-initiated bidi at the client before the WT marker
  peek could fire. Now: bidi role-validation is deferred to
  `processBidiState` whenever any WebTransport session is pending
  or established (`webTransportEndpointActive()`), and the server
  exposes `WebTransportServerStream.openBidiStream()` mirroring the
  client side. The non-WebTransport path continues to fire
  `H3_STREAM_CREATION_ERROR` eagerly (verified by the existing
  RFC 9114 §6.1 ¶3 conformance test). Locally-opened WT bidi
  streams pre-register their `bidi_kind` and `wt_session_id` so
  peer response bytes aren't mis-parsed as a fresh prefix.
- Done: tightened `.buffer` policy. Buffered streams are now
  tracked in a `wt_buffered_streams` insertion-ordered list (sorted
  by stream id at replay time so events surface in the order the
  peer opened the streams, not in hash-map order). `observeFin` on
  a still-buffered stream parks the FIN as `wt_buffered_fin`; the
  replay path emits `webtransport_stream_finished` after the
  matching `_opened` and `_data` events instead of letting it race
  ahead. Integration test exercises 8 streams open + write + FIN
  before accept, verifies replay order matches client-open order
  and per-stream open precedes data precedes finished.
- Done: WebTransport flow-control enforcement
  (draft-ietf-webtrans-http3 §5.6). Per-session `WTSessionFlowState`
  carries peer-advertised `peer_max_data` /
  `peer_max_streams_{bidi,uni}`, locally-advertised counterparts,
  outbound counters (`local_data_sent`,
  `local_streams_opened_*`), and BLOCKED-emission bookkeeping.
  `openWebTransportUniStream` / `openWebTransportBidiStream` /
  `writeWebTransportStream` gate against the peer's limits and
  return `WebTransportStreamLimitExceeded` /
  `WebTransportFlowControlExceeded`, auto-emitting `WT_STREAMS_BLOCKED_*` /
  `WT_DATA_BLOCKED` capsules (deduplicated per limit value).
  Inbound capsules flow through `observeWebTransportCapsule` —
  applications iterate `.data` capsules out of CONNECT-stream
  events and forward them, mirroring the existing CLOSE/DRAIN
  pattern. Public API on `WebTransportClientStream` /
  `WebTransportServerStream`: `flowState()`, `sendMaxData()`,
  `sendMaxStreams{Bidi,Uni}()`, `observeCapsule()`,
  `recordPeerDataReceived()`. Opt-in by default — null peer limits
  mean no enforcement (preserves backward compatibility for
  callers that don't care).
- Done: connection-level WebTransport fuzz target
  (`zig build run-fuzz-smoke -- webtransport-session`). Drives
  fuzzer corpus through a wider, structured set of WebTransport
  codec entry points than the existing transport-free
  `webtransport` target: truncated WT_STREAM bidi/uni prefixes,
  `CLOSE_WEBTRANSPORT_SESSION` with the 4-byte code + UTF-8 reason
  boundary, malformed `DRAIN_WEBTRANSPORT_SESSION` with non-empty
  values, all six flow-control capsules round-tripped through
  encoder + `capsule.decode` + `classifyCapsule`, the capsule
  iterator chained into `classifyCapsule`,
  `parseAvailableProtocols`, `isOfferedProtocol`, and the
  `appErrorToHttp3` / `http3ToAppError` round-trip across u32.
- Done: external WebTransport interop harness
  (`interop/external_wt/client.zig`, build target
  `external-wt-client`, run target `run-external-wt-client`).
  Mirrors the existing `external_h3` pattern — reads
  `WT_INTEROP_URL` from the environment, opens a UDP socket, drives
  a real `quic_zig.Connection` handshake (`--insecure` /
  `--verify-system` flags), brings up `http3_zig.Session` with
  WebTransport enabled, exchanges SETTINGS, opens a
  `Client.startWebTransport`, sends a datagram + a uni stream + a
  `CLOSE_WEBTRANSPORT_SESSION` capsule, and exits cleanly. When
  `WT_INTEROP_URL` is unset, the harness prints a friendly skip
  message and exits 0 — same convention as the other interop
  harnesses.
- Done: receive-side WebTransport flow-control adoption. The
  session now auto-bumps `peer_data_received` and
  `peer_streams_opened_{bidi,uni}` as it emits
  `webtransport_stream_data` / `_opened` events — the explicit
  `recordPeerDataReceived` call from the application is no longer
  required for those counters. When the peer's bytes or stream
  opens would push the relevant counter past our advertised
  `local_max_data` / `local_max_streams_{bidi,uni}`, the offending
  stream is reset with `WEBTRANSPORT_SESSION_GONE` (per
  draft-ietf-webtrans-http3 §5.6) and a typed
  `webtransport_flow_violated` event is emitted carrying the
  violation `kind` and the limit value, so the application can
  decide between session-close and per-stream rejection.
- Done: external WebTransport interop **matrix** runner. New
  `interop/external_wt/matrix.zig` + `wt-interop-matrix` build
  step iterates over the URLs in `WT_INTEROP_MATRIX_URLS`
  (newline- or comma-separated), runs the per-target client
  against each, and exits non-zero only if **every** non-skipped
  target failed — so a missing aioquic doesn't mask a working
  webtransport-go. Skip-friendly when the env var is unset. The
  third-party server now pinned in CI is webtransport-go; recipes
  for other implementations stay documented in
  [`interop/external_wt/README.md`](interop/external_wt/README.md)
  but only webtransport-go is anchored in the workflow.
- Done: GitHub Actions CI for http3-zig.
  [`.github/workflows/test.yml`](.github/workflows/test.yml) gates
  every push and PR with `zig build` + `zig build test --summary
  all` on Ubuntu and macOS, mirroring quic-zig's setup
  ([mise-pinned](mise.toml) toolchain).
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml) runs
  the codec smoke corpus *and* the seeded `fuzz/corpus/` (~105
  inputs across 16 targets) on each push.
  [`.github/workflows/wt-interop.yml`](.github/workflows/wt-interop.yml)
  runs the WebTransport interop matrix on a weekly cron + on
  manual dispatch — by default it runs the skip path (no
  `WT_INTEROP_MATRIX_URLS` configured), so a fresh checkout never
  fails for lack of an external server; an operator can flip the
  workflow inputs to point at real servers when ready.
  [`.github/workflows/wt-interop-self-test.yml`](.github/workflows/wt-interop-self-test.yml)
  brings up the in-tree WebTransport echo server
  ([`interop/external_wt/server.zig`](interop/external_wt/server.zig))
  on a real UDP socket and runs the matrix runner against it —
  this is a per-push gate covering the real-socket pump path
  (which the in-process integration tests don't reach), without
  depending on a third-party server.
- Done: seeded fuzz corpus
  ([`fuzz/corpus/`](fuzz/corpus/), 105 hand-curated inputs across
  16 codec targets). [`fuzz/seed.zig`](fuzz/seed.zig) regenerates
  the corpus from the project's own encoders for well-formed cases
  + hand-crafted boundary/malformed cases (truncated headers,
  reserved-HTTP/2 frame types, RFC 7541 Huffman vectors,
  non-minimal WebSocket lengths, WT error-code stride boundaries,
  …). [`fuzz/corpus_main.zig`](fuzz/corpus_main.zig) walks the
  directory at runtime and feeds each file through `runTarget`.
  Coverage-guided fuzzers can drop new files into the same dirs to
  extend coverage without code changes.
- Done: in-tree WebTransport echo server harness for self-tests.
  Mirrors the existing
  [`interop/curl_h3/server.zig`](interop/curl_h3/server.zig)
  pattern (real UDP socket, drive `quic_zig.Connection` +
  `http3_zig.Session`, flush via `TransportEndpoint`) but with
  WebTransport-specific application logic: accepts WT CONNECTs,
  echoes datagrams back, opens server-initiated uni streams
  carrying inbound payloads. Build / run targets:
  `external-wt-server`, `run-external-wt-server`. The harness
  exits cleanly after `--max-sessions` round-trips or the
  `--max-lifetime-ms` cap fires, both knobs with sensible CI
  defaults.
- Done: third-party WebTransport server pinned in
  [`wt-interop.yml`](.github/workflows/wt-interop.yml). The workflow
  installs Go, builds the in-repo
  [`interop/external_wt/server_go/`](interop/external_wt/server_go/)
  echo server (using `quic-go/webtransport-go` master, which speaks
  draft-15 — pre-tagged-release because v0.10.0 is still draft-13),
  brings it up against `tests/data/test_cert.pem` on a kernel-chosen
  port, parses the `READY <port>` line, and points the matrix runner
  at `https://127.0.0.1:<port>/wt-go-interop`. Operators can stack
  additional URLs on top via the `urls` workflow input. The peer
  binary mirrors the in-tree Zig server's CLI (`--listen / --cert /
  --key / --max-sessions / --max-lifetime-ms`) so the same workflow
  scaffolding can drive either.
- Done: draft-15 wire-format pin. The implementation now tracks
  draft-ietf-webtrans-http3-15 (July 2025 revision). The most visible
  change is the SETTINGS bootstrap: draft-13's numeric
  `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29` was retired in favor of the
  boolean `SETTINGS_WT_ENABLED = 0x2c7cf000`. `Settings.wt_enabled :
  bool` replaces `Settings.wt_max_sessions : ?u64`, the
  `ProductionOptions.wt_max_sessions` knob is gone (no SETTINGS-side
  session count to advertise), and the corresponding N+1 server-side
  rejection path was removed because there is no longer a numeric
  limit to enforce. Conformance tests cite §9.2 of draft-15 and pin
  the codepoint numerically so an accidental revision drift surfaces
  loudly. webtransport-go's master branch (post-PR #254, 2026-03-12)
  speaks the same revision; it advertises both `0x2b603742`
  (draft-06, kept for backward compat) and `0x2c7cf000` (draft-15) so
  http3-zig's draft-15-only client interoperates cleanly.

## Phase 5: Hardening

- Memory-budget enforcement and field-section size limits.
- Done: transport-free codec fuzz harness and smoke corpus for HTTP/3 frames,
  SETTINGS, capsules, DATAGRAM payloads, QPACK integers, Huffman strings,
  field sections, and encoder/decoder stream instructions.
- Done: abuse tests now cover critical stream closure, duplicate SETTINGS,
  invalid frame placement, duplicate critical streams, server-side push streams,
  malformed peer GOAWAY sequencing, DATAGRAM negotiation and size failures,
  malformed pseudo-headers, truncated capsules, DATA-after-trailers, oversized
  decoded field sections, QPACK decoder feedback errors, and peer QPACK dynamic
  table capacity/entry overflow, plus CONNECT-UDP context registry failures,
  bounded unknown-context buffering limits, and oversized UDP payload
  stream-abort classification.
- Done: sustained MASQUE unknown-context DATAGRAM capsule pressure cases now
  cover bounded pending-buffer count/byte limits, malformed capsule
  non-buffering, ignored capsule types, and repeated drain/drop accounting.
- Done: bounded MASQUE extension capsule registries now reject reserved
  DATAGRAM/GREASE types, enforce capacity, and leave unknown extension capsule
  values ignorable and unbuffered.
- Partial: send-side stream buffering, outgoing capsule values, session event
  queues, tracker body accumulation, decoded QPACK field sections, and the
  production session preset now have opt-in caps. Long-lived-stream
  pressure now has explicit coverage
  (`tests/integration/webtransport.zig` — 64-cycle write+drain on a
  WebTransport uni stream verifies the per-stream
  `buffered_bytes` high-water mark stays bounded and quiesces to
  zero between drains). Flow-control stalls are exercised by the
  WebTransport flow-control suite (`writeStream` → BLOCKED →
  unblock-on-MAX_DATA). External-peer traffic patterns still
  require running servers; the matrix harness is in place
  (`zig build wt-interop-matrix`) but real-server runs are
  scheduled rather than gating.
- Remaining: broader fuzz corpus growth (the smoke corpus is small;
  long-running fuzz campaigns through `zig build fuzz-codecs` against
  a larger seeded corpus are not yet automated).
- Interop matrix across quic-go, ngtcp2, lsquic, aioquic, and
  Chromium/curl where practical — the
  [`wt-interop` workflow](.github/workflows/wt-interop.yml) and
  per-server recipes in
  [`interop/external_wt/README.md`](interop/external_wt/README.md)
  set up the harness; standing up the actual servers in CI is the
  open work.
