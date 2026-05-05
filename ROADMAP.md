# null3 Roadmap

Target: a production-ready HTTP/3 stack over `nullq` and `boringssl-zig`.
Normative core: RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 9218
(Extensible Priorities), RFC 9220 (extended CONNECT), RFC 9297 (HTTP
Datagrams / capsules), and the QUIC RFCs already tracked by `nullq`.

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
- `nullq.Connection` adapter for control stream and optional QPACK streams.

## Phase 1: HTTP/3 State Machine

- Done: per-connection control stream validation and duplicate critical stream
  checks in `session.Session`.
- Done: SETTINGS exchange, peer capability storage, and connection-error mapping
  for decoded HTTP/3/QPACK/message errors.
- Done: request/response stream parser and writer for HEADERS/DATA/trailers,
  including deep-owned application events.
- Done: in-process `nullq` integration test with `h3` ALPN, request body,
  response body, stream FIN validation, and GOAWAY delivery.
- Done: incoming RESET_STREAM observability via session reset events, plus
  STOP_SENDING helpers for request rejection/cancellation.
- Done: graceful-drain state, client-side GOAWAY request blocking, and
  server-side rejection/discard of non-compliant request streams above a local
  GOAWAY limit.
- Done: opt-in dynamic QPACK encoder/decoder stream processing in
  `session.Session`, including dynamic response field-section references and
  decoder feedback over the in-process `nullq` exchange.
- Done: send-side RESET_STREAM convenience over `nullq.streamReset`, including
  client request aborts, server response aborts, and QPACK blocked-stream
  cancellation cleanup.
- Done: `nullq` connection-close events are surfaced through the typed
  session/client/server event model with copied reasons and HTTP/3 application
  error metadata when available.
- Done: `nullq` flow-control blocked events are surfaced through the typed
  session/client/server event model and runner batch summaries.
- Done: `nullq` connection-ID replenishment events are surfaced through the
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
  decoder-feedback bytes.
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
- Done: first external HTTP/3 client interop harness over ordinary
  `nullq.Connection` APIs, using the public `Client`, `ClientRunner`, and
  transport driver endpoint helpers against IP-literal UDP peers.
- Done: optional external-peer matrix runner for quic-go, ngtcp2, lsquic, and
  aioquic style servers, with skip-friendly peer wrappers and caller-provided
  server commands.
- Next: wire concrete peer command recipes into local/CI jobs as those
  dependencies are installed, keep curl-as-client coverage current, and add
  more examples layered on the shared driver.

## Phase 4: Production Extensions

- RFC 9218 Priority header parsing and PRIORITY_UPDATE scheduling hooks.
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
- Next: server push completion polish, including cache/authority policy
  helpers and higher-level pushed-response tracking.
- Done: HTTP/3 DATAGRAM groundwork over `nullq` DATAGRAM frames, including
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
- Next: deeper MASQUE protocol state, including extension-specific capsule
  registration semantics and external proxy interop.

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
  table capacity/entry overflow, plus CONNECT-UDP context registry failures and
  oversized UDP payload stream-abort classification.
- Partial: send-side stream buffering, outgoing capsule values, session event
  queues, tracker body accumulation, and decoded QPACK field sections now have
  opt-in caps; broader sustained resource-pressure coverage is still needed,
  especially around extension-specific capsule state.
- Remaining: broader corpus growth plus sustained memory/flow/resource-pressure cases.
- Interop matrix across quic-go, ngtcp2, lsquic, aioquic, and Chromium/curl where practical.
