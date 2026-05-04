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
- Next: richer higher-level client/server request APIs over session events.

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
- Parked: cross-implementation dynamic-table QPACK fixture tests, pending
  quic-go/qpack dynamic-table support or an agreed alternate peer.

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
- Done: optional curl HTTP/3 interop harness with localhost UDP server
  coverage for GET, request metadata, POST echo, large response, and GOAWAY.
- Next: integration harness against `go-quic-peer` once `nullq` upload interop
  lands, plus broader close/reset coverage in the curl interop harness.

## Phase 4: Production Extensions

- RFC 9218 Priority header parsing and PRIORITY_UPDATE scheduling hooks.
- Server push APIs with `MAX_PUSH_ID`, `PUSH_PROMISE`, cancellation, and disable knobs.
- Extended CONNECT, WebSocket-over-H3, HTTP datagrams, and capsule protocol.
- Observability hooks: keylog passthrough, qlog-friendly events, metrics counters.

## Phase 5: Hardening

- Fuzz frame/QPACK decoders.
- Memory-budget enforcement and field-section size limits.
- Abuse tests for critical stream closure, duplicate SETTINGS, invalid frame types,
  malformed pseudo-headers, and oversized dynamic-table state.
- Interop matrix across quic-go, ngtcp2, lsquic, aioquic, and Chromium/curl where practical.
