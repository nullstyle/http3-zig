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
- Next: send-side RESET_STREAM convenience once `nullq` exposes it publicly,
  plus higher-level client/server request APIs over session events.

## Phase 2: QPACK Complete

- Full static table, Huffman codec, dynamic table, encoder/decoder streams.
- Blocked stream accounting, acknowledgments, cancellations, and capacity changes.
- Configurable indexing policy with safe defaults for sensitive fields.
- RFC 9204 examples and cross-implementation fixture tests.

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
- Next: integration harness against `go-quic-peer` once `nullq` upload interop
  lands, plus send-side RESET_STREAM convenience once `nullq` exposes it
  publicly.

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
