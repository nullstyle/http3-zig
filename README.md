# null3

A Zig-first HTTP/3 implementation for Zig 0.16.0, built on top of
[`nullq`](../nullq) for QUIC transport and [`boringssl-zig`](../boringssl-zig)
for TLS 1.3 / ALPN configuration.

**Status: session scaffold.** The package now provides the stable protocol
surfaces plus a first HTTP/3 session layer over `nullq.Connection`: HTTP/3
constants, SETTINGS and frame codecs, non-blocking QPACK field-section
encoding/decoding with static-table, Huffman string, and dynamic table core
support plus dynamic field-section representations, encoder/decoder stream
instruction codecs, state-sync accounting, and configurable indexing policy,
header validation, priority parameter parsing, TLS context helpers,
transport-free message codecs, critical stream setup, SETTINGS exchange,
opt-in dynamic QPACK stream integration, GOAWAY handling, graceful-drain state,
reset events, transport close events, structured HTTP/3/QPACK error
classification, QUIC flow-control blocked observability, HTTP/3 DATAGRAM
send/receive groundwork, reusable transport driver helpers, request lifecycle
tracking, response lifecycle tracking, client/server event runners, Extended
CONNECT negotiation and request metadata, Capsule Protocol codecs,
context-aware DATAGRAM helpers, opt-in send-buffer backpressure limits, and
lightweight request-response facades with configurable tracker body and session
event-queue budgets.

```sh
mise install
just test
```

## Design Shape

- `null3` owns HTTP semantics: request/response state, HTTP/3 frames,
  SETTINGS, QPACK, priorities, push, WebTransport/extended CONNECT, and
  application-facing APIs.
- `nullq` owns QUIC transport: packets, streams, flow control, datagrams,
  loss recovery, migration, and connection IDs.
- `boringssl-zig` owns TLS 1.3 and ALPN. `null3.client` and `null3.server`
  provide convenience context constructors that advertise `h3`.
- The library stays I/O-decoupled. Embedders own sockets and event loops,
  drive `nullq.Connection.handle` / `poll`, then hand stream bytes to `null3`.

## Current Modules

- `protocol`: RFC constants and GREASE helpers.
- `settings`: HTTP/3 SETTINGS parser/encoder, including QPACK limits,
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`, max field section size, and HTTP/3
  DATAGRAM negotiation.
- `frame`: HTTP/3 frame parser/encoder, including RFC 9218 PRIORITY_UPDATE.
- `qpack`: QPACK primitives plus static-table/literal field-section codecs,
  RFC 7541 Huffman string literal support, and a transport-free dynamic table
  with QPACK absolute, relative, and post-base indexing helpers. It also
  provides dynamic-aware field-section codecs for indexed, name-reference, and
  post-base representations, transport-free encoder/decoder stream instruction
  codecs, configurable indexing policy with conservative defaults for
  sensitive fields and blocking risk, a dynamic-table apply helper for encoder
  instructions, plus Known Received Count, blocked-stream, acknowledgment,
  cancellation, and field-section prefix accounting helpers.
- `headers`: HTTP field validation for request/response scaffolding.
  Extended CONNECT `:protocol` validation is gated by negotiated support.
- `priority`: RFC 9218 urgency/incremental parameter parsing.
- `errors`: structured HTTP/3 application error code metadata plus local
  cause, connection-close, and stream-reset classification helpers.
- `stream`: stream type helpers plus frame-context validation.
- `message`: transport-free request/response HEADERS, DATA, and trailer
  encoding/decoding with stream-order validation.
- `datagram`: RFC 9297 HTTP/3 DATAGRAM quarter-stream-id payload codec plus
  reusable Context ID payload helpers for datagram-using extensions.
- `capsule`: RFC 9297 Capsule Protocol TLV codec, including DATAGRAM capsules.
- `driver`: small `nullq`/`null3` transport-driving helpers for tests,
  examples, and interop peers. It keeps socket and clock ownership with the
  embedder while centralizing the handle/poll/tick/session-drain order.
- `runner`: client/server event runners that compose raw `session.Event`
  classification with owned request/response lifecycle trackers and batch
  completion summaries.
- `session`: HTTP/3 session state over `nullq.Connection`, including control
  streams, peer SETTINGS, request stream draining, response writes, FIN
  validation, optional dynamic QPACK encoder/decoder stream processing,
  GOAWAY policy enforcement, Extended CONNECT negotiation checks, HTTP/3
  DATAGRAM events over QUIC DATAGRAM frames, DATAGRAM capsule send helpers,
  nullq flow-control blocked events, reset/close events, and deep-owned
  application events. `Session.Config.max_stream_send_buffered` can cap
  per-stream bytes accepted by nullq but not yet acknowledged, and
  `StreamSendState` exposes written/acked/buffered byte counters. Session
  drain can also cap emitted event count and owned event payload bytes before
  DATA, DATAGRAM, capsule, push, or close-reason payloads are copied.
- `connection`: `nullq.Connection` adapter for control stream, optional QPACK
  streams, and request/data frame writes.
- `client` / `server`: BoringSSL TLS context helpers with ALPN set to `h3`,
  plus thin `Client` / `Server` facades that classify session events and proxy
  common request/response operations. `Client.startRequest` and
  `Server.startResponse` return streaming writers for incremental bodies and
  trailers, `Client.request` / `Server.respond` provide one-shot helpers, and
  `client.ResponseTracker` / `server.RequestTracker` build owned per-stream
  reader state that can outlive the drained event batch, with optional maximum
  accumulated body bytes. `ClientRunner` and `ServerRunner` wrap the trackers
  for applications that want batch-oriented event processing.
  `RequestHeadOptions.connect_protocol` opens the Extended CONNECT path once
  the peer advertises support, and `RequestReader.protocol` exposes the
  received protocol token.
  Request/response writers can send context-aware unreliable datagrams and
  reliable DATAGRAM capsules.

## Verified

- `zig build test` covers unit codecs and an in-process `h3` ALPN integration
  where a `null3.Session` client sends a request over `nullq` streams, a
  `null3.Server` tracks and returns a response, the `null3.Client` tracks the
  response lifecycle, the server sends GOAWAY, the client refuses excluded
  request streams, the server rejects a deliberately non-compliant request
  stream above its GOAWAY limit, and send-side RESET_STREAM plus CONNECTION_CLOSE
  and flow-control blocked events surface through the typed
  session/client/server APIs. It also covers negotiated HTTP/3 DATAGRAM exchange
  in both directions over `nullq` DATAGRAM frames, including tracked send IDs
  and DATAGRAM ACK propagation, nullq connection-ID replenishment events,
  send-buffer cap enforcement, tracker body-budget enforcement, session
  event-budget enforcement, RFC 9204 Appendix B exact-byte
  QPACK examples for dynamic table insertion, field-section references,
  acknowledgments, cancellations, and eviction, an opt-in dynamic QPACK
  response header over the in-process `nullq` exchange, plus exact-byte
  quic-go/qpack interop vectors for the shared static/literal/Huffman profile.
  Extended CONNECT coverage checks SETTINGS negotiation, client-side gating,
  and server-side `:protocol` request metadata. Capsule coverage includes
  DATAGRAM capsules and context-aware payloads over both QUIC DATAGRAM frames
  and DATA-frame capsules.
- `just qpack-interop` runs the optional Go-side fixture harness against
  `github.com/quic-go/qpack`.
- `just curl-h3-interop` builds a small localhost `null3` HTTP/3 server and
  drives `/opt/homebrew/opt/curl/bin/curl --http3-only` through handshake,
  request metadata, POST echo, large response, client-side cancellation,
  response reset, connection-close-after-response, and GOAWAY scenarios.
  The server and in-process integration tests share the reusable transport
  driver helper instead of open-coding the packet pump, and the server uses
  `ServerRunner` for request lifecycle assembly.

See [ROADMAP.md](ROADMAP.md) for the production plan.
