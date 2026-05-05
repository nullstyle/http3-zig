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
header validation, Priority field parsing, HTTP/3 PRIORITY_UPDATE hooks, TLS context helpers,
transport-free message codecs, critical stream setup, SETTINGS exchange,
opt-in dynamic QPACK stream integration, GOAWAY handling, graceful-drain state,
reset events, transport close events, structured HTTP/3/QPACK error
classification, QUIC flow-control blocked observability, HTTP/3 DATAGRAM
send/receive groundwork, reusable transport driver helpers, request lifecycle
tracking, response lifecycle tracking, client/server event runners, Extended
CONNECT negotiation and request metadata, Capsule Protocol codecs,
context-aware DATAGRAM helpers, WebSocket-over-HTTP/3 tunnel helpers, HTTP/3
trace callbacks and metrics snapshots, TLS keylog / QUIC qlog passthrough
hooks, CONNECT-UDP receiver helpers, context registry, receive dispositions,
bounded unknown-context datagram buffering, Context ID allocation checks,
and UDP payload limits, first server-push support with `MAX_PUSH_ID`,
`PUSH_PROMISE`, push streams, `CANCEL_PUSH`, duplicate-promise validation, and
client push policy, opt-in send-buffer backpressure limits, and lightweight
request-response facades with configurable tracker body and session event-queue
budgets. `SessionConfig.production(.{})` provides an opt-in conservative
session preset with bounded field sections, decoded QPACK storage, event
payloads, reliable capsules, datagrams, and send buffering.

```sh
mise install
just test
just fuzz-smoke
just example-loopback-get
just external-h3-client
just external-h3-interop
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
- `priority`: RFC 9218 Priority field helpers for urgency/incremental
  parameters, including request/response field extraction.
- `errors`: structured HTTP/3 application error code metadata plus local
  cause, connection-close, and stream-reset classification helpers.
- `stream`: stream type helpers plus frame-context validation.
- `message`: transport-free request/response HEADERS, DATA, and trailer
  encoding/decoding with stream-order validation.
- `datagram`: RFC 9297 HTTP/3 DATAGRAM quarter-stream-id payload codec plus
  reusable Context ID payload helpers for datagram-using extensions.
- `capsule`: RFC 9297 Capsule Protocol TLV codec, including DATAGRAM capsules.
- `masque`: CONNECT-UDP helper foundation over Extended CONNECT, Context ID 0
  UDP payloads, checked context registry and receiver helpers, Context ID
  allocation validation, bounded unknown-context datagram buffering,
  capsule-aware pending buffering, drop/buffer/abort receive dispositions for
  DATAGRAM frames and DATAGRAM capsules, and `capsule-protocol: ?1`
  negotiation headers.
- `driver`: small `nullq`/`null3` transport-driving helpers for tests,
  examples, and interop peers. It keeps socket and clock ownership with the
  embedder while centralizing the handle/poll/tick/session-drain order.
- `runner`: client/server event runners that compose raw `session.Event`
  classification with owned request/response lifecycle trackers and batch
  completion summaries.
- `observability`: embedder-owned diagnostics hooks: TLS keylog callback
  aliases, QUIC qlog callback aliases, typed HTTP/3 trace events, and metrics
  counters.
- `websocket`: RFC 9220 handshake helpers for WebSocket-over-HTTP/3 Extended
  CONNECT tunnels plus RFC 6455 frame and message codecs with masking,
  close-code checks, incremental fragmentation tracking, assembled
  text/binary messages, UTF-8 validation, and interleaved control-frame events.
- `session`: HTTP/3 session state over `nullq.Connection`, including control
  streams, peer SETTINGS, request stream draining, response writes, FIN
  validation, optional dynamic QPACK encoder/decoder stream processing,
  GOAWAY policy enforcement, Extended CONNECT negotiation checks, HTTP/3
  DATAGRAM events over QUIC DATAGRAM frames, DATAGRAM capsule send helpers,
  server push opt-in and push-stream decoding, nullq flow-control blocked
  events, reset/close events, and deep-owned application events.
  Client sessions can emit request and push `PRIORITY_UPDATE` frames; server
  sessions surface typed priority-update events and retain latest priority
  state for application scheduling policy.
  `Session.Config.max_stream_send_buffered` can cap
  per-stream bytes accepted by nullq but not yet acknowledged, and
  `StreamSendState` exposes written/acked/buffered byte counters. Session
  drain can also cap emitted event count and owned event payload bytes before
  DATA, DATAGRAM, capsule, push, or close-reason payloads are copied. QPACK
  decode can cap decoded field-line count and decoded field storage separately
  from encoded HEADERS payload size, and outgoing reliable capsules can be
  capped before their DATA-frame payload is allocated.
  `SessionConfig.production(.{})` collects those caps into a recommended
  production baseline without changing compatibility-oriented defaults.
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
  received protocol token. `Client.startWebSocket` and `Server.acceptWebSocket`
  provide typed Extended CONNECT tunnel helpers for the `websocket` protocol
  token. `null3.websocket.frame` provides the transport-free WebSocket frame
  codec, and `null3.websocket.message` assembles owned text/binary messages
  while validating text/close UTF-8 and preserving ping/pong/close events.
  `WebSocketClientStream.writeMessage` and `WebSocketServerStream.writeMessage`
  provide typed message writes.
  `Client.startConnectUdp` and `Server.acceptConnectUdp` provide typed
  CONNECT-UDP tunnel helpers with UDP payload send/receive conveniences,
  Context ID 0 validation, UDP payload length guards, and stream-failure
  helpers that use `H3_CONNECT_ERROR`. `MasqueConnectUdpReceiver` gives
  embedders a reusable per-tunnel receive classifier for unreliable DATAGRAM
  payloads and reliable DATAGRAM capsules, while
  `MasquePendingDatagramBuffer` provides bounded temporary storage for
  unknown Context IDs until extension registration state arrives.
  `Server.startPush` / `Server.push` provide the first server-push facade for
  promised requests and pushed responses once the client advertises
  `MAX_PUSH_ID`, and `Client.cancelPush` / `Server.cancelPush` exchange
  `CANCEL_PUSH` control frames for promised resources. Client sessions track
  duplicate `PUSH_PROMISE` IDs by decoded request fields and can use
  `PushPolicy.cancel_promises` to auto-cancel valid promised resources.
  `PushedResponseTracker` assembles pushed response headers, body, trailers,
  completion, reset, cancellation, and originating promise metadata, while
  `Server.startPushFromRequest` / `Server.pushFromRequest` provide same-origin
  cacheable promise helpers for ordinary request-derived pushes.
  Request/response readers expose parsed Priority fields, request writers can
  send request priority updates, clients can reprioritize promised pushes, and
  servers can query latest request/push priority state.
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
  send-buffer cap enforcement, tracker body-budget enforcement, production
  session preset coverage, capsule send-budget enforcement, session
  event-budget and QPACK decoded-field budget enforcement, RFC 9204 Appendix B exact-byte
  QPACK examples for dynamic table insertion, field-section references,
  acknowledgments, cancellations, and eviction, a dedicated dynamic-table
  QPACK fixture runner for those exact bytes, an opt-in dynamic QPACK response
  header over the in-process `nullq` exchange, plus exact-byte quic-go/qpack
  interop vectors for the shared static/literal/Huffman profile.
  Extended CONNECT coverage checks SETTINGS negotiation, client-side gating,
  and server-side `:protocol` request metadata. Capsule coverage includes
  DATAGRAM capsules and context-aware payloads over both QUIC DATAGRAM frames
  and DATA-frame capsules. Observability coverage checks TLS keylog hook
  configuration plus HTTP/3 trace callback and metrics accounting for emitted
  events. WebSocket-over-HTTP/3 coverage checks negotiated Extended CONNECT
  gating, tunnel request/accept helpers, RFC 6455 frame encoding/decoding, and
  message byte flow in both directions. CONNECT-UDP coverage checks MASQUE
  tunnel setup, target parsing, Context ID 0 HTTP Datagrams, reliable UDP
  DATAGRAM capsules, receiver classification, context registry policy, and
  bounded unknown-context datagram and DATAGRAM-capsule buffering/release/drop
  behavior under small sustained budgets, endpoint Context ID allocation
  parity, and oversized UDP payload stream-abort classification. DATAGRAM abuse
  coverage includes malformed HTTP/3 DATAGRAM
  connection closes with `H3_DATAGRAM_ERROR`. Server-push coverage checks
  client `MAX_PUSH_ID` opt-in, server `PUSH_PROMISE` emission, push-stream
  response headers, pushed DATA, pushed stream completion, `CANCEL_PUSH` in
  both directions, invalid cancellation placement, push-ID limit enforcement,
  and duplicate push stream ID rejection. It also covers duplicate
  `PUSH_PROMISE` consistency and
  policy-driven auto-cancellation, same-origin/cacheable push promise helper
  validation, and higher-level pushed-response tracking through `ClientRunner`.
  Priority coverage checks typed Priority field extraction, request and push
  `PRIORITY_UPDATE` send/receive state, observability counters, invalid target
  rejection, forbidden server senders, and malformed Priority field values.
- `just qpack-interop` runs the optional Go-side fixture harness against
  `github.com/quic-go/qpack`.
- `just qpack-dynamic-interop` runs the transport-free dynamic-table fixture
  corpus for RFC 9204 Appendix B encoder streams, field sections, table
  snapshots, decoder feedback bytes, and malformed dynamic-input rejection.
- `just fuzz-smoke` runs the transport-free codec fuzz harness across HTTP/3
  frames, SETTINGS, capsules, HTTP/3 DATAGRAM payloads, QPACK integers,
  Huffman strings, field sections, encoder/decoder stream instructions, and
  WebSocket frames, WebSocket messages, and MASQUE CONNECT-UDP helpers.
- `just curl-h3-interop` builds a small localhost `null3` HTTP/3 server and
  drives `/opt/homebrew/opt/curl/bin/curl --http3-only` through handshake,
  request metadata, status/header checks, POST echo, large upload echo,
  multi-request connection reuse, large response, client-side cancellation,
  response reset, connection-close-after-response, and GOAWAY scenarios.
  The server and in-process integration tests share the reusable transport
  driver helper instead of open-coding the packet pump, and the server uses
  `ServerRunner` for request lifecycle assembly.
- `just external-h3-client` builds a null3-as-client HTTP/3 interop harness
  that targets an IP-literal UDP endpoint with caller-supplied SNI, authority,
  method, path, and optional body. Peer-specific scripts for quic-go, ngtcp2,
  lsquic, and aioquic can layer above this binary.
- `just external-h3-interop` runs the optional external-peer matrix. It skips
  peers whose server command environment variables are not configured, and can
  drive quic-go, ngtcp2, lsquic, and aioquic style servers through the shared
  null3-as-client harness.
- `just example-loopback-get` runs a compact in-process client/server example
  over `TransportLoopback` with the public `Client`, `Server`,
  `ClientRunner`, and `ServerRunner` APIs.

See [ROADMAP.md](ROADMAP.md) for the production plan.
