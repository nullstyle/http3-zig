# http3-zig

A Zig-first HTTP/3 implementation for Zig 0.16.0, built on top of
[`quic-zig`](https://github.com/nullstyle/quic-zig) for QUIC transport
and [`boringssl-zig`](https://github.com/nullstyle/boringssl-zig)
for TLS 1.3 / ALPN configuration.

**Wire-format pin:**

| Spec | Revision |
|---|---|
| HTTP/3 | RFC 9114 |
| QPACK | RFC 9204 |
| HTTP Datagrams | RFC 9297 |
| Extended CONNECT | RFC 9220 |
| Priority | RFC 9218 |
| WebSocket-over-H3 | RFC 8441 / 9220 |
| CONNECT-UDP / MASQUE | RFC 9298 |
| WebTransport | **draft-ietf-webtrans-http3-15** (`SETTINGS_WT_ENABLED = 0x2c7cf000`) |

**License:** Apache 2.0 — see [`LICENSE`](LICENSE).
**Security:** disclosure policy in [`SECURITY.md`](SECURITY.md).
**Changelog:** [`CHANGELOG.md`](CHANGELOG.md).

## Install

http3-zig is a Zig package; consume it via `zig fetch`:

```sh
zig fetch --save https://github.com/nullstyle/http3-zig/archive/<commit-or-tag>.tar.gz
```

Then in your `build.zig`:

```zig
const http3_zig = b.dependency("http3_zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("http3_zig", http3_zig.module("http3_zig"));
```

http3-zig pulls in `quic-zig` and `boringssl-zig` as transitive
dependencies; no extra wiring is required for those.

## Quick example

The simplest end-to-end shape is the in-process loopback under
[`examples/loopback_get.zig`](examples/loopback_get.zig):

```zig
const std = @import("std");
const http3_zig = @import("http3_zig");

// 1. Bring up `quic_zig.Connection` instances on both sides
//    (handshake, transport params, etc.).
// 2. Build paired `http3_zig.Session` objects with the production
//    config preset:
const cfg = http3_zig.session.Config.production(.{
    .max_field_section_size = 64 * 1024,
});
var client_session = http3_zig.Session.init(allocator, .client, &client_quic, cfg);
defer client_session.deinit();
var server_session = http3_zig.Session.init(allocator, .server, &server_quic, cfg);
defer server_session.deinit();

// 3. Wire `Client` / `Server` facades on top:
var client = http3_zig.Client.init(&client_session);
var server = http3_zig.Server.init(&server_session);

// 4. Drive a request:
var req = try client.startRequest(allocator, .{
    .authority = "example.com",
    .path = "/",
});
try req.finish();
// ... pump packets, drain events, observe responses ...
```

See [`examples/loopback_get.zig`](examples/loopback_get.zig) for the facade
loopback shape, [`examples/manual_pump_get.zig`](examples/manual_pump_get.zig)
for the same GET with the QUIC/H3 pump order open-coded, and
[`examples/loopback_wt.zig`](examples/loopback_wt.zig) for the endpoint
WebTransport variant. [`examples/observability_metrics.zig`](examples/observability_metrics.zig)
shows trace callbacks and metrics snapshots around the same request/response
shape, and [`examples/request_reset.zig`](examples/request_reset.zig) shows a
client request reset surfacing as a typed server-side lifecycle event.
Intermediaries can start from
[`examples/webtransport_proxy.zig`](examples/webtransport_proxy.zig), which
forwards WT control capsules, QUIC DATAGRAM payloads, WT substream data, FIN,
and resets across two in-process HTTP/3 pairs while keeping proxy policy in
application code. Applications that need streaming response-body budgets can
start from [`examples/bounded_body_sink.zig`](examples/bounded_body_sink.zig),
which consumes raw response events into a caller-owned bounded sink instead of
using the facade runners' body accumulation; streaming request-body producers
can start from [`examples/streaming_upload.zig`](examples/streaming_upload.zig),
which writes POST body chunks through `RequestWriter.canWrite` and lets the
server consume raw request DATA under its own budget. Graceful shutdown policy
is modeled in [`examples/graceful_shutdown.zig`](examples/graceful_shutdown.zig),
which sends GOAWAY after accepting an in-flight request, lets that response
finish, and rejects the next client request. For an application-author
walkthrough of the WebTransport API (handshake, streams, datagrams, flow
control, drain, close), see
[`docs/webtransport-tour.md`](docs/webtransport-tour.md).

## Datagram sends

http3-zig exposes three transport paths for HTTP Datagram payloads.
They are not equivalent — the QUIC-DATAGRAM path is unreliable and
fast; the capsule fallback is reliable and ordered with stream bytes;
the context-id variants add MASQUE-style multiplexing on either path.
Pick the row that matches your protocol contract:

| Path | Method (writer) | Method (handle) | Wire shape | Reliability | Ordering | Gating | WebTransport-spec? |
|---|---|---|---|---|---|---|---|
| QUIC-DATAGRAM (raw) | `RequestWriter.datagram` / `datagramTracked` | `Client.sendDatagram` / `Server.sendDatagram` / `WebTransportClientStream.sendDatagram` / `WebTransportServerStream.sendDatagram` | RFC 9297 §2: `[quarter-stream-id, payload]` in a QUIC DATAGRAM frame | unreliable, may be lost | unordered | `SETTINGS_H3_DATAGRAM = 1` AND QUIC `max_datagram_frame_size > 0` | yes (the only WT-spec path) |
| QUIC-DATAGRAM (with context-id) | `RequestWriter.datagramWithContext` / `datagramWithContextTracked` | `Client.sendDatagramWithContext` / `Server.sendDatagramWithContext` | RFC 9297 §2.1 / draft-masque: above + `context-id` varint | unreliable | unordered | same as above | no (CONNECT-UDP / MASQUE only) |
| Capsule (request/response body) | `RequestWriter.datagramCapsule` | `Client.sendDatagramCapsule` / `Server.sendDatagramCapsule` | RFC 9297 §3.4: `DATAGRAM` capsule on the request stream | reliable, ordered | ordered with stream bytes | `SETTINGS_H3_DATAGRAM = 1` only | no (out-of-spec for WT datagrams) |
| Capsule (with context-id) | `RequestWriter.datagramContextCapsule` | `Client.sendDatagramContextCapsule` / `Server.sendDatagramContextCapsule` | DATAGRAM capsule + context-id varint | reliable, ordered | ordered | `SETTINGS_H3_DATAGRAM = 1` only | no (MASQUE multiplexing on the reliable fallback) |

The `Tracked` suffix on the QUIC-DATAGRAM variants returns the QUIC
datagram-id (a `u64`) for later correlation with `datagram_acked` /
`datagram_lost` events. The untracked variants discard that id.

For WebTransport specifically: only the QUIC-DATAGRAM path
(`sendDatagram` / `sendDatagramTracked` on `WebTransportClientStream` /
`WebTransportServerStream`) is correct. The WebTransport draft mandates
QUIC DATAGRAM. The capsule path (and its context-id sibling) is
exposed on the underlying writer accessible via `requestWriter()` /
`responseWriter()`, but calling those for a WT datagram is out of spec —
they target the CONNECT stream's body, not WT's per-session datagram
channel. Use the capsule paths only for pure RFC 9297 datagram-on-stream
cases or non-WT MASQUE multiplexing. WT control / extension capsules are
different: intermediary code may forward them with
`WebTransport*Stream.forwardCapsuleTo`, which observes the inbound capsule
locally and writes the exact capsule on the paired outbound CONNECT stream.
`examples/webtransport_proxy.zig` shows the rest of the datapath that remains
application-owned: stream-id maps, datagram routing, and CONNECT FIN/reset
policy.

## Stream lifecycle

Five named verbs cover the stream-end vocabulary across `RequestWriter`,
`ResponseWriter`, `Client`, `Server`, and the typed wrappers
(`WebTransport*Stream`, `WebSocket*Stream`, `ConnectUdp*Stream`). Each
has a distinct wire effect:

| Verb | Wire effect | Side | Meaning |
|---|---|---|---|
| `finish` | QUIC FIN on send side | outbound | clean half-close, no error code |
| `finishStream` | QUIC FIN on a *WT substream* | outbound | WT-only; routes through `Session.finishWebTransportStream` |
| `reset(code)` | RESET_STREAM with `error_code` | outbound | drop our own buffered/in-flight bytes |
| `resetStream(code)` / `resetStreamWithCode(wire)` | RESET_STREAM on a *WT substream* | outbound | WT-only; first variant runs an app-code through draft §4.6 mapping, second takes a wire code raw |
| `abort()` | RESET_STREAM with default code | outbound | convenience: client default `request_cancelled`, server default `internal_error` |
| `cancel()` | STOP_SENDING with `request_cancelled` | inbound | ask peer to stop sending; client-only on `RequestWriter` |
| `close(code, reason)` | `CLOSE_WEBTRANSPORT_SESSION` capsule + FIN | both | WT-session-level, distinct from stream lifecycle |

Decision rule:

- **outbound abort** (we want to drop our send side with a reason) →
  `reset(code)` for a specific code, or `abort()` for the role-default
  code.
- **inbound abort** (we want the peer to stop sending us) → `cancel()`
  on the client side. (`ResponseWriter` has no symmetric `cancel`
  because the server cannot ask the client to stop sending the
  request body without a RESET, which is what `reset` already does.)
- **bidirectional abort** (both sides) → `try self.abort(); try
  self.cancel();`.

For the WebTransport-specific subset (CONNECT control stream vs WT
substream vs WT-session-level capsule close) see
[`docs/webtransport-tour.md`](docs/webtransport-tour.md).

## Status

http3-zig is a pre-1.0 HTTP/3 session layer over `quic-zig.Connection`. It
provides:

- **Protocol codecs** — HTTP/3 constants, SETTINGS and frame codecs,
  transport-free message codecs, header validation, TLS context helpers, and
  Priority field / `PRIORITY_UPDATE` parsing.
- **QPACK** — non-blocking field-section encoding/decoding with the static
  table, Huffman strings, and dynamic-table support: encoder/decoder stream
  instruction codecs, state-sync accounting, configurable indexing policy,
  opt-in dynamic-stream integration, and implementation-neutral dynamic
  fixture manifests for external peer harnesses.
- **Session lifecycle** — critical-stream setup and SETTINGS exchange,
  request/response lifecycle tracking, client/server event runners, reusable
  transport-driver helpers, GOAWAY handling, graceful-drain state, reset and
  transport-close events, and structured HTTP/3/QPACK error classification.
- **Extensions** — Extended CONNECT negotiation and request metadata, Capsule
  Protocol codecs, HTTP/3 DATAGRAM send/receive with a context registry,
  receive dispositions, bounded unknown-context buffering and Context ID
  allocation checks, WebSocket-over-HTTP/3 tunnel helpers, and CONNECT-UDP
  receiver helpers. WebTransport exposes endpoint flow-control helpers and
  explicit intermediary capsule forwarding helpers; socket/datagram/stream
  proxy loops stay application-owned.
- **Server push** — `MAX_PUSH_ID`, `PUSH_PROMISE`, push streams,
  `CANCEL_PUSH`, duplicate-promise validation, and client push policy.
- **Observability & limits** — trace callbacks and metrics snapshots, TLS
  keylog / QUIC qlog passthrough, QUIC flow-control blocked observability,
  opt-in send-buffer backpressure, drain/event budgets, and WebTransport
  buffering caps.

`SessionConfig.production(.{})` provides a conservative preset with bounded
field sections, decoded QPACK storage, event payloads, reliable capsules,
datagrams, send buffering, and pre-confirmation WebTransport buffering. See
[docs/production-limits.md](docs/production-limits.md). The
[embedding guide](docs/embedding-guide.md) shows the application-owned event
loop shape, event lifetime rules, and when to choose raw events versus runners.

```sh
mise install
just test
just fuzz-smoke
just run-examples
just example-loopback-get
just example-manual-pump-get
just example-observability-metrics
just example-request-reset
just example-bounded-body-sink
just example-streaming-upload
just example-graceful-shutdown
just external-h3-client
just external-h3-interop
```

## Design Shape

- `http3-zig` owns HTTP semantics: request/response state, HTTP/3 frames,
  SETTINGS, QPACK, priorities, push, WebTransport/extended CONNECT, and
  application-facing APIs.
- `quic-zig` owns QUIC transport: packets, streams, flow control, datagrams,
  loss recovery, migration, and connection IDs.
- `boringssl-zig` owns TLS 1.3 and ALPN. `http3-zig.client` and `http3-zig.server`
  provide convenience context constructors that advertise `h3`.
- The library stays I/O-decoupled. Embedders own sockets and event loops,
  drive `quic-zig.Connection.handle` / `poll`, then hand stream bytes to `http3-zig`.
  See [docs/embedding-guide.md](docs/embedding-guide.md) for the pump order,
  event ownership, and backpressure choices.

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
  capsule-aware pending buffering, bounded extension capsule type registration,
  drop/buffer/abort receive dispositions for DATAGRAM frames and DATAGRAM
  capsules, and `capsule-protocol: ?1` negotiation headers.
- `driver`: small `quic-zig`/`http3-zig` transport-driving helpers for tests,
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
- `session`: HTTP/3 session state over `quic-zig.Connection`, including control
  streams, peer SETTINGS, request stream draining, response writes, FIN
  validation, optional dynamic QPACK encoder/decoder stream processing,
  GOAWAY policy enforcement, Extended CONNECT negotiation checks, HTTP/3
  DATAGRAM events over QUIC DATAGRAM frames, DATAGRAM capsule send helpers,
  server push opt-in and push-stream decoding, quic-zig flow-control blocked
  events, reset/close events, and deep-owned application events.
  Client sessions can emit request and push `PRIORITY_UPDATE` frames; server
  sessions surface typed priority-update events and retain latest priority
  state for application scheduling policy.
  `Session.Config.max_stream_send_buffered` can cap
  per-stream bytes accepted by quic-zig but not yet acknowledged, and
  `StreamSendState` exposes written/acked/buffered byte counters. Session
  drain can also cap emitted event count and owned event payload bytes before
  DATA, DATAGRAM, capsule, push, or close-reason payloads are copied. QPACK
  decode can cap decoded field-line count and decoded field storage separately
  from encoded HEADERS payload size, and outgoing reliable capsules can be
  capped before their DATA-frame payload is allocated.
  `SessionConfig.production(.{})` collects those caps into a recommended
  production baseline without changing compatibility-oriented defaults.
- `connection`: `quic-zig.Connection` adapter for control stream, optional QPACK
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
  Tracker scope is **HTTP request/response messages on a request stream**
  — including the CONNECT bootstrap exchange for WebTransport,
  WebSocket, and CONNECT-UDP tunnels. Trackers do **not** accumulate
  WebTransport substream data; for that, process
  `webtransport_stream_data` events directly. See
  [`docs/webtransport-tour.md`](docs/webtransport-tour.md) for the WT
  substream event flow.
  `RequestHeadOptions.connect_protocol` opens the Extended CONNECT path once
  the peer advertises support, and `RequestReader.protocol` exposes the
  received protocol token. `Client.startWebSocket` and `Server.acceptWebSocket`
  provide typed Extended CONNECT tunnel helpers for the `websocket` protocol
  token. `http3-zig.websocket.frame` provides the transport-free WebSocket frame
  codec, and `http3-zig.websocket.message` assembles owned text/binary messages
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
  where a `http3-zig.Session` client sends a request over `quic-zig` streams, a
  `http3-zig.Server` tracks and returns a response, the `http3-zig.Client` tracks the
  response lifecycle, the server sends GOAWAY, the client refuses excluded
  request streams, the server rejects a deliberately non-compliant request
  stream above its GOAWAY limit, and send-side RESET_STREAM plus CONNECTION_CLOSE
  and flow-control blocked events surface through the typed
  session/client/server APIs. It also covers negotiated HTTP/3 DATAGRAM exchange
  in both directions over `quic-zig` DATAGRAM frames, including tracked send IDs
  and DATAGRAM ACK propagation, quic-zig connection-ID replenishment events,
  send-buffer cap enforcement, tracker body-budget enforcement, production
  session preset coverage, capsule send-budget enforcement, session
  event-budget and QPACK decoded-field budget enforcement, RFC 9204 Appendix B exact-byte
  QPACK examples for dynamic table insertion, field-section references,
  acknowledgments, cancellations, and eviction, a dedicated dynamic-table
  QPACK fixture runner for those exact bytes, an opt-in dynamic QPACK response
  header over the in-process `quic-zig` exchange, plus exact-byte quic-go/qpack
  interop vectors for the shared static/literal/Huffman profile.
  Extended CONNECT coverage checks SETTINGS negotiation, client-side gating,
  and server-side `:protocol` request metadata. Capsule coverage includes
  DATAGRAM capsules and context-aware payloads over both QUIC DATAGRAM frames
  and DATA-frame capsules, plus WebTransport control-capsule forwarding across
  a two-hop intermediary fixture. Observability coverage checks TLS keylog hook
  configuration plus HTTP/3 trace callback and metrics accounting for emitted
  events. WebSocket-over-HTTP/3 coverage checks negotiated Extended CONNECT
  gating, tunnel request/accept helpers, RFC 6455 frame encoding/decoding, and
  message byte flow in both directions. CONNECT-UDP coverage checks MASQUE
  tunnel setup, target parsing, Context ID 0 HTTP Datagrams, reliable UDP
  DATAGRAM capsules, receiver classification, context registry policy, and
  bounded unknown-context datagram and DATAGRAM-capsule buffering/release/drop
  behavior under small sustained budgets, endpoint Context ID allocation
  parity, extension capsule registration/routing, and oversized UDP payload
  stream-abort classification. DATAGRAM abuse coverage includes malformed HTTP/3 DATAGRAM
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
  snapshots, decoder feedback bytes, and malformed dynamic-input rejection,
  including a drift check for the committed JSON manifest consumed by external
  peers.
- `just qpack-dynamic-fixtures` prints the committed dynamic-table fixture
  manifest (`interop/qpack_dynamic/fixtures.json`) from the Zig source
  vectors.
- `just fuzz-smoke` runs the transport-free codec fuzz harness across HTTP/3
  frames, SETTINGS, capsules, HTTP/3 DATAGRAM payloads, QPACK integers,
  Huffman strings, field sections, encoder/decoder stream instructions, and
  WebSocket frames, WebSocket messages, and MASQUE CONNECT-UDP helpers.
- `just curl-h3-interop` builds a small localhost `http3-zig` HTTP/3 server and
  drives `/opt/homebrew/opt/curl/bin/curl --http3-only` through handshake,
  request metadata, status/header checks, POST echo, large upload echo,
  multi-request connection reuse, large response, client-side cancellation,
  response reset, connection-close-after-response, and GOAWAY scenarios.
  The server and in-process integration tests share the reusable transport
  driver helper instead of open-coding the packet pump, and the server uses
  `ServerRunner` for request lifecycle assembly.
- `just external-h3-client` builds a http3-zig-as-client HTTP/3 interop harness
  that targets an IP-literal UDP endpoint with caller-supplied SNI, authority,
  method, path, and optional body. Peer-specific scripts for quic-go, ngtcp2,
  lsquic, and aioquic can layer above this binary.
- `just external-h3-interop` runs the optional external-peer matrix. It skips
  peers whose server command environment variables are not configured, and can
  drive quic-go, ngtcp2, lsquic, and aioquic style servers through the shared
  http3-zig-as-client harness. Pinned quic-go and aioquic peers are available
  in-tree via `bash interop/external_h3/peers/quic-go.sh` and
  `bash interop/external_h3/peers/aioquic.sh`; CI runs both from the advisory
  `h3-interop` workflow. See
  [docs/h3-third-party-interop.md](docs/h3-third-party-interop.md).
- `just examples` builds every runnable in-process example; `just run-examples`
  runs the full example cookbook and is covered by CI on Ubuntu.
- `just example-loopback-get` runs a compact in-process client/server example
  over `TransportLoopback` with the public `Client`, `Server`,
  `ClientRunner`, and `ServerRunner` APIs.
- `just example-manual-pump-get` runs the same basic GET while open-coding the
  QUIC `tick` / `poll` / `handle` and HTTP/3 `drain` order.
- `just example-observability-metrics` runs a compact request/response with
  `ObservabilityHooks` installed and prints trace/metrics counters.
- `just example-request-reset` runs a client-side request reset and shows the
  server's typed peer reset classification.
- `just example-bounded-body-sink` runs the same in-process pattern with raw
  `RequestEvent` / `ResponseEvent` classification and caller-owned streaming
  body storage.
- `just example-streaming-upload` runs a client-side streaming POST with
  `RequestWriter.canWrite` checks and server-side raw request DATA budgeting.
- `just example-graceful-shutdown` runs a server-initiated GOAWAY drain where
  one in-flight request completes and the client's next request is blocked.
- `just example-loopback-wt` runs the endpoint WebTransport loopback example.
- `just example-webtransport-proxy` runs a two-hop WebTransport proxy datapath
  example over two in-process H3 pairs.

See [docs/embedding-guide.md](docs/embedding-guide.md) for the event-loop
integration shape, and [ROADMAP.md](ROADMAP.md) for the production plan.
