# null3

A Zig-first HTTP/3 implementation for Zig 0.16.0, built on top of
[`nullq`](../nullq) for QUIC transport and [`boringssl-zig`](../boringssl-zig)
for TLS 1.3 / ALPN configuration.

**Status: session scaffold.** The package now provides the stable protocol
surfaces plus a first HTTP/3 session layer over `nullq.Connection`: HTTP/3
constants, SETTINGS and frame codecs, non-blocking QPACK field-section
encoding/decoding with static-table support, header validation, priority
parameter parsing, TLS context helpers, transport-free message codecs, critical
stream setup, SETTINGS exchange, GOAWAY handling, graceful-drain state, reset
events, structured HTTP/3/QPACK error classification, request lifecycle
tracking, and lightweight client/server request-response facades.

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
- `settings`: HTTP/3 SETTINGS parser/encoder.
- `frame`: HTTP/3 frame parser/encoder, including RFC 9218 PRIORITY_UPDATE.
- `qpack`: QPACK primitives plus static-table/literal field-section codecs.
- `headers`: HTTP field validation for request/response scaffolding.
- `priority`: RFC 9218 urgency/incremental parameter parsing.
- `errors`: structured HTTP/3 application error code metadata plus local
  cause, connection-close, and stream-reset classification helpers.
- `stream`: stream type helpers plus frame-context validation.
- `message`: transport-free request/response HEADERS, DATA, and trailer
  encoding/decoding with stream-order validation.
- `session`: HTTP/3 session state over `nullq.Connection`, including control
  streams, peer SETTINGS, request stream draining, response writes, FIN
  validation, GOAWAY policy enforcement, reset events, and deep-owned
  application events.
- `connection`: `nullq.Connection` adapter for control stream, optional QPACK
  streams, and request/data frame writes.
- `client` / `server`: BoringSSL TLS context helpers with ALPN set to `h3`,
  plus thin `Client` / `Server` facades that classify session events and proxy
  common request/response operations. `Client.startRequest` and
  `Server.startResponse` return streaming writers for incremental bodies and
  trailers, `Client.request` / `Server.respond` provide one-shot helpers, and
  `server.RequestTracker` builds owned per-stream request lifecycle state.

## Verified

- `zig build test` covers unit codecs and an in-process `h3` ALPN integration
  where a `null3.Session` client sends a request over `nullq` streams, a
  `null3.Server` tracks and returns a response, the server sends GOAWAY, the
  `null3.Client` refuses excluded request streams, and the server rejects a
  deliberately non-compliant request stream above its GOAWAY limit.

See [ROADMAP.md](ROADMAP.md) for the production plan.
