# API Stability

http3-zig is pre-1.0. Per semver, **any 0.x release may include breaking
changes.** This document exists so an embedder can judge *which* surfaces are
load-bearing versus volatile, and what the path to 1.0 looks like — not to
promise that nothing moves before then.

At 1.0 the **Stable** tier below graduates to a semver guarantee: no breaking
changes to it without a major version bump. The other tiers carry no such
promise even after 1.0. The module name in Zig code is `http3_zig`.

## Tiers

### Stable — depend on these freely

The intended long-term embedding surface. It may still be refined before 1.0,
but changes will be deliberate, called out in `CHANGELOG.md`, and kept minimal.

- **Session core:** `Session` and its lifecycle — `init` / `deinit` / `start`
  / `drain` / `close`, the send-side entry points (`openRequest`,
  `sendGoaway`, `stopSending`, `resetStream`, the datagram/capsule sends), and
  `SessionConfig` / `SessionProductionOptions` / `SessionConfig.production`.
- **Facades:** `Client` and `Server`, their request/response/push option
  structs and streaming writer handles (`RequestWriter`, `ResponseWriter`,
  `PushWriter`), and the reader/tracker convenience types (`ResponseReader` /
  `RequestReader`, `ResponseTracker` / `RequestTracker` /
  `PushedResponseTracker`, `ClientRunner` / `ServerRunner`).
- **Event model:** `session.Event` (the tagged union `drain` yields),
  `event.deinit`, and the ownership contract documented in `src/root.zig` —
  subject to the forward-compatibility contract below.
- **Error model:** `errors.*` — `ApplicationError`, `ConnectionError`,
  `StreamError`, `ErrorScope` / `ErrorSource` / `ErrorCategory`, and the
  mapping from the `Error` set a public method documents to RFC 9114 / 9204 /
  9297 codes. New variants may be added (handle errors with an `else`);
  existing ones will not be silently repurposed.
- **Observability:** the qlog / keylog / trace callback hooks
  (`ObservabilityHooks`, `KeylogCallback`, `Quic*` passthrough, `Metrics`).
- **Extension facades** — API *shape* is stable; their on-wire format is
  draft-tracked (see *Draft-extension sunset path*): `WebTransportClientStream`
  / `WebTransportServerStream` and the WT event types, `WebSocketClientStream`
  / `WebSocketServerStream`, and the CONNECT-UDP tunnel wrappers.

### Unstable / evolving — usable, but expect movement

- **Draft-based extensions.** WebTransport over HTTP/3 tracks
  `draft-ietf-webtrans-http3-15`; it changes with the draft or on RFC
  publication — see *Draft-extension sunset path*. The MASQUE surface
  (`Masque*`, CONNECT-UDP) is scoped as framing/helper primitives, not a full
  proxy, and its capsule-extension registry is still settling. (WebSocket over
  HTTP/3 tracks the published RFC 9220 + RFC 6455 and is not draft-volatile.)
- **The low-level codecs.** `frame`, `qpack`, `message`, `settings`,
  `headers`, `capsule`, `datagram`, `stream`, and the WebSocket frame/message
  codecs are exported for advanced use and testing. They are usable, but their
  signatures may be refined; they are not the primary embedding surface and
  are **not** covered by the Stable guarantee.
- **`Config` naming** is a known pre-1.0 cleanup target: field names and the
  `null`-to-disable vs `bool` conventions across `SessionConfig` /
  `ProductionOptions` (size caps, flow-control knobs, policy enums) will be
  normalized before 1.0. New `Config` fields are always added with
  production-safe defaults.
- **Newly added surfaces** — e.g. the DoS hardening knobs
  (`max_incoming_frame_length`) — may see minor signature or naming
  refinement as they are exercised for the first time.

### Internal — do not depend on

- Anything named `_internal`, any decl prefixed with `_`, and non-`pub`
  fields (e.g. `WTSessionFlowState` — only the read-only
  `WTSessionFlowSnapshot` is public).
- Test-only helpers and fixtures under `tests/`.

## `Event` forward-compatibility contract

`session.Event` is a tagged union that embedders `switch` over (directly, or
via the runner/tracker `observe` / `classify` helpers). The contract, which
1.0 will keep:

- **New variants may be added in a minor release.** Handle unknown variants
  with an `else` branch — a `switch` without one will fail to compile against
  a newer http3-zig, which is the intended signal to review it.
- **Existing variant tags will not be removed or repurposed** within a release
  series. A tag's payload shape is stable; an incompatible payload change is
  introduced as a new tag.

## Config forward-compatibility

New `Config` fields are additive and default to safe, backward-compatible
behavior. Existing fields will not silently change meaning. The naming /
semantics normalization noted above is the one planned pre-1.0 churn to this
surface.

## Draft-extension sunset path

WebTransport over HTTP/3 is pinned to a specific draft revision
(`draft-ietf-webtrans-http3-15`), with SETTINGS codepoints and capsule types
asserted numerically in the conformance suite so an accidental revision drift
surfaces loudly. When the corresponding RFC — or a newer draft — is published:

1. The implementation moves to the new revision.
2. The superseded revision's code path is kept for **one minor release** with a
   deprecation note in `CHANGELOG.md`, then removed.
3. If a wire format changes incompatibly, the new format is introduced under a
   new namespaced entry rather than silently altering the existing one, so a
   deployment can migrate deliberately.

## Relationship to quic-zig

http3-zig pins a specific `quic-zig` version (see `build.zig.zon`) and depends
on quic-zig's **Stable** tier (`Connection`, the raw connection cycle, the
stream and lifecycle helpers, `ConnectionEvent`). It deliberately avoids
quic-zig's internal `conn.*` tier via the top-level re-exports quic-zig 0.5.0
added; the one remaining reach-in is `conn.state.Error` (the aggregate
transport error set), which has no top-level alias. A quic-zig upgrade is a
coordinated event: it can change transport behavior (e.g. the 0.4.0
terminal-stream reaping), so it is pinned and bumped deliberately, not tracked
as a floating range.
