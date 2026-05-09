# API narrowing proposal — v0.2

Status: proposal, read-only audit. Not implemented.

Scope: WebTransport-adjacent public API across `client.zig`, `server.zig`,
`session.zig`, `webtransport.zig`, and the `root.zig` re-exports. The
proposal is opinionated; "keep both — load-bearing" appears where the two
paths really do not collapse, and "deprecate / consolidate" appears where
they do.

## Inventory

Grouped by exported type. Doc paths refer to the methods at HEAD.

### `RequestWriter` (`client.zig:126`)
`write` · `sendState` · `canBuffer` · `canWrite` · `datagram` ·
`datagramTracked` · `datagramWithContext` · `datagramWithContextTracked` ·
`capsule` · `datagramCapsule` · `datagramContextCapsule` ·
`updatePriority` · `trailers` · **`finish`** · **`reset`** ·
**`abort`** · **`cancel`**.

### `ResponseWriter` (`server.zig:178`)
`write` · `sendState` · `canBuffer` · `canWrite` · `datagram` ·
`datagramTracked` · `datagramWithContext` · `datagramWithContextTracked` ·
`capsule` · `datagramCapsule` · `datagramContextCapsule` · `trailers` ·
**`finish`** · **`reset`** · **`abort`**. (No `cancel` — server side has
no symmetric inbound-abort verb on the writer.)

### `WebTransportClientStream` (`client.zig:372`)
`streamId` · `sessionId` · `sendDatagram` · `sendDatagramTracked` ·
`openUniStream` · `openBidiStream` · `writeStream` · `finishStream` ·
**`resetStream`** · **`resetStreamWithCode`** · `sendDrain` ·
`sendMaxData` · `sendMaxStreamsBidi` · `sendMaxStreamsUni` ·
`observeCapsule` · `flowState` · `close` · **`finishSend`** · **`reset`** ·
**`abort`** · `requestWriter`.

### `WebTransportServerStream` (`server.zig:444`)
Mirror of the client struct — same set, plus `responseWriter()` instead of
`requestWriter()`.

### `Client` (`client.zig:1237`)
`init` · `open` · `sendData` · `streamSendState` · `canBufferStreamBytes` ·
`canSendData` · `metrics` · `setObservabilityHooks` · `setQuicQlogCallback` ·
`sendDatagram` · `sendDatagramTracked` · `sendDatagramWithContext` ·
`sendDatagramWithContextTracked` · `sendCapsule` · `sendDatagramCapsule` ·
`sendDatagramContextCapsule` · `sendTrailers` · **`finish`** · **`reset`** ·
**`abort`** · **`cancel`** · `cancelPush` ·
`sendPriorityUpdateForRequest` · `sendPriorityUpdateForPush` · `request` ·
`startRequest` · `startConnectUdp` · `startWebSocket` · `startWebTransport` ·
`classify`.

### `Server` (`server.zig:744`)
`init` · `sendHeaders` · `sendData` · `streamSendState` ·
`canBufferStreamBytes` · `canSendData` · `metrics` · `setObservabilityHooks` ·
`setQuicQlogCallback` · `sendDatagram` · `sendDatagramTracked` ·
`sendDatagramWithContext` · `sendDatagramWithContextTracked` · `sendCapsule` ·
`sendDatagramCapsule` · `sendDatagramContextCapsule` · `sendTrailers` ·
`sendPushData` · `sendPushTrailers` · **`finish`** · **`reset`** ·
**`abort`** · **`resetPush`** · **`cancelPush`** · `priorityForRequest` ·
`priorityForPush` · `reject` · `goaway` · `respond` · `push` ·
`pushFromRequest` · `startPush` · `startPushFromRequest` · `startResponse` ·
`acceptConnectUdp` · `acceptWebSocket` · `acceptWebTransport` · `classify`.

### `Session` (`session.zig:965`)
The full primitive surface. The lifecycle-relevant subset is:
`finishStream` · `resetStream` · `resetRequest` · `resetResponse` ·
`stopSending` · `rejectRequest` · `cancelRequest` ·
`finishWebTransportStream` · `resetWebTransportStream` ·
`resetWebTransportStreamWithCode` · `close`. Datagram-relevant subset:
`sendDatagram` / `sendDatagramTracked` / `sendDatagramWithContext` /
`sendDatagramWithContextTracked` (QUIC-DATAGRAM path) plus
`sendRequestCapsule` · `sendRequestDatagramCapsule` ·
`sendRequestDatagramContextCapsule` and the `sendResponse*` mirror
(capsule path).

### `RequestTracker` / `ResponseTracker`
`init` · `initWithConfig` · `deinit` · `get` · `remove` · `observe`.

### `webtransport.zig` exports
Constants (`protocol_token`, header names, reserved error codes, stream
prefixes, capsule type codes), config (`ConnectOptions`, `AcceptOptions`),
predicates (`isProtocolToken`, `isRequest`, `responseAccepted`,
`peerEnabled`, `validateLocalSettings`), header-list helpers
(`requestAvailableProtocolsRaw`, `responseSelectedProtocolRaw`,
`validateSubprotocolToken`, `availableProtocolsEncodedLen`,
`formatAvailableProtocols`, `allocAvailableProtocols`,
`parseAvailableProtocols`, `isOfferedProtocol`),
**`StreamKind`** (`enum { uni, bidi }`), stream-prefix codecs, capsule
codecs (`CloseSession`, encode/decode for drain / close /
`WT_MAX_DATA` / `WT_DATA_BLOCKED` / `WT_MAX_STREAMS_BIDI` /
`WT_STREAMS_BLOCKED_BIDI` / `WT_MAX_STREAMS_UNI` / `WT_STREAMS_BLOCKED_UNI`),
`CapsuleEvent`, `classifyCapsule`, error-code mapping (`appErrorToHttp3`,
`http3ToAppError`, `isReservedStreamCode`).

### `root.zig` re-exports of WT-relevant types
`WebTransportConnectOptions` (= `client.WebTransportConnectOptions` =
`webtransport.ConnectOptions`), `WebTransportAcceptOptions` (similar),
`WebTransportClientStream`, `WebTransportServerStream`,
`WebTransportCloseSession`, `WebTransportParsedAvailableProtocols`,
`WebTransportCapsuleEvent`, `WebTransportStreamHeader`,
`WebTransportStreamHeaderDecoded`, **`WebTransportStreamKind`** (=
`webtransport.StreamKind`), `WebTransportStreamOpenedEvent`,
`WebTransportStreamDataEvent`, `WebTransportStreamFinishedEvent`,
`WebTransportStreamResetEvent`, `WebTransportFlowViolationEvent`,
`WebTransportFlowViolationKind`, `WTSessionFlowSnapshot`,
**`WTStreamDirection`** (= `session.WTStreamDirection`).

## Redundancy analysis

### Datagram sends — cluster of 3 paths × {tracked, untracked} × {raw, with-context} = 8 callable variants

Current paths through `RequestWriter` / `ResponseWriter`:

1. **`datagram` / `datagramTracked`** — RFC 9297 §2 QUIC-DATAGRAM path.
   Encodes `[quarter-stream-id, payload]` into a QUIC DATAGRAM frame.
   Tracked variant returns the QUIC datagram-id for ack/loss correlation
   via `datagram_acked` / `datagram_lost` events.
2. **`datagramWithContext` / `datagramWithContextTracked`** — Same as
   above but adds an HTTP Datagram Context-ID prefix
   (RFC 9297 §2.1 / draft-ietf-masque-h3-datagram). Used by MASQUE
   CONNECT-UDP (context-id 0) and any other context-id-multiplexed
   protocol. Differs from `datagram` only in that the codec emits the
   context-id varint inside the payload.
3. **`datagramCapsule` / `datagramContextCapsule`** — RFC 9297 §3.4
   capsule-protocol fallback path. Wraps the same payload in a
   `DATAGRAM` capsule and writes it on the *control stream* via the
   stream send buffer, so it survives middleboxes that drop QUIC
   DATAGRAM frames and works when QUIC `max_datagram_frame_size = 0`
   but the peer still set `SETTINGS_H3_DATAGRAM = 1`. The `Context`
   variant is the same trick layered with a context-id.

These are not equivalent. The QUIC-DATAGRAM path (#1, #2) is the fast
path: lossy, unordered, gated on the QUIC transport parameter
`max_datagram_frame_size > 0`. The capsule path (#3) is the
reliability-fallback / middlebox-survival path: ordered, reliable,
stream-buffered, gated only on `SETTINGS_H3_DATAGRAM = 1`. They have
different delivery contracts and applications can legitimately want
either, sometimes both depending on payload importance. The
session-level gating differs accordingly:
`validateDatagramSend` checks both settings AND the QUIC transport
param; `validatePeerDatagramEnabled` checks only settings.

The `Tracked` suffix is well-justified: it's a different return type
(`u64` for the quic datagram-id vs `void`), so the two cannot be
collapsed without forcing every caller to discard a u64. The untracked
variant is implemented as `_ = sendDatagramTracked(...)` already, so
the cost is one inline forwarder.

For WebTransport specifically: WT's per-session datagrams use the
`sessionId == request stream id` encoding via path #1 only. The
capsule fallback path is *not part of the WebTransport draft* (draft
mandates QUIC DATAGRAM); it's only used for raw HTTP Datagrams
(RFC 9297) and for MASQUE.

**Recommendation: keep all six variants. Document them.** Add a
"Datagram send paths" doc section to `RequestWriter` and the
`WebTransport*Stream` types laying out:

  - default-recommended path is `datagram` / `datagramTracked`
    (QUIC-DATAGRAM, fast, gated on `max_datagram_frame_size > 0`),
  - capsule fallback is `datagramCapsule` / `datagramContextCapsule`
    (reliable-on-stream, gated on `SETTINGS_H3_DATAGRAM = 1` only,
    not WebTransport),
  - context-id variants are the MASQUE / draft-ietf-masque-h3-datagram
    multiplexing path,
  - on the WebTransport handle types, `sendDatagram*` is the only
    WT-correct path; do NOT call the capsule variants (which exist on
    the underlying `RequestWriter` accessor but should only be used
    for non-WT contexts).

A non-controversial follow-up for v0.2: rename the WT-typed
`requestWriter()` / `responseWriter()` accessors to
`underlyingWriter()` and add a doc note that capsule sends through
that accessor are out-of-spec for WT.

### Lifecycle verbs — cluster of 5 named verbs across 4 types

Documented semantics from the doc comments at HEAD (Round 5 added them):

| Verb           | Wire effect                                   | Side       | Meaning                                  |
| -------------- | --------------------------------------------- | ---------- | ---------------------------------------- |
| `finish`       | QUIC FIN on send side                         | outbound   | clean half-close, no error code          |
| `finishSend`   | QUIC FIN on send side                         | outbound   | exactly the same as `finish`             |
| `finishStream` | QUIC FIN on a *WT* substream                  | outbound   | WT-only: routes through `Session.finishWebTransportStream` |
| `reset`        | RESET_STREAM with `error_code`                | outbound   | drop our own buffered/in-flight bytes    |
| `resetStream`  | RESET_STREAM on a *WT* substream              | outbound   | WT-only, same wire effect, app-mapped code |
| `resetStreamWithCode` | RESET_STREAM on a *WT* substream w/ wire code | outbound | WT-only, bypasses app-code mapping       |
| `abort`        | RESET_STREAM with a default code              | outbound   | convenience: client default `request_cancelled`, server default `internal_error` |
| `cancel`       | STOP_SENDING with `request_cancelled`         | inbound    | ask peer to stop sending; client-only on `RequestWriter` |
| `close`        | CLOSE_WEBTRANSPORT_SESSION capsule + FIN      | both       | WT-session-level, distinct from stream lifecycle |

Three observations:

1. **`finish` vs `finishSend`** — Identical wire effect. The split is
   stylistic: `finishSend` appears on the WebSocket / ConnectUDP /
   WebTransport stream wrappers (which keep their `RequestWriter`
   inside a `writer` field) to make the asymmetry with `finishStream`
   (the WT *substream* variant) clearer. On `RequestWriter` /
   `ResponseWriter` it's just `finish`. This is genuine surface-area
   waste: a caller looking at `WebTransportClientStream` sees
   `finishSend`, `finishStream`, `close`, `reset`, `resetStream`,
   `resetStreamWithCode`, `abort` — seven verbs that are
   non-trivially distinct, plus `finishSend` which is the same as
   `finish` on the underlying writer they could already reach via
   `requestWriter()`.

2. **`reset` vs `abort`** — `abort` is `reset(default_code)`. It is a
   one-line convenience method per type. Justifies its existence on
   `RequestWriter` (where `request_cancelled` is the universally
   correct code) and `ResponseWriter` (where `internal_error` is the
   pessimist's choice), but on the wrapper types (WT, WS, ConnectUDP)
   it just forwards to the inner writer's `abort`. That's two
   indirections to do something a `RequestWriter.reset(code)` can do
   in one.

3. **`reset` vs `cancel`** — Genuinely different wire effects.
   `reset` is RESET_STREAM (we stop sending), `cancel` is
   STOP_SENDING (we ask peer to stop sending us). For a full
   bidirectional abort the caller has to issue both. The doc comment
   on `Client.cancel` is explicit about this. Not redundant.

4. **`resetStream` vs `resetStreamWithCode` (WT)** — Both target the
   *WebTransport substream* (not the CONNECT control stream). The
   first takes a u32 application code and runs it through the
   draft-ietf-webtrans-http3 §4.6 mapping; the second takes a u64
   wire code and bypasses the mapping (used for the two reserved
   codes `BUFFERED_STREAM_REJECTED` and `SESSION_GONE`). Two
   different domains; the split is justified.

5. **`close` (WT)** — Distinct from everything else: it sends the
   `CLOSE_WEBTRANSPORT_SESSION` capsule and then FINs the CONNECT
   stream. Session-level, not stream-level.

**Recommendation:**

  - **Deprecate `finishSend` in v0.2; remove in v0.3.** It is exactly
    `finish` and the doubled name forces the reader to verify that. On
    the wrapper types, rename to `finish` to match the underlying
    writer. (The wrappers also have `requestWriter()` /
    `responseWriter()` accessors so callers who want to reach the
    underlying primitive can already do so.)
  - **Keep `abort`.** The convenience is real — every HTTP/3 client
    needs `request_cancelled` and every server needs `internal_error`,
    and the right code for "I'm bailing" varies by side. Document that
    `abort()` is `reset(default_for_role)` and link to the protocol
    error-code reference.
  - **Keep `cancel` on `RequestWriter` and `Client`.** Different wire
    effect, called out in the doc comment. Add a doc-comment note that
    "abort + cancel" is the bidirectional abort pattern (and consider
    a future v0.3 helper `bidiAbort()` that does both — out of scope
    for v0.2).
  - **Keep `finishStream`, `resetStream`, `resetStreamWithCode` on the
    WT handle types.** They operate on a different stream than
    `finishSend` / `reset` / `abort` (the WT substream vs the CONNECT
    control stream). After dropping `finishSend`, the type's lifecycle
    surface is `finish` (CONNECT FIN), `reset` / `abort` (CONNECT
    RESET), `close` (WT-session capsule + CONNECT FIN), and the
    substream-targeted `finishStream` / `resetStream` /
    `resetStreamWithCode`. That's still nine verbs but now each one is
    semantically distinct.

### WT stream-open paths — cluster of 2

`openUniStream` and `openBidiStream` are not redundant: they target
different QUIC stream classes (uni vs server-initiated bidi), and the
write-prefix is different (length-prefixed framing vs `0x41` frame
type). The "with options" / "without options" pattern doesn't apply
here — neither variant takes options. The bidirectional case is the
WebTransport carve-out from RFC 9114 §6.1 ¶3 (server bidi open),
documented in the `openBidiStream` doc comment.

**Recommendation: keep both, no change.** The names match the draft
exactly.

### Trackers vs raw events

`RequestTracker` and `ResponseTracker` are *opt-in conveniences* on
top of the raw `Event` stream. A caller can entirely ignore them and
walk events themselves (`Server.classify` / `Client.classify` does the
event-type narrowing); the trackers add buffered headers/body/trailers
state addressed by stream id, and a `complete` flag.

For WT specifically: the trackers apply to the CONNECT
request/response stream (because that *is* an HTTP request); they do
not apply to WT substreams. The substream events
(`webtransport_stream_*`) are explicitly handled with the empty
arms in `observe`'s switch — they fall through to a no-op. This is
correct: an application that wants to buffer a WT substream's data
needs its own per-substream state, because substream lifecycles are
not symmetric with HTTP request/response.

**Recommendation: keep both. Document it.** Add a paragraph to the
README's WebTransport section spelling out: trackers are for the
CONNECT bootstrap message, not for WT substreams; for substreams,
process `webtransport_stream_data` events directly. No code change.

### Re-export duplication — cluster of 4

Looking at `root.zig`:

1. **`WebTransportStreamKind` (`webtransport.StreamKind`) vs
   `WTStreamDirection` (`session.WTStreamDirection`)** — Two enums
   with the same domain (`uni` vs `bidi`), different definitions, both
   re-exported. This is genuine duplication. The one in `webtransport`
   is older (used by the wire codecs, predates the session API); the
   one in `session` was added when the per-session flow-control
   accounting needed it. They are not interchangeable in code because
   they're distinct types.

2. **`WebTransportConnectOptions`** is re-exported once via
   `client.WebTransportConnectOptions` which itself aliases
   `webtransport.ConnectOptions`. Two-level alias, but a single
   public name from `root.zig` — fine.

3. **`WebTransportCapsuleEvent`** = `webtransport.CapsuleEvent`. One
   public name. Fine.

4. **`Push` / `LocalPush`** — `server.Push` aliases
   `session.LocalPush`; `root.zig` re-exports `server.Push` only.
   Fine.

**Recommendation:**

  - **Consolidate `WebTransportStreamKind` and `WTStreamDirection`.**
    For v0.2: pick `WebTransportStreamKind` as the canonical name (it
    matches the draft's terminology — "WebTransport Stream" — and is
    namespaced consistently with the rest of the WT re-exports), make
    `session.WTStreamDirection = webtransport.StreamKind`, and stop
    re-exporting the separate alias from `root.zig`. The session
    primitives that take a direction
    (`openWebTransportUniStream` / `openWebTransportBidiStream` are
    direction-encoded in the function name; the only API that takes
    the enum as a runtime argument is `sendWebTransportMaxStreams`,
    which is a small migration). Mark `WTStreamDirection` deprecated
    in v0.2, remove in v0.3.

### Out-of-scope WT helpers worth a small narrowing

`WebTransportClientStream.requestWriter()` /
`WebTransportServerStream.responseWriter()` are escape hatches that
expose the underlying writer. Useful (callers may need
`updatePriority`, raw `capsule`, `sendState`/`canBuffer`/`canWrite`
plumbing), but easy to misuse — calling `datagramCapsule` through
them is non-WT-spec.

**Recommendation: keep, rename to `underlyingWriter()` for symmetry
across WT/WS/ConnectUDP, and add a doc warning that calling capsule
sends through the underlying writer is out-of-spec for WT.** Defer to
v0.3 — renaming forces a deprecation cycle.

## Recommended changes for v0.2

Numbered, with rationale and cost estimates.

1. **Deprecate `finishSend` on `WebTransportClientStream`,
   `WebTransportServerStream`, `WebSocketClientStream`,
   `WebSocketServerStream`, `ConnectUdpClientStream`,
   `ConnectUdpServerStream`. Add `finish` aliases in v0.2; remove
   `finishSend` in v0.3.**
   Rationale: identical wire effect to `finish` on the underlying
   writer; the separate name fragments the lifecycle vocabulary across
   wrapper types vs raw writers without semantic gain. Cost: six
   one-liners.

2. **Document the three datagram send paths in a single
   `## Datagram sends` README section and in doc comments on
   `RequestWriter.datagram` / `RequestWriter.datagramCapsule` /
   `RequestWriter.datagramWithContext`.** Cross-link from the WT
   handle types: only the QUIC-DATAGRAM path is WT-spec.
   Rationale: the cluster is justified, but a reader of the public
   API has to read three doc comments to understand the choice. One
   paragraph in the README pays for itself.

3. **Document the lifecycle-verb decision tree.** Add a
   `## Stream lifecycle` README section that is the table from the
   "Lifecycle verbs" cluster above, plus the rule: "outbound abort →
   `reset(code)` or `abort()`; inbound abort (client only) →
   `cancel()`; both → `abort(); cancel();`".
   Rationale: every reader of this codebase has to derive this table
   from the doc comments today. Round 5 added the doc comments; this
   adds the index.

4. **Document trackers as CONNECT-message-only.** One paragraph in
   the WebTransport README section saying trackers do not apply to
   WT substreams and pointing to `webtransport_stream_data` events
   for substream data accumulation. Rationale: nothing in the
   trackers' doc comments tells the reader this today; the no-op
   arms for `webtransport_stream_*` events are easy to mistake for
   bugs.

5. **Mark `WTStreamDirection` deprecated in v0.2, alias to
   `webtransport.StreamKind`. Remove in v0.3.** Rationale: two enums
   with the same domain on the public surface is gratuitous.
   Consolidating onto `StreamKind` matches the draft's terminology;
   the session-level re-export is the newer name (added when WT flow
   control was wired up) and has fewer call sites.

6. **Add a doc note to `WebTransportClientStream.requestWriter()` /
   `WebTransportServerStream.responseWriter()` saying that
   `datagramCapsule` / `datagramContextCapsule` invoked through this
   accessor are NOT valid WebTransport sends.** Rationale: the
   accessor is a pragmatic escape hatch but its blast radius is wide.

## Recommended changes for v0.3+

Items that need a deprecation cycle, gathered here for follow-up
issues:

1. **Remove `finishSend` after v0.2 deprecation**. (See #1 above.)
2. **Remove `WTStreamDirection`**. (See #5 above.)
3. **Rename `requestWriter()` / `responseWriter()` to
   `underlyingWriter()`.** Cross-type symmetry; the current names
   suggest "give me a fresh writer for the request" rather than
   "give me the writer that's already inside this wrapper".
4. **Consider a `bidiAbort()` helper on `RequestWriter` /
   `WebTransportClientStream` that does
   `try self.reset(code); try self.cancel();`** Real-world abort
   needs both. Today every caller has to remember.
5. **Consider promoting the WT substream lifecycle to its own typed
   handle**, e.g. `WebTransportStream` returned from `openUniStream`
   / `openBidiStream` rather than a raw `u64`. Currently the caller
   passes the substream id back to `writeStream` /
   `finishStream` / `resetStream` / `resetStreamWithCode`; a typed
   handle would scope that surface and stop callers from accidentally
   passing a session-level method a substream id (which today would
   end the session). Out of scope for v0.2 because it touches every
   WT example and test.

## Out of scope

  - **MASQUE-specific verbs.** `ConnectUdpClientStream.fail` /
    `failForError` are in the same family as `abort` but with
    MASQUE-specific error codes. They look redundant with `reset` but
    they exist because MASQUE has its own abort-code domain
    (`masque_mod.streamAbortForError`). Keep, no audit needed.
  - **Push streams.** `PushWriter` / `Server.resetPush` /
    `Server.cancelPush`: out of the WebTransport remit.
  - **WebSocket-specific writers.** `writeText` / `writeBinary` /
    `writeMessage` / `writeFrame` / `writeFrameWithOptions` /
    `writeClose`: these are WebSocket protocol shaping, not
    WebTransport. They look like a similar fan-out but the audit
    here is bounded to WT.
  - **`Session`'s primitive surface.** `Session` is documented as
    the low-level primitive layer; surface-area rules differ. The
    inventory above includes it for traceability but the
    recommendations target the `Client` / `Server` / `*Stream` layer.
  - **`webtransport.zig` codec helpers.** The TLV
    encode/decode/encodedLen functions for each capsule type are not
    redundant with each other; they're per-capsule by design.
