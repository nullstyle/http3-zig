# WebTransport draft-15 error code audit (v0.2)

Date: 2026-05-09
Reference: draft-ietf-webtrans-http3-15
Status: DRIFT (6 items — all "missing identifier" gaps; zero
codepoint mismatches on the values we *do* define)

## Methodology

Spec values were sourced from `draft-ietf-webtrans-http3-15` via two
independent fetches:

- `https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15.html`
- `https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-15`

Both fetches agreed on every numeric value cited below. The relevant
IANA-registration sections are §9.2 (SETTINGS), §9.3
(bidirectional-stream frame type), §9.4 (unidirectional-stream type),
§9.5 (HTTP/3 error codes), and §9.6 (capsule types). The
application-error-code mapping formula is in §4.4.

Codebase values were read from:

- `/Users/nullstyle/prj/ai-workspace/http3-zig/src/protocol.zig`
- `/Users/nullstyle/prj/ai-workspace/http3-zig/src/webtransport.zig`
- `/Users/nullstyle/prj/ai-workspace/http3-zig/src/settings.zig`

A `grep -n "0x"` sweep over each of those three files plus targeted
greps for the spec-named identifiers
(`WT_FLOW_CONTROL_ERROR`, `WT_ALPN_ERROR`,
`WT_REQUIREMENTS_NOT_MET`, `WT_INITIAL_MAX_*`, `0x045d4487`,
`0x0817b3dd`, `0x212c0d48`, `0x2b61`, `0x2b64`, `0x2b65`)
confirmed the absences listed under "Drift summary".

No source files were modified by this audit.

## Findings

### SETTINGS

| Name (spec)                            | Spec value   | Our value  | Defined at                       | Match  |
|----------------------------------------|--------------|------------|----------------------------------|--------|
| SETTINGS_WT_ENABLED                    | `0x2c7cf000` | `0x2c7cf000` | protocol.zig:56 (`SettingId.wt_enabled`); re-exported webtransport.zig:67 | MATCH  |
| SETTINGS_WT_INITIAL_MAX_DATA           | `0x2b61`     | (missing)  | —                                | DRIFT  |
| SETTINGS_WT_INITIAL_MAX_STREAMS_UNI    | `0x2b64`     | (missing)  | —                                | DRIFT  |
| SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI   | `0x2b65`     | (missing)  | —                                | DRIFT  |

### Capsule types

| Name (spec)                       | Spec value     | Our value    | Defined at                                   | Match |
|-----------------------------------|----------------|--------------|----------------------------------------------|-------|
| WT_CLOSE_SESSION                  | `0x2843`       | `0x2843`     | webtransport.zig:78 (`CapsuleType.close_session`)    | MATCH |
| WT_DRAIN_SESSION                  | `0x78ae`       | `0x78ae`     | webtransport.zig:79 (`CapsuleType.drain_session`)    | MATCH |
| WT_MAX_DATA                       | `0x190b4d3d`   | `0x190b4d3d` | webtransport.zig:83 (`CapsuleType.max_data`)         | MATCH |
| WT_MAX_STREAMS_BIDI               | `0x190b4d3f`   | `0x190b4d3f` | webtransport.zig:85 (`CapsuleType.max_streams_bidi`) | MATCH |
| WT_MAX_STREAMS_UNI                | `0x190b4d40`   | `0x190b4d40` | webtransport.zig:87 (`CapsuleType.max_streams_uni`)  | MATCH |
| WT_DATA_BLOCKED                   | `0x190b4d41`   | `0x190b4d41` | webtransport.zig:89 (`CapsuleType.data_blocked`)     | MATCH |
| WT_STREAMS_BLOCKED_BIDI           | `0x190b4d43`   | `0x190b4d43` | webtransport.zig:91 (`CapsuleType.streams_blocked_bidi`) | MATCH |
| WT_STREAMS_BLOCKED_UNI            | `0x190b4d44`   | `0x190b4d44` | webtransport.zig:93 (`CapsuleType.streams_blocked_uni`)  | MATCH |

### Error codes (HTTP/3 application space)

| Name (spec)                           | Spec value         | Our value    | Defined at                                    | Match |
|---------------------------------------|--------------------|--------------|-----------------------------------------------|-------|
| WT_BUFFERED_STREAM_REJECTED           | `0x3994bd84`       | `0x3994bd84` | webtransport.zig:60 (`buffered_stream_rejected_code`) | MATCH |
| WT_SESSION_GONE                       | `0x170d7b68`       | `0x170d7b68` | webtransport.zig:64 (`session_gone_code`)             | MATCH |
| WT_FLOW_CONTROL_ERROR                 | `0x045d4487`       | (missing)    | —                                             | DRIFT |
| WT_ALPN_ERROR                         | `0x0817b3dd`       | (missing)    | —                                             | DRIFT |
| WT_REQUIREMENTS_NOT_MET               | `0x212c0d48`       | (missing)    | —                                             | DRIFT |
| WT_APPLICATION_ERROR (range first)    | `0x52e4a40fa8db`   | `0x52e4a40fa8db` | webtransport.zig:719 (`wt_error_first`)        | MATCH |
| WT_APPLICATION_ERROR (range last)     | `0x52e5ac983162`   | computed = `0x52e4a40fa8db + 2^32 + (2^32 / 30)` = `0x52e5ac983162` | webtransport.zig:725 (`wt_error_last`, comptime block) | MATCH |
| Mapping formula `first + n + n/0x1e`  | per §4.4           | `wt_error_first + n + (n / 30)` (30 = `0x1e`) | webtransport.zig:732 (`appErrorToHttp3`)               | MATCH |
| Reverse mapping (skip stride 31)      | per §4.4           | offset stride `wt_error_stride_wire = 31`     | webtransport.zig:740 (`http3ToAppError`)               | MATCH |

### Stream type IDs

| Name (spec)                                   | Spec value | Our value | Defined at                                              | Match |
|-----------------------------------------------|------------|-----------|---------------------------------------------------------|-------|
| WebTransport unidirectional stream type       | `0x54`     | `0x54`    | protocol.zig:39 (`StreamType.webtransport_uni_stream`); re-exported webtransport.zig:72 | MATCH |
| WebTransport bidirectional stream signal/frame type (WT_STREAM) | `0x41` | `0x41` | protocol.zig:28 (`FrameType.webtransport_bidi_stream`); re-exported webtransport.zig:74 | MATCH |

## Drift summary

All six drift items are *missing identifiers* — i.e. constants the
spec registers but our codebase does not yet name. None of them are
codepoint mismatches; every value we currently emit matches the
spec exactly. The likely user-visible impact is that we cannot emit
or recognise these spec-defined errors / SETTINGS at all (rather
than emitting them with a wrong number).

1. **WT_FLOW_CONTROL_ERROR** — spec `0x045d4487`, ours: not defined.
   Suggested fix: add `pub const wt_flow_control_error: u64 =
   0x045d4487;` to `protocol.zig` `ErrorCode` (or as a sibling to
   `buffered_stream_rejected_code` / `session_gone_code` in
   `webtransport.zig`, near line 64). Used by an endpoint that
   detects a flow-control violation in the WebTransport session.

2. **WT_ALPN_ERROR** — spec `0x0817b3dd`, ours: not defined.
   Suggested fix: same site as (1). Sent on
   CONNECT-stream reset when application-protocol negotiation
   (`wt-available-protocols`) fails to converge.

3. **WT_REQUIREMENTS_NOT_MET** — spec `0x212c0d48`, ours: not
   defined. Suggested fix: same site as (1). Used as the
   CONNECTION_CLOSE error when the peer's SETTINGS lack a required
   WebTransport feature; this is what we currently raise as
   `error.WebTransportSettingsMissing` internally
   (webtransport.zig:104, 195, 196, 200) but never translate to the
   wire code.

4. **SETTINGS_WT_INITIAL_MAX_DATA** — spec `0x2b61`, ours: not
   defined. Suggested fix: add to `protocol.zig` `SettingId` (near
   line 56) and surface a typed field on
   `settings.Settings`. Required for any session-level flow-control
   bootstrap before the first `WT_MAX_DATA` capsule; without it we
   default to 0 and would never accept inbound stream data.

5. **SETTINGS_WT_INITIAL_MAX_STREAMS_UNI** — spec `0x2b64`, ours:
   not defined. Suggested fix: same site as (4). Required to permit
   any uni stream creation before the first `WT_MAX_STREAMS_UNI`
   capsule.

6. **SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI** — spec `0x2b65`, ours:
   not defined. Suggested fix: same site as (4). Required to permit
   any bidi stream creation before the first `WT_MAX_STREAMS_BIDI`
   capsule.

A reasonable single follow-up could land all six together (three
new error codepoints in `protocol.zig::ErrorCode`, three new
SETTINGS in `protocol.zig::SettingId` plus matching fields on
`settings.Settings`), with parser/serialiser updates. Triage and
ordering left to the maintainer; this audit is read-only.

## Out of scope

- **`H3_DATAGRAM` setting (`0x33`, protocol.zig:49)** — RFC 9297, not
  draft-15. Used by WebTransport but registered elsewhere; verified
  against RFC 9297 only incidentally.
- **`enable_connect_protocol` (`0x08`, protocol.zig:48)** — RFC 9220,
  not draft-15. Required by WT but registered elsewhere.
- **HTTP/3 base error codes `0x0100`–`0x0202`** (protocol.zig:62–81)
  — RFC 9114 / RFC 9204, not draft-15.
- **Datagram-error code `0x33`** (protocol.zig:61) — RFC 9297.
- **GREASE and HTTP/2 reserved-codepoint helpers** (protocol.zig:84–91)
  — generic IANA hygiene, not WebTransport-specific.
- **Subprotocol-negotiation headers** (`wt-available-protocols`,
  `wt-protocol`; webtransport.zig:37, 41) — these are HTTP field
  names, not numeric codepoints, and the audit task scope was
  numeric error codes / IDs.
- **The `protocol_token = "webtransport"` constant**
  (webtransport.zig:32) — string token, not a codepoint. Note that
  draft-15 §9.1 mentions a separate `webtransport-h3` upgrade token
  alongside `webtransport`; the current constant matches the latter.
  Whether the implementation should additionally expose
  `webtransport-h3` is outside the scope of this codepoint audit.
