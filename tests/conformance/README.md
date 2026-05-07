# null3 RFC-traceable conformance suites

These suites are **conformance** tests, not behaviour tests. Each test
asserts a specific normative requirement from an RFC, named with the
BCP 14 keyword the RFC uses, and cited back to its section. The shape
follows the [RFC-traceable ZSpec testing
guide](../../../zspec-rfc-testing.md), adapted to plain `std.testing`
(no third-party runner). The layout mirrors `nullq/tests/conformance/`.

## Run

```sh
zig build conformance                                          # whole suite
zig build conformance -Dconformance-filter='RFC9114 §7.2'      # one section
zig build conformance -Dconformance-filter='MUST NOT'          # one keyword
zig build test                                                 # full suite (also runs conformance)
```

`-Dconformance-filter` is a compile-time substring filter — Zig's
default test runner has no runtime filtering. The filter participates
in the compile cache key, so changing it does a fast incremental
rebuild.

## Test-name grammar

```
<KEYWORD> <observable behaviour> [RFC#### §section ¶paragraph]
```

| Keyword                         | Meaning                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `MUST`, `REQUIRED`, `SHALL`     | Implementation is non-conforming if this fails. Hard pass/fail assertion.                             |
| `MUST NOT`, `SHALL NOT`         | Implementation is non-conforming if it permits this. Assert rejection / absence — never "doesn't crash". |
| `SHOULD`, `RECOMMENDED`         | Test the recommended default; document any accepted deviation alongside.                              |
| `SHOULD NOT`, `NOT RECOMMENDED` | Test the avoided behaviour; deviation needs an explicit reason.                                       |
| `MAY`, `OPTIONAL`               | Only if implemented; also test interop with peers that omit it.                                       |
| `NORMATIVE`                     | Normative RFC text that does **not** use a BCP 14 keyword. Don't fake `MUST`.                         |

Examples:

```zig
test "MUST reject a HEADERS frame received on the control stream [RFC9114 §7.2.2 ¶3]" {}
test "MUST NOT include the :status pseudo-header on a request [RFC9114 §4.3.1 ¶2]" {}
test "SHOULD send PRIORITY_UPDATE only on a stream the peer has accepted [RFC9218 §7.2 ¶4]" {}
test "MAY include the SETTINGS_H3_DATAGRAM=1 setting [RFC9297 §2.1 ¶1]" {}
```

### Skipping (visible conformance debt)

Use `skip_` as a name prefix **and** return `error.SkipZigTest` from
the body. The name keeps the gap visible in the test list; the body
keeps the test green:

```zig
test "skip_MUST reject a duplicate critical-stream type [RFC9114 §6.2.1 ¶7]" {
    // TODO(issue-NN): not yet wired through public API.
    return error.SkipZigTest;
}
```

Never use `skip_` to imply that an optional `MAY` feature is required.

## File layout

```
tests/
  conformance.zig                            # entry point (sibling of tests/root.zig)
  conformance/
    README.md                                # this file
    rfc9114_protocol.zig                     # §6, §7.2 frame-type IANA + GREASE
    rfc9114_settings.zig                     # §7.2.4 SETTINGS frame + §7.2.4.1 IDs
    rfc9114_frames.zig                       # §7.2 DATA, HEADERS, CANCEL_PUSH, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID
    rfc9114_streams.zig                      # §6 stream layer, §6.2 unidirectional/control streams
    rfc9114_session.zig                      # §5 connections, §7.2.4 SETTINGS handshake, §5.2 GOAWAY
    rfc9114_messages.zig                     # §4 expressing HTTP semantics
    rfc9114_errors.zig                       # §8 error handling, §11.2.3 error codes registry
    rfc9204_qpack_static.zig                 # static table + integer + Huffman + literal sections
    rfc9204_qpack_dynamic.zig                # dynamic table, encoder/decoder streams, prefix accounting
    rfc9218_priority.zig                     # Priority field + PRIORITY_UPDATE
    rfc9220_websocket_h3.zig                 # WebSocket-over-HTTP/3 bootstrap
    rfc6455_websocket.zig                    # WebSocket frame + message codecs
    rfc9297_datagrams.zig                    # HTTP/3 DATAGRAM + Capsule Protocol
    rfc9298_masque.zig                       # CONNECT-UDP target path + Context ID 0 payloads
```

The entry point lives at `tests/conformance.zig` (one level up) so the
Zig package boundary widens to `tests/`. Suites that need
`@embedFile("../data/test_cert.pem")` get a valid in-package path that
way (mirrors the nullq layout).

## Suite skeleton

Tests live at **file scope** (Zig's default test runner only walks
top-level `test` blocks in compiled files; tests nested inside `pub
const Foo = struct {}` are not discovered). Use comment dividers and
the citation in the test name itself for grouping.

```zig
//! RFC 9114 §7.2 — HTTP/3 frames.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §7.2.1 ¶1  MUST     DATA frame body is the unframed payload
//!   RFC9114 §7.2.4 ¶3  MUST NOT duplicate a SETTINGS identifier
//!   ...
//!
//! Visible debt:
//!   RFC9114 §X.Y ¶N   MUST   ...
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §6.2     control-stream rules → rfc9114_streams.zig

const std = @import("std");
const null3 = @import("null3");

// ---------------------------------------------------------------- §7.2.1 DATA

test "MUST treat the DATA frame body as opaque [RFC9114 §7.2.1 ¶1]" {
    // ... arrange / act / assert one observable behaviour ...
}
```

There is no `tests:before/after` hook mechanism in `std.testing`; use
local helper functions and `defer` instead. Shared setup that's used
across files goes in a `_<name>.zig` fixture file (leading underscore
keeps it lexically distinct from per-RFC suites; underscore-prefixed
files are not imported by the entry point unless they contain tests).

## Author checklist (review gate)

- [ ] Every test name starts with a BCP 14 keyword (or `NORMATIVE` /
      `skip_` prefix).
- [ ] Keyword strength matches the RFC — no upgrading `SHOULD` to `MUST`.
- [ ] Citation is precise: `[RFC#### §X.Y ¶N]` or `[RFC#### §X.Y]`.
- [ ] One observable behaviour per test.
- [ ] `MUST NOT` tests assert rejection / absence / error — never
      just "did not crash".
- [ ] **Test exercises a null3 (or null3.qpack / null3.session / etc.)
      surface — not stdlib arithmetic, not a file-local helper standing
      in as the oracle.** Every non-skipped conformance test must call
      into `null3.*` (or a fixture that does) at least once. If you
      find yourself asserting `5 << 1` directly, you're testing
      arithmetic, not null3 — route through the relevant null3
      function (`frame.parse`, `qpack.encodeInteger`, `Session.feed`,
      etc.). Add a small public wrapper to null3 if the path is
      currently private.
- [ ] Coverage block at the top lists Covered / Visible debt / Out of
      scope (where applicable).
- [ ] Tests run cleanly: `zig build conformance`.
- [ ] `zig build conformance -Dconformance-filter='RFC#### §X.Y'`
      runs a meaningful subset.

## What to test

For a clean-room implementation of an RFC, the requirements that
matter most are: receive-side parsing/validation (`MUST reject`,
`MUST NOT accept`), encoding constraints (`MUST set`, `MUST NOT
emit`), state-machine invariants, and bounded-resource limits. Skip
purely internal details (cache shape, struct layout) — they are not
RFC requirements.

When the implementation already enforces a `MUST` via a unit test
inside `src/`, **don't delete it** — duplicate it as a conformance
test here. The conformance suite is the auditor-facing artifact; the
unit tests remain the developer-facing regression net.

## RFC scope index

| RFC  | Subject                                          | Suite file(s)                              |
| ---- | ------------------------------------------------ | ------------------------------------------ |
| 9114 | HTTP/3                                           | `rfc9114_*.zig`                            |
| 9204 | QPACK                                            | `rfc9204_qpack_static.zig`, `rfc9204_qpack_dynamic.zig` |
| 9218 | Extensible Priorities                            | `rfc9218_priority.zig`                     |
| 9220 | Bootstrapping WebSockets with HTTP/3             | `rfc9220_websocket_h3.zig`                 |
| 6455 | The WebSocket Protocol                           | `rfc6455_websocket.zig`                    |
| 9297 | HTTP Datagrams + Capsule Protocol                | `rfc9297_datagrams.zig`                    |
| 9298 | Proxying UDP in HTTP (CONNECT-UDP / MASQUE)      | `rfc9298_masque.zig`                       |

RFC 7541 (HPACK Huffman) is exercised inside `rfc9204_qpack_static.zig`
because RFC 9204 §4.1.2 incorporates it by reference for QPACK string
literals.
