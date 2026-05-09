//! RFC-traceable conformance test entry point.
//!
//! Each `_ = @import(...)` below pulls in one suite file. Zig's
//! default test runner discovers each file's top-level `test` blocks
//! automatically when the file is compiled.
//!
//! Conventions every suite MUST follow:
//!   * Test names use BCP 14 keywords literally, end with
//!     `[RFC#### §X.Y ¶N]` (paragraph optional but encouraged).
//!   * One observable behavior per test.
//!   * Tests live at file scope (NOT inside `pub const Foo = struct`)
//!     because Zig's default runner doesn't walk nested-struct tests.
//!   * `skip_` prefix + `return error.SkipZigTest` for visible debt.
//!     Never use it to imply MAY.
//!   * See `tests/conformance/README.md` for the full grammar.
//!
//! This entry-point file lives at `tests/conformance.zig` (sibling of
//! `tests/root.zig`) instead of `tests/conformance/root.zig` so the
//! Zig package boundary for the conformance test binary is `tests/`.
//! Suites that need to `@embedFile("../data/test_cert.pem")` for the
//! Server-fixture path get a valid in-package path that way.
//!
//! Run filtered subsets:
//!     zig build conformance -Dconformance-filter='RFC9114 §7.2'
//!     zig build conformance -Dconformance-filter='MUST NOT'

test {
    // RFC 9114 — HTTP/3
    _ = @import("conformance/rfc9114_protocol.zig");
    _ = @import("conformance/rfc9114_settings.zig");
    _ = @import("conformance/rfc9114_frames.zig");
    _ = @import("conformance/rfc9114_streams.zig");
    _ = @import("conformance/rfc9114_session.zig");
    _ = @import("conformance/rfc9114_messages.zig");
    _ = @import("conformance/rfc9114_errors.zig");
    // RFC 9204 — QPACK
    _ = @import("conformance/rfc9204_qpack_static.zig");
    _ = @import("conformance/rfc9204_qpack_dynamic.zig");
    // RFC 9218 — Extensible Priorities
    _ = @import("conformance/rfc9218_priority.zig");
    // RFC 9297 — HTTP Datagrams + Capsule Protocol
    _ = @import("conformance/rfc9297_datagrams.zig");
    // RFC 9220 — Bootstrapping WebSockets with HTTP/3
    _ = @import("conformance/rfc9220_websocket_h3.zig");
    // RFC 6455 — WebSocket Protocol
    _ = @import("conformance/rfc6455_websocket.zig");
    // RFC 9298 — Proxying UDP in HTTP (CONNECT-UDP)
    _ = @import("conformance/rfc9298_masque.zig");
    // draft-ietf-webtrans-http3 — WebTransport over HTTP/3
    _ = @import("conformance/draft_webtrans_http3.zig");
}
