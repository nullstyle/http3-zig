//! Integration test entry point.
//!
//! The actual tests live in `tests/integration/`, split per feature area.
//! This file just pulls each one in so Zig's default test runner walks
//! their top-level `test` blocks. Shared helpers (handshake, pumpH3,
//! H3Pair, etc.) live in `tests/integration/_fixtures.zig`.

test {
    _ = @import("integration/tls.zig");
    _ = @import("integration/codecs.zig");
    _ = @import("integration/priority.zig");
    _ = @import("integration/messages.zig");
    _ = @import("integration/facades.zig");
    _ = @import("integration/extended_connect.zig");
    _ = @import("integration/webtransport.zig");
    _ = @import("integration/webtransport_multiplexing.zig");
    _ = @import("integration/webtransport_races.zig");
    _ = @import("integration/webtransport_forwarding.zig");
    _ = @import("integration/push.zig");
    _ = @import("integration/session_errors.zig");
    _ = @import("integration/budgets.zig");
    _ = @import("integration/lifecycle_streams.zig");
    _ = @import("integration/lifecycle_datagrams.zig");
    _ = @import("integration/lifecycle_close.zig");
    _ = @import("integration/transport_driver.zig");
    _ = @import("integration/production_preset.zig");
    _ = @import("integration/public_api_smoke.zig");
}
