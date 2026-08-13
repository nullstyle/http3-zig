//! Out-of-tree consumer smoke test.
//!
//! Consumes http3-zig the way an application does (a build.zig.zon
//! dependency) and asserts the property that broke real consumers once:
//! the quic/boringssl module instances exported by http3-zig's
//! build.zig — and the `http3_zig.quic` / `http3_zig.boringssl`
//! re-exports — are the same modules the http3_zig API is typed against,
//! so a `*quic.Connection` obtained through either path is accepted
//! by `Session.init`. Compiling is the test; main only prints versions.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");
const boringssl = @import("boringssl");

comptime {
    // Named-module imports and root re-exports must be the same instance.
    std.debug.assert(quic.Connection == http3_zig.quic.Connection);
    std.debug.assert(boringssl.tls.Context == http3_zig.boringssl.tls.Context);
}

/// The load-bearing identity check: an app-held `*quic.Connection`
/// (imported from the named module) must satisfy `Session.init`.
fn wireSession(
    allocator: std.mem.Allocator,
    conn: *quic.Connection,
) http3_zig.Session {
    return http3_zig.Session.init(
        allocator,
        .server,
        conn,
        http3_zig.SessionConfig.production(.{}),
    );
}

pub fn main() void {
    _ = &wireSession; // force semantic analysis of the identity check
    std.debug.print(
        "consumer-smoke ok: http3-zig {s} / quic-zig {s}\n",
        .{ http3_zig.version(), quic.version() },
    );
}
