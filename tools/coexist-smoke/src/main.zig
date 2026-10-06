//! Out-of-tree coexist smoke test.
//!
//! An application links http3-zig AND a sibling package that takes
//! quic the way capnp-zig, qmsg, qmesh-zig and nest do (quic's exported
//! modules, the shared option map; see sibling/build.zig). The build
//! must hold ONE quic module and ONE BoringSSL module: otherwise Zig
//! stops with "file exists in modules", or two copies of quic and
//! BoringSSL end up in one binary. Compiling is the test; main only
//! prints versions.

const std = @import("std");
const http3_zig = @import("http3_zig");
const sibling = @import("sibling");

comptime {
    // The sibling's quic/boringssl are http3-zig's quic/boringssl.
    std.debug.assert(sibling.quic == http3_zig.quic);
    std.debug.assert(sibling.boringssl == http3_zig.boringssl);
    std.debug.assert(sibling.quic.Connection == http3_zig.quic.Connection);
    std.debug.assert(sibling.boringssl.tls.Context == http3_zig.boringssl.tls.Context);
}

/// A connection the sibling made must satisfy `Session.init`.
fn wireSession(
    allocator: std.mem.Allocator,
    conn: *sibling.quic.Connection,
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
        "coexist-smoke ok: http3-zig {s} / quic-zig {s} (one quic, one boringssl)\n",
        .{ http3_zig.version(), sibling.quic.version() },
    );
}
