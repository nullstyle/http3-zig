//! One-process smoke harness for the udp_server/udp_client example
//! pair: runs the `udp_server.zig` loop on a background thread, drives
//! the `udp_client.zig` GET / round-trip against it over real loopback
//! UDP, and exits non-zero unless a 200 with the expected HTML body
//! actually came back.
//!
//! ```sh
//! zig build run-udp-smoke
//! ```
//!
//! This is a standalone binary (not a `zig build test` target) so it
//! can exercise real sockets, threads, and both `runUdp*` loops
//! end-to-end without dragging network flakiness into the unit-test
//! suite. CI runs it on the Linux Debug leg after `run-examples`.

const std = @import("std");
const udp_server = @import("udp_server.zig");
const udp_client = @import("udp_client.zig");

/// Overall give-up budget for the client round-trip. Generous: it
/// covers a lost first flight (recovered by PTO retransmit if the
/// client's Initial beats the server thread to the socket) with a wide
/// margin for slow CI runners.
const client_timeout_us: u64 = 30 * std.time.us_per_s;

const ServerTask = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown: *const std.atomic.Value(bool),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(task: *ServerTask) void {
        udp_server.serve(task.allocator, task.io, task.listen, task.shutdown) catch |err| {
            std.debug.print("udp-smoke: server loop failed: {s}\n", .{@errorName(err)});
            task.failed.store(true, .release);
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // Pick a free loopback UDP port: bind :0, read the resolved
    // ephemeral port back off the socket, release it. (The tiny
    // close-to-rebind race is acceptable for a smoke harness;
    // `runUdpServer` owns its socket, so we can't bind-and-hand-off.)
    const port: u16 = blk: {
        const probe_addr = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
        const probe = try std.Io.net.IpAddress.bind(&probe_addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        defer probe.close(io);
        break :blk probe.address.getPort();
    };
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port});

    var shutdown = std.atomic.Value(bool).init(false);
    var task: ServerTask = .{
        .allocator = allocator,
        .io = io,
        .listen = addr,
        .shutdown = &shutdown,
    };

    const server_thread = try std.Thread.spawn(.{}, ServerTask.run, .{&task});
    // Deferred in reverse order: flip the flag first, then join, so the
    // server thread always winds down — including on the error paths
    // below. The flag starts the server's GOAWAY drain; with zero open
    // requests it hands off to the loop shutdown immediately.
    defer server_thread.join();
    defer shutdown.store(true, .release);

    // Let the server thread reach its bind before the client's first
    // Initial. Not load-bearing (a lost first flight is retransmitted
    // on PTO); it just keeps the happy path fast.
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake);

    // `run` only returns cleanly when a 200 with the exact index body
    // round-tripped (`UnexpectedStatus` / `UnexpectedBody` /
    // `RequestTimedOut` / `RequestIncomplete` otherwise) — that is the
    // smoke assertion.
    udp_client.run(allocator, io, .{
        .target = addr,
        .sni = "localhost",
        .path = "/",
        .insecure = true, // self-signed localhost test cert
    }, client_timeout_us, udp_server.index_body) catch |err| {
        std.debug.print("udp-smoke: FAIL ({s})\n", .{@errorName(err)});
        return err;
    };

    if (task.failed.load(.acquire)) {
        std.debug.print("udp-smoke: FAIL (server loop error)\n", .{});
        return error.ServerLoopFailed;
    }

    std.debug.print("udp-smoke: PASS (HTTP/3 GET / returned 200 + expected body on {s})\n", .{addr});
}
