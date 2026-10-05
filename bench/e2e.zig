//! Real-socket bench tier (sprint 2026-10-W2, tasks B1 and B2).
//!
//! Every other http3-zig benchmark runs one process over an in-memory
//! shim: no sockets, no kernel, and a handshake that never builds a
//! Handshake packet. This one runs a `quic.Server` loop on a background
//! thread and real QUIC clients on the main thread, over loopback UDP,
//! so the packet path, the server's connection-ID demux and the C heap
//! are all in play.
//!
//! Cells:
//!
//!   * `h3_connect` — N sequential connections: handshake, SETTINGS,
//!     one `GET /`, close. Connections per second, latency, and per
//!     connection: allocations (client and server) and packets/bytes.
//!   * `h3_get` — N sequential `GET /` on ONE connection. Requests per
//!     second, latency, and per request: allocations and packets/bytes.
//!   * `soak` — N sequential connections (as `h3_connect`) while peak
//!     process RSS (C heap included) is sampled; reports bytes of RSS
//!     growth per connection after a warm-up. A leak in BoringSSL's C
//!     heap (quic v0.21.1 fixed one) shows here and nowhere else.
//!
//! Wall-clock numbers are reported, not gated: on a shared runner they
//! move by several percent with nothing changed (quic-zig measured ~5%
//! from code layout alone). The counts and the RSS slope are the
//! stable numbers a gate can use (task B3).
//!
//! ```sh
//! zig build bench-e2e
//! zig build bench-e2e -- --cell h3_get --n 2000 --json bench-e2e.json
//! ```
//!
//! Run from the repository root: the server reads the test certificate
//! from `tests/data/`.

const std = @import("std");
const builtin = @import("builtin");
const boringssl = @import("boringssl");
const quic = @import("quic");
const http3_zig = @import("http3_zig");

const Net = std.Io.net;

const response_body = "ok\n";
const cid_len = 8;
const op_timeout_us: u64 = 10 * std.time.us_per_s;

// ---------------------------------------------------------------------
// Counting allocator (one per thread; the counters are atomic so the
// main thread can read the server thread's totals).
// ---------------------------------------------------------------------

const Counting = struct {
    backing: std.mem.Allocator,
    allocs: std.atomic.Value(u64) = .init(0),
    bytes_in_use: std.atomic.Value(u64) = .init(0),

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const result = self.backing.rawAlloc(len, alignment, ret_addr);
        if (result != null) {
            _ = self.allocs.fetchAdd(1, .monotonic);
            _ = self.bytes_in_use.fetchAdd(len, .monotonic);
        }
        return result;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const ok = self.backing.rawResize(memory, alignment, new_len, ret_addr);
        if (ok) self.adjust(memory.len, new_len);
        return ok;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const result = self.backing.rawRemap(memory, alignment, new_len, ret_addr);
        if (result != null) self.adjust(memory.len, new_len);
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ret_addr);
        self.adjust(memory.len, 0);
    }

    fn adjust(self: *Counting, old_len: usize, new_len: usize) void {
        if (new_len >= old_len) {
            _ = self.bytes_in_use.fetchAdd(new_len - old_len, .monotonic);
        } else {
            _ = self.bytes_in_use.fetchSub(old_len - new_len, .monotonic);
        }
    }
};

fn nowUs(io: std.Io) u64 {
    const ns = std.Io.Clock.awake.now(io).nanoseconds;
    return @intCast(@divTrunc(@max(ns, 0), std.time.ns_per_us));
}

/// Bytes malloc reports in use (C heap: BoringSSL, and the Zig side,
/// which runs on `c_allocator` here). Unlike RSS it ignores free pages
/// the allocator keeps, so a per-connection leak shows as a clean slope.
fn mallocInUseBytes() !u64 {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => {
            const Stats = extern struct {
                blocks_in_use: c_uint,
                size_in_use: usize,
                max_size_in_use: usize,
                size_allocated: usize,
            };
            const ext = struct {
                extern "c" fn malloc_zone_statistics(zone: ?*anyopaque, stats: *Stats) void;
            };
            var stats: Stats = undefined;
            ext.malloc_zone_statistics(null, &stats);
            return stats.size_in_use;
        },
        .linux => {
            if (builtin.abi.isMusl()) return error.UnsupportedLibc;
            const Info = extern struct {
                arena: usize,
                ordblks: usize,
                smblks: usize,
                hblks: usize,
                hblkhd: usize,
                usmblks: usize,
                fsmblks: usize,
                uordblks: usize,
                fordblks: usize,
                keepcost: usize,
            };
            const ext = struct {
                extern "c" fn mallinfo2() Info;
            };
            const info = ext.mallinfo2();
            return info.uordblks + info.hblkhd;
        },
        else => return error.UnsupportedOs,
    }
}

/// Current resident set size of this process, in bytes (C heap
/// included). Darwin: `task_info`; Linux: `/proc/self/statm`.
fn currentRssBytes(io: std.Io) !u64 {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => {
            var info: std.c.mach_task_basic_info = undefined;
            var count: std.c.mach_msg_type_number_t = std.c.MACH.TASK.BASIC.INFO_COUNT;
            const rc = std.c.task_info(std.c.mach_task_self(), std.c.MACH.TASK.BASIC.INFO, @ptrCast(&info), &count);
            if (rc != 0) return error.TaskInfoFailed;
            return info.resident_size;
        },
        .linux => {
            var buf: [256]u8 = undefined;
            const text = try std.Io.Dir.cwd().readFile(io, "/proc/self/statm", &buf);
            var it = std.mem.tokenizeScalar(u8, text, ' ');
            _ = it.next() orelse return error.BadStatm;
            const pages = try std.fmt.parseInt(u64, it.next() orelse return error.BadStatm, 10);
            return pages * std.heap.pageSize();
        },
        else => return error.UnsupportedOs,
    }
}

/// Peer-provoked send faults drop the datagram (loss recovery covers
/// it); local faults propagate.
fn sendTolerant(io: std.Io, sock: anytype, dst: *const Net.IpAddress, bytes: []const u8) !void {
    sock.send(io, dst, bytes) catch |err| switch (quic.transport.classifySendError(err)) {
        .tolerate => {},
        .canceled, .fatal => return err,
    };
}

fn transportParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 16,
        .max_udp_payload_size = 65527,
        .active_connection_id_limit = 8,
    };
}

// ---------------------------------------------------------------------
// Server: `quic.Server` on its own thread, one H3 session per slot,
// `GET` answered with 200 + `response_body`.
// ---------------------------------------------------------------------

const ServerConn = struct {
    session: http3_zig.Session,
    facade: http3_zig.Server,
    endpoint: http3_zig.TransportEndpoint,
    events: std.ArrayList(http3_zig.session.Event),
    runner: http3_zig.ServerRunner,
};

const ServerTask = struct {
    counting: Counting,
    io: std.Io,
    sock: Net.Socket,
    cert_pem: []const u8,
    key_pem: []const u8,
    stop: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    served: std.atomic.Value(u64) = .init(0),
    /// Live slots after the last loop iteration (closing ones included).
    live_slots: std.atomic.Value(u64) = .init(0),

    fn run(task: *ServerTask) void {
        task.loop() catch |err| {
            std.debug.print("bench-e2e: server loop failed: {s}\n", .{@errorName(err)});
            task.failed.store(true, .release);
        };
    }

    fn stateOf(slot: *quic.Server.Slot) ?*ServerConn {
        const ptr = slot.user_data orelse return null;
        return @ptrCast(@alignCast(ptr));
    }

    fn onWillClose(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
        const task: *ServerTask = @ptrCast(@alignCast(ctx.?));
        const state = stateOf(slot) orelse return;
        const allocator = task.counting.allocator();
        state.session.clearEvents(&state.events);
        state.events.deinit(allocator);
        state.runner.deinit();
        state.session.deinit();
        allocator.destroy(state);
        slot.user_data = null;
    }

    fn ensureState(task: *ServerTask, slot: *quic.Server.Slot) !*ServerConn {
        if (stateOf(slot)) |state| return state;
        const allocator = task.counting.allocator();
        const state = try allocator.create(ServerConn);
        state.* = .{
            .session = http3_zig.Session.init(allocator, .server, slot.conn, http3_zig.SessionConfig.production(.{})),
            .facade = undefined,
            .endpoint = undefined,
            .events = .empty,
            .runner = http3_zig.ServerRunner.init(allocator),
        };
        state.facade = http3_zig.Server.init(&state.session);
        state.endpoint = http3_zig.TransportEndpoint.withSession(slot.conn, &state.session, &state.events);
        slot.user_data = state;
        return state;
    }

    fn pump(task: *ServerTask, state: *ServerConn) !void {
        const allocator = task.counting.allocator();
        _ = try state.endpoint.drainSession();
        defer _ = state.endpoint.clearEvents();
        for (state.events.items) |event| {
            switch (try state.runner.observe(event)) {
                .request_complete => |request| {
                    const stream_id = request.stream_id;
                    _ = try state.facade.respond(allocator, stream_id, .{ .status = "200", .body = response_body });
                    // Release the finished exchange: a long-lived
                    // connection must not keep every request it served.
                    if (state.runner.tracker.remove(stream_id)) |done| {
                        done.deinit(state.runner.tracker.allocator);
                        state.runner.tracker.allocator.destroy(done);
                    }
                    _ = task.served.fetchAdd(1, .monotonic);
                },
                else => {},
            }
        }
    }

    fn loop(task: *ServerTask) !void {
        const allocator = task.counting.allocator();
        const alpn = [_][]const u8{"h3"};
        var server = try quic.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = task.cert_pem,
            .tls_key_pem = task.key_pem,
            .alpn_protocols = &alpn,
            .transport_params = transportParams(),
            .on_connection_will_close = onWillClose,
            .on_connection_will_close_user_data = task,
            // Thousands of handshakes from one source address are this
            // bench's whole point; the per-source Initial limit would
            // throttle the soak cell.
            .initial_source_rate_limit = .disabled,
            .source_byte_rate_limit = .disabled,
            .listener_datagram_rate_limit = .disabled,
            .listener_byte_rate_limit = .disabled,
        });
        defer server.deinit();

        var rx: [64 * 1024]u8 = undefined;
        var tx: [64 * 1024]u8 = undefined;
        var iteration: u64 = 0;
        while (!task.stop.load(.acquire)) : (iteration += 1) {
            const maybe_msg = task.sock.receiveTimeout(task.io, &rx, .{
                .duration = .{ .raw = std.Io.Duration.fromMilliseconds(1), .clock = .awake },
            }) catch |err| switch (quic.transport.classifyReceiveError(err)) {
                .tolerate => null,
                .fatal => return err,
            };
            const now_us = nowUs(task.io);
            if (maybe_msg) |msg| {
                _ = server.feed(msg.data, quic.transport.udp_batch.ipAddressToPathAddress(msg.from), now_us) catch {};
                while (server.drainStatelessResponse()) |response| {
                    const dst = quic.transport.udp_server.pathAddressToIpAddress(response.dst) orelse continue;
                    try sendTolerant(task.io, task.sock, &dst, response.slice());
                }
            }
            for (server.iterator()) |slot| {
                const state = task.ensureState(slot) catch continue;
                task.pump(state) catch state.session.close(http3_zig.protocol.ErrorCode.internal_error, "");
            }
            for (server.iterator()) |slot| {
                if (slot.conn.closeState() == .closed) continue;
                slot.conn.tick(now_us) catch {};
                while (slot.conn.pollDatagram(&tx, now_us) catch null) |out| {
                    const to = out.to orelse slot.peer_addr orelse continue;
                    const dst = quic.transport.udp_server.pathAddressToIpAddress(to) orelse continue;
                    try sendTolerant(task.io, task.sock, &dst, tx[0..out.len]);
                }
            }
            if (iteration % 64 == 0) _ = server.reap();
            task.live_slots.store(server.connectionCount(), .monotonic);
        }
    }
};

// ---------------------------------------------------------------------
// Client: one QUIC connection + H3 session over its own UDP socket.
// ---------------------------------------------------------------------

const ClientConn = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    sock: Net.Socket,
    server_addr: Net.IpAddress,
    conn: *quic.Connection,
    h3: http3_zig.Session,
    facade: http3_zig.Client,
    runner: http3_zig.ClientRunner,
    events: std.ArrayList(http3_zig.session.Event),
    endpoint: http3_zig.TransportEndpoint,
    rx: [64 * 1024]u8 = undefined,
    tx: [64 * 1024]u8 = undefined,

    /// Opens the socket and the connection; `self` must stay at this
    /// address (the facade and endpoint point into it).
    fn init(
        self: *ClientConn,
        allocator: std.mem.Allocator,
        io: std.Io,
        tls: boringssl.tls.Context,
        server_addr: Net.IpAddress,
    ) !void {
        const local = try Net.IpAddress.parseLiteral("127.0.0.1:0");
        const sock = try Net.IpAddress.bind(&local, io, .{ .mode = .dgram, .protocol = .udp });
        errdefer sock.close(io);
        const conn = try quic.Connection.createClient(allocator, tls, "localhost");
        errdefer conn.destroy();
        var initial_dcid: [cid_len]u8 = undefined;
        var local_scid: [cid_len]u8 = undefined;
        try boringssl.crypto.rand.fillBytes(&initial_dcid);
        try boringssl.crypto.rand.fillBytes(&local_scid);
        try conn.setInitialDcid(&initial_dcid);
        try conn.setPeerDcid(&initial_dcid);
        try conn.setLocalScid(&local_scid);
        try conn.setTransportParams(transportParams());

        self.* = .{
            .allocator = allocator,
            .io = io,
            .sock = sock,
            .server_addr = server_addr,
            .conn = conn,
            .h3 = http3_zig.Session.init(allocator, .client, conn, http3_zig.SessionConfig.production(.{})),
            .facade = undefined,
            .runner = http3_zig.ClientRunner.init(allocator),
            .events = .empty,
            .endpoint = undefined,
        };
        self.facade = http3_zig.Client.init(&self.h3);
        self.endpoint = http3_zig.TransportEndpoint.withSession(conn, &self.h3, &self.events);
    }

    fn deinit(self: *ClientConn) void {
        self.h3.clearEvents(&self.events);
        self.events.deinit(self.allocator);
        self.runner.deinit();
        self.h3.deinit();
        self.conn.destroy();
        self.sock.close(self.io);
    }

    /// One loop step: drive TLS, drain H3, send, wait up to 1 ms for a
    /// datagram, handle it, tick.
    fn step(self: *ClientConn) !void {
        const now_us = nowUs(self.io);
        try self.conn.advance();
        _ = try self.endpoint.drainSession();
        for (self.events.items) |event| _ = try self.runner.observe(event);
        _ = self.endpoint.clearEvents();
        while (try self.conn.poll(&self.tx, now_us)) |n| {
            try sendTolerant(self.io, self.sock, &self.server_addr, self.tx[0..n]);
        }
        const maybe_msg = self.sock.receiveTimeout(self.io, &self.rx, .{
            .duration = .{ .raw = std.Io.Duration.fromMilliseconds(1), .clock = .awake },
        }) catch |err| switch (quic.transport.classifyReceiveError(err)) {
            .tolerate => null,
            .fatal => return err,
        };
        if (maybe_msg) |msg| try self.conn.handle(msg.data, null, nowUs(self.io));
        try self.conn.tick(nowUs(self.io));
    }

    /// `GET /` and wait for the complete 200. Frees the response state.
    fn get(self: *ClientConn) !void {
        const request = try self.facade.request(self.allocator, .{
            .method = "GET",
            .scheme = "https",
            .authority = "localhost",
            .path = "/",
            .end_stream = true,
        });
        const deadline = nowUs(self.io) + op_timeout_us;
        while (true) {
            if (nowUs(self.io) > deadline) return error.RequestTimedOut;
            if (self.conn.isClosed()) return error.ConnectionClosed;
            try self.step();
            const response = self.runner.getResponse(request.stream_id) orelse continue;
            if (!response.complete) continue;
            const reader = response.reader();
            if (!std.mem.eql(u8, reader.status() orelse "", "200")) return error.UnexpectedStatus;
            if (!std.mem.eql(u8, reader.body(), response_body)) return error.UnexpectedBody;
            if (self.runner.tracker.remove(request.stream_id)) |done| {
                done.deinit(self.runner.tracker.allocator);
                self.runner.tracker.allocator.destroy(done);
            }
            return;
        }
    }

    /// H3 close plus a few steps so the CONNECTION_CLOSE leaves.
    fn close(self: *ClientConn) void {
        self.h3.close(http3_zig.protocol.ErrorCode.no_error, "");
        for (0..3) |_| self.step() catch break;
    }
};

// ---------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------

const Cell = enum { h3_connect, h3_get, soak };

const Latency = struct {
    samples: std.ArrayList(u64) = .empty,

    fn percentile(self: *Latency, p: u64) u64 {
        if (self.samples.items.len == 0) return 0;
        std.mem.sort(u64, self.samples.items, {}, std.sort.asc(u64));
        const idx = (self.samples.items.len - 1) * p / 100;
        return self.samples.items[idx];
    }
};

const CellResult = struct {
    cell: Cell,
    ops: u64,
    wall_us: u64,
    p50_us: u64 = 0,
    p99_us: u64 = 0,
    client_allocs_per_op: f64,
    server_allocs_per_op: f64,
    client_packets_sent_per_op: f64 = 0,
    client_packets_received_per_op: f64 = 0,
    client_bytes_sent_per_op: f64 = 0,
    client_bytes_received_per_op: f64 = 0,
    rss_warm_bytes: u64 = 0,
    rss_end_bytes: u64 = 0,
    rss_growth_bytes_per_op: f64 = 0,
    malloc_warm_bytes: u64 = 0,
    malloc_end_bytes: u64 = 0,
    malloc_growth_bytes_per_op: f64 = 0,
    client_heap_warm: u64 = 0,
    client_heap_end: u64 = 0,
    server_heap_warm: u64 = 0,
    server_heap_end: u64 = 0,
    server_live_slots_end: u64 = 0,
};

const Bench = struct {
    allocator: std.mem.Allocator,
    client_counting: *Counting,
    io: std.Io,
    server: *ServerTask,
    server_addr: Net.IpAddress,
    tls: boringssl.tls.Context,
    seed_leak_bytes: usize = 0,

    fn perOp(total: u64, ops: u64) f64 {
        return @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(@max(ops, 1)));
    }

    /// Open, `GET /`, close: one full connection. Adds its packet and
    /// byte totals to `totals`.
    fn oneConnection(self: *Bench, totals: *quic.ConnectionStats) !void {
        const conn = try self.allocator.create(ClientConn);
        defer self.allocator.destroy(conn);
        try conn.init(self.allocator, self.io, self.tls, self.server_addr);
        defer conn.deinit();
        try conn.get();
        conn.close();
        const s = conn.conn.stats();
        totals.packets_sent += s.packets_sent;
        totals.packets_received += s.packets_received;
        totals.bytes_sent += s.bytes_sent;
        totals.bytes_received += s.bytes_received;
    }

    fn h3Connect(self: *Bench, n: u64) !CellResult {
        var latency: Latency = .{};
        defer latency.samples.deinit(std.heap.page_allocator);
        try latency.samples.ensureTotalCapacity(std.heap.page_allocator, n);
        var totals = std.mem.zeroes(quic.ConnectionStats);
        // One warm-up connection keeps first-use costs out of the counts.
        try self.oneConnection(&totals);
        totals = std.mem.zeroes(quic.ConnectionStats);
        const c0 = self.client_counting.allocs.load(.monotonic);
        const s0 = self.server.counting.allocs.load(.monotonic);
        const t0 = nowUs(self.io);
        for (0..n) |_| {
            const start = nowUs(self.io);
            try self.oneConnection(&totals);
            latency.samples.appendAssumeCapacity(nowUs(self.io) - start);
        }
        const wall = nowUs(self.io) - t0;
        return .{
            .cell = .h3_connect,
            .ops = n,
            .wall_us = wall,
            .p50_us = latency.percentile(50),
            .p99_us = latency.percentile(99),
            .client_allocs_per_op = perOp(self.client_counting.allocs.load(.monotonic) - c0, n),
            .server_allocs_per_op = perOp(self.server.counting.allocs.load(.monotonic) - s0, n),
            .client_packets_sent_per_op = perOp(totals.packets_sent, n),
            .client_packets_received_per_op = perOp(totals.packets_received, n),
            .client_bytes_sent_per_op = perOp(totals.bytes_sent, n),
            .client_bytes_received_per_op = perOp(totals.bytes_received, n),
        };
    }

    fn h3Get(self: *Bench, n: u64) !CellResult {
        var latency: Latency = .{};
        defer latency.samples.deinit(std.heap.page_allocator);
        try latency.samples.ensureTotalCapacity(std.heap.page_allocator, n);
        const conn = try self.allocator.create(ClientConn);
        defer self.allocator.destroy(conn);
        try conn.init(self.allocator, self.io, self.tls, self.server_addr);
        defer conn.deinit();
        // Warm-up: handshake, SETTINGS, QPACK state, first stream.
        for (0..16) |_| try conn.get();
        const before = conn.conn.stats();
        const c0 = self.client_counting.allocs.load(.monotonic);
        const s0 = self.server.counting.allocs.load(.monotonic);
        const t0 = nowUs(self.io);
        for (0..n) |_| {
            const start = nowUs(self.io);
            try conn.get();
            latency.samples.appendAssumeCapacity(nowUs(self.io) - start);
        }
        const wall = nowUs(self.io) - t0;
        const after = conn.conn.stats();
        conn.close();
        return .{
            .cell = .h3_get,
            .ops = n,
            .wall_us = wall,
            .p50_us = latency.percentile(50),
            .p99_us = latency.percentile(99),
            .client_allocs_per_op = perOp(self.client_counting.allocs.load(.monotonic) - c0, n),
            .server_allocs_per_op = perOp(self.server.counting.allocs.load(.monotonic) - s0, n),
            .client_packets_sent_per_op = perOp(after.packets_sent - before.packets_sent, n),
            .client_packets_received_per_op = perOp(after.packets_received - before.packets_received, n),
            .client_bytes_sent_per_op = perOp(after.bytes_sent - before.bytes_sent, n),
            .client_bytes_received_per_op = perOp(after.bytes_received - before.bytes_received, n),
        };
    }

    /// Waits until the server has reaped every connection (closing and
    /// draining ones hold about a megabyte each), so an RSS sample
    /// measures what stays, not what is in flight.
    fn quiesce(self: *Bench) !void {
        const deadline = nowUs(self.io) + op_timeout_us;
        while (self.server.live_slots.load(.monotonic) != 0) {
            if (nowUs(self.io) > deadline) return error.ServerNeverQuiesced;
            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(5), .awake);
        }
    }

    fn soak(self: *Bench, n: u64) !CellResult {
        var totals = std.mem.zeroes(quic.ConnectionStats);
        // Warm-up: allocator pools, TLS caches, the server's slot table.
        const warm = @max(n / 10, 50);
        for (0..warm) |_| try self.oneConnection(&totals);
        try self.quiesce();
        const rss_warm = try currentRssBytes(self.io);
        const malloc_warm = try mallocInUseBytes();
        const client_heap_warm = self.client_counting.bytes_in_use.load(.monotonic);
        const server_heap_warm = self.server.counting.bytes_in_use.load(.monotonic);
        const c0 = self.client_counting.allocs.load(.monotonic);
        const s0 = self.server.counting.allocs.load(.monotonic);
        const t0 = nowUs(self.io);
        for (0..n) |_| {
            try self.oneConnection(&totals);
            // `--seed-leak`: a C-heap leak per connection, to prove the
            // gate trips (ablation). Never freed, by design.
            if (self.seed_leak_bytes != 0) {
                const p = std.c.malloc(self.seed_leak_bytes) orelse return error.OutOfMemory;
                @memset(@as([*]u8, @ptrCast(p))[0..self.seed_leak_bytes], 0xa5);
                // Without this the optimizer may delete an allocation
                // that is never read (it did, in ReleaseSafe).
                std.mem.doNotOptimizeAway(p);
            }
        }
        const wall = nowUs(self.io) - t0;
        try self.quiesce();
        const rss_end = try currentRssBytes(self.io);
        const malloc_end = try mallocInUseBytes();
        return .{
            .cell = .soak,
            .ops = n,
            .wall_us = wall,
            .client_allocs_per_op = perOp(self.client_counting.allocs.load(.monotonic) - c0, n),
            .server_allocs_per_op = perOp(self.server.counting.allocs.load(.monotonic) - s0, n),
            .rss_warm_bytes = rss_warm,
            .rss_end_bytes = rss_end,
            .rss_growth_bytes_per_op = perOp(rss_end -| rss_warm, n),
            .malloc_warm_bytes = malloc_warm,
            .malloc_end_bytes = malloc_end,
            .malloc_growth_bytes_per_op = (@as(f64, @floatFromInt(malloc_end)) - @as(f64, @floatFromInt(malloc_warm))) /
                @as(f64, @floatFromInt(@max(n, 1))),
            .client_heap_warm = client_heap_warm,
            .client_heap_end = self.client_counting.bytes_in_use.load(.monotonic),
            .server_heap_warm = server_heap_warm,
            .server_heap_end = self.server.counting.bytes_in_use.load(.monotonic),
            .server_live_slots_end = self.server.live_slots.load(.monotonic),
        };
    }
};

fn printResult(r: CellResult) void {
    const ops_per_s = @as(f64, @floatFromInt(r.ops)) * 1e6 / @as(f64, @floatFromInt(@max(r.wall_us, 1)));
    std.debug.print("{s}: {d} ops in {d:.1} ms ({d:.1} ops/s)", .{
        @tagName(r.cell), r.ops, @as(f64, @floatFromInt(r.wall_us)) / 1000.0, ops_per_s,
    });
    if (r.p50_us != 0) std.debug.print(", p50 {d} us, p99 {d} us", .{ r.p50_us, r.p99_us });
    std.debug.print("\n  allocs/op: client {d:.1}, server {d:.1}\n", .{ r.client_allocs_per_op, r.server_allocs_per_op });
    if (r.client_packets_sent_per_op != 0) {
        std.debug.print("  client/op: packets sent {d:.2}, received {d:.2}; bytes sent {d:.0}, received {d:.0}\n", .{
            r.client_packets_sent_per_op, r.client_packets_received_per_op,
            r.client_bytes_sent_per_op,   r.client_bytes_received_per_op,
        });
    }
    if (r.cell == .soak) {
        std.debug.print("  RSS after quiesce: {d} -> {d} bytes ({d:.1} bytes/connection)\n", .{
            r.rss_warm_bytes, r.rss_end_bytes, r.rss_growth_bytes_per_op,
        });
        std.debug.print("  malloc in use after quiesce: {d} -> {d} bytes ({d:.1} bytes/connection)\n", .{
            r.malloc_warm_bytes, r.malloc_end_bytes, r.malloc_growth_bytes_per_op,
        });
        std.debug.print("  Zig heap in use: client {d} -> {d}, server {d} -> {d}; server live slots at end {d}\n", .{
            r.client_heap_warm, r.client_heap_end, r.server_heap_warm, r.server_heap_end, r.server_live_slots_end,
        });
    }
}

fn writeJson(io: std.Io, path: []const u8, results: []const CellResult) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.print("{{\"schema\":\"http3-zig-bench-e2e-v1\",\"os\":\"{s}\",\"arch\":\"{s}\",\"optimize\":\"{s}\",\"cells\":[", .{
        @tagName(builtin.os.tag), @tagName(builtin.cpu.arch), @tagName(builtin.mode),
    });
    for (results, 0..) |r, i| {
        if (i != 0) try w.writeAll(",");
        try w.print(
            "{{\"cell\":\"{s}\",\"ops\":{d},\"wall_us\":{d},\"p50_us\":{d},\"p99_us\":{d}," ++
                "\"client_allocs_per_op\":{d:.3},\"server_allocs_per_op\":{d:.3}," ++
                "\"client_packets_sent_per_op\":{d:.3},\"client_packets_received_per_op\":{d:.3}," ++
                "\"client_bytes_sent_per_op\":{d:.1},\"client_bytes_received_per_op\":{d:.1}," ++
                "\"rss_warm_bytes\":{d},\"rss_end_bytes\":{d},\"rss_growth_bytes_per_op\":{d:.1}," ++
                "\"malloc_warm_bytes\":{d},\"malloc_end_bytes\":{d},\"malloc_growth_bytes_per_op\":{d:.1}}}",
            .{
                @tagName(r.cell),           r.ops,                          r.wall_us,
                r.p50_us,                   r.p99_us,                       r.client_allocs_per_op,
                r.server_allocs_per_op,     r.client_packets_sent_per_op,   r.client_packets_received_per_op,
                r.client_bytes_sent_per_op, r.client_bytes_received_per_op, r.rss_warm_bytes,
                r.rss_end_bytes,            r.rss_growth_bytes_per_op,      r.malloc_warm_bytes,
                r.malloc_end_bytes,         r.malloc_growth_bytes_per_op,
            },
        );
    }
    try w.writeAll("]}\n");
    try w.flush();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var cells: [3]Cell = undefined;
    var cell_count: usize = 0;
    var n_override: ?u64 = null;
    var json_path: ?[]const u8 = null;
    var seed_leak_bytes: usize = 0;
    {
        var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
        defer args.deinit();
        _ = args.next();
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--cell")) {
                const name = args.next() orelse return error.MissingCell;
                cells[cell_count] = std.meta.stringToEnum(Cell, name) orelse return error.UnknownCell;
                cell_count += 1;
            } else if (std.mem.eql(u8, arg, "--n")) {
                n_override = try std.fmt.parseInt(u64, args.next() orelse return error.MissingN, 10);
            } else if (std.mem.eql(u8, arg, "--seed-leak")) {
                seed_leak_bytes = try std.fmt.parseInt(usize, args.next() orelse return error.MissingSeedLeak, 10);
            } else if (std.mem.eql(u8, arg, "--json")) {
                json_path = try init.arena.allocator().dupe(u8, args.next() orelse return error.MissingJsonPath);
            } else return error.UnknownArgument;
        }
    }
    if (cell_count == 0) {
        cells = .{ .h3_connect, .h3_get, .soak };
        cell_count = 3;
    }

    var cert_buf: [16 * 1024]u8 = undefined;
    var key_buf: [16 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    const listen = try Net.IpAddress.parseLiteral("127.0.0.1:0");
    const server_sock = try Net.IpAddress.bind(&listen, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);
    const server_addr = server_sock.address;

    var server: ServerTask = .{
        .counting = .{ .backing = std.heap.c_allocator },
        .io = io,
        .sock = server_sock,
        .cert_pem = cert_pem,
        .key_pem = key_pem,
    };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&server});
    defer thread.join();
    defer server.stop.store(true, .release);

    var client_counting: Counting = .{ .backing = std.heap.c_allocator };
    var tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer tls.deinit();

    var bench: Bench = .{
        .allocator = client_counting.allocator(),
        .client_counting = &client_counting,
        .io = io,
        .server = &server,
        .server_addr = server_addr,
        .tls = tls,
        .seed_leak_bytes = seed_leak_bytes,
    };

    std.debug.print("bench-e2e: real loopback UDP, server on 127.0.0.1:{d}, {s}\n", .{ server_addr.getPort(), @tagName(builtin.mode) });
    var results: [3]CellResult = undefined;
    for (cells[0..cell_count], 0..) |cell, i| {
        results[i] = switch (cell) {
            .h3_connect => try bench.h3Connect(n_override orelse 200),
            .h3_get => try bench.h3Get(n_override orelse 2000),
            .soak => try bench.soak(n_override orelse 1000),
        };
        printResult(results[i]);
        if (server.failed.load(.acquire)) return error.ServerLoopFailed;
    }
    if (json_path) |path| try writeJson(io, path, results[0..cell_count]);
}
