//! Long-running-session memory profile for WebTransport over HTTP/3.
//!
//! Sister to `bench/wt_bench.zig`, but where `wt_bench` measures
//! per-operation latency this binary measures *allocator footprint over
//! time*. We hold a single H3Pair plus one established WebTransport
//! session and beat it with N iterations of one fixed unit of work:
//!
//!   1. Open a uni stream, write 256 bytes, finish.
//!   2. Drain server events until the stream has been observed
//!      `_opened` + `_data` + `_finished`.
//!   3. Send a 64-byte datagram client→server.
//!   4. Send a 64-byte datagram server→client (echo).
//!   5. Pump until both sides are quiescent (no new events on either
//!      side after a single drained pump).
//!   6. Free every drained event via `Session.freeEvent` so any
//!      cloned bytes go back to the allocator immediately.
//!
//! The harness wraps the project's `DebugAllocator` (the 0.16 rename of
//! `GeneralPurposeAllocator`) with a thin `CountingAllocator` so we can
//! read live `bytes_in_use` and `max_bytes_ever` after every iteration
//! window. We sample at four points and emit a Markdown table:
//!
//!   - warm-up complete (right after WT establishment)
//!   - after 1 000 iterations
//!   - after 5 000 iterations
//!   - after 10 000 iterations
//!
//! `gpa.deinit()` runs at the end so the leak detector can fire on any
//! payload that escaped `freeEvent`.
//!
//! Numbers reflect *library overhead only* — the loopback shim hands
//! buffers between two `quic_zig.Connection` instances in-process. No
//! kernel sockets, no real network. The numbers exist to detect
//! monotonic growth across a single long-lived session, not to claim
//! any particular working-set size.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

const Allocator = std.mem.Allocator;

// Cert + key buffers populated at startup from
// `tests/data/test_cert.pem` / `tests/data/test_key.pem` via the
// process cwd. `zig build mem-profile` runs with cwd = project root,
// matching `bench/wt_bench.zig`.
var cert_buf: [64 * 1024]u8 = undefined;
var key_buf: [64 * 1024]u8 = undefined;
var cert_pem: []const u8 = &.{};
var key_pem: []const u8 = &.{};

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

const total_iterations: usize = 2_000;
const sample_at_iters = [_]usize{ 500, 1_000, 2_000 };

const stream_payload_len: usize = 256;
const datagram_payload_len: usize = 64;

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

// ---------------------------------------------------------------------
// CountingAllocator — minimal pass-through that tracks bytes-in-use and
// the high-water-mark seen so far. Wraps any backing `Allocator`. We
// deliberately roll this ourselves: 0.16's std doesn't ship a
// `MeteredAllocator`, and the shape we want (live bytes-in-use, total
// max-ever) is small enough that the indirection is cheaper than
// pulling in a third-party metered allocator.
// ---------------------------------------------------------------------

const CountingAllocator = struct {
    backing: Allocator,
    bytes_in_use: usize = 0,
    max_bytes_ever: usize = 0,
    alloc_count: u64 = 0,
    free_count: u64 = 0,

    pub fn allocator(self: *CountingAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.backing.rawAlloc(len, alignment, ret_addr);
        if (result != null) {
            self.bytes_in_use += len;
            if (self.bytes_in_use > self.max_bytes_ever) self.max_bytes_ever = self.bytes_in_use;
            self.alloc_count += 1;
        }
        return result;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = self.backing.rawResize(memory, alignment, new_len, ret_addr);
        if (ok) {
            // Adjust bytes-in-use by the delta.
            if (new_len >= memory.len) {
                self.bytes_in_use += new_len - memory.len;
                if (self.bytes_in_use > self.max_bytes_ever) self.max_bytes_ever = self.bytes_in_use;
            } else {
                self.bytes_in_use -= memory.len - new_len;
            }
        }
        return ok;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.backing.rawRemap(memory, alignment, new_len, ret_addr);
        if (result != null) {
            // remap() succeeded — old memory is freed, new allocation of
            // `new_len` bytes is in its place. Adjust by the net delta.
            if (new_len >= memory.len) {
                self.bytes_in_use += new_len - memory.len;
                if (self.bytes_in_use > self.max_bytes_ever) self.max_bytes_ever = self.bytes_in_use;
            } else {
                self.bytes_in_use -= memory.len - new_len;
            }
        }
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ret_addr);
        // Underflow guard: pathological accounting shouldn't take down the binary.
        if (memory.len > self.bytes_in_use) {
            self.bytes_in_use = 0;
        } else {
            self.bytes_in_use -= memory.len;
        }
        self.free_count += 1;
    }
};

// ---------------------------------------------------------------------
// Persistent session — a single H3Pair plus one established WT session
// that we beat on for `total_iterations` units of work.
// ---------------------------------------------------------------------

const Persistent = struct {
    allocator: Allocator,
    client_tls: boringssl.tls.Context,
    server_tls: boringssl.tls.Context,
    client_quic: quic_zig.Connection,
    server_quic: quic_zig.Connection,
    client_h3: http3_zig.Session,
    server_h3: http3_zig.Session,
    client: http3_zig.Client,
    server: http3_zig.Server,
    client_runner: http3_zig.runner.ClientRunner,
    server_runner: http3_zig.runner.ServerRunner,
    client_events: std.ArrayList(http3_zig.session.Event),
    server_events: std.ArrayList(http3_zig.session.Event),
    client_wt: http3_zig.WebTransportClientStream,
    server_wt: http3_zig.WebTransportServerStream,
    session_id: u64,
    now_us: u64,
    packet: [4096]u8,

    fn init(self: *Persistent, allocator: Allocator) !void {
        self.allocator = allocator;
        self.now_us = 1_000_000;

        self.client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
        errdefer self.client_tls.deinit();
        self.server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
        errdefer self.server_tls.deinit();

        self.client_quic = try quic_zig.Connection.initClient(allocator, self.client_tls, "localhost");
        errdefer self.client_quic.deinit();
        self.server_quic = try quic_zig.Connection.initServer(allocator, self.server_tls);
        errdefer self.server_quic.deinit();

        try connectQuic(&self.client_quic, &self.server_quic);

        self.client_h3 = http3_zig.Session.init(allocator, .client, &self.client_quic, .{ .settings = wt_settings });
        errdefer self.client_h3.deinit();
        self.server_h3 = http3_zig.Session.init(allocator, .server, &self.server_quic, .{ .settings = wt_settings });
        errdefer self.server_h3.deinit();
        try self.client_h3.start();
        try self.server_h3.start();

        self.client_runner = http3_zig.ClientRunner.init(allocator);
        errdefer self.client_runner.deinit();
        self.server_runner = http3_zig.ServerRunner.init(allocator);
        errdefer self.server_runner.deinit();

        self.client_events = .empty;
        self.server_events = .empty;
        errdefer {
            clearEvents(allocator, &self.client_events);
            self.client_events.deinit(allocator);
            clearEvents(allocator, &self.server_events);
            self.server_events.deinit(allocator);
        }

        // SETTINGS exchange.
        var iters: u32 = 0;
        while (self.client_h3.peer_settings == null or self.server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.SettingsTimedOut;
            try self.pumpOnce();
            clearEvents(allocator, &self.server_events);
            clearEvents(allocator, &self.client_events);
        }

        self.client = http3_zig.Client.init(&self.client_h3);
        self.server = http3_zig.Server.init(&self.server_h3);

        self.client_wt = try self.client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = "/wt",
        });
        self.session_id = self.client_wt.sessionId();

        var server_wt_opt: ?http3_zig.WebTransportServerStream = null;
        var client_saw_response = false;
        iters = 0;
        while (!client_saw_response or server_wt_opt == null) : (iters += 1) {
            if (iters >= 20_000) return error.EstablishTimedOut;
            try self.pumpOnce();

            for (self.server_events.items) |event| {
                switch (try self.server_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (server_wt_opt == null and request.headers().len > 0 and request.isWebTransport()) {
                            server_wt_opt = try self.server.acceptWebTransport(allocator, request, .{});
                        }
                    },
                    else => {},
                }
            }
            clearEvents(allocator, &self.server_events);

            for (self.client_events.items) |event| {
                switch (try self.client_runner.observe(event)) {
                    .response_updated, .response_complete => |response_state| {
                        const response = response_state.reader();
                        if (response.headers().len > 0 and response.webTransportAccepted()) {
                            client_saw_response = true;
                        }
                    },
                    else => {},
                }
            }
            clearEvents(allocator, &self.client_events);
        }
        self.server_wt = server_wt_opt.?;
    }

    fn deinit(self: *Persistent) void {
        clearEvents(self.allocator, &self.server_events);
        self.server_events.deinit(self.allocator);
        clearEvents(self.allocator, &self.client_events);
        self.client_events.deinit(self.allocator);
        self.server_runner.deinit();
        self.client_runner.deinit();
        self.server_h3.deinit();
        self.client_h3.deinit();
        self.server_quic.deinit();
        self.client_quic.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
    }

    fn pumpOnce(self: *Persistent) !void {
        var driver = http3_zig.TransportLoopback.init(
            http3_zig.TransportEndpoint.withSession(&self.client_quic, &self.client_h3, &self.client_events),
            http3_zig.TransportEndpoint.withSession(&self.server_quic, &self.server_h3, &self.server_events),
            .{
                .now_us = self.now_us,
                .max_datagrams_per_direction = 1,
            },
        );
        _ = try driver.step(&self.packet);
        self.now_us = driver.now_us;
    }
};

// ---------------------------------------------------------------------
// One iteration of work: open uni, write 256B, finish, observe events,
// exchange one 64-byte datagram each direction, drain to quiescence,
// freeEvent everything.
// ---------------------------------------------------------------------

fn doWorkUnit(p: *Persistent, stream_payload: []const u8, datagram_payload: []const u8) !void {
    // ---- Stream half ----
    // The peer's `initial_max_streams_uni` (4096) is below our 10 000
    // iteration count, so once the initial credit is exhausted we have
    // to wait for the MAX_STREAMS replenishment quic_zig sends as
    // streams close. Pump until `openUniStream` succeeds — this is
    // the same pattern the "16 concurrent uni streams" test uses.
    const uni_id = blk: while (true) {
        if (p.client_wt.openUniStream()) |id| {
            break :blk id;
        } else |err| switch (err) {
            error.StreamLimitExceeded => {
                try p.pumpOnce();
                for (p.server_events.items) |event| {
                    _ = try p.server_runner.observe(event);
                    p.server_h3.freeEvent(event);
                }
                p.server_events.clearRetainingCapacity();
                for (p.client_events.items) |event| {
                    _ = try p.client_runner.observe(event);
                    p.client_h3.freeEvent(event);
                }
                p.client_events.clearRetainingCapacity();
            },
            else => return err,
        }
    };
    try p.client_wt.writeStream(uni_id, stream_payload);
    try p.client_wt.finishStream(uni_id);

    var saw_opened = false;
    var saw_data_bytes: usize = 0;
    var saw_finished = false;

    var iters: u32 = 0;
    while (!(saw_opened and saw_data_bytes >= stream_payload.len and saw_finished)) : (iters += 1) {
        if (iters >= 5_000) return error.StreamServerTimedOut;
        try p.pumpOnce();

        for (p.server_events.items) |event| {
            switch (event) {
                .webtransport_stream_opened => |opened| {
                    if (opened.session_id == p.session_id) saw_opened = true;
                },
                .webtransport_stream_data => |data| {
                    if (data.session_id == p.session_id) saw_data_bytes += data.data.len;
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == p.session_id) saw_finished = true;
                },
                else => {},
            }
            _ = try p.server_runner.observe(event);
            // Free immediately via the session — releases any
            // deep-cloned payload back to the counting allocator.
            p.server_h3.freeEvent(event);
        }
        p.server_events.clearRetainingCapacity();

        for (p.client_events.items) |event| {
            _ = try p.client_runner.observe(event);
            p.client_h3.freeEvent(event);
        }
        p.client_events.clearRetainingCapacity();
    }

    // ---- Datagram half (one each direction) ----
    try p.client_wt.sendDatagram(datagram_payload);

    var server_saw_dgram = false;
    iters = 0;
    while (!server_saw_dgram) : (iters += 1) {
        if (iters >= 5_000) return error.DatagramServerTimedOut;
        try p.pumpOnce();

        for (p.server_events.items) |event| {
            switch (event) {
                .datagram => |d| {
                    if (d.stream_id == p.session_id) server_saw_dgram = true;
                },
                else => {},
            }
            _ = try p.server_runner.observe(event);
            p.server_h3.freeEvent(event);
        }
        p.server_events.clearRetainingCapacity();

        for (p.client_events.items) |event| {
            _ = try p.client_runner.observe(event);
            p.client_h3.freeEvent(event);
        }
        p.client_events.clearRetainingCapacity();
    }

    try p.server_wt.sendDatagram(datagram_payload);

    var client_saw_dgram = false;
    iters = 0;
    while (!client_saw_dgram) : (iters += 1) {
        if (iters >= 5_000) return error.DatagramClientTimedOut;
        try p.pumpOnce();

        for (p.client_events.items) |event| {
            switch (event) {
                .datagram => |d| {
                    if (d.stream_id == p.session_id) client_saw_dgram = true;
                },
                else => {},
            }
            _ = try p.client_runner.observe(event);
            p.client_h3.freeEvent(event);
        }
        p.client_events.clearRetainingCapacity();

        for (p.server_events.items) |event| {
            _ = try p.server_runner.observe(event);
            p.server_h3.freeEvent(event);
        }
        p.server_events.clearRetainingCapacity();
    }

    // ---- Drain to quiescence ----
    // After both sides have observed everything they cared about, do a
    // bounded drain to flush ACKs, runner-level cleanup, and any
    // straggler events. A single pump that produces no events on
    // either side is our quiescence signal.
    var quiescent_pumps: u32 = 0;
    iters = 0;
    while (quiescent_pumps < 2) : (iters += 1) {
        if (iters >= 100) break; // bounded; we don't want to spin forever
        try p.pumpOnce();
        const empty = p.server_events.items.len == 0 and p.client_events.items.len == 0;
        for (p.server_events.items) |event| {
            _ = try p.server_runner.observe(event);
            p.server_h3.freeEvent(event);
        }
        p.server_events.clearRetainingCapacity();
        for (p.client_events.items) |event| {
            _ = try p.client_runner.observe(event);
            p.client_h3.freeEvent(event);
        }
        p.client_events.clearRetainingCapacity();
        if (empty) quiescent_pumps += 1 else quiescent_pumps = 0;
    }
}

// ---------------------------------------------------------------------
// Entry point + sampling.
// ---------------------------------------------------------------------

const Sample = struct {
    label: []const u8,
    iters_done: usize,
    bytes_in_use: usize,
    max_bytes_ever: usize,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    // Backing allocator: a fresh DebugAllocator with safety on. This is
    // the 0.16 rename of `GeneralPurposeAllocator(.{ .verbose_log =
    // false, .safety = true })`; we keep both knobs explicit so the
    // intent matches the spec.
    var gpa: std.heap.DebugAllocator(.{ .safety = true, .verbose_log = false }) = .init;
    var counting: CountingAllocator = .{ .backing = gpa.allocator() };
    const allocator = counting.allocator();

    try stdout.print("# http3-zig WebTransport long-running memory profile\n\n", .{});
    try stdout.print(
        "Iterations: {d} (samples at {d} / {d} / {d}). Per iteration: 1x uni stream ({d}B), 1x datagram round-trip ({d}B each direction), drain to quiescence, freeEvent on every drained event.\n\n",
        .{ total_iterations, sample_at_iters[0], sample_at_iters[1], sample_at_iters[2], stream_payload_len, datagram_payload_len },
    );
    try stdout.flush();

    var p: Persistent = undefined;
    try p.init(allocator);

    var stream_payload: [stream_payload_len]u8 = undefined;
    for (&stream_payload, 0..) |*b, i| b.* = @truncate(i);
    var datagram_payload: [datagram_payload_len]u8 = undefined;
    for (&datagram_payload, 0..) |*b, i| b.* = @truncate(i ^ 0x55);

    // Sample 0: warm-up complete, before any iterations.
    const warmup_sample: Sample = .{
        .label = "warm-up",
        .iters_done = 0,
        .bytes_in_use = counting.bytes_in_use,
        .max_bytes_ever = counting.max_bytes_ever,
    };

    var samples: [4]Sample = undefined;
    samples[0] = warmup_sample;
    var samples_len: usize = 1;

    var next_sample_idx: usize = 0;
    var i: usize = 0;
    while (i < total_iterations) : (i += 1) {
        try doWorkUnit(&p, &stream_payload, &datagram_payload);

        if (next_sample_idx < sample_at_iters.len and (i + 1) == sample_at_iters[next_sample_idx]) {
            const at = sample_at_iters[next_sample_idx];
            samples[samples_len] = .{
                .label = labelFor(at),
                .iters_done = at,
                .bytes_in_use = counting.bytes_in_use,
                .max_bytes_ever = counting.max_bytes_ever,
            };
            samples_len += 1;
            next_sample_idx += 1;
        }
    }

    try printSampleTable(stdout, samples[0..samples_len]);
    try stdout.flush();

    // Tear down the session before deinit'ing the GPA so all session
    // allocations are released.
    p.deinit();

    const check = gpa.deinit();
    if (check == .leak) {
        try stdout.print("\n**LEAK DETECTED**: DebugAllocator reported leaks. See stderr for details.\n", .{});
        try stdout.flush();
        return error.LeakDetected;
    } else {
        try stdout.print("\nLeak check: ok (no leaked allocations after teardown).\n", .{});
        try stdout.flush();
    }
}

fn labelFor(iters: usize) []const u8 {
    return switch (iters) {
        10 => "10 iters",
        50 => "50 iters",
        100 => "100 iters",
        500 => "500 iters",
        1_000 => "1k iters",
        2_000 => "2k iters",
        5_000 => "5k iters",
        10_000 => "10k iters",
        else => "n iters",
    };
}

fn printSampleTable(stdout: anytype, samples: []const Sample) !void {
    try stdout.print(
        "| Stage | iters | bytes-in-use | max-bytes-ever | Δ vs warm-up |\n",
        .{},
    );
    try stdout.print(
        "| --- | ---: | ---: | ---: | ---: |\n",
        .{},
    );
    const baseline = if (samples.len > 0) samples[0].bytes_in_use else 0;
    for (samples) |s| {
        const delta: i128 = @as(i128, @intCast(s.bytes_in_use)) - @as(i128, @intCast(baseline));
        const sign: []const u8 = if (delta >= 0) "+" else "";
        try stdout.print(
            "| {s} | {d} | {d} | {d} | {s}{d} |\n",
            .{ s.label, s.iters_done, s.bytes_in_use, s.max_bytes_ever, sign, delta },
        );
    }
    if (samples.len >= 2) {
        const last = samples[samples.len - 1];
        const total_delta: i128 = @as(i128, @intCast(last.bytes_in_use)) - @as(i128, @intCast(baseline));
        const iters_delta: i128 = @intCast(last.iters_done);
        const per_iter: f64 = if (iters_delta == 0) 0 else @as(f64, @floatFromInt(total_delta)) / @as(f64, @floatFromInt(iters_delta));
        const sign: []const u8 = if (total_delta >= 0) "+" else "";
        try stdout.print(
            "\nΔ bytes-in-use {s} → {s}: {s}{d} bytes over {d} iters (≈ {d:.4} bytes/iter)\n",
            .{ samples[0].label, last.label, sign, total_delta, iters_delta, per_iter },
        );
    }
}

// ---------------------------------------------------------------------
// Helpers — copied from `bench/wt_bench.zig` (deliberate: this binary
// is its own profiler tool, not a refactor of the bench file).
// ---------------------------------------------------------------------

fn clearEvents(allocator: Allocator, events: *std.ArrayList(http3_zig.session.Event)) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    // The memory profile opens a fresh uni stream every iteration for
    // 10 000 iterations on a single connection. The 16-stream cap used
    // by the bench / fixtures runs out almost immediately. Set the
    // initial uni-stream count to quic_zig's per-connection ceiling
    // (`max_streams_per_connection = 4096`) so the initial credit is
    // as generous as possible; the MAX_STREAMS frames the peer sends
    // as streams close will keep us going past that floor over the
    // 10 000-iter run.
    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 32,
        .initial_max_streams_uni = 4096,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    if (!client.handshakeDone() or !server.handshakeDone()) return error.HandshakeTimedOut;

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    _ = server.markPathValidated(server.activePathId());
}
