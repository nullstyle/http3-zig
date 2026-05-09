//! WebTransport baseline microbenchmark.
//!
//! Measures three operations against an in-process H3 + QUIC pair driven
//! by `http3_zig.TransportLoopback`:
//!
//!   1. **Session establishment** — fresh QUIC handshake, SETTINGS
//!      exchange, Extended CONNECT (`startWebTransport` →
//!      `acceptWebTransport`), client observes a 200 status.
//!   2. **Datagram round-trip** — on a persistent session, send a
//!      64-byte datagram client→server, server echoes, client receives.
//!   3. **Uni stream 1-KiB round-trip** — on a persistent session, open
//!      a uni stream, write 1 KiB, finish, observe the
//!      `webtransport_stream_finished` event on the server.
//!
//! Per operation: 10 warmup + 1000 measured iterations. Reports p50,
//! p99, mean, max in nanoseconds (and µs for readability).
//!
//! Numbers reflect *library overhead only* — the loopback shim hands
//! buffers between two `quic_zig.Connection` instances in-process. No
//! kernel sockets, no real network. They are useful as a regression
//! signal, not as a wire-line latency claim.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

// Cert + key buffers populated at startup from
// `tests/data/test_cert.pem` / `tests/data/test_key.pem` via the
// process cwd. `zig build bench` always runs with cwd = project root,
// matching `examples/loopback_wt.zig`.
var cert_buf: [64 * 1024]u8 = undefined;
var key_buf: [64 * 1024]u8 = undefined;
var cert_pem: []const u8 = &.{};
var key_pem: []const u8 = &.{};

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

const warmup_iters: usize = 10;
const measured_iters: usize = 1000;

const datagram_payload_len: usize = 64;
const stream_payload_len: usize = 1024;

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("# http3-zig WebTransport baseline benchmark\n\n", .{});
    try stdout.print(
        "Iterations: {d} warmup + {d} measured per operation.\n\n",
        .{ warmup_iters, measured_iters },
    );
    try stdout.flush();

    const establish_samples = try allocator.alloc(u64, measured_iters);
    defer allocator.free(establish_samples);
    try benchEstablish(allocator, io, establish_samples);

    const datagram_samples = try allocator.alloc(u64, measured_iters);
    defer allocator.free(datagram_samples);
    try benchDatagram(allocator, io, datagram_samples);

    const stream_samples = try allocator.alloc(u64, measured_iters);
    defer allocator.free(stream_samples);
    try benchStream(allocator, io, stream_samples);

    try printTable(stdout, &.{
        .{ .name = "Session establish", .samples = establish_samples },
        .{ .name = "Datagram RT (64B)", .samples = datagram_samples },
        .{ .name = "Uni stream RT (1KiB)", .samples = stream_samples },
    });
    try stdout.flush();
}

const ResultRow = struct {
    name: []const u8,
    samples: []u64,
};

fn printTable(stdout: anytype, rows: []const ResultRow) !void {
    try stdout.print("| Operation | p50 | p99 | mean | max |\n", .{});
    try stdout.print("| --- | ---: | ---: | ---: | ---: |\n", .{});
    for (rows) |row| {
        const stats = computeStats(row.samples);
        try stdout.print(
            "| {s} | {d:.2} µs | {d:.2} µs | {d:.2} µs | {d:.2} µs |\n",
            .{
                row.name,
                @as(f64, @floatFromInt(stats.p50)) / 1000.0,
                @as(f64, @floatFromInt(stats.p99)) / 1000.0,
                @as(f64, @floatFromInt(stats.mean_ns)) / 1000.0,
                @as(f64, @floatFromInt(stats.max)) / 1000.0,
            },
        );
    }
    try stdout.print("\nRaw nanoseconds (for regression diffs):\n", .{});
    try stdout.print("| Operation | p50 ns | p99 ns | mean ns | max ns |\n", .{});
    try stdout.print("| --- | ---: | ---: | ---: | ---: |\n", .{});
    for (rows) |row| {
        const stats = computeStats(row.samples);
        try stdout.print(
            "| {s} | {d} | {d} | {d} | {d} |\n",
            .{ row.name, stats.p50, stats.p99, stats.mean_ns, stats.max },
        );
    }
}

const Stats = struct {
    p50: u64,
    p99: u64,
    mean_ns: u64,
    max: u64,
};

fn computeStats(samples: []u64) Stats {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const n = samples.len;
    var sum: u128 = 0;
    for (samples) |s| sum += s;
    const p50_idx = n / 2;
    // p99: floor(n * 0.99). For n=1000 that's index 990 (the 991st entry).
    const p99_idx = (n * 99) / 100;
    return .{
        .p50 = samples[p50_idx],
        .p99 = samples[p99_idx],
        .mean_ns = @intCast(sum / @as(u128, n)),
        .max = samples[n - 1],
    };
}

// ---------------------------------------------------------------------
// Operation 1: Session establishment
// ---------------------------------------------------------------------

fn benchEstablish(allocator: std.mem.Allocator, io: std.Io, samples: []u64) !void {
    var i: usize = 0;
    while (i < warmup_iters) : (i += 1) {
        _ = try runEstablishOnce(allocator, io, null);
    }
    i = 0;
    while (i < samples.len) : (i += 1) {
        var ns: u64 = 0;
        _ = try runEstablishOnce(allocator, io, &ns);
        samples[i] = ns;
    }
}

/// Run a fresh end-to-end session-establishment cycle and return the
/// elapsed nanoseconds in `out_ns` (if provided).
fn runEstablishOnce(allocator: std.mem.Allocator, io: std.Io, out_ns: ?*u64) !void {
    const start_ts = nowNs(io);

    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var client_quic = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client_quic.deinit();
    var server_quic = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server_quic.deinit();

    try connectQuic(&client_quic, &server_quic);

    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, .{ .settings = wt_settings });
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, .{ .settings = wt_settings });
    defer server_h3.deinit();
    try client_h3.start();
    try server_h3.start();

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var packet: [4096]u8 = undefined;
    var now_us: u64 = 1_000_000;

    // SETTINGS exchange.
    {
        var iters: u32 = 0;
        while (client_h3.peer_settings == null or server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.SettingsTimedOut;
            try pump(&client_quic, &server_quic, &client_h3, &server_h3, &client_events, &server_events, &now_us, &packet);
            clearEvents(allocator, &server_events);
            clearEvents(allocator, &client_events);
        }
    }

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);

    const client_wt = try client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;

    var iters: u32 = 0;
    while (!client_saw_response) : (iters += 1) {
        if (iters >= 20_000) return error.EstablishTimedOut;
        try pump(&client_quic, &server_quic, &client_h3, &server_h3, &client_events, &server_events, &now_us, &packet);

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.headers().len > 0 and response.webTransportAccepted()) {
                        client_saw_response = true;
                    }
                },
                else => {},
            }
        }
        clearEvents(allocator, &client_events);
    }

    if (server_wt == null) return error.ServerWtMissing;
    _ = client_wt;

    const end_ts = nowNs(io);
    if (out_ns) |slot| slot.* = elapsedNs(start_ts, end_ts);
}

// ---------------------------------------------------------------------
// Operation 2 + 3: persistent-session microbenchmarks.
// ---------------------------------------------------------------------

/// Holds a fully-established WT session that we reuse across many
/// datagram or stream round-trips. Set up once, torn down after the
/// loop completes.
const Persistent = struct {
    allocator: std.mem.Allocator,
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

    fn init(self: *Persistent, allocator: std.mem.Allocator) !void {
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

fn benchDatagram(allocator: std.mem.Allocator, io: std.Io, samples: []u64) !void {
    var p: Persistent = undefined;
    try p.init(allocator);
    defer p.deinit();

    var payload: [datagram_payload_len]u8 = undefined;
    for (&payload, 0..) |*b, idx| b.* = @truncate(idx);

    var i: usize = 0;
    while (i < warmup_iters) : (i += 1) {
        _ = try datagramRoundTrip(&p, io, &payload, null);
    }
    i = 0;
    while (i < samples.len) : (i += 1) {
        var ns: u64 = 0;
        try datagramRoundTrip(&p, io, &payload, &ns);
        samples[i] = ns;
    }
}

fn datagramRoundTrip(p: *Persistent, io: std.Io, payload: []const u8, out_ns: ?*u64) !void {
    const start_ts = nowNs(io);

    try p.client_wt.sendDatagram(payload);

    var server_saw = false;
    var iters: u32 = 0;
    // Drain client+server until server receives the datagram, then echo,
    // then drain until client receives it.
    while (!server_saw) : (iters += 1) {
        if (iters >= 5_000) return error.DatagramServerTimedOut;
        try p.pumpOnce();

        for (p.server_events.items) |event| {
            // Look directly at session events for the datagram.
            switch (event) {
                .datagram => |d| {
                    if (d.stream_id == p.session_id) server_saw = true;
                },
                else => {},
            }
            // Also drain via runner so request state stays consistent.
            _ = try p.server_runner.observe(event);
        }
        clearEvents(p.allocator, &p.server_events);

        for (p.client_events.items) |event| {
            _ = try p.client_runner.observe(event);
        }
        clearEvents(p.allocator, &p.client_events);
    }

    try p.server_wt.sendDatagram(payload);

    var client_saw = false;
    iters = 0;
    while (!client_saw) : (iters += 1) {
        if (iters >= 5_000) return error.DatagramClientTimedOut;
        try p.pumpOnce();

        for (p.client_events.items) |event| {
            switch (event) {
                .datagram => |d| {
                    if (d.stream_id == p.session_id) client_saw = true;
                },
                else => {},
            }
            _ = try p.client_runner.observe(event);
        }
        clearEvents(p.allocator, &p.client_events);

        for (p.server_events.items) |event| {
            _ = try p.server_runner.observe(event);
        }
        clearEvents(p.allocator, &p.server_events);
    }

    const end_ts = nowNs(io);
    if (out_ns) |slot| slot.* = elapsedNs(start_ts, end_ts);
}

fn benchStream(allocator: std.mem.Allocator, io: std.Io, samples: []u64) !void {
    var p: Persistent = undefined;
    try p.init(allocator);
    defer p.deinit();

    var payload: [stream_payload_len]u8 = undefined;
    for (&payload, 0..) |*b, idx| b.* = @truncate(idx);

    var i: usize = 0;
    while (i < warmup_iters) : (i += 1) {
        _ = try streamRoundTrip(&p, io, &payload, null);
    }
    i = 0;
    while (i < samples.len) : (i += 1) {
        var ns: u64 = 0;
        try streamRoundTrip(&p, io, &payload, &ns);
        samples[i] = ns;
    }
}

fn streamRoundTrip(p: *Persistent, io: std.Io, payload: []const u8, out_ns: ?*u64) !void {
    const start_ts = nowNs(io);

    const uni_id = try p.client_wt.openUniStream();
    try p.client_wt.writeStream(uni_id, payload);
    try p.client_wt.finishStream(uni_id);

    var server_saw_finish = false;
    var iters: u32 = 0;
    while (!server_saw_finish) : (iters += 1) {
        if (iters >= 5_000) return error.StreamServerTimedOut;
        try p.pumpOnce();

        for (p.server_events.items) |event| {
            switch (event) {
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == p.session_id) server_saw_finish = true;
                },
                else => {},
            }
            _ = try p.server_runner.observe(event);
        }
        clearEvents(p.allocator, &p.server_events);

        for (p.client_events.items) |event| {
            _ = try p.client_runner.observe(event);
        }
        clearEvents(p.allocator, &p.client_events);
    }

    const end_ts = nowNs(io);
    if (out_ns) |slot| slot.* = elapsedNs(start_ts, end_ts);
}

// ---------------------------------------------------------------------
// Helpers — mirror the `examples/loopback_wt.zig` shim.
// ---------------------------------------------------------------------

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

fn elapsedNs(start: i96, end: i96) u64 {
    const delta = end - start;
    if (delta < 0) return 0;
    return @intCast(delta);
}

fn pump(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
    packet: []u8,
) !void {
    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(client, client_h3, client_events),
        http3_zig.TransportEndpoint.withSession(server, server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 1,
        },
    );
    _ = try driver.step(packet);
    now_us.* = driver.now_us;
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
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

    // Mirror tests/integration/_fixtures.zig: bypass primary-path
    // validation since the in-process shim never carries real datagrams
    // and so wouldn't flip the validated bit otherwise.
    _ = server.markPathValidated(server.activePathId());
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
