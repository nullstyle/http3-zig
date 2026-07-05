//! External WebTransport interop server harness.
//!
//! Brings up an http3-zig WebTransport server on a real UDP socket
//! and runs an echo loop that:
//!
//!   * accepts a WebTransport `CONNECT` (`:protocol = webtransport`),
//!   * echoes inbound datagrams back to the peer,
//!   * surfaces inbound peer-opened unidirectional WT streams via
//!     `webtransport_stream_data` events and echoes the payload on a
//!     server-initiated unidirectional WT stream while the session is open,
//!   * stays running until `--max-sessions` sessions have completed
//!     (default 1) or the connection closes.
//!
//! Used by `.github/workflows/wt-interop-self-test.yml` as the peer
//! the existing `external-wt-client` / `wt-interop-matrix` runners
//! exercise. The harness deliberately mirrors the structure of
//! `interop/curl_h3/server.zig` (UDP receive + drive
//! `quic_zig.Connection` + `http3_zig.Session` + flush via
//! `TransportEndpoint`), so the two are easy to read side-by-side.
//!
//! Exit codes:
//!   * 0 — the server completed `max_sessions` round-trips cleanly,
//!         OR shut down because the peer closed the connection
//!         (when `--allow-close` is set, the default).
//!   * 1 — a session ended in a protocol error.
//!   * 2 — setup / network error (cert load, socket bind, ...).

const std = @import("std");
const boringssl = @import("boringssl");
const quic_zig = @import("quic_zig");
const http3_zig = @import("http3_zig");

const Net = std.Io.net;

const server_cid = [_]u8{ 0xc3, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

const Options = struct {
    listen: []const u8 = "127.0.0.1:0",
    cert: []const u8 = "tests/data/test_cert.pem",
    key: []const u8 = "tests/data/test_key.pem",
    /// Number of WebTransport sessions to accept before the server
    /// exits. Set to 0 to run until killed.
    max_sessions: u64 = 1,
    /// Wallclock cap on the server's lifetime, in milliseconds.
    /// Defends against a stuck client wedging the harness in CI.
    max_lifetime_ms: u64 = 30_000,
};

const Category = enum { protocol, setup };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const options = parseArgs(init, allocator) catch |err| {
        std.debug.print("external_wt server: argument parse failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };

    runServer(allocator, io, options) catch |err| {
        const category = classifyError(err);
        std.debug.print(
            "external_wt server: harness failed with {s} ({s})\n",
            .{ @errorName(err), @tagName(category) },
        );
        std.process.exit(switch (category) {
            .protocol => 1,
            .setup => 2,
        });
    };
}

fn runServer(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const listen_addr = try Net.IpAddress.parseLiteral(options.listen);
    const sock = try Net.IpAddress.bind(&listen_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    var cert_buf: [16 * 1024]u8 = undefined;
    var key_buf: [16 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, options.cert, &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, options.key, &key_buf);

    var server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var conn = try quic_zig.Connection.initServer(allocator, server_tls);
    defer conn.deinit();
    try conn.bind();
    try conn.setLocalScid(&server_cid);

    var h3 = http3_zig.Session.init(allocator, .server, &conn, .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 4,
            .max_field_section_size = 16 * 1024 * 1024,
            .enable_connect_protocol = true,
            .h3_datagram = true,
            .wt_enabled = true,
        },
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 16 * 1024 * 1024,
        .max_data_frame_payload = 16 * 1024,
    });
    defer h3.deinit();
    var h3_server = http3_zig.Server.init(&h3);

    var app = App.init(allocator, options.max_sessions);
    defer app.deinit();

    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.print("READY {d}\n", .{sock.address.getPort()});
    try stdout.flush();

    var peer: ?Net.IpAddress = null;
    var transport_params_set = false;
    var now_us: u64 = 1_000_000;
    const start_us = now_us;
    const lifetime_us: u64 = options.max_lifetime_ms * 1_000;
    var rx: [64 * 1024]u8 = undefined;
    var tx: [4096]u8 = undefined;
    var events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }
    var driver = http3_zig.TransportEndpoint.withSession(&conn, &h3, &events);

    const UdpSink = struct {
        socket: @TypeOf(sock),
        io: std.Io,
        peer: Net.IpAddress,

        pub fn send(self: *@This(), bytes: []const u8) !void {
            try self.socket.send(self.io, &self.peer, bytes);
        }
    };

    while (!conn.isClosed() and !app.isDone(now_us)) {
        if (now_us - start_us > lifetime_us) {
            try stdout.print("EXIT lifetime {d}ms exceeded\n", .{options.max_lifetime_ms});
            try stdout.flush();
            break;
        }

        const maybe_msg = sock.receiveTimeout(io, &rx, .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(5),
                .clock = .awake,
            },
        }) catch |err| switch (err) {
            error.Timeout => null,
            else => return err,
        };

        if (maybe_msg) |msg| {
            peer = msg.from;
            if (!transport_params_set) {
                const ids = peekInitialIds(msg.data) orelse continue;
                const params: quic_zig.tls.TransportParams = .{
                    .original_destination_connection_id = quic_zig.conn.path.ConnectionId.fromSlice(ids.dcid),
                    .initial_source_connection_id = quic_zig.conn.path.ConnectionId.fromSlice(&server_cid),
                    .max_idle_timeout_ms = 30_000,
                    .initial_max_data = 16 * 1024 * 1024,
                    .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
                    .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
                    .initial_max_stream_data_uni = 1024 * 1024,
                    .initial_max_streams_bidi = 128,
                    .initial_max_streams_uni = 128,
                    .max_udp_payload_size = 1200,
                    .active_connection_id_limit = 8,
                    .max_datagram_frame_size = 1200,
                };
                try conn.acceptInitial(msg.data, params);
                transport_params_set = true;
            }
            try driver.handle(msg.data, null, now_us);
        }

        _ = try driver.drainSession();
        for (events.items) |event| try app.observe(&h3_server, event, now_us);
        clearEvents(allocator, &events);

        if (peer) |p| {
            var sink = UdpSink{ .socket = sock, .io = io, .peer = p };
            _ = try driver.flush(&tx, now_us, &sink);
        }
        try driver.tick(now_us);
        now_us += http3_zig.driver.default_step_us;
    }

    try stdout.print(
        "EXIT sessions={d}/{d} closed={any}\n",
        .{ app.sessions_completed, options.max_sessions, conn.isClosed() },
    );
    try stdout.flush();
}

const App = struct {
    const completion_drain_us: u64 = 1_000_000;

    const AcceptedSession = struct {
        wt: http3_zig.WebTransportServerStream,
        completed: bool = false,
    };

    allocator: std.mem.Allocator,
    runner: http3_zig.ServerRunner,
    accepted: std.AutoHashMapUnmanaged(u64, AcceptedSession) = .empty,
    max_sessions: u64,
    sessions_completed: u64 = 0,
    completed_at_us: ?u64 = null,

    fn init(allocator: std.mem.Allocator, max_sessions: u64) App {
        return .{
            .allocator = allocator,
            .runner = http3_zig.ServerRunner.init(allocator),
            .max_sessions = max_sessions,
        };
    }

    fn deinit(self: *App) void {
        self.runner.deinit();
        self.accepted.deinit(self.allocator);
    }

    fn isDone(self: *const App, now_us: u64) bool {
        if (self.max_sessions == 0) return false;
        if (self.sessions_completed < self.max_sessions) return false;
        const completed_at = self.completed_at_us orelse return false;
        return now_us - completed_at >= completion_drain_us;
    }

    fn observe(self: *App, server: *http3_zig.Server, event: http3_zig.session.Event, now_us: u64) !void {
        // The runner classifies HTTP/3 frame events; WebTransport-
        // specific stream events fall through as `.ignored` from the
        // tracker's perspective, so we inspect them on the raw event
        // first.
        switch (event) {
            .webtransport_stream_data => |data| {
                std.debug.print(
                    "OBSERVED wt stream data session={d} stream={d} kind={s} bytes={d}\n",
                    .{ data.session_id, data.stream_id, @tagName(data.kind), data.data.len },
                );
                try self.echoUni(data.session_id, data.data);
            },
            .webtransport_stream_finished => |finished| {
                std.debug.print(
                    "OBSERVED wt stream finished session={d} stream={d}\n",
                    .{ finished.session_id, finished.stream_id },
                );
            },
            .webtransport_stream_reset => |reset| {
                std.debug.print(
                    "OBSERVED wt stream reset session={d} stream={d} code={d}\n",
                    .{ reset.session_id, reset.stream_id, reset.error_code },
                );
            },
            .webtransport_flow_violated => |v| {
                std.debug.print(
                    "OBSERVED wt flow violated session={d} stream={d} kind={s} limit={d}\n",
                    .{ v.session_id, v.stream_id, @tagName(v.kind), v.limit },
                );
            },
            .datagram => |dg| {
                if (self.accepted.getPtr(dg.stream_id)) |entry| {
                    var wt = entry.wt;
                    try wt.sendDatagram(dg.payload);
                    entry.wt = wt;
                    std.debug.print("OBSERVED wt datagram echo session={d} bytes={d}\n", .{ dg.stream_id, dg.payload.len });
                }
            },
            else => {},
        }

        switch (try self.runner.observe(event)) {
            .request_updated, .request_complete => |request_state| {
                const request = request_state.reader();
                if (!self.accepted.contains(request.streamId()) and request.headers().len > 0 and request.isWebTransport()) {
                    const wt = try server.acceptWebTransport(self.allocator, request, .{});
                    try self.accepted.put(self.allocator, request.streamId(), .{ .wt = wt });
                    std.debug.print("OBSERVED wt accepted session={d}\n", .{request.streamId()});
                }
                if (request.complete()) {
                    if (self.accepted.getPtr(request.streamId())) |entry| {
                        if (!entry.completed) {
                            var wt = entry.wt;
                            try wt.finish();
                            entry.wt = wt;
                            entry.completed = true;
                            self.sessions_completed += 1;
                            if (self.max_sessions != 0 and
                                self.sessions_completed >= self.max_sessions and
                                self.completed_at_us == null)
                            {
                                self.completed_at_us = now_us;
                            }
                        }
                        std.debug.print("OBSERVED wt session done session={d} total={d}\n", .{ request.streamId(), self.sessions_completed });
                    }
                }
            },
            .connection_closed => |closed| {
                std.debug.print(
                    "OBSERVED connection close source={s} space={s} code={d} reason={s}\n",
                    .{
                        @tagName(closed.source),
                        @tagName(closed.error_space),
                        closed.error_code,
                        closed.reason,
                    },
                );
            },
            else => {},
        }
    }

    fn echoUni(self: *App, session_id: u64, payload: []const u8) !void {
        const entry = self.accepted.getPtr(session_id) orelse return;
        if (entry.completed) {
            std.debug.print("OBSERVED wt stream echo skipped session={d} reason=session-complete\n", .{session_id});
            return;
        }
        var wt = entry.wt;
        const stream_id = try wt.openUniStream();
        try wt.writeStream(stream_id, payload);
        try wt.finishStream(stream_id);
        entry.wt = wt;
    }
};

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--listen")) {
            options.listen = args.next() orelse return error.MissingListenAddress;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            options.cert = args.next() orelse return error.MissingCertPath;
        } else if (std.mem.eql(u8, arg, "--key")) {
            options.key = args.next() orelse return error.MissingKeyPath;
        } else if (std.mem.eql(u8, arg, "--max-sessions")) {
            options.max_sessions = try std.fmt.parseInt(u64, args.next() orelse return error.MissingSessionCount, 10);
        } else if (std.mem.eql(u8, arg, "--max-lifetime-ms")) {
            options.max_lifetime_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingLifetime, 10);
        } else {
            return error.UnknownArgument;
        }
    }
    return options;
}

fn clearEvents(allocator: std.mem.Allocator, events: *std.ArrayList(http3_zig.session.Event)) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

const InitialIds = struct {
    dcid: []const u8,
    scid: []const u8,
};

fn peekInitialIds(bytes: []const u8) ?InitialIds {
    if (bytes.len < 6) return null;
    if ((bytes[0] & 0x80) == 0) return null;
    const long_type_bits = (bytes[0] >> 4) & 0x03;
    if (long_type_bits != 0) return null;
    const dcid_len = bytes[5];
    if (dcid_len > 20) return null;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return null;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = bytes[pos];
    if (scid_len > 20) return null;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return null;
    const scid = bytes[pos .. pos + scid_len];

    return .{ .dcid = dcid, .scid = scid };
}

fn classifyError(err: anyerror) Category {
    return switch (err) {
        error.AddressInUse,
        error.AddressNotAvailable,
        error.PermissionDenied,
        error.AccessDenied,
        error.FileNotFound,
        error.MissingListenAddress,
        error.MissingCertPath,
        error.MissingKeyPath,
        error.MissingSessionCount,
        error.MissingLifetime,
        error.UnknownArgument,
        => .setup,
        else => .protocol,
    };
}
