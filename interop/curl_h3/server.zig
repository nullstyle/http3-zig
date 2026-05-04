const std = @import("std");
const boringssl = @import("boringssl");
const nullq = @import("nullq");
const null3 = @import("null3");

const Net = std.Io.net;

const server_cid = [_]u8{ 0xc3, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
const trace_packets = false;

const Options = struct {
    listen: []const u8 = "127.0.0.1:0",
    cert: []const u8 = "tests/data/test_cert.pem",
    key: []const u8 = "tests/data/test_key.pem",
    max_requests: u64 = 1,
    idle_timeout_ms: u64 = 1_000,
};

const App = struct {
    allocator: std.mem.Allocator,
    tracker: null3.RequestTracker,
    responded: std.AutoHashMapUnmanaged(u64, void) = .empty,
    responses_sent: u64 = 0,

    fn init(allocator: std.mem.Allocator) App {
        return .{
            .allocator = allocator,
            .tracker = null3.RequestTracker.init(allocator),
        };
    }

    fn deinit(self: *App) void {
        self.tracker.deinit();
        self.responded.deinit(self.allocator);
    }

    fn observe(self: *App, server: *null3.Server, event: null3.session.Event) !void {
        const request_event = server.classify(event) orelse return;
        const request = (try self.tracker.observe(request_event)) orelse return;
        if (!request.complete or request.headers == null) return;
        if (self.responded.contains(request.stream_id)) return;

        try self.responded.put(self.allocator, request.stream_id, {});
        try self.respond(server, request);
        self.responses_sent += 1;
    }

    fn respond(self: *App, server: *null3.Server, request: *const null3.RequestState) !void {
        const path = request.path() orelse "/";
        if (std.mem.startsWith(u8, path, "/hello")) {
            try self.respondText(server, request.stream_id, "200", "hello\n");
        } else if (std.mem.startsWith(u8, path, "/inspect")) {
            try self.respondInspect(server, request);
        } else if (std.mem.startsWith(u8, path, "/echo")) {
            try self.respondBytes(server, request.stream_id, "200", request.bodyBytes());
        } else if (std.mem.startsWith(u8, path, "/large")) {
            try self.respondLarge(server, request.stream_id, parseBytesQuery(path) orelse 262_144);
        } else if (std.mem.startsWith(u8, path, "/goaway")) {
            try self.respondText(server, request.stream_id, "200", "bye\n");
            try server.goaway(request.stream_id + 4);
        } else {
            try self.respondText(server, request.stream_id, "404", "not found\n");
        }
    }

    fn respondInspect(self: *App, server: *null3.Server, request: *const null3.RequestState) !void {
        const x_test = fieldValue(request.headerFields(), "x-null3-test") orelse "";
        const body = try std.fmt.allocPrint(
            self.allocator,
            "method={s}\npath={s}\nauthority={s}\nx-null3-test={s}\n",
            .{
                request.method() orelse "",
                request.path() orelse "",
                request.authority() orelse "",
                x_test,
            },
        );
        defer self.allocator.free(body);
        try self.respondText(server, request.stream_id, "200", body);
    }

    fn respondText(
        self: *App,
        server: *null3.Server,
        stream_id: u64,
        status: []const u8,
        body: []const u8,
    ) !void {
        const headers = [_]null3.FieldLine{
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "x-null3-interop", .value = "curl-h3" },
        };
        _ = try server.respond(self.allocator, stream_id, .{
            .status = status,
            .headers = &headers,
            .body = body,
        });
    }

    fn respondBytes(
        self: *App,
        server: *null3.Server,
        stream_id: u64,
        status: []const u8,
        body: []const u8,
    ) !void {
        const headers = [_]null3.FieldLine{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "x-null3-interop", .value = "curl-h3" },
        };
        _ = try server.respond(self.allocator, stream_id, .{
            .status = status,
            .headers = &headers,
            .body = body,
        });
    }

    fn respondLarge(self: *App, server: *null3.Server, stream_id: u64, size: usize) !void {
        const headers = [_]null3.FieldLine{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "x-null3-interop", .value = "curl-h3" },
        };
        var writer = try server.startResponse(self.allocator, stream_id, .{
            .status = "200",
            .headers = &headers,
        });

        var remaining = size;
        var chunk: [8192]u8 = undefined;
        fillPattern(&chunk);
        while (remaining > 0) {
            const n = @min(remaining, chunk.len);
            try writer.write(chunk[0..n]);
            remaining -= n;
        }
        try writer.finish();
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const options = try parseArgs(init, allocator);

    const bind_addr = try Net.IpAddress.parseLiteral(options.listen);
    const sock = try Net.IpAddress.bind(&bind_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    var cert_buf: [64 * 1024]u8 = undefined;
    var key_buf: [64 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, options.cert, &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, options.key, &key_buf);

    var server_tls = try null3.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var conn = try nullq.Connection.initServer(allocator, server_tls);
    defer conn.deinit();
    try conn.bind();
    try conn.setLocalScid(&server_cid);

    var h3 = null3.Session.init(allocator, .server, &conn, .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 4,
            .max_field_section_size = 16 * 1024 * 1024,
        },
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = null3.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 16 * 1024 * 1024,
        .max_data_frame_payload = 16 * 1024,
    });
    defer h3.deinit();
    var h3_server = null3.Server.init(&h3);
    var app = App.init(allocator);
    defer app.deinit();

    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.print("READY {d}\n", .{sock.address.getPort()});
    try stdout.flush();

    var peer: ?Net.IpAddress = null;
    var transport_params_set = false;
    var now_us: u64 = 1_000_000;
    var idle_after_done_ms: u64 = 0;
    var rx: [64 * 1024]u8 = undefined;
    var tx: [4096]u8 = undefined;
    var events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    while (!conn.isClosed()) {
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
            idle_after_done_ms = 0;
            if (!transport_params_set) {
                const ids = peekInitialIds(msg.data) orelse continue;
                const params: nullq.tls.TransportParams = .{
                    .original_destination_connection_id = nullq.conn.path.ConnectionId.fromSlice(ids.dcid),
                    .initial_source_connection_id = nullq.conn.path.ConnectionId.fromSlice(&server_cid),
                    .max_idle_timeout_ms = 30_000,
                    .initial_max_data = 32 * 1024 * 1024,
                    .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
                    .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
                    .initial_max_stream_data_uni = 1024 * 1024,
                    .initial_max_streams_bidi = 128,
                    .initial_max_streams_uni = 16,
                    .max_udp_payload_size = 1200,
                    .active_connection_id_limit = 8,
                    .max_datagram_frame_size = 1200,
                };
                try conn.acceptInitial(msg.data, params);
                transport_params_set = true;
            }
            try conn.handle(msg.data, null, now_us);
        }

        try h3.start();
        try h3.drain(&events);
        for (events.items) |event| try app.observe(&h3_server, event);
        clearEvents(allocator, &events);

        while (try conn.poll(&tx, now_us)) |n| {
            if (peer) |p| {
                if (trace_packets) std.debug.print("tx {d} bytes\n", .{n});
                try sock.send(io, &p, tx[0..n]);
            } else break;
        }
        try conn.tick(now_us);
        now_us += 1_000;

        if (options.max_requests > 0 and app.responses_sent >= options.max_requests) {
            idle_after_done_ms += 5;
            if (idle_after_done_ms >= options.idle_timeout_ms) break;
        }
    }
}

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
        } else if (std.mem.eql(u8, arg, "--max-requests")) {
            options.max_requests = try std.fmt.parseInt(u64, args.next() orelse return error.MissingRequestCount, 10);
        } else if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            options.idle_timeout_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingIdleTimeout, 10);
        } else {
            return error.UnknownArgument;
        }
    }
    return options;
}

fn clearEvents(allocator: std.mem.Allocator, events: *std.ArrayList(null3.session.Event)) void {
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

fn parseBytesQuery(path: []const u8) ?usize {
    const marker = "bytes=";
    const start = std.mem.indexOf(u8, path, marker) orelse return null;
    var end = start + marker.len;
    while (end < path.len and path[end] >= '0' and path[end] <= '9') : (end += 1) {}
    return std.fmt.parseInt(usize, path[start + marker.len .. end], 10) catch null;
}

fn fillPattern(buf: []u8) void {
    const pattern = "0123456789abcdef";
    for (buf, 0..) |*b, i| b.* = pattern[i % pattern.len];
}

fn fieldValue(fields: []const null3.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
