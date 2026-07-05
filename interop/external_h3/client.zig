const std = @import("std");
const boringssl = @import("boringssl");
const quic_zig = @import("quic_zig");
const http3_zig = @import("http3_zig");

const Net = std.Io.net;

const initial_dcid = [_]u8{ 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
const local_scid = [_]u8{ 0xc3, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

const Options = struct {
    connect: []const u8 = "127.0.0.1:4433",
    local: []const u8 = "0.0.0.0:0",
    sni: []const u8 = "localhost",
    authority: []const u8 = "localhost",
    method: []const u8 = "GET",
    path: []const u8 = "/",
    body: ?[]const u8 = null,
    max_time_ms: u64 = 10_000,
    verify: boringssl.tls.VerifyMode = .none,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const options = try parseArgs(init, allocator);

    const remote_addr = try Net.IpAddress.parseLiteral(options.connect);
    const local_addr = try Net.IpAddress.parseLiteral(options.local);
    const sock = try Net.IpAddress.bind(&local_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    const sni = try allocator.dupeSentinel(u8, options.sni, 0);
    defer allocator.free(sni);

    var client_tls = try http3_zig.client.initTlsContext(.{
        .verify = options.verify,
    });
    defer client_tls.deinit();

    var conn = try quic_zig.Connection.initClient(allocator, client_tls, sni);
    defer conn.deinit();
    try conn.bind();

    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&initial_dcid);
    try conn.setLocalScid(&local_scid);
    try conn.setTransportParams(.{
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .initial_max_streams_uni = 16,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
    });

    var h3 = http3_zig.Session.init(allocator, .client, &conn, .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 4,
            .h3_datagram = true,
            .enable_connect_protocol = true,
        },
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 16 * 1024 * 1024,
        .max_data_frame_payload = 16 * 1024,
    });
    defer h3.deinit();

    var h3_client = http3_zig.Client.init(&h3);
    _ = try h3_client.request(allocator, .{
        .method = options.method,
        .scheme = "https",
        .authority = options.authority,
        .path = options.path,
        .body = options.body,
        .end_stream = true,
    });

    var runner = http3_zig.ClientRunner.init(allocator);
    defer runner.deinit();
    var events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &events);
        events.deinit(allocator);
    }
    var completed: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed.deinit(allocator);

    var endpoint = http3_zig.TransportEndpoint.withSession(&conn, &h3, &events);

    const UdpSink = struct {
        socket: @TypeOf(sock),
        io: @TypeOf(io),
        peer: Net.IpAddress,

        pub fn send(self: *@This(), bytes: []const u8) !void {
            try self.socket.send(self.io, &self.peer, bytes);
        }
    };

    var now_us: u64 = 1_000_000;
    const deadline_us = now_us + options.max_time_ms * 1000;
    var rx: [64 * 1024]u8 = undefined;
    var tx: [4096]u8 = undefined;
    while (completed.items.len == 0 and !conn.isClosed()) {
        if (now_us >= deadline_us) return error.ExternalInteropTimedOut;

        _ = try endpoint.drainSession();
        _ = try runner.observeBatch(events.items, &completed);
        clearEvents(allocator, &events);

        var sink = UdpSink{ .socket = sock, .io = io, .peer = remote_addr };
        _ = try endpoint.flush(&tx, now_us, &sink);

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
            try endpoint.handle(msg.data, null, now_us);
        }

        try endpoint.tick(now_us);
        now_us += http3_zig.driver.default_step_us;
    }

    if (completed.items.len == 0) return error.NoResponse;
    const response = completed.items[0].reader();

    var stdout_buf: [8192]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.print("STATUS {s}\n", .{response.status() orelse ""});
    for (response.headers()) |field| {
        if (field.name.len > 0 and field.name[0] != ':') {
            try stdout.print("{s}: {s}\n", .{ field.name, field.value });
        }
    }
    try stdout.writeAll("\n");
    try stdout.writeAll(response.body());
    try stdout.flush();
}

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--connect")) {
            options.connect = args.next() orelse return error.MissingConnectAddress;
        } else if (std.mem.eql(u8, arg, "--local")) {
            options.local = args.next() orelse return error.MissingLocalAddress;
        } else if (std.mem.eql(u8, arg, "--sni")) {
            options.sni = args.next() orelse return error.MissingSni;
        } else if (std.mem.eql(u8, arg, "--authority")) {
            options.authority = args.next() orelse return error.MissingAuthority;
        } else if (std.mem.eql(u8, arg, "--method")) {
            options.method = args.next() orelse return error.MissingMethod;
        } else if (std.mem.eql(u8, arg, "--path")) {
            options.path = args.next() orelse return error.MissingPath;
        } else if (std.mem.eql(u8, arg, "--body")) {
            options.body = args.next() orelse return error.MissingBody;
        } else if (std.mem.eql(u8, arg, "--max-time-ms")) {
            options.max_time_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingTimeout, 10);
        } else if (std.mem.eql(u8, arg, "--verify-system")) {
            options.verify = .system;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            options.verify = .none;
        } else {
            return error.UnknownArgument;
        }
    }
    return options;
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
