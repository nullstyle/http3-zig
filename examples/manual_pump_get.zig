const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x4d, 0x61, 0x6e, 0x75, 0x43, 0x6c, 0x69, 0x00 };
const ServerCid = [_]u8{ 0x4d, 0x61, 0x6e, 0x75, 0x53, 0x72, 0x76, 0x00 };
const step_us: u64 = 1_000;
const max_datagrams_per_direction: usize = 16;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var cert_buf: [64 * 1024]u8 = undefined;
    var key_buf: [64 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var client_quic = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client_quic.deinit();
    var server_quic = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server_quic.deinit();

    try connectQuic(&client_quic, &server_quic);

    const session_config = http3_zig.SessionConfig.production(.{});
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, session_config);
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, session_config);
    defer server_h3.deinit();
    try client_h3.start();
    try server_h3.start();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    const request = try client.request(allocator, .{
        .authority = "localhost",
        .path = "/manual",
    });

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
    var completed_responses: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed_responses.deinit(allocator);

    var response_sent = false;
    var packet: [4096]u8 = undefined;
    var now_us: u64 = 1_000_000;
    var steps: u32 = 0;
    while (completed_responses.items.len == 0) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        try pumpOnce(
            &client_quic,
            &server_quic,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
            &packet,
        );

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_complete => |incoming| {
                    if (!response_sent and incoming.stream_id == request.stream_id) {
                        const reader = incoming.reader();
                        const path = headerValue(reader.headers(), ":path") orelse return error.MissingPath;
                        if (!std.mem.eql(u8, path, "/manual")) return error.UnexpectedPath;
                        _ = try server.respond(allocator, incoming.stream_id, .{
                            .status = "200",
                            .body = "manual pump ok\n",
                        });
                        response_sent = true;
                    }
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            }
        }
        clearEvents(allocator, &server_events);

        _ = try client_runner.observeBatch(client_events.items, &completed_responses);
        clearEvents(allocator, &client_events);
    }

    const response = completed_responses.items[0].reader();
    if (!std.mem.eql(u8, response.status() orelse "", "200")) return error.UnexpectedStatus;
    if (!std.mem.eql(u8, response.body(), "manual pump ok\n")) return error.UnexpectedBody;

    std.debug.print("status={s}\nbody={s}pump=manual\n", .{
        response.status() orelse "",
        response.body(),
    });
}

fn pumpOnce(
    client_quic: *quic_zig.Connection,
    server_quic: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
    packet: []u8,
) !void {
    try client_quic.tick(now_us.*);
    try server_quic.tick(now_us.*);
    try relayDatagrams(client_quic, server_quic, packet, now_us.*);
    try relayDatagrams(server_quic, client_quic, packet, now_us.*);
    try server_h3.drain(server_events);
    try client_h3.drain(client_events);
    now_us.* += step_us;
}

fn relayDatagrams(
    from: *quic_zig.Connection,
    to: *quic_zig.Connection,
    packet: []u8,
    now_us: u64,
) !void {
    var sent: usize = 0;
    while (sent < max_datagrams_per_direction) : (sent += 1) {
        const n = (try from.poll(packet, now_us)) orelse break;
        try to.handle(packet[0..n], null, now_us);
    }
}

fn headerValue(fields: []const http3_zig.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    // The in-process TLS handshake shim uses `peer`; the HTTP/3 traffic below
    // is still driven through the same `tick` / `poll` / `handle` calls an
    // embedder wires to sockets.
    client.peer = server;
    server.peer = client;

    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
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
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
