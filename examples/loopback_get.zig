const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var cert_buf: [64 * 1024]u8 = undefined;
    var key_buf: [64 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try null3.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var client_quic = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client_quic.deinit();
    var server_quic = try nullq.Connection.initServer(allocator, server_tls);
    defer server_quic.deinit();

    try connectQuic(&client_quic, &server_quic);

    var client_h3 = null3.Session.init(allocator, .client, &client_quic, .{});
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server_quic, .{});
    defer server_h3.deinit();

    var client = null3.Client.init(&client_h3);
    var server = null3.Server.init(&server_h3);
    var client_runner = null3.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

    const request = try client.request(allocator, .{
        .authority = "localhost",
        .path = "/hello",
    });

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }
    var completed_responses: std.ArrayList(*null3.ResponseState) = .empty;
    defer completed_responses.deinit(allocator);

    var driver = null3.TransportLoopback.init(
        null3.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        null3.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var response_sent = false;
    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (completed_responses.items.len == 0) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        _ = try driver.step(&packet);

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_complete => |incoming| {
                    if (!response_sent and incoming.stream_id == request.stream_id) {
                        _ = try server.respond(allocator, incoming.stream_id, .{
                            .status = "200",
                            .body = "hello from null3\n",
                        });
                        response_sent = true;
                    }
                },
                else => {},
            }
        }
        clearEvents(allocator, &server_events);

        _ = try client_runner.observeBatch(client_events.items, &completed_responses);
        clearEvents(allocator, &client_events);
    }

    const response = completed_responses.items[0].reader();
    std.debug.print("status={s}\nbody={s}", .{
        response.status() orelse "",
        response.body(),
    });
}

fn connectQuic(client: *nullq.Connection, server: *nullq.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    const tp: nullq.tls.TransportParams = .{
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
    events: *std.ArrayList(null3.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
