const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x47, 0x4f, 0x41, 0x57, 0x43, 0x6c, 0x69, 0x00 };
const ServerCid = [_]u8{ 0x47, 0x4f, 0x41, 0x57, 0x53, 0x72, 0x76, 0x00 };
const goaway_id: u64 = 4;

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

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    const request = try client.request(allocator, .{
        .authority = "localhost",
        .path = "/drain",
    });

    var client_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }
    var completed_responses: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed_responses.deinit(allocator);

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var response_sent = false;
    var goaway_seen = false;
    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (completed_responses.items.len == 0 or !goaway_seen) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        _ = try driver.step(&packet);

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_complete => |incoming| {
                    if (!response_sent and incoming.stream_id == request.stream_id) {
                        const reader = incoming.reader();
                        const path = headerValue(reader.headers(), ":path") orelse return error.MissingPath;
                        if (!std.mem.eql(u8, path, "/drain")) return error.UnexpectedPath;

                        _ = try server.respond(allocator, incoming.stream_id, .{
                            .status = "200",
                            .body = "completed before drain\n",
                        });
                        try server.goaway(goaway_id);
                        response_sent = true;
                    }
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            }
        }
        http3_zig.clearEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_complete => |response_state| {
                    if (response_state.stream_id == request.stream_id and completed_responses.items.len == 0) {
                        try completed_responses.append(allocator, response_state);
                    }
                },
                .goaway => |id| {
                    if (id != goaway_id) return error.UnexpectedGoawayId;
                    goaway_seen = true;
                },
                .connection_closed => return error.ClientConnectionClosed,
                else => {},
            }
        }
        http3_zig.clearEvents(allocator, &client_events);
    }

    const response = completed_responses.items[0].reader();
    if (!std.mem.eql(u8, response.status() orelse "", "200")) return error.UnexpectedStatus;
    if (!std.mem.eql(u8, response.body(), "completed before drain\n")) return error.UnexpectedBody;
    if (server_h3.shutdownState() != .draining) return error.ServerNotDraining;
    if (client_h3.shutdownState() != .draining) return error.ClientNotDraining;

    if (client.startRequest(allocator, .{
        .authority = "localhost",
        .path = "/after-goaway",
    })) |unexpected| {
        var writer = unexpected;
        try writer.abort();
        return error.ExpectedRequestBlockedByGoaway;
    } else |err| switch (err) {
        error.RequestBlockedByGoaway => {},
        else => return err,
    }

    std.debug.print(
        "status={s}\nbody={s}goaway={d}\nclient_state={s}\nserver_state={s}\nnew_request_blocked=true\n",
        .{
            response.status() orelse "",
            response.body(),
            goaway_id,
            @tagName(client_h3.shutdownState()),
            @tagName(server_h3.shutdownState()),
        },
    );
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
