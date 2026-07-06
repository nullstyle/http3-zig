const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x44, 0x67, 0x72, 0x43, 0x6c, 0x69, 0x00, 0x03 };
const ServerCid = [_]u8{ 0x44, 0x67, 0x72, 0x53, 0x72, 0x76, 0x00, 0x03 };

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

    const session_config: http3_zig.SessionConfig = .{
        .settings = .{ .h3_datagram = true },
    };
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, session_config);
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, session_config);
    defer server_h3.deinit();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);

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

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var packet: [4096]u8 = undefined;
    try waitForDatagramSettings(&driver, &packet, &client, &server, &client_events, &server_events, allocator);

    var writer = try client.startRequest(allocator, .{
        .method = "CONNECT",
        .authority = "localhost",
    });
    const stream_id = writer.stream_id;

    var server_saw_connect = false;
    var steps: u32 = 0;
    while (!server_saw_connect) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;
        _ = try driver.step(&packet);
        for (server_events.items) |event| {
            const request_event = server.classify(event) orelse continue;
            switch (request_event) {
                .headers => |headers| {
                    if (headers.stream_id == stream_id) server_saw_connect = true;
                },
                else => {},
            }
        }
        clearEvents(allocator, &server_events);
        clearEvents(allocator, &client_events);
    }

    const client_send_id = try writer.datagramTracked("from-client");
    var server_send_id: ?u64 = null;
    var server_saw_client_datagram = false;
    var client_saw_client_ack = false;
    var client_saw_server_datagram = false;
    var server_saw_server_ack = false;

    steps = 0;
    while (!server_saw_client_datagram or
        !client_saw_client_ack or
        !client_saw_server_datagram or
        !server_saw_server_ack) : (steps += 1)
    {
        if (steps >= 20_000) return error.ExampleTimedOut;
        _ = try driver.step(&packet);

        for (server_events.items) |event| {
            const request_event = server.classify(event) orelse continue;
            switch (request_event) {
                .datagram => |datagram| {
                    if (datagram.stream_id == stream_id and std.mem.eql(u8, datagram.payload, "from-client")) {
                        server_saw_client_datagram = true;
                        if (server_send_id == null) {
                            server_send_id = try server.sendDatagramTracked(stream_id, "from-server");
                        }
                    }
                },
                .datagram_acked => |acked| {
                    if (server_send_id) |id| {
                        if (acked.id == id) server_saw_server_ack = true;
                    }
                },
                .datagram_lost => |lost| {
                    if (server_send_id) |id| {
                        if (lost.id == id) return error.ServerDatagramLost;
                    }
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            }
        }

        for (client_events.items) |event| {
            const response_event = client.classify(event) orelse continue;
            switch (response_event) {
                .datagram => |datagram| {
                    if (datagram.stream_id == stream_id and std.mem.eql(u8, datagram.payload, "from-server")) {
                        client_saw_server_datagram = true;
                    }
                },
                .datagram_acked => |acked| {
                    if (acked.id == client_send_id) client_saw_client_ack = true;
                },
                .datagram_lost => |lost| {
                    if (lost.id == client_send_id) return error.ClientDatagramLost;
                },
                .connection_closed => return error.ClientConnectionClosed,
                else => {},
            }
        }

        clearEvents(allocator, &server_events);
        clearEvents(allocator, &client_events);
    }

    std.debug.print(
        "stream={d}\nclient_datagram_id={d}\nserver_datagram_id={d}\nacks=2\n",
        .{
            stream_id,
            client_send_id,
            server_send_id orelse return error.MissingServerSendId,
        },
    );
}

fn waitForDatagramSettings(
    driver: *http3_zig.TransportLoopback,
    packet: []u8,
    client: *http3_zig.Client,
    server: *http3_zig.Server,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    allocator: std.mem.Allocator,
) !void {
    var client_saw_settings = false;
    var server_saw_settings = false;
    var steps: u32 = 0;
    while (!client_saw_settings or !server_saw_settings) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;
        _ = try driver.step(packet);

        for (client_events.items) |event| {
            const response_event = client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    if (settings.h3_datagram) client_saw_settings = true;
                },
                else => {},
            }
        }
        for (server_events.items) |event| {
            const request_event = server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    if (settings.h3_datagram) server_saw_settings = true;
                },
                else => {},
            }
        }

        clearEvents(allocator, server_events);
        clearEvents(allocator, client_events);
    }
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
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
