const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixt = @import("_fixtures.zig");

// Aliases — pulls in only the helpers this file's tests reference. It's
// fine to over-alias; unused aliases compile away.
const test_cert_pem = fixt.test_cert_pem;
const test_key_pem = fixt.test_key_pem;
const ClientCid = fixt.ClientCid;
const ServerCid = fixt.ServerCid;
const discardKeylog = fixt.discardKeylog;
const handshake = fixt.handshake;
const initConnectedQuic = fixt.initConnectedQuic;
const clearSessionEvents = fixt.clearSessionEvents;
const pumpH3 = fixt.pumpH3;
const pumpUntilH3Error = fixt.pumpUntilH3Error;
const writeFrame = fixt.writeFrame;
const writeQpackEncoderInstruction = fixt.writeQpackEncoderInstruction;
const writeStreamType = fixt.writeStreamType;
const writeVarint = fixt.writeVarint;
const openUniWithType = fixt.openUniWithType;
const writeHeadersFrame = fixt.writeHeadersFrame;
const writePushPromiseFrame = fixt.writePushPromiseFrame;
const expectLastCloseCode = fixt.expectLastCloseCode;
const fieldValue = fixt.fieldValue;
const H3Pair = fixt.H3Pair;
const expectPairH3Error = fixt.expectPairH3Error;
const exchangePairSettings = fixt.exchangePairSettings;
const openGetAndAwaitServerHeaders = fixt.openGetAndAwaitServerHeaders;
const sendRawH3Datagram = fixt.sendRawH3Datagram;

test "session negotiates and surfaces extended CONNECT requests" {
    const allocator = std.testing.allocator;

    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try http3_zig.server.initTlsContext(
        .{},
        test_cert_pem,
        test_key_pem,
    );
    defer server_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    const h3_settings: http3_zig.Settings = .{ .enable_connect_protocol = true };
    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{
        .settings = h3_settings,
    });
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{
        .settings = h3_settings,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = http3_zig.Client.init(&client_h3);

    try std.testing.expectError(
        http3_zig.session.Error.MissingSettings,
        h3_client.startRequest(allocator, .{
            .method = "CONNECT",
            .authority = "localhost",
            .path = "/socket",
            .connect_protocol = "websocket",
        }),
    );

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var client_saw_settings = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_settings) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    try std.testing.expect(settings.enable_connect_protocol);
                    client_saw_settings = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    var writer = try h3_client.startRequest(allocator, .{
        .method = "CONNECT",
        .authority = "localhost",
        .path = "/socket",
        .connect_protocol = "websocket",
    });
    const stream_id = writer.stream_id;
    try writer.finish();

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var completed: std.ArrayList(*http3_zig.RequestState) = .empty;
    defer completed.deinit(allocator);

    iters = 0;
    while (completed.items.len == 0) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        _ = try server_runner.observeBatch(server_events.items, &completed);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const request = completed.items[0].reader();
    try std.testing.expectEqual(stream_id, request.streamId());
    try std.testing.expect(request.complete());
    try std.testing.expect(request.isExtendedConnect());
    try std.testing.expectEqualStrings("CONNECT", request.method().?);
    try std.testing.expectEqualStrings("/socket", request.path().?);
    try std.testing.expectEqualStrings("websocket", request.protocol().?);
}

test "WebSocket helper requires negotiated Extended CONNECT support" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    try std.testing.expectError(
        error.ExtendedConnectNotEnabled,
        h3_client.startWebSocket(allocator, .{
            .authority = "localhost",
            .path = "/chat",
        }),
    );
}

test "WebSocket over HTTP/3 helper opens tunnel and streams bytes" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{ .enable_connect_protocol = true };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_ws = try h3_client.startWebSocket(allocator, .{
        .authority = "localhost",
        .path = "/chat",
    });
    const stream_id = client_ws.streamId();
    try client_ws.writeMessage(.text, "ping", .{ 1, 2, 3, 4 });
    try client_ws.finish();

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var accepted = false;
    var server_complete = false;
    var client_complete = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(accepted and server_complete and client_complete)) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (!accepted and request.headers().len > 0) {
                        try std.testing.expectEqual(stream_id, request.streamId());
                        try std.testing.expect(request.isExtendedConnect());
                        try std.testing.expect(request.isWebSocket());
                        try std.testing.expectEqualStrings("CONNECT", request.method().?);
                        try std.testing.expectEqualStrings("/chat", request.path().?);
                        try std.testing.expectEqualStrings(http3_zig.websocket.protocol_token, request.protocol().?);

                        var server_ws = try h3_server.acceptWebSocket(allocator, request, .{});
                        try server_ws.writeMessage(.text, "pong");
                        try server_ws.finish();
                        accepted = true;
                    }

                    if (!server_complete and request.complete()) {
                        var decoder = http3_zig.websocket.message.Decoder.init(allocator, .{
                            .frame = .{ .mask_policy = .required },
                        });
                        defer decoder.deinit();
                        try decoder.push(request.body());
                        const ws_event = (try decoder.next()).?;
                        defer ws_event.deinit(allocator);
                        switch (ws_event) {
                            .text => |payload| try std.testing.expectEqualStrings("ping", payload),
                            else => return error.UnexpectedWebSocketEvent,
                        }
                        try std.testing.expect((try decoder.next()) == null);
                        server_complete = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.headers().len > 0) {
                        try std.testing.expect(response.webSocketAccepted());
                        try std.testing.expectEqualStrings("200", response.status().?);
                    }

                    if (!client_complete and response.complete()) {
                        var decoder = http3_zig.websocket.message.Decoder.init(allocator, .{
                            .frame = .{ .mask_policy = .forbidden },
                        });
                        defer decoder.deinit();
                        try decoder.push(response.body());
                        const ws_event = (try decoder.next()).?;
                        defer ws_event.deinit(allocator);
                        switch (ws_event) {
                            .text => |payload| try std.testing.expectEqualStrings("pong", payload),
                            else => return error.UnexpectedWebSocketEvent,
                        }
                        try std.testing.expect((try decoder.next()) == null);
                        client_complete = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "CONNECT-UDP helper opens MASQUE tunnel and exchanges UDP payloads" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_udp = try h3_client.startConnectUdp(allocator, .{
        .authority = "proxy.example",
        .target_host = "example.com",
        .target_port = 443,
    });
    const stream_id = client_udp.streamId();

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var server_udp: ?http3_zig.ConnectUdpServerStream = null;
    var client_udp_receiver = http3_zig.MasqueConnectUdpReceiver.init();
    var server_udp_receiver = http3_zig.MasqueConnectUdpReceiver.init();
    var accepted = false;
    var client_saw_response = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!accepted or !client_saw_response) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_updated => |request_state| {
                    const request = request_state.reader();
                    if (!accepted and request.headers().len > 0) {
                        try std.testing.expectEqual(stream_id, request.streamId());
                        try std.testing.expect(request.isExtendedConnect());
                        try std.testing.expect(request.isConnectUdp());
                        try std.testing.expect(request.capsuleProtocolEnabled());
                        try std.testing.expectEqualStrings("CONNECT", request.method().?);
                        try std.testing.expectEqualStrings(http3_zig.masque.connect_udp_protocol, request.protocol().?);

                        const target = try request.connectUdpTarget(allocator);
                        defer target.deinit(allocator);
                        try std.testing.expectEqualStrings("example.com", target.host);
                        try std.testing.expectEqual(@as(u16, 443), target.port);

                        server_udp = try h3_server.acceptConnectUdp(allocator, request, .{});
                        accepted = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated => |response_state| {
                    const response = response_state.reader();
                    if (response.headers().len > 0) {
                        try std.testing.expect(response.connectUdpAccepted());
                        try std.testing.expect(response.capsuleProtocolEnabled());
                        try std.testing.expectEqualStrings("200", response.status().?);
                        client_saw_response = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    const tracked_client_datagram_id = try client_udp.sendUdpTracked("client-packet");
    try client_udp.sendUdpCapsule("client-capsule");
    if (server_udp) |*udp| {
        try udp.sendUdp("server-packet");
        try udp.sendUdpCapsule("server-capsule");
    } else {
        return error.MissingConnectUdpStream;
    }

    var server_saw_udp = false;
    var client_saw_udp = false;
    var server_saw_capsule = false;
    var client_saw_capsule = false;
    var client_saw_ack = false;
    iters = 0;
    while (!server_saw_udp or !client_saw_udp or !server_saw_capsule or !client_saw_capsule or !client_saw_ack) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .datagram => |datagram| {
                    server_saw_udp = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    switch (datagram.connectUdp(&server_udp_receiver)) {
                        .udp_payload => |payload| try std.testing.expectEqualStrings("client-packet", payload),
                        else => return error.UnexpectedConnectUdpDisposition,
                    }
                },
                .request_updated => |request_state| {
                    const request = request_state.reader();
                    if (request.body().len > 0) {
                        server_saw_capsule = true;
                        const decoded_capsule = try http3_zig.capsule.decode(request.body());
                        try std.testing.expect(decoded_capsule.capsule.isDatagram());
                        switch (server_udp_receiver.classifyCapsule(decoded_capsule.capsule)) {
                            .udp_payload => |payload| try std.testing.expectEqualStrings("client-capsule", payload),
                            else => return error.UnexpectedConnectUdpDisposition,
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .datagram => |datagram| {
                    client_saw_udp = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    switch (datagram.connectUdp(&client_udp_receiver)) {
                        .udp_payload => |payload| try std.testing.expectEqualStrings("server-packet", payload),
                        else => return error.UnexpectedConnectUdpDisposition,
                    }
                },
                .datagram_acked => |acked| {
                    if (acked.id == tracked_client_datagram_id) client_saw_ack = true;
                },
                .response_updated => |response_state| {
                    const response = response_state.reader();
                    if (response.body().len > 0) {
                        client_saw_capsule = true;
                        const decoded_capsule = try http3_zig.capsule.decode(response.body());
                        try std.testing.expect(decoded_capsule.capsule.isDatagram());
                        switch (client_udp_receiver.classifyCapsule(decoded_capsule.capsule)) {
                            .udp_payload => |payload| try std.testing.expectEqualStrings("server-capsule", payload),
                            else => return error.UnexpectedConnectUdpDisposition,
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}
