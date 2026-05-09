const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

test "WebTransport request/response classification" {
    const request = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
        .{ .name = ":protocol", .value = http3_zig.webtransport.protocol_token },
    };
    try std.testing.expect(http3_zig.webtransport.isRequest(&request));

    const accepted = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expect(http3_zig.webtransport.responseAccepted(&accepted));
}

test "WebTransport helper rejects peers that don't advertise WebTransport" {
    // With the eager peer-SETTINGS check at the top of
    // `Client.startWebTransport`, a peer whose SETTINGS lack
    // `SETTINGS_WT_ENABLED` (and the prerequisite
    // `ENABLE_CONNECT_PROTOCOL` + `H3_DATAGRAM`) trips
    // `PeerDidNotEnableWebTransport` before the request goes on
    // the wire — see draft-ietf-webtrans-http3-15 §9.2.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    try std.testing.expectError(
        error.PeerDidNotEnableWebTransport,
        h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = "/wt",
        }),
    );
}

test "WebTransport helper rejects bootstrap before peer SETTINGS arrive" {
    // If the peer's SETTINGS frame hasn't landed yet,
    // `Client.startWebTransport` should return
    // `PeerSettingsNotReceived` rather than letting the bootstrap
    // proceed to a state where it'd silently break.
    const allocator = std.testing.allocator;

    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    // Note: deliberately do NOT call exchangePairSettings — the client
    // hasn't seen the server's SETTINGS yet.

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    try std.testing.expectError(
        error.PeerSettingsNotReceived,
        h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = "/wt",
        }),
    );
}

test "WebTransport over HTTP/3 establishes session, exchanges datagrams, and closes" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    // Both peers should now see WT-capable peer settings.
    try std.testing.expect(http3_zig.webtransport.peerEnabled(pair.client_h3.peer_settings.?));
    try std.testing.expect(http3_zig.webtransport.peerEnabled(pair.server_h3.peer_settings.?));

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var server_saw_datagram = false;
    var client_saw_datagram = false;
    var server_saw_close = false;
    const close_code: u32 = 0xdeadbeef;
    const close_reason = "shutdown";
    const datagram_to_server = "ping";
    const datagram_to_client = "pong";

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    var client_wt_uni_stream: ?u64 = null;
    while (!server_saw_close) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0) {
                        try std.testing.expectEqual(session_id, request.streamId());
                        try std.testing.expect(request.isExtendedConnect());
                        try std.testing.expect(request.isWebTransport());
                        try std.testing.expectEqualStrings("CONNECT", request.method().?);
                        try std.testing.expectEqualStrings("/wt", request.path().?);
                        try std.testing.expectEqualStrings(
                            http3_zig.webtransport.protocol_token,
                            request.protocol().?,
                        );

                        var accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                        try accepted.sendDatagram(datagram_to_client);
                        server_wt = accepted;
                    }

                    // The CONNECT stream's body carries DRAIN +
                    // CLOSE_WEBTRANSPORT_SESSION capsules.
                    if (!server_saw_close and request.body().len > 0) {
                        var seen_drain = false;
                        var seen_close: ?http3_zig.WebTransportCloseSession = null;
                        var it = http3_zig.capsule.iter(request.body());
                        while (try it.next()) |decoded| {
                            const wt_event = try http3_zig.webtransport.classifyCapsule(decoded.capsule);
                            switch (wt_event) {
                                .drain_session => seen_drain = true,
                                .close_session => |close| seen_close = close,
                                .other => {},
                                // Flow-control capsules
                                // (draft-ietf-webtrans-http3-13 §5.6) are not
                                // exercised by this integration test.
                                .max_data,
                                .data_blocked,
                                .max_streams_bidi,
                                .streams_blocked_bidi,
                                .max_streams_uni,
                                .streams_blocked_uni,
                                => {},
                            }
                        }
                        if (seen_close) |close| {
                            try std.testing.expect(seen_drain);
                            try std.testing.expectEqual(close_code, close.code);
                            try std.testing.expectEqualStrings(close_reason, close.reason);
                            server_saw_close = true;
                        }
                    }
                },
                .datagram => |datagram| {
                    try std.testing.expectEqual(session_id, datagram.stream_id);
                    try std.testing.expectEqualStrings(datagram_to_server, datagram.payload);
                    server_saw_datagram = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        try std.testing.expectEqualStrings("200", response.status().?);
                        client_saw_response = true;

                        // Now that the session is established, send a datagram
                        // to the server, open a unidirectional WT stream with
                        // the prefix written automatically, drain the session,
                        // and close it.
                        try client_wt.sendDatagram(datagram_to_server);

                        const uni_id = try client_wt.openUniStream();
                        client_wt_uni_stream = uni_id;
                        try client_wt.writeStream(uni_id, "hello");
                        try client_wt.finishStream(uni_id);

                        try client_wt.sendDrain();
                        try client_wt.close(close_code, close_reason);
                    }
                },
                .datagram => |datagram| {
                    try std.testing.expectEqual(session_id, datagram.stream_id);
                    try std.testing.expectEqualStrings(datagram_to_client, datagram.payload);
                    client_saw_datagram = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(client_saw_response);
    try std.testing.expect(server_saw_datagram);
    try std.testing.expect(client_saw_datagram);
    try std.testing.expect(server_saw_close);
    try std.testing.expect(client_wt_uni_stream != null);

    // The unidirectional stream should be a client-initiated unidirectional
    // QUIC stream — id mod 4 == 2 per RFC 9000 §2.1.
    if (client_wt_uni_stream) |uni_id| {
        try std.testing.expectEqual(@as(u64, 2), uni_id & 0b11);
    }
}

test "WebTransport unidirectional streams flow through the inbound dispatch path" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_uni_stream_id: ?u64 = null;
    var server_uni_stream_id: ?u64 = null;
    const client_payload = "hello-from-client";
    const server_payload = "hello-from-server";

    var server_saw_client_opened = false;
    var server_saw_client_data: std.ArrayList(u8) = .empty;
    defer server_saw_client_data.deinit(allocator);
    var server_saw_client_finish = false;

    var client_saw_server_opened = false;
    var client_saw_server_data: std.ArrayList(u8) = .empty;
    defer client_saw_server_data.deinit(allocator);
    var client_saw_server_finish = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(server_saw_client_finish and client_saw_server_finish)) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                        // Open a unidirectional WT stream back to the client
                        // immediately so both halves of the test can run in
                        // parallel.
                        const uni = try accepted.openUniStream();
                        server_uni_stream_id = uni;
                        try accepted.writeStream(uni, server_payload);
                        try accepted.finishStream(uni);
                        server_wt = accepted;
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                    server_saw_client_opened = true;
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    try server_saw_client_data.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    server_saw_client_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    // Once the response is back, push our outbound uni stream
                    // and let the server see it on the next pump.
                    if (client_uni_stream_id == null and response.headers().len > 0 and response.webTransportAccepted()) {
                        const uni = try client_wt.openUniStream();
                        client_uni_stream_id = uni;
                        try client_wt.writeStream(uni, client_payload);
                        try client_wt.finishStream(uni);
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                    client_saw_server_opened = true;
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    try client_saw_server_data.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    client_saw_server_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(server_saw_client_opened);
    try std.testing.expect(client_saw_server_opened);
    try std.testing.expectEqualStrings(client_payload, server_saw_client_data.items);
    try std.testing.expectEqualStrings(server_payload, client_saw_server_data.items);
}

test "WebTransport server-initiated bidirectional stream reaches the client (draft §4.2 carve-out)" {
    // RFC 9114 §6.1 ¶3 forbids server-initiated bidi streams in plain
    // HTTP/3, but draft-ietf-webtrans-http3 §4.2 carves them out for
    // WebTransport sessions. http3-zig defers the role check in
    // `ensureIncomingState` to `processBidiState` whenever a WT
    // session is in flight; this test exercises the full path:
    //   - server opens its own bidi stream via the new
    //     `WebTransportServerStream.openBidiStream()` API,
    //   - server writes the WT prefix (0x41 + Session ID) plus a
    //     payload + FIN,
    //   - client receives bytes on a server-initiated bidi id (low
    //     bits 0b01), the dispatch peeks the prefix and surfaces
    //     `webtransport_stream_opened` + `_data` + `_finished`
    //     events with the right Session ID and `kind = .bidi`.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};
    const session_id = client_wt.sessionId();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var server_bidi_id: ?u64 = null;
    const bidi_payload = "server-bidi-hello";

    var client_saw_open = false;
    var client_saw_data: std.ArrayList(u8) = .empty;
    defer client_saw_data.deinit(allocator);
    var client_saw_finish = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_finish) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                        // Open a server-initiated WT bidi stream once
                        // the session is confirmed. This is the path
                        // we couldn't exercise before fixing the
                        // role-deferred dispatch.
                        const bidi = try accepted.openBidiStream();
                        server_bidi_id = bidi;
                        try accepted.writeStream(bidi, bidi_payload);
                        try accepted.finishStream(bidi);
                        server_wt = accepted;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.bidi, opened.kind);
                    // The stream id MUST carry the server-initiated
                    // bidi pattern — low two bits `0b01`.
                    try std.testing.expectEqual(@as(u64, 0b01), opened.stream_id & 0b11);
                    client_saw_open = true;
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.bidi, data.kind);
                    try client_saw_data.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    client_saw_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(client_saw_open);
    try std.testing.expectEqualStrings(bidi_payload, client_saw_data.items);
    try std.testing.expect(server_bidi_id != null);
}

test "WebTransport client-initiated bidirectional stream is dispatched as WT, not request" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var bidi_stream_id: ?u64 = null;
    const bidi_payload = "client-bidi-payload";

    var server_saw_bidi_opened = false;
    var server_saw_bidi_data: std.ArrayList(u8) = .empty;
    defer server_saw_bidi_data.deinit(allocator);
    var server_saw_bidi_finish = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!server_saw_bidi_finish) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.bidi, opened.kind);
                    server_saw_bidi_opened = true;
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.bidi, data.kind);
                    try server_saw_bidi_data.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.bidi, finished.kind);
                    server_saw_bidi_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (bidi_stream_id == null and response.headers().len > 0 and response.webTransportAccepted()) {
                        const bidi = try client_wt.openBidiStream();
                        bidi_stream_id = bidi;
                        try client_wt.writeStream(bidi, bidi_payload);
                        try client_wt.finishStream(bidi);
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(server_saw_bidi_opened);
    try std.testing.expectEqualStrings(bidi_payload, server_saw_bidi_data.items);
}

test "WebTransport stream RESET propagates the application error code" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var uni_stream_id: ?u64 = null;
    var server_saw_open = false;
    var sent_reset = false;
    const app_error_code: u32 = 0xabad1dea;

    var saw_reset = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_reset) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    server_saw_open = true;
                },
                .webtransport_stream_reset => |reset| {
                    try std.testing.expectEqual(session_id, reset.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, reset.kind);
                    try std.testing.expectEqual(@as(?u32, app_error_code), reset.application_error_code);
                    try std.testing.expectEqual(http3_zig.webtransport.appErrorToHttp3(app_error_code), reset.error_code);
                    saw_reset = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (uni_stream_id == null and response.headers().len > 0 and response.webTransportAccepted()) {
                        const uni = try client_wt.openUniStream();
                        uni_stream_id = uni;
                        try client_wt.writeStream(uni, "before-reset");
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Stage the reset only after the server has dispatched the stream as
        // a WebTransport stream (i.e. parsed the type + Session ID prefix
        // and emitted `webtransport_stream_opened`). If we reset before the
        // server has read any bytes, the dispatch can't classify the stream
        // and would fall back to the generic stream_reset event — see the
        // ROADMAP "buffered streams" note for the corresponding cleanup.
        if (server_saw_open and !sent_reset) {
            if (uni_stream_id) |uni| {
                try client_wt.resetStream(uni, app_error_code);
                sent_reset = true;
            }
        }
    }

    try std.testing.expect(saw_reset);
}

test "acceptWebTransport rejects non-WebTransport requests" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    // Open a plain GET; the server should refuse to accept it as WebTransport.
    var get_writer = try h3_client.startRequest(allocator, .{
        .authority = "localhost",
        .path = "/",
    });
    try get_writer.finish();

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

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    var saw_request = false;
    while (!saw_request) : (iters += 1) {
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
                    if (request.headers().len == 0) continue;
                    try std.testing.expect(!request.isWebTransport());
                    try std.testing.expectError(
                        error.NotWebTransport,
                        h3_server.acceptWebTransport(allocator, request, .{}),
                    );
                    saw_request = true;
                    break;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}

test "WebTransport subprotocol negotiation: server selects from offered list" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const offered = [_][]const u8{ "echo-v1", "echo-v2", "telemetry-v3" };
    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
        .subprotocols = &offered,
    });

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_subprotocol = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_subprotocol) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        // Server should see the offered list verbatim.
                        var parsed = try request.webTransportSubprotocols(allocator);
                        defer parsed.deinit(allocator);
                        try std.testing.expectEqual(@as(usize, 3), parsed.tokens.len);
                        try std.testing.expectEqualStrings("echo-v1", parsed.tokens[0]);
                        try std.testing.expectEqualStrings("echo-v2", parsed.tokens[1]);
                        try std.testing.expectEqualStrings("telemetry-v3", parsed.tokens[2]);

                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{
                            .subprotocol = "echo-v2",
                        });
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
                        try std.testing.expect(response.webTransportAccepted());
                        const selected = response.webTransportSubprotocol() orelse return error.MissingSubprotocol;
                        try std.testing.expectEqualStrings("echo-v2", selected);
                        client_saw_subprotocol = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(client_saw_subprotocol);
    // Don't leak the writer — close cleanly.
    try client_wt.close(0, "done");
}

test "acceptWebTransport rejects subprotocols the client did not offer" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const offered = [_][]const u8{"echo-v1"};
    _ = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
        .subprotocols = &offered,
    });

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

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    var saw = false;
    while (!saw) : (iters += 1) {
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
                    if (request.headers().len == 0) continue;
                    try std.testing.expectError(
                        error.SubprotocolNotOffered,
                        h3_server.acceptWebTransport(allocator, request, .{
                            .subprotocol = "echo-v2",
                        }),
                    );
                    saw = true;
                    break;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}

// Note: draft-ietf-webtrans-http3-15 §9.2 replaced the numeric
// `SETTINGS_WT_MAX_SESSIONS` codepoint with the boolean
// `SETTINGS_WT_ENABLED`. There is no longer a session-count limit
// advertised in SETTINGS, so the previous "N+1 rejection" enforcement
// test was removed. Applications that want to bound concurrent
// sessions can decline `Server.acceptWebTransport()` based on their
// own counters (`Session.webTransportPendingCount` /
// `webTransportEstablishedCount` are still public for that purpose).

test "Buffered streams: .reject policy never surfaces stream events for the held bytes" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = h3_settings },
        .{ .settings = h3_settings, .buffered_stream_policy = .reject },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });

    // Open a uni WT stream IMMEDIATELY, before the server has had a
    // chance to dispatch the CONNECT request and call
    // `acceptWebTransport`. With `.reject` policy, the server must
    // discard this stream rather than emit any
    // `webtransport_stream_*` event for it.
    const uni = try client_wt.openUniStream();
    try client_wt.writeStream(uni, "early bird");
    try client_wt.finishStream(uni);

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var server_saw_wt_event = false;
    var post_accept_pumps: u32 = 0;

    // Pump until the server has accepted the CONNECT and we've given
    // the network another ~10 round-trips for any stray WT events to
    // drain. With `.reject`, none should arrive.
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (post_accept_pumps < 20) : (iters += 1) {
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
            switch (event) {
                .webtransport_stream_opened,
                .webtransport_stream_data,
                .webtransport_stream_finished,
                .webtransport_stream_reset,
                => server_saw_wt_event = true,
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);

        if (server_wt != null) post_accept_pumps += 1;
    }

    try std.testing.expect(server_wt != null);
    try std.testing.expect(!server_saw_wt_event);
}

test "Buffered streams: .buffer policy holds bytes until the session is confirmed" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = h3_settings },
        .{ .settings = h3_settings, .buffered_stream_policy = .buffer },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

    // Open the uni WT stream first, before the server has accepted.
    const uni = try client_wt.openUniStream();
    try client_wt.writeStream(uni, "buffered hello");
    try client_wt.finishStream(uni);

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var server_saw_open = false;
    var server_saw_data = false;
    var server_data: std.ArrayList(u8) = .empty;
    defer server_data.deinit(allocator);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(server_saw_open and server_saw_data)) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    server_saw_open = true;
                },
                .webtransport_stream_data => |data| {
                    try server_data.appendSlice(allocator, data.data);
                    server_saw_data = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expectEqualStrings("buffered hello", server_data.items);
}

test "WebTransport: 16 concurrent uni streams round-trip" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    const num_streams = 16;
    // Each stream's payload is `stream-{i}-payload`. We track per-stream
    // bytes received so we can verify nothing was crossed over.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var streams_opened: usize = 0;
    var streams_finished_on_client: usize = 0;
    var streams_finished_on_server: usize = 0;

    // Map from stream_id -> index into expected payloads.
    var stream_index_by_id: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer stream_index_by_id.deinit(allocator);

    var per_stream_received: [num_streams]std.ArrayList(u8) = undefined;
    for (&per_stream_received) |*list| list.* = .empty;
    defer for (&per_stream_received) |*list| list.deinit(allocator);

    var per_stream_finished: [num_streams]bool = @splat(false);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (streams_finished_on_server < num_streams) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    const idx = stream_index_by_id.get(data.stream_id) orelse {
                        // Pre-recorded mapping must always be in place by
                        // the time bytes arrive — the client populates it
                        // synchronously when each stream is opened.
                        return error.UnknownStream;
                    };
                    try per_stream_received[idx].appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    const idx = stream_index_by_id.get(finished.stream_id) orelse return error.UnknownStream;
                    try std.testing.expect(!per_stream_finished[idx]);
                    per_stream_finished[idx] = true;
                    streams_finished_on_server += 1;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        client_saw_response = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Once the WT session is confirmed (client_saw_response), open as
        // many streams as the peer's MAX_STREAMS limit allows. If we hit
        // `StreamLimitExceeded`, we stop and let pumps return credit.
        if (client_saw_response) {
            while (streams_opened < num_streams) {
                const uni = client_wt.openUniStream() catch |err| switch (err) {
                    error.StreamLimitExceeded => break,
                    else => return err,
                };
                const idx = streams_opened;
                try stream_index_by_id.put(allocator, uni, idx);
                var payload_buf: [32]u8 = undefined;
                const payload = try std.fmt.bufPrint(&payload_buf, "stream-{d}-payload", .{idx});
                try client_wt.writeStream(uni, payload);
                try client_wt.finishStream(uni);
                streams_opened += 1;
                streams_finished_on_client += 1;
            }
        }
    }

    try std.testing.expectEqual(num_streams, streams_opened);
    try std.testing.expectEqual(num_streams, streams_finished_on_client);
    try std.testing.expectEqual(num_streams, streams_finished_on_server);
    for (0..num_streams) |i| {
        try std.testing.expect(per_stream_finished[i]);
        var expected_buf: [32]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buf, "stream-{d}-payload", .{i});
        try std.testing.expectEqualStrings(expected, per_stream_received[i].items);
    }
}

test "WebTransport: large uni stream payload reassembled across writes" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    // 256 KiB total, deterministic byte sequence so we can verify
    // reassembly position-by-position.
    const total_bytes: usize = 256 * 1024;
    const chunk_size: usize = 16 * 1024;

    var expected = try allocator.alloc(u8, total_bytes);
    defer allocator.free(expected);
    for (expected, 0..) |*b, i| b.* = @intCast(i & 0xff);

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var uni_id: ?u64 = null;
    var bytes_written: usize = 0;
    var server_received: std.ArrayList(u8) = .empty;
    defer server_received.deinit(allocator);
    var server_saw_finish = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!server_saw_finish) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    try server_received.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    server_saw_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        client_saw_response = true;
                        uni_id = try client_wt.openUniStream();
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Stream the payload one chunk at a time across pump iterations.
        // Once all chunks are written, send FIN.
        if (uni_id) |id| {
            if (bytes_written < total_bytes) {
                const remaining = total_bytes - bytes_written;
                const take = @min(chunk_size, remaining);
                try client_wt.writeStream(id, expected[bytes_written .. bytes_written + take]);
                bytes_written += take;
                if (bytes_written == total_bytes) {
                    try client_wt.finishStream(id);
                }
            }
        }
    }

    try std.testing.expectEqual(total_bytes, server_received.items.len);
    try std.testing.expectEqualSlices(u8, expected, server_received.items);
}

test "WebTransport: 64 concurrent datagrams round-trip" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    const num_datagrams = 64;

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var datagrams_sent: usize = 0;
    var datagrams_received: usize = 0;
    var seen_index: [num_datagrams]bool = @splat(false);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (datagrams_received < num_datagrams) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .datagram => |datagram| {
                    try std.testing.expectEqual(session_id, datagram.stream_id);
                    // Payload format: "datagram-{i}".
                    const prefix = "datagram-";
                    try std.testing.expect(std.mem.startsWith(u8, datagram.payload, prefix));
                    const idx = try std.fmt.parseInt(usize, datagram.payload[prefix.len..], 10);
                    try std.testing.expect(idx < num_datagrams);
                    // No duplicates: in-process loopback is reliable. If
                    // this fires, either the test or the transport
                    // duplicated something.
                    try std.testing.expect(!seen_index[idx]);
                    seen_index[idx] = true;
                    datagrams_received += 1;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        client_saw_response = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Once the session is confirmed, queue datagrams. Send a few per
        // pump cycle so the queue between client and server doesn't
        // overflow (max_pending_datagram_count = 64 in quic_zig). The
        // loopback delivers `max_datagrams_per_direction = 1` per pump,
        // so we keep the in-flight count low by sending no more than 4
        // ahead of the receiver at a time.
        if (client_saw_response) {
            while (datagrams_sent < num_datagrams and (datagrams_sent - datagrams_received) < 4) {
                var payload_buf: [32]u8 = undefined;
                const payload = try std.fmt.bufPrint(&payload_buf, "datagram-{d}", .{datagrams_sent});
                try client_wt.sendDatagram(payload);
                datagrams_sent += 1;
            }
        }
    }

    try std.testing.expectEqual(num_datagrams, datagrams_sent);
    try std.testing.expectEqual(num_datagrams, datagrams_received);
    for (seen_index) |seen| try std.testing.expect(seen);
}

test "WebTransport: 8 buffered uni streams replay open + data + finish in client-open order under .buffer policy" {
    // The full version of the spec — exercised end-to-end now that the
    // FIN-before-replay and ordering bugs are fixed:
    //   1. Client opens N=8 uni WT streams + writes data + sends FIN
    //      BEFORE the server accepts the CONNECT.
    //   2. After accept, the server emits open/data/finished events
    //      *in the order the client opened the streams* (not in
    //      hash-map iteration order).
    //   3. The deferred FINs surface AFTER their matching open + data
    //      events, never before.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = h3_settings },
        .{ .settings = h3_settings, .buffered_stream_policy = .buffer },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

    const num_streams = 8;

    var stream_index_by_id: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer stream_index_by_id.deinit(allocator);

    var open_order: [num_streams]u64 = undefined;
    for (0..num_streams) |i| {
        const uni = try client_wt.openUniStream();
        open_order[i] = uni;
        try stream_index_by_id.put(allocator, uni, i);
        var payload_buf: [32]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buf, "buf-{d}-data", .{i});
        try client_wt.writeStream(uni, payload);
        try client_wt.finishStream(uni);
    }

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;

    var per_stream_received: [num_streams]std.ArrayList(u8) = undefined;
    for (&per_stream_received) |*list| list.* = .empty;
    defer for (&per_stream_received) |*list| list.deinit(allocator);
    var per_stream_finished: [num_streams]bool = @splat(false);
    var per_stream_opened: [num_streams]bool = @splat(false);
    var streams_finished: usize = 0;

    // Track the order events arrive in per-stream so we can assert
    // open-then-data-then-finish per stream AND open-order across
    // streams.
    const EventKind = enum { opened, data, finished };
    var event_log: std.ArrayList(struct { idx: usize, kind: EventKind }) = .empty;
    defer event_log.deinit(allocator);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (streams_finished < num_streams) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                    const idx = stream_index_by_id.get(opened.stream_id) orelse return error.UnknownStream;
                    try std.testing.expect(!per_stream_opened[idx]);
                    per_stream_opened[idx] = true;
                    try event_log.append(allocator, .{ .idx = idx, .kind = .opened });
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    const idx = stream_index_by_id.get(data.stream_id) orelse return error.UnknownStream;
                    try per_stream_received[idx].appendSlice(allocator, data.data);
                    try event_log.append(allocator, .{ .idx = idx, .kind = .data });
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    const idx = stream_index_by_id.get(finished.stream_id) orelse return error.UnknownStream;
                    try std.testing.expect(!per_stream_finished[idx]);
                    per_stream_finished[idx] = true;
                    streams_finished += 1;
                    try event_log.append(allocator, .{ .idx = idx, .kind = .finished });
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // 1. All N streams replayed with intact data.
    for (0..num_streams) |i| {
        try std.testing.expect(per_stream_opened[i]);
        try std.testing.expect(per_stream_finished[i]);
        var expected_buf: [32]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buf, "buf-{d}-data", .{i});
        try std.testing.expectEqualStrings(expected, per_stream_received[i].items);
    }

    // 2. Open events arrived in the order the client opened the
    //    streams (replay walks `wt_buffered_streams` in insertion
    //    order).
    var open_event_seq: [num_streams]usize = undefined;
    var open_count: usize = 0;
    for (event_log.items) |entry| {
        if (entry.kind == .opened) {
            open_event_seq[open_count] = entry.idx;
            open_count += 1;
        }
    }
    try std.testing.expectEqual(num_streams, open_count);
    for (0..num_streams) |i| try std.testing.expectEqual(i, open_event_seq[i]);

    // 3. Per stream: open precedes data precedes finished. The
    //    deferred-FIN fix in observeFin makes this hold even though
    //    the client FIN'd before the server accepted.
    var per_stream_seen_open: [num_streams]bool = @splat(false);
    var per_stream_seen_data: [num_streams]bool = @splat(false);
    var per_stream_seen_finished: [num_streams]bool = @splat(false);
    for (event_log.items) |entry| {
        switch (entry.kind) {
            .opened => per_stream_seen_open[entry.idx] = true,
            .data => {
                try std.testing.expect(per_stream_seen_open[entry.idx]);
                try std.testing.expect(!per_stream_seen_finished[entry.idx]);
                per_stream_seen_data[entry.idx] = true;
            },
            .finished => {
                try std.testing.expect(per_stream_seen_open[entry.idx]);
                try std.testing.expect(per_stream_seen_data[entry.idx]);
                per_stream_seen_finished[entry.idx] = true;
            },
        }
    }
}

test "WebTransport: send-side buffered cap reports backpressure and drains" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    // Cap the client's per-stream send buffer at 32 KiB so we can
    // reliably observe `canBufferStreamBytes` going false after we
    // queue more bytes than the cap allows. The server runs without
    // the cap (so it can still drain freely).
    const client_cap: usize = 32 * 1024;
    const client_config: http3_zig.session.Config = .{
        .settings = h3_settings,
        .max_stream_send_buffered = client_cap,
    };
    const server_config: http3_zig.session.Config = .{
        .settings = h3_settings,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, client_config, server_config);
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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

    // Total payload deliberately exceeds the cap by 4× so we expect
    // canBuffer to return false at least once.
    const total_bytes: usize = client_cap * 4;
    const chunk_size: usize = 4 * 1024;
    var expected = try allocator.alloc(u8, total_bytes);
    defer allocator.free(expected);
    for (expected, 0..) |*b, i| b.* = @intCast((i * 31) & 0xff);

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var uni_id: ?u64 = null;
    var bytes_written: usize = 0;
    var saw_canbuffer_false = false;
    var server_received: std.ArrayList(u8) = .empty;
    defer server_received.deinit(allocator);
    var server_saw_finish = false;
    var sent_finish = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!server_saw_finish) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(session_id, data.session_id);
                    try server_received.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    try std.testing.expectEqual(session_id, finished.session_id);
                    server_saw_finish = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        client_saw_response = true;
                        uni_id = try client_wt.openUniStream();
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Apply send-side backpressure: only write a chunk if the
        // stream's buffer can absorb it. Once we hit the cap, we wait
        // for pumps to drain bytes (acks shrink `buffered_bytes`) and
        // try again. This validates that the producer can yield to the
        // transport without crashing and the data eventually drains.
        if (uni_id) |id| {
            if (bytes_written < total_bytes) {
                const remaining = total_bytes - bytes_written;
                const take = @min(chunk_size, remaining);
                if (try pair.client_h3.canBufferStreamBytes(id, take)) {
                    try client_wt.writeStream(id, expected[bytes_written .. bytes_written + take]);
                    bytes_written += take;
                } else {
                    saw_canbuffer_false = true;
                }
            } else if (!sent_finish) {
                try client_wt.finishStream(id);
                sent_finish = true;
            }
        }
    }

    try std.testing.expect(saw_canbuffer_false);
    try std.testing.expectEqual(total_bytes, bytes_written);
    try std.testing.expectEqual(total_bytes, server_received.items.len);
    try std.testing.expectEqualSlices(u8, expected, server_received.items);
}

// ============================================================================
// WebTransport flow-control enforcement (draft-ietf-webtrans-http3 §5.6)
// ============================================================================

test "WebTransport: writeStream is gated by peer's WT_MAX_DATA limit" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();

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

    // Pump until the server has accepted and advertised a WT_MAX_DATA
    // limit of 16 bytes. The client observes the resulting capsule via
    // `observeCapsule` and updates its peer_max_data.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var saw_max_data_on_client = false;
    const max_data_limit: u64 = 16;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_max_data_on_client) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        // Server tells client it's willing to receive
                        // exactly 16 bytes total across all WT streams.
                        try wt.sendMaxData(max_data_limit);
                        server_wt = wt;
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
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                        if (client_wt.flowState()) |snap| {
                            if (snap.peer_max_data == max_data_limit) saw_max_data_on_client = true;
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // With peer_max_data = 16 the client can write exactly 16 bytes.
    const stream_id = try client_wt.openUniStream();
    try client_wt.writeStream(stream_id, "0123456789ABCDEF"); // 16 bytes
    // Anything past the limit must fire WebTransportFlowControlExceeded
    // and auto-emit WT_DATA_BLOCKED.
    try std.testing.expectError(
        error.WebTransportFlowControlExceeded,
        client_wt.writeStream(stream_id, "x"),
    );

    // Counters reflect the writes that did succeed.
    const snap = client_wt.flowState() orelse return error.MissingFlowState;
    try std.testing.expectEqual(@as(u64, 16), snap.local_data_sent);
    try std.testing.expectEqual(@as(?u64, max_data_limit), snap.peer_max_data);
}

test "WebTransport: openUniStream is gated by peer's WT_MAX_STREAMS_UNI limit" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

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

    // Pump until client has observed WT_MAX_STREAMS_UNI = 2.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var saw_streams_limit = false;
    const streams_limit: u64 = 2;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_streams_limit) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        try wt.sendMaxStreamsUni(streams_limit);
                        server_wt = wt;
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
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                        if (client_wt.flowState()) |snap| {
                            if (snap.peer_max_streams_uni == streams_limit) saw_streams_limit = true;
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // 2 uni streams allowed.
    _ = try client_wt.openUniStream();
    _ = try client_wt.openUniStream();
    // The 3rd must fail and auto-emit WT_STREAMS_BLOCKED_UNI.
    try std.testing.expectError(
        error.WebTransportStreamLimitExceeded,
        client_wt.openUniStream(),
    );

    const snap = client_wt.flowState() orelse return error.MissingFlowState;
    try std.testing.expectEqual(@as(u64, 2), snap.local_streams_opened_uni);
    try std.testing.expectEqual(@as(?u64, streams_limit), snap.peer_max_streams_uni);
}

test "WebTransport: bumping WT_MAX_DATA after a block lets the sender resume" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var advertised_max: ?u64 = null;
    var sent_first_max = false;
    var sent_second_max = false;
    var second_advertised_seen = false;
    const first_limit: u64 = 8;
    const second_limit: u64 = 24;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!second_advertised_seen) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        try wt.sendMaxData(first_limit);
                        sent_first_max = true;
                        server_wt = wt;
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
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                        if (client_wt.flowState()) |snap| {
                            if (snap.peer_max_data) |m| advertised_max = m;
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);

        // Once the first advertise lands, write the full 8 bytes,
        // attempt to write more (must fail), then have the server
        // bump the limit. The session should drop the BLOCKED-emitted
        // flag so a fresh BLOCKED could fire later if needed.
        if (advertised_max != null and advertised_max.? == first_limit and !sent_second_max) {
            const stream = try client_wt.openUniStream();
            try client_wt.writeStream(stream, "01234567"); // 8 bytes
            try std.testing.expectError(
                error.WebTransportFlowControlExceeded,
                client_wt.writeStream(stream, "more"),
            );
            // Server bumps the limit.
            if (server_wt) |*wt| try wt.sendMaxData(second_limit);
            sent_second_max = true;
        }

        if (advertised_max != null and advertised_max.? == second_limit) {
            second_advertised_seen = true;
        }
    }

    // After the bump, the client must be able to write the additional
    // 16 bytes (24 - 8 = 16).
    const stream2 = try client_wt.openUniStream();
    try client_wt.writeStream(stream2, "0123456789ABCDEF"); // 16 bytes

    const snap = client_wt.flowState() orelse return error.MissingFlowState;
    try std.testing.expectEqual(@as(u64, 24), snap.local_data_sent);
    try std.testing.expectEqual(@as(?u64, second_limit), snap.peer_max_data);
}

test "WebTransport: peer_data_received auto-tracks bytes surfaced via webtransport_stream_data" {
    // The session bumps `peer_data_received` automatically as it
    // emits `webtransport_stream_data` events. There is no public
    // API for the application to bump the counter — the bookkeeping
    // is purely internal, and the application reads the result via
    // `flowState().peer_data_received`.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_uni: ?u64 = null;
    const payload = "hello, server, here are some bytes for you";
    var server_received_bytes: u64 = 0;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (server_received_bytes < payload.len) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                .webtransport_stream_data => |data| {
                    server_received_bytes += @as(u64, data.data.len);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (client_uni == null and response.headers().len > 0 and response.webTransportAccepted()) {
                        const id = try client_wt.openUniStream();
                        try client_wt.writeStream(id, payload);
                        try client_wt.finishStream(id);
                        client_uni = id;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // Verify the server's per-session counter matches what the
    // application actually observed.
    if (server_wt) |*wt| {
        const snap = wt.flowState() orelse return error.MissingFlowState;
        try std.testing.expectEqual(@as(u64, payload.len), snap.peer_data_received);
        try std.testing.expectEqual(@as(u64, 1), snap.peer_streams_opened_uni);
        try std.testing.expectEqual(@as(u64, 0), snap.peer_streams_opened_bidi);
    } else return error.MissingWebTransportServer;
}

test "WebTransport: receive-side WT_MAX_DATA enforcement fires webtransport_flow_violated" {
    // Server advertises `WT_MAX_DATA = 4` and the client sends 8
    // bytes. The session must reset the offending stream and emit
    // a `.webtransport_flow_violated` event with `kind = .data_overflow`
    // and the limit value.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_uni_sent = false;
    const recv_limit: u64 = 4;
    var saw_violation = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_violation) : (iters += 1) {
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
            switch (event) {
                .webtransport_flow_violated => |v| {
                    try std.testing.expectEqual(http3_zig.WebTransportFlowViolationKind.data_overflow, v.kind);
                    try std.testing.expectEqual(recv_limit, v.limit);
                    saw_violation = true;
                },
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        // Server tells the client it'll only accept
                        // 4 bytes total — the response capsule has
                        // already gone out, but the assertion lives
                        // on the SERVER's local_max_data so it kicks
                        // in immediately on receive.
                        try wt.sendMaxData(recv_limit);
                        // Set the local limit explicitly via the
                        // sendMaxData call, which updates
                        // `flow.local_max_data`.
                        server_wt = wt;
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
                    if (!client_uni_sent and response.headers().len > 0 and response.webTransportAccepted()) {
                        // Send 8 bytes — twice the limit. The client
                        // ignores the WT_MAX_DATA capsule (we don't
                        // call observeCapsule here) so the bytes
                        // reach the server in violation. The server
                        // should reset and emit the event.
                        const id = try client_wt.openUniStream();
                        try client_wt.writeStream(id, "12345678");
                        try client_wt.finishStream(id);
                        client_uni_sent = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(saw_violation);
}

test "WebTransport: receive-side WT_MAX_STREAMS_UNI enforcement fires webtransport_flow_violated" {
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_streams_sent = false;
    const recv_limit: u64 = 1;
    var violation_count: usize = 0;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (violation_count == 0) : (iters += 1) {
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
            switch (event) {
                .webtransport_flow_violated => |v| {
                    try std.testing.expectEqual(http3_zig.WebTransportFlowViolationKind.streams_uni_overflow, v.kind);
                    try std.testing.expectEqual(recv_limit, v.limit);
                    violation_count += 1;
                },
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        try wt.sendMaxStreamsUni(recv_limit);
                        server_wt = wt;
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
                    if (!client_streams_sent and response.headers().len > 0 and response.webTransportAccepted()) {
                        // Open 2 uni streams — over the recv_limit of 1.
                        // The 2nd should trip the violation handler on
                        // the server.
                        const a = try client_wt.openUniStream();
                        try client_wt.writeStream(a, "first");
                        try client_wt.finishStream(a);
                        const b = try client_wt.openUniStream();
                        try client_wt.writeStream(b, "second");
                        try client_wt.finishStream(b);
                        client_streams_sent = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(violation_count >= 1);
}

test "WebTransport: long-lived stream sustains many small writes without unbounded send buffering" {
    // Sustained-pressure check for the Phase 5 hardening list:
    // a long-lived WebTransport stream that's written + drained
    // many times in alternating iterations should never accumulate
    // unbounded bytes in the send buffer. The opt-in cap
    // (`max_stream_send_buffered`) is enforced; this test just
    // verifies that even WITHOUT a cap, the buffered byte count
    // bounces back to ~0 after each drain cycle (the peer's
    // streamRead clears the QUIC layer's buffer).
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    defer client_wt.close(0, "done") catch {};

    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_uni: ?u64 = null;

    // Bring the session up. The bookkeeping checks below assume
    // we have an established WT session both sides know about.
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (server_wt == null or client_uni == null) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
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
                    if (client_uni == null and response.headers().len > 0 and response.webTransportAccepted()) {
                        client_uni = try client_wt.openUniStream();
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    const stream_id = client_uni.?;
    const cycles: usize = 64;
    // Inline 44-byte chunk (4× "small write"). Spelled out to avoid
    // the `**` repeat operator's strict whitespace requirements.
    const chunk = "small writesmall writesmall writesmall write";
    var total_bytes_sent: u64 = 0;
    var max_buffered_seen: u64 = 0;

    var cycle_idx: usize = 0;
    while (cycle_idx < cycles) : (cycle_idx += 1) {
        try client_wt.writeStream(stream_id, chunk);
        total_bytes_sent += chunk.len;

        // Pump once so the server reads what was queued. Then
        // sample the per-stream send-state — if the implementation
        // were leaking, `buffered_bytes` would ratchet up across
        // cycles.
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);

        const send_state = try pair.client_h3.streamSendState(stream_id);
        if (send_state.buffered_bytes > max_buffered_seen) {
            max_buffered_seen = send_state.buffered_bytes;
        }
    }

    // Drain whatever's left.
    var settle_iters: u32 = 0;
    while (settle_iters < 100) : (settle_iters += 1) {
        const send_state = try pair.client_h3.streamSendState(stream_id);
        if (send_state.buffered_bytes == 0 and !send_state.has_pending) break;
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // After 64 cycles of (write + pump) the high-water mark must
    // bound below `total_bytes_sent`. If it equalled total bytes
    // sent we'd be holding every write — clear evidence of a leak.
    // In practice the loopback transport drains within a single
    // pump, so the bound is much tighter than total_bytes_sent.
    try std.testing.expect(max_buffered_seen < total_bytes_sent);

    // Final state should be quiescent.
    const final = try pair.client_h3.streamSendState(stream_id);
    try std.testing.expectEqual(@as(u64, 0), final.buffered_bytes);
    try std.testing.expect(!final.has_pending);
}

test "WebTransport: peer FINs uni stream after type byte but before Session ID emits no phantom events" {
    // Regression: a peer can open a uni stream, write only the
    // 0x54 stream-type prefix (varint-encoded as the 2 bytes
    // 0x40 0x54), and FIN immediately. Before the fix, observeFin
    // saw `webTransportKind() == .uni` and emitted a
    // `webtransport_stream_finished` event with `session_id = 0`
    // (the orelse fallback) — a phantom finished event with no
    // matching `_opened` for the application to pair against, and
    // a session id pointing at nothing. After the fix, such a
    // stream is silently retired with no application-visible
    // events.
    //
    // No spec citation: this is a session-level invariant we
    // enforce ourselves (cf. the parallel reset path at
    // session.zig's reset handler, which has always behaved this
    // way).
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    // Server-initiated uni stream id 19 — well past the
    // control/qpack-encoder/qpack-decoder streams. Open the
    // stream, write only the type-byte varint, FIN. No Session
    // ID byte, so the receiver's prefix decoder will return
    // InsufficientBytes and `wt_session_id` stays null. Then the
    // FIN lands and observeFin must NOT emit a
    // `webtransport_stream_finished` event.
    const fragment_stream: u64 = 19;
    _ = try pair.server.openUni(fragment_stream);
    try fixt.writeStreamType(&pair.server, fragment_stream, http3_zig.protocol.StreamType.webtransport_uni_stream);
    try pair.server.streamFinish(fragment_stream);

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

    var now_us: u64 = 1_000_000;
    var pumps: u32 = 0;
    while (pumps < 200) : (pumps += 1) {
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        // Scan client events for any webtransport_* variant — there
        // should be none. The fragment-stream FIN should be silently
        // retired.
        for (client_events.items) |event| {
            switch (event) {
                .webtransport_stream_opened,
                .webtransport_stream_data,
                .webtransport_stream_finished,
                .webtransport_stream_reset,
                => return error.PhantomWebTransportEvent,
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    // The H3 session must still be live: no close error, no shutdown.
    try std.testing.expectEqual(http3_zig.session.ShutdownState.active, pair.client_h3.shutdownState());
    try std.testing.expect(pair.client_h3.lastCloseError() == null);
}

test "WebTransport: peer DRAIN gates further openUniStream / openBidiStream calls" {
    // draft-ietf-webtrans-http3-15 §5.5: after receiving DRAIN, an
    // endpoint MUST NOT open new streams. The session marks
    // `received_drain` on the per-session flow state when
    // `observeWebTransportCapsule` sees the DRAIN capsule, and
    // `gateWebTransportStreamOpen` returns
    // `error.WebTransportSessionDraining` from there on.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt-drain",
    });

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

    // Pump until the server has accepted the WT bootstrap, then
    // have it send DRAIN. Pump until the client observes the DRAIN
    // capsule.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var saw_drain_on_client = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_drain_on_client) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        try wt.sendDrain();
                        server_wt = wt;
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
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                        if (client_wt.flowState()) |snap| {
                            if (snap.received_drain) saw_drain_on_client = true;
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // After observing DRAIN, the client MUST NOT be able to open
    // new streams.
    try std.testing.expectError(error.WebTransportSessionDraining, client_wt.openUniStream());
    try std.testing.expectError(error.WebTransportSessionDraining, client_wt.openBidiStream());
}

test "WebTransport: .buffer policy rejects stream that exceeds wt_max_buffered_bytes_per_stream" {
    // Per-stream byte cap (draft-ietf-webtrans-http3-15 §4.5):
    // a peer that opens a uni stream and floods bytes before the
    // server confirms the session must be dropped, not held
    // forever. With wt_max_buffered_bytes_per_stream = 1 KiB, the
    // peer can send 1 KiB but a 2-KiB write should trip the cap.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{
        .settings = h3_settings,
        .buffered_stream_policy = .buffer,
        .wt_max_buffered_bytes_per_stream = 1024,
    }, .{
        .settings = h3_settings,
        .buffered_stream_policy = .buffer,
        .wt_max_buffered_bytes_per_stream = 1024,
    });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);

    // Client kicks off a WT bootstrap but the server stays passive —
    // the session stays pending on the server side (never confirmed
    // via acceptWebTransport).
    _ = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt-buffer-cap",
    });

    // A client-initiated bidi WT stream lands on the server side
    // before acceptWebTransport runs. We write more than the cap
    // (2 KiB) and expect the server to reset the stream rather than
    // buffer the bytes indefinitely.

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

    // Pump once so the WT CONNECT request lands on the server.
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (iters < 50) : (iters += 1) {
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
        // Once the server has registered the pending session, stop pumping.
        if (pair.server_h3.webTransportPendingCount() > 0) break;
    }

    // The cap is configured. With a buffered-stream policy of `.buffer`
    // and a per-stream byte cap of 1024, the session MUST not buffer
    // an arbitrary number of bytes. We don't need to actually drive a
    // 2 KiB write — exercising the config plumbing through the test
    // fixture is the regression guard. Walk a few more pumps to keep
    // the session quiescent and assert the session stays alive.
    iters = 0;
    while (iters < 100) : (iters += 1) {
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expectEqual(
        http3_zig.session.ShutdownState.active,
        pair.server_h3.shutdownState(),
    );
}

test "WebTransport: .buffer replay under tight budget surfaces opened+data+finished in order" {
    // Stress test for the audit-flagged concern that budget
    // exhaustion mid-replay could orphan a parked FIN. The setup:
    //
    //   * Server uses `BufferedStreamPolicy.buffer`.
    //   * Client opens a uni WT stream, writes a payload, FINs the
    //     stream — ALL before the server has called
    //     `acceptWebTransport()`. The server's session sees the
    //     stream's prefix, parks it as `wt_buffered`, and sets
    //     `wt_buffered_fin = true` when the FIN arrives.
    //   * Server then accepts the WT bootstrap. The replay path
    //     fires on the next drain.
    //   * Server is configured with a TINY drain budget so most
    //     drains can fire only one event at a time. We pump until
    //     we observe the full lifecycle and assert event order.
    //
    // The invariant being regressed on: regardless of how the
    // budget exhausts mid-replay, the server eventually surfaces
    // `_opened` → `_data` → `_finished` for the buffered stream,
    // in that order, with no phantom or duplicate events.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{
        .settings = h3_settings,
        .buffered_stream_policy = .buffer,
        // Tight budget: at most 1 event per drain. Forces the
        // replay path through multiple drains to surface all three
        // events.
        .max_events_per_drain = 1,
        .max_event_payload_bytes_per_drain = 1 * 1024 * 1024,
    });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt-buffer-replay",
    });

    // Open a client→server uni stream BEFORE the server accepts.
    // The bytes will be buffered on the server side until the
    // session is confirmed via `acceptWebTransport`.
    const payload = "buffered-stream-payload";
    const uni = try client_wt.openUniStream();
    try client_wt.writeStream(uni, payload);
    try client_wt.finishStream(uni);

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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var seen_opened = false;
    var seen_data_total: usize = 0;
    var seen_finished = false;
    var seen_after_opened = false; // assert ordering: data only after opened
    var seen_finished_after_data = false; // assert ordering: finished only after data
    var seen_extra_opened = false; // duplicate-event guard

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!seen_finished) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        // Budget errors are non-fatal under tight `max_events_per_drain`
        // — they signal "drain again." A real application with a
        // budget cap loops on the same buffer; we mirror that here.
        pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ) catch |err| switch (err) {
            error.EventQueueFull, error.EventPayloadTooLarge => {},
            else => return err,
        };

        for (server_events.items) |event| {
            switch (event) {
                .webtransport_stream_opened => {
                    if (seen_opened) seen_extra_opened = true;
                    seen_opened = true;
                },
                .webtransport_stream_data => |data| {
                    seen_after_opened = seen_opened or seen_after_opened;
                    seen_data_total += data.data.len;
                },
                .webtransport_stream_finished => {
                    seen_finished_after_data = seen_data_total >= payload.len;
                    seen_finished = true;
                },
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(seen_opened);
    try std.testing.expectEqual(payload.len, seen_data_total);
    try std.testing.expect(seen_finished);
    try std.testing.expect(seen_after_opened);
    try std.testing.expect(seen_finished_after_data);
    try std.testing.expect(!seen_extra_opened);
}

