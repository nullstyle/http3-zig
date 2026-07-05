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

test "session surfaces quic_zig connection close events" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();

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

    server_h3.close(http3_zig.protocol.ErrorCode.no_error, "server shutdown");
    try server_h3.drain(&server_events);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, server_h3.shutdownState());
    try std.testing.expectEqual(@as(usize, 1), server_events.items.len);
    switch (server_events.items[0]) {
        .connection_closed => |closed| {
            try std.testing.expectEqual(quic_zig.CloseSource.local, closed.source);
            try std.testing.expectEqual(quic_zig.CloseErrorSpace.application, closed.error_space);
            try std.testing.expectEqual(http3_zig.protocol.ErrorCode.no_error, closed.error_code);
            try std.testing.expectEqualStrings("server shutdown", closed.reason);
            try std.testing.expectEqualStrings("H3_NO_ERROR", closed.application.?.name);
        },
        else => return error.TestExpectedEqual,
    }
    clearSessionEvents(allocator, &server_events);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    var client_saw_close = false;
    while (!client_saw_close) : (iters += 1) {
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
            switch (event) {
                .connection_closed => |closed| {
                    client_saw_close = true;
                    try std.testing.expectEqual(quic_zig.CloseSource.peer, closed.source);
                    try std.testing.expectEqual(quic_zig.CloseErrorSpace.application, closed.error_space);
                    try std.testing.expectEqual(http3_zig.protocol.ErrorCode.no_error, closed.error_code);
                    try std.testing.expectEqualStrings("server shutdown", closed.reason);
                    try std.testing.expectEqualStrings("H3_NO_ERROR", closed.application.?.name);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, client_h3.shutdownState());
}

test "client send-side reset is surfaced as server request reset" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();
    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);

    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/reset-me",
    });
    const request_stream_id = writer.stream_id;
    try writer.write("partial body");

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
    while (server.stream(request_stream_id) == null) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.reset(http3_zig.protocol.ErrorCode.request_cancelled);

    iters = 0;
    var server_saw_reset = false;
    while (!server_saw_reset) : (iters += 1) {
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

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .reset => |reset| {
                    server_saw_reset = true;
                    try std.testing.expectEqual(request_stream_id, reset.stream_id);
                    try std.testing.expectEqual(http3_zig.protocol.ErrorCode.request_cancelled, reset.error_code);
                    try std.testing.expect(reset.final_size > 0);
                    const info = reset.errorInfo();
                    try std.testing.expectEqual(http3_zig.ErrorSource.peer, info.source);
                    try std.testing.expectEqual(http3_zig.ErrorCategory.request, info.application.category);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}

test "peer RESET reclaims the half-closed stream when reclaim_peer_reset_streams is set" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    // The reclaim is a receive-side reaction to the peer's RESET, so it is
    // the *server's* config that governs whether its lingering StreamState
    // is released.
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{ .reclaim_peer_reset_streams = true });
    defer server_h3.deinit();
    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);

    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/reset-me",
    });
    const request_stream_id = writer.stream_id;
    // Body without a FIN — the server never responds, so absent the reclaim
    // the stream stays half-closed (recv terminal after the RESET, local send
    // side never closed) and lingers in `streams`.
    try writer.write("partial body");

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
    while (!server_h3.streams.contains(request_stream_id)) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(&client, &server, &client_h3, &server_h3, &client_events, &server_events, &now_us);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.reset(http3_zig.protocol.ErrorCode.request_cancelled);

    iters = 0;
    var server_saw_reset = false;
    while (!server_saw_reset) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(&client, &server, &client_h3, &server_h3, &client_events, &server_events, &now_us);
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .reset => |reset| {
                    try std.testing.expectEqual(request_stream_id, reset.stream_id);
                    server_saw_reset = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // The reset event was surfaced and the per-drain GC ran in the same
    // drain, so the StreamState is already gone.
    try std.testing.expect(!server_h3.streams.contains(request_stream_id));
}

test "peer RESET leaves the stream tracked when reclaim_peer_reset_streams is off (default)" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();
    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);

    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/reset-me",
    });
    const request_stream_id = writer.stream_id;
    try writer.write("partial body");

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
    while (!server_h3.streams.contains(request_stream_id)) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(&client, &server, &client_h3, &server_h3, &client_events, &server_events, &now_us);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.reset(http3_zig.protocol.ErrorCode.request_cancelled);

    iters = 0;
    var server_saw_reset = false;
    while (!server_saw_reset) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(&client, &server, &client_h3, &server_h3, &client_events, &server_events, &now_us);
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .reset => server_saw_reset = true,
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Default behavior: the server never closed its send side, so the
    // half-closed StreamState is still tracked (bounded only by
    // `max_concurrent_peer_streams`), not reclaimed.
    try std.testing.expect(server_h3.streams.contains(request_stream_id));
}

test "server send-side reset is surfaced as client response reset" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: quic_zig.Connection = undefined;
    var server: quic_zig.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();
    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);
    var request_tracker = http3_zig.RequestTracker.init(allocator);
    defer request_tracker.deinit();

    const request = try h3_client.request(allocator, .{
        .method = "GET",
        .authority = "localhost",
        .path = "/server-reset",
    });

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
    var response_reset_sent = false;
    var client_saw_reset = false;
    while (!client_saw_reset) : (iters += 1) {
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

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            const request_state = (try request_tracker.observe(request_event)) orelse continue;
            if (!response_reset_sent and request_state.headers != null and request_state.complete) {
                var response_writer = try h3_server.startResponse(allocator, request.stream_id, .{
                    .status = "503",
                });
                try response_writer.write("not today");
                try response_writer.reset(http3_zig.protocol.ErrorCode.internal_error);
                response_reset_sent = true;
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .reset => |reset| {
                    client_saw_reset = true;
                    try std.testing.expectEqual(request.stream_id, reset.stream_id);
                    try std.testing.expectEqual(http3_zig.protocol.ErrorCode.internal_error, reset.error_code);
                    try std.testing.expect(reset.final_size > 0);
                    const info = reset.errorInfo();
                    try std.testing.expectEqual(http3_zig.ErrorSource.peer, info.source);
                    try std.testing.expectEqual(http3_zig.ErrorCategory.internal, info.application.category);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(response_reset_sent);
}
