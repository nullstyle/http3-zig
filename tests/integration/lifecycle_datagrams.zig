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

test "session exchanges HTTP/3 datagrams over quic_zig datagram frames" {
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

    const h3_settings: http3_zig.Settings = .{ .h3_datagram = true };
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
    var h3_server = http3_zig.Server.init(&server_h3);

    try std.testing.expectError(
        http3_zig.session.Error.MissingSettings,
        h3_client.sendDatagram(0, "too-soon"),
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
    var server_saw_settings = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_settings or !server_saw_settings) : (iters += 1) {
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
                    try std.testing.expect(settings.h3_datagram);
                    client_saw_settings = true;
                },
                else => {},
            }
        }
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    try std.testing.expect(settings.h3_datagram);
                    server_saw_settings = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    // Classic CONNECT request: per RFC 9114 §4.4 ¶3, `:scheme`
    // and `:path` are omitted on the wire. `buildRequestFields`
    // auto-detects this when `:method = "CONNECT"` and no
    // `:protocol` is set; we leave `path` at its default since
    // the builder won't emit it.
    var writer = try h3_client.startRequest(allocator, .{
        .method = "CONNECT",
        .authority = "localhost",
    });
    const stream_id = writer.stream_id;
    const tracked_client_datagram_id = try writer.datagramTracked("from-client");

    var server_saw_datagram = false;
    var client_saw_datagram_ack = false;
    iters = 0;
    while (!server_saw_datagram or !client_saw_datagram_ack) : (iters += 1) {
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
                .datagram => |datagram| {
                    server_saw_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    try std.testing.expectEqualStrings("from-client", datagram.payload);
                    try std.testing.expect(!datagram.arrived_in_early_data);
                },
                else => {},
            }
        }
        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .datagram_acked => |acked| {
                    client_saw_datagram_ack = true;
                    try std.testing.expectEqual(tracked_client_datagram_id, acked.id);
                    try std.testing.expect(acked.len >= "from-client".len);
                    try std.testing.expectEqual(@as(u32, 0), acked.path_id);
                    try std.testing.expect(!acked.arrived_in_early_data);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.datagramWithContext(7, "ctx-client");

    var server_saw_context_datagram = false;
    iters = 0;
    while (!server_saw_context_datagram) : (iters += 1) {
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
                .datagram => |datagram| {
                    server_saw_context_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    const context = try datagram.context();
                    try std.testing.expectEqual(@as(u64, 7), context.context_id);
                    try std.testing.expectEqualStrings("ctx-client", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const tracked_server_datagram_id = try h3_server.sendDatagramTracked(stream_id, "from-server");

    var client_saw_datagram = false;
    var server_saw_datagram_ack = false;
    iters = 0;
    while (!client_saw_datagram or !server_saw_datagram_ack) : (iters += 1) {
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
                .datagram => |datagram| {
                    client_saw_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    try std.testing.expectEqualStrings("from-server", datagram.payload);
                    try std.testing.expect(!datagram.arrived_in_early_data);
                },
                else => {},
            }
        }
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .datagram_acked => |acked| {
                    server_saw_datagram_ack = true;
                    try std.testing.expectEqual(tracked_server_datagram_id, acked.id);
                    try std.testing.expect(acked.len >= "from-server".len);
                    try std.testing.expectEqual(@as(u32, 0), acked.path_id);
                    try std.testing.expect(!acked.arrived_in_early_data);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try h3_server.sendDatagramWithContext(stream_id, 9, "ctx-server");

    var client_saw_context_datagram = false;
    iters = 0;
    while (!client_saw_context_datagram) : (iters += 1) {
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
                .datagram => |datagram| {
                    client_saw_context_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    const context = try datagram.context();
                    try std.testing.expectEqual(@as(u64, 9), context.context_id);
                    try std.testing.expectEqualStrings("ctx-server", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try writer.datagramContextCapsule(11, "capsule-client");

    var server_saw_datagram_capsule = false;
    iters = 0;
    while (!server_saw_datagram_capsule) : (iters += 1) {
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
                .data => |data| {
                    server_saw_datagram_capsule = true;
                    const decoded_capsule = try data.capsule();
                    try std.testing.expect(decoded_capsule.capsule.isDatagram());
                    const context = try http3_zig.datagram.decodeContextPayload(decoded_capsule.capsule.value);
                    try std.testing.expectEqual(@as(u64, 11), context.context_id);
                    try std.testing.expectEqualStrings("capsule-client", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const capsule_headers = [_]http3_zig.FieldLine{
        .{ .name = "capsule-protocol", .value = "?1" },
    };
    var response_writer = try h3_server.startResponse(allocator, stream_id, .{
        .status = "200",
        .headers = &capsule_headers,
    });
    try response_writer.datagramContextCapsule(13, "capsule-server");

    var client_saw_datagram_capsule = false;
    iters = 0;
    while (!client_saw_datagram_capsule) : (iters += 1) {
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
                .data => |data| {
                    client_saw_datagram_capsule = true;
                    const decoded_capsule = try data.capsule();
                    try std.testing.expect(decoded_capsule.capsule.isDatagram());
                    const context = try http3_zig.datagram.decodeContextPayload(decoded_capsule.capsule.value);
                    try std.testing.expectEqual(@as(u64, 13), context.context_id);
                    try std.testing.expectEqualStrings("capsule-server", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try std.testing.expectError(
        error.InvalidDatagramStream,
        h3_client.sendDatagram(stream_id + 1, "bad stream"),
    );
}
