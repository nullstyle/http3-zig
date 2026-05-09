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

test "session exposes send buffer state and enforces configured cap" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .max_stream_send_buffered = 256 },
        .{},
    );
    defer pair.deinit();

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/buffered",
    });

    const before = try writer.sendState();
    try std.testing.expectEqual(writer.stream_id, before.stream_id);
    try std.testing.expect(before.written_bytes > 0);
    try std.testing.expectEqual(@as(u64, 0), before.acked_bytes);
    try std.testing.expectEqual(before.written_bytes, before.buffered_bytes);
    try std.testing.expect(before.has_pending);
    try std.testing.expect(!before.overLimit(256));

    var body: [512]u8 = @splat('x');
    try std.testing.expect(!try writer.canWrite(body.len));
    try std.testing.expectError(error.SendBufferFull, writer.write(&body));

    const after = try writer.sendState();
    try std.testing.expectEqual(before.written_bytes, after.written_bytes);
    try std.testing.expectEqual(before.buffered_bytes, after.buffered_bytes);
}

test "session enforces drain event count budget" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .max_events_per_drain = 0 },
        .{},
    );
    defer pair.deinit();

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
    try std.testing.expectError(
        error.EventQueueFull,
        pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ),
    );
    try std.testing.expect(pair.client_h3.shutdownState() != .closed);
}

test "session enforces drain event payload budget" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{},
        .{
            .settings = .{ .h3_datagram = true },
            .max_event_payload_size = 1,
        },
    );
    defer pair.deinit();

    try sendRawH3Datagram(&pair.client, 0, "xx");

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

    var saw_budget_error = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_budget_error) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ) catch |err| {
            try std.testing.expectEqual(error.EventPayloadTooLarge, err);
            saw_budget_error = true;
        };
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    try std.testing.expect(pair.server_h3.shutdownState() != .closed);
}
test "production session config supports ordinary request flow" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        http3_zig.SessionConfig.production(.{}),
        http3_zig.SessionConfig.production(.{}),
    );
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    var h3_client = http3_zig.Client.init(&pair.client_h3);
    const stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    try std.testing.expectEqual(@as(u64, 0), stream_id);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), pair.client_h3.peer_settings.?.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 4096), pair.client_h3.peer_settings.?.qpack_max_table_capacity);
}

test "production session config advertises limits and enforces caps" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        http3_zig.SessionConfig.production(.{}),
        http3_zig.SessionConfig.production(.{
            .max_field_lines = 3,
        }),
    );
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), pair.client_h3.peer_settings.?.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 4096), pair.client_h3.peer_settings.?.qpack_max_table_capacity);

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &fields);

    try expectPairH3Error(allocator, &pair, error.TooManyFieldLines);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.message_error);
}

test "session caps concurrent peer-opened streams via max_concurrent_peer_streams" {
    // Defense-in-depth: a peer that opens streams without finishing
    // them should hit Config.max_concurrent_peer_streams and be
    // rejected with STOP_SENDING(H3_REQUEST_REJECTED), rather than
    // growing the session's `streams` map unboundedly.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .max_concurrent_peer_streams = 4 },
        .{ .max_concurrent_peer_streams = 4 },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);

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

    // Open many request streams without finishing any. The cap on the
    // server side should reject the late ones via STOP_SENDING.
    var opened: u32 = 0;
    while (opened < 16) : (opened += 1) {
        const req = h3_client.startRequest(allocator, .{
            .authority = "localhost",
            .path = "/abuse",
        }) catch break;
        _ = req;
    }
    try std.testing.expect(opened > 0);

    // Pump: the server tracks each opened stream until it hits its cap,
    // then rejects further ones. We just want to confirm the count
    // doesn't grow unboundedly.
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (iters < 5000) : (iters += 1) {
        try fixt.pumpH3(
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
        if (pair.server_h3.streams.count() >= 4) break;
    }

    // Server's tracked stream map MUST NOT exceed the cap. Without
    // enforcement, count() would equal `opened` (plus any control
    // streams). With enforcement, count is capped at 4.
    try std.testing.expect(pair.server_h3.streams.count() <= 4);

    // Cap rejection is per-stream, not a connection-killer.
    try std.testing.expectEqual(
        http3_zig.session.ShutdownState.active,
        pair.server_h3.shutdownState(),
    );
    try std.testing.expectEqual(
        http3_zig.session.ShutdownState.active,
        pair.client_h3.shutdownState(),
    );
}
