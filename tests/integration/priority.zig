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

test "priority field helpers surface request and response priorities" {
    var request_headers = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=0, i" },
    };
    var request_state = http3_zig.RequestState{
        .stream_id = 0,
        .headers = &request_headers,
    };
    const request_priority = (try request_state.reader().priority()).?;
    try std.testing.expectEqual(@as(u3, 0), request_priority.urgency);
    try std.testing.expect(request_priority.incremental);

    var response_headers = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "Priority", .value = "u=6" },
    };
    var response_state = http3_zig.ResponseState{
        .stream_id = 0,
        .headers = &response_headers,
    };
    const response_priority = (try response_state.reader().priority()).?;
    try std.testing.expectEqual(@as(u3, 6), response_priority.urgency);
    try std.testing.expect(!response_priority.incremental);
}

test "client PRIORITY_UPDATE for request reaches server state" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/priority",
    });
    const request_stream_id = request.stream_id;
    try request.updatePriority(.{ .urgency = 1, .incremental = true });

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

    var saw_priority = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_priority) : (iters += 1) {
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
                .priority_update => |update| {
                    saw_priority = true;
                    switch (update.target) {
                        .request_stream => |stream_id| try std.testing.expectEqual(request_stream_id, stream_id),
                        else => return error.TestExpectedEqual,
                    }
                    try std.testing.expectEqual(@as(u3, 1), update.priority.urgency);
                    try std.testing.expect(update.priority.incremental);
                    try std.testing.expectEqualStrings("u=1, i", update.priority_field_value);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const stored = h3_server.priorityForRequest(request_stream_id).?;
    try std.testing.expectEqual(@as(u3, 1), stored.urgency);
    try std.testing.expect(stored.incremental);
    try std.testing.expectEqual(@as(u64, 1), h3_client.metrics().priority_updates_sent);
    try std.testing.expectEqual(@as(u64, 1), h3_server.metrics().priority_updates_received);

    // The server also propagated the RFC 9218 hint to quic-zig's send
    // scheduler (0.6.0), so its response bytes on this stream schedule by
    // urgency — the transport side of the co-design.
    const quic_priority = pair.server.streamPriority(request_stream_id).?;
    try std.testing.expectEqual(@as(u3, 1), quic_priority.urgency);
    try std.testing.expect(quic_priority.incremental);
}

test "server reclaims a request priority hint when the stream is reaped" {
    // The RFC 9218 priority cache (`request_priorities`) is keyed by stream
    // id. Without reclamation it grows once per request and never shrinks —
    // a slow leak that the `max_tracked_priorities` cap bounds but never
    // releases. `gcClosedStreams` must drop the hint when the stream reaps.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/reclaim",
    });
    const request_stream_id = request.stream_id;
    try request.updatePriority(.{ .urgency = 2, .incremental = false });
    try request.finish();

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

    // Drive the full request/response so the stream fully closes on both
    // ends, then keep pumping until the server reaps it. `respond` FINs the
    // response; the client's FIN was already sent. Reclamation is observed
    // via `priorityForRequest` returning null once the stream is gone.
    var saw_priority = false;
    var response_sent = false;
    var reclaimed = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!reclaimed) : (iters += 1) {
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
                .request_complete => |incoming| {
                    if (!response_sent and incoming.stream_id == request_stream_id) {
                        _ = try h3_server.respond(allocator, incoming.stream_id, .{
                            .status = "200",
                            .body = "reclaimed\n",
                        });
                        response_sent = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);

        // The hint must be recorded while the stream is still live, and gone
        // once it reaps — proving reclamation, not that it was never stored.
        if (h3_server.priorityForRequest(request_stream_id) != null) {
            saw_priority = true;
        } else if (saw_priority and response_sent) {
            reclaimed = true;
        }
    }

    try std.testing.expect(saw_priority);
    try std.testing.expect(h3_server.priorityForRequest(request_stream_id) == null);
    try std.testing.expectEqual(@as(usize, 0), pair.server_h3.request_priorities.count());
    // Reclamation rides the stream reap, so the stream itself is gone too.
    try std.testing.expect(!pair.server_h3.streams.contains(request_stream_id));
}

test "client PRIORITY_UPDATE for push reaches server state" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/priority.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
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

    var sent_update = false;
    var saw_priority = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_priority) : (iters += 1) {
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

        if (!sent_update) {
            for (client_events.items) |event| {
                const response_event = h3_client.classify(event) orelse continue;
                switch (response_event) {
                    .push_promise => |promise| {
                        try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                        try h3_client.sendPriorityUpdateForPush(0, .{ .urgency = 0 });
                        sent_update = true;
                    },
                    else => {},
                }
            }
        }

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .priority_update => |update| {
                    saw_priority = true;
                    switch (update.target) {
                        .push => |push_id| try std.testing.expectEqual(@as(u64, 0), push_id),
                        else => return error.TestExpectedEqual,
                    }
                    try std.testing.expectEqual(@as(u3, 0), update.priority.urgency);
                    try std.testing.expect(!update.priority.incremental);
                    try std.testing.expectEqualStrings("u=0", update.priority_field_value);
                },
                else => {},
            }
        }

        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const stored = h3_server.priorityForPush(0).?;
    try std.testing.expectEqual(@as(u3, 0), stored.urgency);
    try std.testing.expect(!stored.incremental);
}

test "PRIORITY_UPDATE rejects invalid request stream targets" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 2,
            .priority_field_value = "u=1",
        },
    });

    try expectPairH3Error(allocator, &pair, error.InvalidPriorityTarget);
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.id_error);
}

test "PRIORITY_UPDATE rejects server senders" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=1",
        },
    });

    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try expectLastCloseCode(&pair.client_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
}

test "PRIORITY_UPDATE rejects structurally malformed Priority field values" {
    // RFC 9218 §4 ¶7 says out-of-range / wrong-type parameter values
    // MUST be silently ignored, so "u=9" no longer triggers a close.
    // A truly malformed Structured Fields dictionary (RFC 8941 §4.2.1
    // forbids empty member keys) still surfaces as a parse error and
    // maps to H3_GENERAL_PROTOCOL_ERROR.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "=42",
        },
    });

    try expectPairH3Error(allocator, &pair, error.InvalidParameter);
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.general_protocol_error);
}
