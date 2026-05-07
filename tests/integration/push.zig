const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");
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

test "server push sends PUSH_PROMISE and push stream response" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);

    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
    });
    const request_stream_id = request.stream_id;
    try request.finish();

    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var push_started = false;
    var push_stream_id: ?u64 = null;
    var saw_push_promise = false;
    var saw_push_stream = false;
    var saw_push_headers = false;
    var saw_push_data = false;
    var saw_push_finished = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_push_promise or !saw_push_stream or !saw_push_headers or !saw_push_data or !saw_push_finished) : (iters += 1) {
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
                    const reader = request_state.reader();
                    if (!push_started and reader.headers().len > 0) {
                        try std.testing.expectEqual(request_stream_id, reader.streamId());
                        var push = try h3_server.startPush(allocator, reader.streamId(), .{
                            .promise_headers = &promised_headers,
                            .response = .{
                                .status = "200",
                                .headers = &[_]null3.FieldLine{
                                    .{ .name = "content-type", .value = "text/css" },
                                },
                            },
                        });
                        push_stream_id = push.stream_id;
                        try push.write("body { color: #111; }");
                        try push.finish();
                        push_started = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .push_promise => |promise| {
                    saw_push_promise = true;
                    try std.testing.expectEqual(request_stream_id, promise.stream_id);
                    try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                    try std.testing.expectEqualStrings("/style.css", fieldValue(promise.fields, ":path").?);
                },
                .push_stream => |push| {
                    saw_push_stream = true;
                    try std.testing.expectEqual(@as(u64, 0), push.push_id);
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, push.stream_id);
                },
                .push_headers => |headers| {
                    saw_push_headers = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, headers.stream_id);
                    try std.testing.expectEqualStrings("200", fieldValue(headers.fields, ":status").?);
                },
                .push_data => |data| {
                    saw_push_data = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, data.stream_id);
                    try std.testing.expectEqualStrings("body { color: #111; }", data.bytes);
                },
                .push_finished => |finished| {
                    saw_push_finished = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, finished.stream_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "server push helpers build and validate same-authority cacheable promises" {
    const allocator = std.testing.allocator;

    var request_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var request_state = null3.RequestState{
        .stream_id = 0,
        .headers = &request_headers,
    };
    const request = request_state.reader();

    const built = try null3.server.allocPushPromiseFields(allocator, request, .{
        .path = "/style.css",
        .headers = &[_]null3.FieldLine{
            .{ .name = "accept", .value = "text/css" },
        },
    });
    defer allocator.free(built);
    try std.testing.expectEqualStrings("GET", fieldValue(built, ":method").?);
    try std.testing.expectEqualStrings("https", fieldValue(built, ":scheme").?);
    try std.testing.expectEqualStrings("example.com", fieldValue(built, ":authority").?);
    try std.testing.expectEqualStrings("/style.css", fieldValue(built, ":path").?);
    try null3.server.validatePushPromisePolicy(request, built, .{});

    const cross_authority = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "cdn.example.com" },
    };
    try std.testing.expectError(
        error.CrossAuthorityPush,
        null3.server.validatePushPromisePolicy(request, &cross_authority, .{}),
    );
    try null3.server.validatePushPromisePolicy(request, &cross_authority, .{
        .require_same_authority = false,
    });

    const post_promise = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/mutate" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(
        error.UncacheablePushMethod,
        null3.server.validatePushPromisePolicy(request, &post_promise, .{}),
    );

    const extended_connect = [_]null3.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/tunnel" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        error.ExtendedConnectPush,
        null3.server.validatePushPromisePolicy(request, &extended_connect, .{
            .require_cacheable_method = false,
        }),
    );
}

test "client pushed response tracker assembles promised response lifecycle" {
    const allocator = std.testing.allocator;

    var promise_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var promise_block: [128]u8 = undefined;
    const promise_block_n = try null3.qpack.encodeFieldSection(&promise_block, &promise_fields);
    var response_headers = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/css" },
    };
    var response_trailers = [_]null3.FieldLine{
        .{ .name = "x-push-complete", .value = "yes" },
    };

    var tracker = null3.PushedResponseTracker.initWithConfig(allocator, .{
        .max_body_bytes = 64,
        .max_promise_field_section_bytes = 128,
    });
    defer tracker.deinit();

    const promised = (try tracker.observe(.{ .push_promise = .{
        .stream_id = 0,
        .push_id = 7,
        .field_section = promise_block[0..promise_block_n],
        .fields = &promise_fields,
    } })).?;
    try std.testing.expectEqual(@as(u64, 7), promised.push_id);
    try std.testing.expectEqual(@as(usize, 1), promised.requestStreamIds().len);
    try std.testing.expectEqual(@as(u64, 0), promised.requestStreamIds()[0]);

    try std.testing.expectEqualStrings("/style.css", fieldValue(promised.reader().promiseFields(), ":path").?);

    _ = try tracker.observe(.{ .push_stream = .{ .stream_id = 14, .push_id = 7 } });
    _ = try tracker.observe(.{ .push_headers = .{ .stream_id = 14, .fields = &response_headers } });
    _ = try tracker.observe(.{ .push_data = .{ .stream_id = 14, .bytes = "body { color: #111; }" } });
    _ = try tracker.observe(.{ .push_trailers = .{ .stream_id = 14, .fields = &response_trailers } });
    const completed = (try tracker.observe(.{ .push_finished = .{ .stream_id = 14 } })).?;

    const by_stream = tracker.getByStream(14).?;
    try std.testing.expectEqual(completed, by_stream);
    const reader = completed.reader();
    try std.testing.expectEqual(@as(?u64, 14), reader.streamId());
    try std.testing.expectEqualStrings("200", reader.status().?);
    try std.testing.expectEqualStrings("body { color: #111; }", reader.body());
    try std.testing.expectEqualStrings("yes", fieldValue(reader.trailers(), "x-push-complete").?);
    try std.testing.expect(reader.complete());
    try std.testing.expect(!reader.cancelled());

    var runner = null3.ClientRunner.init(allocator);
    defer runner.deinit();
    _ = try runner.observeResponseEvent(.{ .push_promise = .{
        .stream_id = 0,
        .push_id = 9,
        .field_section = promise_block[0..promise_block_n],
        .fields = &promise_fields,
    } });
    switch (try runner.observeResponseEvent(.{ .push_stream = .{ .stream_id = 18, .push_id = 9 } })) {
        .pushed_response_updated => |pushed| try std.testing.expectEqual(@as(u64, 9), pushed.push_id),
        else => return error.ExpectedPushedResponseUpdate,
    }
    _ = try runner.observeResponseEvent(.{ .push_headers = .{ .stream_id = 18, .fields = &response_headers } });
    _ = try runner.observeResponseEvent(.{ .push_data = .{ .stream_id = 18, .bytes = "ok" } });
    switch (try runner.observeResponseEvent(.{ .push_finished = .{ .stream_id = 18 } })) {
        .pushed_response_complete => |pushed| {
            try std.testing.expectEqual(@as(u64, 9), pushed.push_id);
            try std.testing.expectEqualStrings("ok", pushed.bodyBytes());
        },
        else => return error.ExpectedPushedResponseCompletion,
    }
    try std.testing.expect(runner.getPushedResponse(9).?.complete);
    try std.testing.expectEqual(runner.getPushedResponse(9).?, runner.getPushedResponseByStream(18).?);
}

test "server push requires client MAX_PUSH_ID opt-in" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_server = null3.Server.init(&pair.server_h3);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(
        error.PushNotEnabled,
        h3_server.startPush(allocator, 0, .{
            .promise_headers = &promised_headers,
            .response = .{},
        }),
    );
}

test "server push enforces advertised MAX_PUSH_ID limit" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try std.testing.expectError(
        error.PushLimitExceeded,
        h3_server.startPush(allocator, request_stream_id, .{
            .promise_headers = &promised_headers,
            .response = .{ .status = "200" },
        }),
    );
}

test "client CANCEL_PUSH reaches server" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try h3_client.cancelPush(0);

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        clearSessionEvents(allocator, &client_events);
    }
}

test "server CANCEL_PUSH reaches client" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try h3_server.cancelPush(0);

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "session rejects CANCEL_PUSH for unpromised push IDs" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .cancel_push = 0 });

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects CANCEL_PUSH above advertised MAX_PUSH_ID" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .cancel_push = 1 });

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects push streams above advertised MAX_PUSH_ID" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try openUniWithType(&pair.server, 7, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 7, 1);

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects duplicate push stream IDs" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    try openUniWithType(&pair.server, 7, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 7, 0);

    var now_us: u64 = 1_000_000;
    var saw_push = false;
    var iters: u32 = 0;
    while (!saw_push) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);
        for (client_events.items) |event| {
            switch (event) {
                .push_stream => |push| {
                    saw_push = true;
                    try std.testing.expectEqual(@as(u64, 0), push.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try openUniWithType(&pair.server, 11, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 11, 0);

    try pumpUntilH3Error(
        allocator,
        &pair.client,
        &pair.server,
        &pair.client_h3,
        &pair.server_h3,
        &client_events,
        &server_events,
        &now_us,
        error.InvalidPushId,
    );
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session accepts duplicate PUSH_PROMISE with identical fields" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    const first_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const second_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    try writePushPromiseFrame(&pair.server, first_stream_id, 0, &promised_headers);
    try writePushPromiseFrame(&pair.server, second_stream_id, 0, &promised_headers);

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var promises: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (promises < 2) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);
        for (client_events.items) |event| {
            switch (event) {
                .push_promise => |promise| {
                    promises += 1;
                    try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "session rejects duplicate PUSH_PROMISE with inconsistent fields" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    const first_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const second_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const conflicting_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/script.js" },
        .{ .name = ":authority", .value = "example.com" },
    };

    try writePushPromiseFrame(&pair.server, first_stream_id, 0, &promised_headers);
    try writePushPromiseFrame(&pair.server, second_stream_id, 0, &conflicting_headers);

    try expectPairH3Error(allocator, &pair, error.InconsistentPushPromise);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.message_error);
}

test "client push policy auto-cancels promised resources" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{
        .max_push_id = 0,
        .push_policy = .cancel_promises,
    }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
        clearSessionEvents(allocator, &client_events);
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
    }
}
