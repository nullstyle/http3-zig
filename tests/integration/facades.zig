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

test "client and server facades classify session events" {
    const request_fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const response_fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "204" },
    };

    const request_headers: http3_zig.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .request,
        .fields = @constCast(&request_fields),
    } };
    try std.testing.expect(http3_zig.client.ResponseEvent.from(request_headers) == null);
    switch (http3_zig.server.RequestEvent.from(request_headers).?) {
        .headers => |headers| {
            try std.testing.expectEqual(@as(u64, 0), headers.stream_id);
            try std.testing.expectEqualStrings("GET", headers.fields[0].value);
        },
        else => return error.TestExpectedEqual,
    }

    const response_headers: http3_zig.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .response,
        .fields = @constCast(&response_fields),
    } };
    try std.testing.expect(http3_zig.server.RequestEvent.from(response_headers) == null);
    switch (http3_zig.client.ResponseEvent.from(response_headers).?) {
        .headers => |headers| try std.testing.expectEqualStrings("204", headers.fields[0].value),
        else => return error.TestExpectedEqual,
    }

    const request_data: http3_zig.session.Event = .{ .data = .{
        .stream_id = 0,
        .kind = .request,
        .data = @constCast("body"),
    } };
    switch (http3_zig.server.RequestEvent.from(request_data).?) {
        .data => |data| try std.testing.expectEqualStrings("body", data.bytes),
        else => return error.TestExpectedEqual,
    }

    const rejected: http3_zig.session.Event = .{ .request_rejected = .{
        .stream_id = 4,
        .error_code = http3_zig.protocol.ErrorCode.request_rejected,
    } };
    switch (http3_zig.server.RequestEvent.from(rejected).?) {
        .rejected => |event| {
            try std.testing.expectEqual(@as(u64, 4), event.stream_id);
            try std.testing.expectEqual(http3_zig.protocol.ErrorCode.request_rejected, event.error_code);
        },
        else => return error.TestExpectedEqual,
    }

    const flow_blocked: http3_zig.session.Event = .{ .flow_blocked = .{
        .source = .local,
        .kind = .streams,
        .limit = 0,
        .bidi = true,
    } };
    switch (http3_zig.client.ResponseEvent.from(flow_blocked).?) {
        .flow_blocked => |event| {
            try std.testing.expectEqual(http3_zig.FlowBlockedSource.local, event.source);
            try std.testing.expectEqual(http3_zig.FlowBlockedKind.streams, event.kind);
            try std.testing.expectEqual(@as(?bool, true), event.bidi);
        },
        else => return error.TestExpectedEqual,
    }
    switch (http3_zig.server.RequestEvent.from(flow_blocked).?) {
        .flow_blocked => |event| {
            try std.testing.expectEqual(http3_zig.FlowBlockedSource.local, event.source);
            try std.testing.expectEqual(http3_zig.FlowBlockedKind.streams, event.kind);
            try std.testing.expectEqual(@as(u64, 0), event.limit);
        },
        else => return error.TestExpectedEqual,
    }

    const connection_ids_needed: http3_zig.session.Event = .{ .connection_ids_needed = .{
        .path_id = 0,
        .reason = .retired,
        .active_count = 1,
        .active_limit = 2,
        .issue_budget = 1,
        .next_sequence_number = 3,
    } };
    switch (http3_zig.client.ResponseEvent.from(connection_ids_needed).?) {
        .connection_ids_needed => |event| {
            try std.testing.expectEqual(@as(u32, 0), event.path_id);
            try std.testing.expectEqual(@as(usize, 1), event.issue_budget);
        },
        else => return error.TestExpectedEqual,
    }
    switch (http3_zig.server.RequestEvent.from(connection_ids_needed).?) {
        .connection_ids_needed => |event| {
            try std.testing.expectEqual(@as(usize, 2), event.active_limit);
            try std.testing.expectEqual(@as(u64, 3), event.next_sequence_number);
        },
        else => return error.TestExpectedEqual,
    }
}

test "request tracker owns server request lifecycle" {
    const allocator = std.testing.allocator;
    var tracker = http3_zig.RequestTracker.init(allocator);
    defer tracker.deinit();

    const request_fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/tracked" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const trailers = [_]http3_zig.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    _ = try tracker.observe(.{ .headers = .{
        .stream_id = 0,
        .fields = @constCast(&request_fields),
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "hello",
    } });
    _ = try tracker.observe(.{ .trailers = .{
        .stream_id = 0,
        .fields = @constCast(&trailers),
    } });
    const state = (try tracker.observe(.{ .finished = .{ .stream_id = 0 } })).?;

    try std.testing.expectEqual(@as(u64, 0), state.stream_id);
    try std.testing.expectEqualStrings("/tracked", state.headerFields()[2].value);
    try std.testing.expectEqualStrings("hello", state.bodyBytes());
    try std.testing.expectEqualStrings("ok", state.trailerFields()[0].value);
    try std.testing.expect(state.complete);

    const reader = state.reader();
    try std.testing.expectEqual(@as(u64, 0), reader.streamId());
    try std.testing.expectEqualStrings("POST", reader.method().?);
    try std.testing.expectEqualStrings("https", reader.scheme().?);
    try std.testing.expectEqualStrings("localhost", reader.authority().?);
    try std.testing.expectEqualStrings("/tracked", reader.path().?);
    try std.testing.expectEqualStrings("hello", reader.body());
    try std.testing.expect(reader.complete());

    const removed = tracker.remove(0).?;
    defer {
        removed.deinit(allocator);
        allocator.destroy(removed);
    }
    try std.testing.expect(tracker.get(0) == null);
}

test "request tracker enforces body budget" {
    const allocator = std.testing.allocator;
    var tracker = http3_zig.RequestTracker.initWithConfig(allocator, .{ .max_body_bytes = 5 });
    defer tracker.deinit();

    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "hel",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "lo",
    } });
    try std.testing.expectError(error.BodyTooLarge, tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "!",
    } }));

    const state = tracker.get(0).?;
    try std.testing.expectEqualStrings("hello", state.bodyBytes());
}

test "response tracker owns client response lifecycle" {
    const allocator = std.testing.allocator;
    var tracker = http3_zig.ResponseTracker.init(allocator);
    defer tracker.deinit();

    const response_fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]http3_zig.FieldLine{
        .{ .name = "server-timing", .value = "app;dur=1" },
    };

    _ = try tracker.observe(.{ .headers = .{
        .stream_id = 0,
        .fields = @constCast(&response_fields),
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "po",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "ng",
    } });
    _ = try tracker.observe(.{ .trailers = .{
        .stream_id = 0,
        .fields = @constCast(&trailers),
    } });
    const state = (try tracker.observe(.{ .finished = .{ .stream_id = 0 } })).?;

    const reader = state.reader();
    try std.testing.expectEqual(@as(u64, 0), reader.streamId());
    try std.testing.expectEqualStrings("200", reader.status().?);
    try std.testing.expectEqualStrings("pong", reader.body());
    try std.testing.expectEqualStrings("app;dur=1", reader.trailers()[0].value);
    try std.testing.expect(reader.complete());

    const removed = tracker.remove(0).?;
    defer {
        removed.deinit(allocator);
        allocator.destroy(removed);
    }
    try std.testing.expect(tracker.get(0) == null);
}

test "response tracker enforces body budget" {
    const allocator = std.testing.allocator;
    var tracker = http3_zig.ResponseTracker.initWithConfig(allocator, .{ .max_body_bytes = 4 });
    defer tracker.deinit();

    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "po",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "ng",
    } });
    try std.testing.expectError(error.BodyTooLarge, tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "!",
    } }));

    const state = tracker.get(0).?;
    try std.testing.expectEqualStrings("pong", state.bodyBytes());
}

test "server runner classifies and tracks request batches" {
    const allocator = std.testing.allocator;
    var runner = http3_zig.ServerRunner.init(allocator);
    defer runner.deinit();

    var fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/runner" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var body = [_]u8{ 'o', 'k' };
    const events = [_]http3_zig.session.Event{
        .{ .peer_settings = .{ .h3_datagram = true } },
        .{ .datagram_acked = .{
            .id = 7,
            .len = 13,
        } },
        .{ .datagram_lost = .{
            .id = 8,
            .len = 21,
        } },
        .{ .flow_blocked = .{
            .source = .peer,
            .kind = .stream_data,
            .limit = 64,
            .stream_id = 0,
        } },
        .{ .headers = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.request,
            .fields = &fields,
        } },
        .{ .data = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.request,
            .data = &body,
        } },
        .{ .stream_finished = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.request,
        } },
    };
    var completed: std.ArrayList(*http3_zig.RequestState) = .empty;
    defer completed.deinit(allocator);

    const stats = try runner.observeBatch(&events, &completed);
    try std.testing.expectEqual(@as(usize, 7), stats.observed);
    try std.testing.expectEqual(@as(usize, 1), stats.settings);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_acks);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_losses);
    try std.testing.expectEqual(@as(usize, 1), stats.flow_blocked);
    try std.testing.expectEqual(@as(usize, 2), stats.state_updates);
    try std.testing.expectEqual(@as(usize, 1), stats.completions);
    try std.testing.expectEqual(@as(usize, 1), completed.items.len);
    try std.testing.expect(runner.peer_settings.?.h3_datagram);

    const request = completed.items[0].reader();
    try std.testing.expectEqual(@as(u64, 0), request.streamId());
    try std.testing.expect(request.complete());
    try std.testing.expectEqualStrings("POST", request.method().?);
    try std.testing.expectEqualStrings("/runner", request.path().?);
    try std.testing.expectEqualStrings("ok", request.body());
}

test "client runner classifies and tracks response batches" {
    const allocator = std.testing.allocator;
    var runner = http3_zig.ClientRunner.init(allocator);
    defer runner.deinit();

    var fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-runner", .value = "yes" },
    };
    var body = [_]u8{ 'd', 'o', 'n', 'e' };
    const events = [_]http3_zig.session.Event{
        .{ .datagram_acked = .{
            .id = 3,
            .len = 9,
        } },
        .{ .datagram_lost = .{
            .id = 4,
            .len = 11,
        } },
        .{ .flow_blocked = .{
            .source = .local,
            .kind = .data,
            .limit = 128,
        } },
        .{ .headers = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.response,
            .fields = &fields,
        } },
        .{ .data = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.response,
            .data = &body,
        } },
        .{ .stream_finished = .{
            .stream_id = 0,
            .kind = http3_zig.message.Kind.response,
        } },
        .{ .goaway = 4 },
    };
    var completed: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed.deinit(allocator);

    const stats = try runner.observeBatch(&events, &completed);
    try std.testing.expectEqual(@as(usize, 7), stats.observed);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_acks);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_losses);
    try std.testing.expectEqual(@as(usize, 1), stats.flow_blocked);
    try std.testing.expectEqual(@as(usize, 2), stats.state_updates);
    try std.testing.expectEqual(@as(usize, 1), stats.completions);
    try std.testing.expectEqual(@as(usize, 1), stats.goaways);
    try std.testing.expectEqual(@as(?u64, 4), runner.last_goaway);
    try std.testing.expectEqual(@as(usize, 1), completed.items.len);

    const response = completed.items[0].reader();
    try std.testing.expectEqual(@as(u64, 0), response.streamId());
    try std.testing.expect(response.complete());
    try std.testing.expectEqualStrings("204", response.status().?);
    try std.testing.expectEqualStrings("done", response.body());
}

test "runners pass body budgets to lifecycle trackers" {
    const allocator = std.testing.allocator;

    var client_runner = http3_zig.ClientRunner.initWithConfig(allocator, .{
        .response_tracker = .{ .max_body_bytes = 2 },
    });
    defer client_runner.deinit();
    try std.testing.expectError(error.BodyTooLarge, client_runner.observeResponseEvent(.{ .data = .{
        .stream_id = 0,
        .bytes = "abc",
    } }));

    var server_runner = http3_zig.ServerRunner.initWithConfig(allocator, .{
        .request_tracker = .{ .max_body_bytes = 2 },
    });
    defer server_runner.deinit();
    try std.testing.expectError(error.BodyTooLarge, server_runner.observeRequestEvent(.{ .data = .{
        .stream_id = 0,
        .bytes = "abc",
    } }));
}
