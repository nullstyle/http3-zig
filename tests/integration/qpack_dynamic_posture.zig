//! Opt-in dynamic-QPACK posture coverage.
//!
//! Dynamic QPACK is off by default (`qpack_indexing = .static_only`, encoder
//! capacity 0) — see docs/production-limits.md. These tests exercise the
//! opt-in postures end to end through a session pair:
//!
//!   - PUSH_PROMISE byte stability: under the default static posture the
//!     PUSH_PROMISE field section is byte-identical to the static encoder.
//!   - PUSH_PROMISE dynamic routing: under an opt-in posture PUSH_PROMISE
//!     rides the same dynamic-capable path as HEADERS.
//!   - Aggressive posture + non-zero encoder capacity round-trips request
//!     and response headers using dynamic-table references.
//!   - A peer SETTINGS_QPACK_BLOCKED_STREAMS budget of zero degrades to
//!     literal field sections, not request failure (RFC 9204 §2.1.2).
//!   - A long-lived pair with repeated hot headers eventually emits a
//!     Duplicate instruction on the encoder stream (RFC 9204 §2.1.1.1 /
//!     §4.3.4), observable as two identical entries in the dynamic tables.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const pumpH3 = fixt.pumpH3;
const fieldValue = fixt.fieldValue;
const H3Pair = fixt.H3Pair;
const exchangePairSettings = fixt.exchangePairSettings;
const openGetAndAwaitServerHeaders = fixt.openGetAndAwaitServerHeaders;

const qpack = http3_zig.qpack;

/// Session config for a dynamic-QPACK opt-in endpoint: advertise a decoder
/// table, allow blocked streams, and run the aggressive indexing policy
/// with a non-zero encoder table.
fn dynamicConfig(capacity: u64, blocked_streams: u64) http3_zig.session.Config {
    return .{
        .settings = .{
            .qpack_max_table_capacity = capacity,
            .qpack_blocked_streams = blocked_streams,
        },
        .qpack_encoder_table_capacity = @intCast(capacity),
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
    };
}

/// True when `table` holds two live entries with identical name and value.
/// Under this encoder that state is only ever produced by a Duplicate
/// instruction: `chooseInsertInstruction` refuses to re-insert a full match
/// through any other instruction shape, so an identical pair is proof that
/// a Duplicate was emitted on the encoder stream and applied.
fn hasDuplicateEntryPair(table: *const qpack.DynamicTable) bool {
    const items = table.entries.items;
    for (items, 0..) |a, i| {
        for (items[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.name, b.name) and std.mem.eql(u8, a.value, b.value)) {
                return true;
            }
        }
    }
    return false;
}

test "PUSH_PROMISE bytes under the default static posture match the static encoder exactly" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    // Default configs: static_only indexing, encoder capacity 0. The client
    // opts into push.
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);

    const promised_headers = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });

    // The pinned contract: under default (static_only) config the encoded
    // PUSH_PROMISE field section is exactly what the static encoder
    // produces for the same field list.
    var expected: [256]u8 = undefined;
    const expected_n = try qpack.encodeFieldSection(&expected, &promised_headers);

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

    var saw_promise = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_promise) : (iters += 1) {
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
                    saw_promise = true;
                    try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                    try std.testing.expectEqualSlices(u8, expected[0..expected_n], promise.field_section);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "PUSH_PROMISE routes through dynamic QPACK under an opt-in posture" {
    const allocator = std.testing.allocator;

    var client_config = dynamicConfig(256, 4);
    client_config.max_push_id = 0;
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, client_config, dynamicConfig(256, 4));
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);

    const promised_headers = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "x-promise", .value = "dyn" },
    };
    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        // Static-only response headers, so every dynamic insert observed
        // below is attributable to the PUSH_PROMISE field section.
        .response = .{ .status = "200" },
    });
    // The PUSH_PROMISE encode ran synchronously: the server's encoder table
    // gained entries for the promise's dynamic-eligible fields.
    try std.testing.expect(pair.server_h3.qpack_encoder_table.insert_count > 0);

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

    var saw_promise = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_promise) : (iters += 1) {
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
                    saw_promise = true;
                    // Field section carries a non-zero Required Insert
                    // Count (first prefix byte) — it references the
                    // dynamic table rather than falling back to the
                    // static/literal profile.
                    try std.testing.expect(promise.field_section.len > 0);
                    try std.testing.expect(promise.field_section[0] != 0);
                    // And it decodes to the promised request.
                    try std.testing.expectEqualStrings("dyn", fieldValue(promise.fields, "x-promise").?);
                    try std.testing.expectEqualStrings("/style.css", fieldValue(promise.fields, ":path").?);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // The client's decoder table mirrored the server's encoder-stream
    // inserts to decode the promise.
    try std.testing.expect(pair.client_h3.qpack_decoder_table.insert_count > 0);
}

test "aggressive posture round-trips request and response headers through dynamic references" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, dynamicConfig(256, 4), dynamicConfig(256, 4));
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const request_headers = [_]http3_zig.FieldLine{
        .{ .name = "x-req", .value = "alpha" },
    };
    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
        .headers = &request_headers,
    });
    const request_stream_id = request.stream_id;
    try request.finish();

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

    var server_saw_request = false;
    var response_sent = false;
    var client_saw_response = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_response) : (iters += 1) {
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
                .headers => |headers| {
                    if (headers.kind != .request) continue;
                    try std.testing.expectEqual(request_stream_id, headers.stream_id);
                    try std.testing.expectEqualStrings("alpha", fieldValue(headers.fields, "x-req").?);
                    server_saw_request = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (server_saw_request and !response_sent) {
            const response_headers = [_]http3_zig.FieldLine{
                .{ .name = "x-resp", .value = "beta" },
            };
            var response = try h3_server.startResponse(allocator, request_stream_id, .{
                .status = "200",
                .headers = &response_headers,
            });
            try response.finish();
            response_sent = true;
        }

        for (client_events.items) |event| {
            switch (event) {
                .headers => |headers| {
                    if (headers.kind != .response) continue;
                    try std.testing.expectEqual(request_stream_id, headers.stream_id);
                    try std.testing.expectEqualStrings("beta", fieldValue(headers.fields, "x-resp").?);
                    client_saw_response = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // Both directions actually used the dynamic table: each side's decoder
    // table replayed the peer's encoder-stream inserts.
    try std.testing.expect(pair.server_h3.qpack_decoder_table.insert_count > 0);
    try std.testing.expect(pair.client_h3.qpack_decoder_table.insert_count > 0);
    // And the encoders saw acknowledgments back (references released).
    try std.testing.expect(pair.client_h3.qpack_encoder_state.known_received_count > 0);
}

test "peer blocked-streams budget of zero degrades to literal field sections, not request failure" {
    const allocator = std.testing.allocator;

    // Both sides advertise SETTINGS_QPACK_BLOCKED_STREAMS = 0: the encoder
    // may not let any stream block on the dynamic table (RFC 9204 §2.1.2).
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, dynamicConfig(256, 0), dynamicConfig(256, 0));
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);

    const request_headers = [_]http3_zig.FieldLine{
        .{ .name = "x-req", .value = "alpha" },
    };
    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
        .headers = &request_headers,
    });
    const request_stream_id = request.stream_id;
    try request.finish();

    // The encoder still emitted insert instructions (the table can warm up
    // for later, acknowledged references) …
    try std.testing.expect(pair.client_h3.qpack_encoder_table.insert_count > 0);
    // … but the field section fell back to the non-blocking literal/static
    // profile: no section was tracked against the blocked-streams budget.
    try std.testing.expectEqual(@as(usize, 0), pair.client_h3.qpack_encoder_state.sections.items.len);
    try std.testing.expectEqual(@as(usize, 0), pair.client_h3.qpack_encoder_state.blockedStreamCount());

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

    // The request still succeeds: the server decodes the literal section.
    var server_saw_request = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!server_saw_request) : (iters += 1) {
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
            switch (event) {
                .headers => |headers| {
                    if (headers.kind != .request) continue;
                    try std.testing.expectEqual(request_stream_id, headers.stream_id);
                    try std.testing.expectEqualStrings("alpha", fieldValue(headers.fields, "x-req").?);
                    server_saw_request = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client_h3.qpack_encoder_state.blockedStreamCount());
}

test "long-lived pair with repeated hot headers eventually emits Duplicate on the wire" {
    const allocator = std.testing.allocator;

    // 512-byte tables: small enough that a handful of filler headers pushes
    // the hot entry into the RFC 9204 §2.1.1.1 draining region, large
    // enough that the resulting Duplicate does not immediately evict its
    // source — leaving two identical live entries as the observable.
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, dynamicConfig(512, 8), dynamicConfig(512, 8));
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

    const hot = http3_zig.FieldLine{ .name = "x-hot", .value = "v" };
    // 80 filler-value bytes: each filler entry is ~120 table bytes, so a
    // few rounds walk the 512-byte table into the draining regime.
    const filler_value = "01234567890123456789012345678901234567890123456789012345678901234567890123456789";

    var now_us: u64 = 1_000_000;
    var duplicate_seen = false;
    var round: u32 = 0;
    // Alternate hot-only rounds (which give a fired Duplicate a quiet
    // table state to be observed in) with rounds that add a unique filler
    // header (which age the hot entry toward the draining region).
    while (!duplicate_seen and round < 12) : (round += 1) {
        var filler_name_buf: [16]u8 = undefined;
        var fields_buf: [2]http3_zig.FieldLine = undefined;
        fields_buf[0] = hot;
        var fields: []const http3_zig.FieldLine = fields_buf[0..1];
        if (round % 2 == 1) {
            const filler_name = try std.fmt.bufPrint(&filler_name_buf, "x-fill-{d}", .{round});
            fields_buf[1] = .{ .name = filler_name, .value = filler_value };
            fields = fields_buf[0..2];
        }

        var request = try h3_client.startRequest(allocator, .{
            .authority = "example.com",
            .path = "/",
            .headers = fields,
        });
        try request.finish();

        // Pump until the decoder acknowledged this round's field section
        // (all outstanding sections drained), so later rounds may evict
        // acknowledged, unreferenced entries.
        var iters: u32 = 0;
        while (pair.client_h3.qpack_encoder_state.sections.items.len != 0) : (iters += 1) {
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
            clearSessionEvents(allocator, &server_events);
        }

        duplicate_seen = hasDuplicateEntryPair(&pair.client_h3.qpack_encoder_table);
    }

    // The encoder duplicated the aging hot entry …
    try std.testing.expect(duplicate_seen);
    // … and the instruction reached the peer: the server's decoder table
    // shows the same identical pair. (Its HEADERS decode required the
    // duplicate's insert count, so the instruction has been applied.)
    try std.testing.expect(hasDuplicateEntryPair(&pair.server_h3.qpack_decoder_table));
}
