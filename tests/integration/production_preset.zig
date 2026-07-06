//! Smoke test for the v0.1.0 `Client.Config.production` /
//! `Server.Config.production` presets.
//!
//! Exercises an end-to-end GET over an in-process H3Pair where both
//! peers were initialized with the production preset, to catch any
//! preset value that would silently break a basic request flow (e.g.
//! a `max_field_section_size` that's smaller than the GET's headers,
//! a `buffered_stream_policy` that interferes with the request stream,
//! a drain cap that strands the response).

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixt = @import("_fixtures.zig");

const H3Pair = fixt.H3Pair;
const clearSessionEvents = fixt.clearSessionEvents;
const pumpH3 = fixt.pumpH3;

test "Client.Config.production + Server.Config.production drive a basic GET end to end" {
    const allocator = std.testing.allocator;

    // Smoke-check that the snapshot constants are reachable as
    // `Client.Config.production` / `Server.Config.production` and that
    // the production overrides match the documented values. These are
    // compile-time constants — if they drift from the doc comment the
    // test breaks immediately.
    const client_preset = http3_zig.Client.Config.production;
    const server_preset = http3_zig.Server.Config.production;
    try std.testing.expectEqual(@as(?usize, 256), client_preset.max_concurrent_peer_streams);
    try std.testing.expectEqual(@as(?u64, 16 * 1024), client_preset.max_field_section_size);
    try std.testing.expectEqual(@as(?usize, 16 * 1024), client_preset.wt_max_buffered_bytes_per_stream);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), client_preset.wt_max_total_buffered_bytes);
    try std.testing.expectEqual(http3_zig.SessionBufferedStreamPolicy.reject, client_preset.buffered_stream_policy);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), client_preset.max_event_payload_bytes_per_drain);
    try std.testing.expectEqual(@as(?usize, 512), client_preset.max_events_per_drain);
    try std.testing.expectEqual(@as(?usize, 1024), client_preset.max_tracked_priorities);
    try std.testing.expectEqual(@as(?usize, 256), client_preset.max_tracked_push_promises);
    try std.testing.expectEqual(@as(?usize, 256), client_preset.max_pending_wt_sessions);

    // The presets are independent types but should agree on every
    // shared field — they describe the same v0.1.0 production posture
    // for both halves of a connection.
    try std.testing.expectEqual(client_preset.max_concurrent_peer_streams, server_preset.max_concurrent_peer_streams);
    try std.testing.expectEqual(client_preset.max_field_section_size, server_preset.max_field_section_size);
    try std.testing.expectEqual(client_preset.wt_max_buffered_bytes_per_stream, server_preset.wt_max_buffered_bytes_per_stream);
    try std.testing.expectEqual(client_preset.wt_max_total_buffered_bytes, server_preset.wt_max_total_buffered_bytes);
    try std.testing.expectEqual(client_preset.buffered_stream_policy, server_preset.buffered_stream_policy);
    try std.testing.expectEqual(client_preset.max_event_payload_bytes_per_drain, server_preset.max_event_payload_bytes_per_drain);
    try std.testing.expectEqual(client_preset.max_events_per_drain, server_preset.max_events_per_drain);
    try std.testing.expectEqual(client_preset.max_tracked_priorities, server_preset.max_tracked_priorities);
    try std.testing.expectEqual(client_preset.max_tracked_push_promises, server_preset.max_tracked_push_promises);
    try std.testing.expectEqual(client_preset.max_pending_wt_sessions, server_preset.max_pending_wt_sessions);

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        client_preset.toSessionConfig(),
        server_preset.toSessionConfig(),
    );
    defer pair.deinit();

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var request_writer = try h3_client.startRequest(allocator, .{
        .method = "GET",
        .authority = "localhost",
        .path = "/hello",
    });
    const request_stream_id = request_writer.stream_id;
    try request_writer.finish();

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
    var completed_responses: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed_responses.deinit(allocator);

    var response_sent = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (completed_responses.items.len == 0) : (iters += 1) {
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
                            .body = "hello from production preset\n",
                        });
                        response_sent = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        _ = try client_runner.observeBatch(client_events.items, &completed_responses);
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(response_sent);
    try std.testing.expectEqual(@as(usize, 1), completed_responses.items.len);
    const response = completed_responses.items[0].reader();
    try std.testing.expectEqualStrings("200", response.status().?);
    try std.testing.expectEqualStrings("hello from production preset\n", response.body());

    // The peer should have observed the production cap on
    // max_field_section_size in the SETTINGS exchange.
    try std.testing.expectEqual(
        @as(?u64, 16 * 1024),
        pair.client_h3.peer_settings.?.max_field_section_size,
    );
    try std.testing.expectEqual(
        @as(?u64, 16 * 1024),
        pair.server_h3.peer_settings.?.max_field_section_size,
    );
}
