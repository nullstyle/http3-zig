//! A short quic write never leaves a partial HTTP/3 frame.
//!
//! `quic.Connection.streamWrite` can take fewer bytes than offered: the
//! stream's send buffer is full, or the connection's memory budget is
//! (since quic 0.38.0 the writer's share is half the budget). Session
//! writes a frame as a header and then a payload. These tests force the
//! short write with a tiny quic send buffer and check that every frame
//! still reaches the peer whole, and that a write Session refuses leaves
//! no bytes behind.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");
const fixt = @import("_fixtures.zig");

const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;
const clearSessionEvents = fixt.clearSessionEvents;

/// quic's per-stream send buffer for streams opened after this call,
/// with the credit-following growth (quic 0.33.0+) turned off so the
/// limit holds.
fn shrinkSendBuffer(conn: *quic.Connection, bytes: usize) void {
    conn.max_buffered_send = bytes;
    conn.send_buffer_follows_credit = false;
}

/// Pump until the server has the request complete; return a copy of
/// its body (caller frees).
fn pumpUntilRequestBody(allocator: std.mem.Allocator, pair: *H3Pair) ![]u8 {
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
    while (iters < 20_000) : (iters += 1) {
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
                .request_complete => |request_state| {
                    return allocator.dupe(u8, request_state.reader().body());
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    return error.ExpectedRequestComplete;
}

fn fillPattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
}

test "a DATA frame larger than quic's send buffer reaches the peer whole" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    shrinkSendBuffer(&pair.client, 4096);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/upload",
    });

    // One write, one DATA frame (16 KiB payload cap per frame by
    // default, so two frames), far past the 4 KiB quic buffer.
    var body: [20_000]u8 = undefined;
    fillPattern(&body);
    try writer.write(&body);
    try writer.finish();

    const received = try pumpUntilRequestBody(allocator, &pair);
    defer allocator.free(received);
    try std.testing.expectEqualSlices(u8, &body, received);
}

test "a write on a stream with unsent frame bytes is refused whole" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    shrinkSendBuffer(&pair.client, 4096);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/upload",
    });

    var first: [10_000]u8 = undefined;
    fillPattern(&first);
    try writer.write(&first);

    // Nothing pumped: the first frame's tail still waits in Session.
    const before = try writer.sendState();
    try std.testing.expect(!try writer.canWrite(1000));
    var second: [1000]u8 = @splat('z');
    try std.testing.expectError(error.SendBufferFull, writer.write(&second));
    const after = try writer.sendState();
    try std.testing.expectEqual(before.written_bytes, after.written_bytes);
    try std.testing.expectEqual(before.buffered_bytes, after.buffered_bytes);

    try writer.finish();
    const received = try pumpUntilRequestBody(allocator, &pair);
    defer allocator.free(received);
    try std.testing.expectEqualSlices(u8, &first, received);
}

test "a reset drops the stream's unsent frame bytes" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    shrinkSendBuffer(&pair.client, 4096);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/upload",
    });
    var body: [20_000]u8 = undefined;
    fillPattern(&body);
    try writer.write(&body);
    try writer.finish();

    // Reset before the tail (and its FIN) went out: the tail is dropped,
    // and later drains neither write it nor send a FIN after the reset.
    try pair.client_h3.resetStream(writer.stream_id, http3_zig.protocol.ErrorCode.request_cancelled);

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
    var saw_reset = false;
    var iters: u32 = 0;
    while (iters < 2_000 and !saw_reset) : (iters += 1) {
        try pumpH3(&pair.client, &pair.server, &pair.client_h3, &pair.server_h3, &client_events, &server_events, &now_us);
        for (server_events.items) |event| switch (event) {
            .stream_reset => |reset| if (reset.stream_id == writer.stream_id) {
                saw_reset = true;
            },
            else => {},
        };
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    try std.testing.expect(saw_reset);
    try std.testing.expect(pair.client_h3.lastCloseError() == null);
    try std.testing.expect(pair.server_h3.lastCloseError() == null);
}
