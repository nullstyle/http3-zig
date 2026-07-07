const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const H3Pair = fixt.H3Pair;

test "TransportLoopback step reports handled datagrams for relayed packets" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
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

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&pair.client, &pair.client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&pair.server, &pair.server_h3, &server_events),
        .{},
    );
    var packet: [2048]u8 = undefined;
    const stats = try driver.step(&packet);

    try std.testing.expect(stats.sent_datagrams > 0);
    try std.testing.expectEqual(stats.sent_datagrams, stats.handled_datagrams);
    try std.testing.expectEqual(
        stats.sent_datagrams,
        stats.client_to_server_datagrams + stats.server_to_client_datagrams,
    );
}
