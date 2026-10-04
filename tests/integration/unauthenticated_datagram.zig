//! SECURITY regression: a datagram that does not authenticate must end
//! no HTTP/3 connection.
//!
//! Before quic v0.25.0, `Connection.handle` returned an error for a
//! short-header packet whose header did not parse, before the AEAD tag
//! was ever checked. Twelve bytes did it: the first byte of a short
//! header, the connection ID, and three more bytes. Anyone who saw one
//! packet of the connection could send them. Every loop in this repo
//! calls `try endpoint.handle(...)` (`src/driver.zig`, the interop
//! harnesses, `examples/manual_pump_get.zig`), so that error ended the
//! loop and with it the connection. quic v0.25.0 drops such a packet
//! inside `handle`, so `try` is correct again.
//!
//! The test feeds the forged datagram through `TransportEndpoint.handle`,
//! the same call the loops make, to both ends of a live connection, and
//! then requires a second request to complete.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const H3Pair = fixt.H3Pair;

/// First byte of a short header (fixed bit set), the destination
/// connection ID, and three bytes: too short to reach the header
/// protection sample, so nothing about it is authenticated.
fn forgedShortHeader(dcid: *const [8]u8) [12]u8 {
    var datagram: [12]u8 = undefined;
    datagram[0] = 0x40;
    @memcpy(datagram[1..9], dcid);
    @memcpy(datagram[9..12], &[_]u8{ 0x00, 0x01, 0x02 });
    return datagram;
}

const Harness = struct {
    allocator: std.mem.Allocator,
    pair: *H3Pair,
    driver: http3_zig.TransportLoopback,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),

    /// One GET that must complete: the server answers 200 and the
    /// client sees the response headers.
    fn get(self: *Harness, path: []const u8) !void {
        const fields = [_]http3_zig.FieldLine{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = path },
            .{ .name = ":authority", .value = "localhost" },
        };
        const stream_id = try self.pair.client_h3.openRequest(&fields);
        try self.pair.client_h3.finishStream(stream_id);

        var packet: [2048]u8 = undefined;
        var steps: u32 = 0;
        while (steps < 2_000) : (steps += 1) {
            _ = try self.driver.step(&packet);

            for (self.server_events.items) |event| switch (event) {
                .headers => |headers| if (headers.stream_id == stream_id and headers.kind == .request) {
                    try self.pair.server_h3.sendResponseHeaders(stream_id, &.{
                        .{ .name = ":status", .value = "200" },
                    });
                    try self.pair.server_h3.finishStream(stream_id);
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            };
            clearSessionEvents(self.allocator, self.server_events);

            var answered = false;
            for (self.client_events.items) |event| switch (event) {
                .headers => |headers| if (headers.stream_id == stream_id and headers.kind == .response) {
                    try std.testing.expectEqualStrings("200", fixt.fieldValue(headers.fields, ":status").?);
                    answered = true;
                },
                .connection_closed => return error.ClientConnectionClosed,
                else => {},
            };
            clearSessionEvents(self.allocator, self.client_events);
            if (answered) return;
        }
        return error.ResponseNotReceived;
    }

    fn expectLive(self: *Harness) !void {
        try std.testing.expect(!self.pair.client.isClosed());
        try std.testing.expect(!self.pair.server.isClosed());
        try std.testing.expectEqual(http3_zig.session.ShutdownState.active, self.pair.client_h3.shutdownState());
        try std.testing.expectEqual(http3_zig.session.ShutdownState.active, self.pair.server_h3.shutdownState());
    }
};

test "a forged 12-byte short-header datagram does not end a live HTTP/3 connection" {
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

    var harness: Harness = .{
        .allocator = allocator,
        .pair = &pair,
        .driver = http3_zig.TransportLoopback.init(
            http3_zig.TransportEndpoint.withSession(&pair.client, &pair.client_h3, &client_events),
            http3_zig.TransportEndpoint.withSession(&pair.server, &pair.server_h3, &server_events),
            .{},
        ),
        .client_events = &client_events,
        .server_events = &server_events,
    };

    // The connection is live: 1-RTT packets flow both ways.
    try harness.get("/before");
    try harness.expectLive();

    // One forged datagram to each end, through the call every loop makes.
    var to_server = forgedShortHeader(&fixt.ServerCid);
    try harness.driver.server.handle(&to_server, null, harness.driver.now_us);
    var to_client = forgedShortHeader(&fixt.ClientCid);
    try harness.driver.client.handle(&to_client, null, harness.driver.now_us);
    try harness.expectLive();

    // The connection still carries requests.
    try harness.get("/after");
    try harness.expectLive();
}
