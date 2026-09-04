//! Allocation-failure regression sweep for drain event emission.
//!
//! `session.appendRawEvent` takes ownership of an event and
//! deinitializes it exactly once when the events-list append fails. The
//! owned-payload emission sites (WebTransport close reason, datagram
//! payloads, WebTransport substream data, connection-close reason) must
//! not ALSO free those payloads on their error paths — that is a double
//! free. These tests drive a real session pair through the WT
//! datagram / substream / close flow with an allocator that fails one
//! late allocation at a time; the testing allocator's invalid-free and
//! leak detection turns any double free or OOM-path leak into a loud
//! failure with the faulting allocation's stack trace.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

/// Establishes a WebTransport session, ships a datagram, a unidirectional
/// substream payload, and a CLOSE capsule with a reason, and runs until
/// the server has observed the typed close event. Every owned-payload
/// event emission path listed in the file comment runs at least once.
fn runScenario(allocator: std.mem.Allocator) !void {
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
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

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_sent_close = false;
    var server_saw_close = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!server_saw_close) : (iters += 1) {
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
                .webtransport_session_closed => server_saw_close = true,
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_sent_close and response.headers().len > 0) {
                        client_sent_close = true;
                        try client_wt.sendDatagram("ping");
                        const uni = try client_wt.openUniStream();
                        try uni.write("hello");
                        try uni.finish();
                        try client_wt.close(0xdeadbeef, "shutdown");
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // One further pump so any events still queued behind the close (e.g.
    // the datagram echo path tearing down) also emit under the sweep.
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
    clearSessionEvents(allocator, &client_events);
}

test "allocation failures during owned-payload event emission free exactly once" {
    const base = std.testing.allocator;

    // Counting pass: the scenario is deterministic, so a clean run's
    // allocation count tells us where the drain-phase tail lives.
    var probe = std.testing.FailingAllocator.init(base, .{});
    try runScenario(probe.allocator());
    const total = probe.allocations;

    // Sweep the tail of the scenario — the phase covering the datagram,
    // substream-data, and close-reason event emissions. Each iteration
    // fails exactly one allocation (all earlier ones succeed, so pair
    // setup is never the faulted step for indexes this high). Errors are
    // expected and tolerated; the net is the testing allocator's
    // double-free / leak detection at the end of the test block.
    const window: usize = 300;
    const start = total -| window;
    var fail_index = start;
    while (fail_index < total) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(base, .{ .fail_index = fail_index });
        runScenario(failing.allocator()) catch {};
    }
}
