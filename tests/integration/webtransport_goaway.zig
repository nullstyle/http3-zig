//! GOAWAY × WebTransport lifecycle tests.
//!
//! [draft-ietf-webtrans-http3] requires ESTABLISHED WebTransport sessions
//! to survive an H3 GOAWAY — including opening new substreams — while new
//! WT CONNECT bootstraps are refused. quic-zig's transport-level
//! `beginGracefulShutdown()` refuses local stream opens, so `sendGoaway`
//! DEFERS it while established sessions exist and `endWebTransportSession`
//! engages it when the last one ends. During the deferral window only the
//! H3-layer gates enforce GOAWAY (the transport keeps granting the peer
//! stream credit — a misbehaving peer can churn transport streams until
//! the latch drops; the H3 auto-reject covers the request layer).
//! Datagrams stay legal after both DRAIN and GOAWAY per draft-16.
//!
//! Keepalive note (upstream-confirmed): the deferral window does not
//! pause `max_idle_timeout` — an embedder whose WT sessions can go
//! traffic-idle during a long drain drives `Connection.requestPing()`
//! (exercised below) or WT-level traffic to keep the connection alive.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

test "GOAWAY: established WT session survives, datagrams flow, and the last session end engages the transport latch" {
    const allocator = std.testing.allocator;
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();

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
    var goaway_sent = false;
    var post_goaway_stream: ?http3_zig.WebTransportStream = null;
    var client_saw_post_goaway_stream = false;
    var client_saw_datagram = false;
    var client_saw_drain = false;
    var drained_and_datagrammed = false;
    var client_new_connect_refused = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(client_saw_post_goaway_stream and client_saw_datagram and
        client_saw_drain and drained_and_datagrammed and client_new_connect_refused)) : (iters += 1)
    {
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
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (server_wt != null and !goaway_sent) {
            // GOAWAY with a live established session: the transport
            // latch must defer...
            try pair.server_h3.sendGoaway(pair.server_h3.gracefulGoawayId());
            goaway_sent = true;
            try std.testing.expectEqual(
                @as(usize, 1),
                pair.server_h3.webTransportEstablishedCount(),
            );

            // ...which is exactly what lets these succeed post-GOAWAY:
            // a server-opened substream on the surviving session, a
            // datagram, a DRAIN, and the keepalive the embedder would
            // drive on a long quiet drain window.
            const stream = try server_wt.?.openUniStream();
            try stream.write("post-goaway stream");
            try stream.finish();
            post_goaway_stream = stream;
            try server_wt.?.sendDatagram("post-goaway datagram");
            try server_wt.?.sendDrain();
            pair.server_h3.quic.requestPing();
        }

        for (client_events.items) |event| {
            switch (event) {
                .webtransport_stream_data => |data| {
                    if (data.session_id == session_id and
                        std.mem.eql(u8, data.data, "post-goaway stream"))
                    {
                        client_saw_post_goaway_stream = true;
                    }
                },
                .datagram => |dg| {
                    if (dg.stream_id == session_id and
                        std.mem.eql(u8, dg.payload, "post-goaway datagram"))
                    {
                        client_saw_datagram = true;
                    }
                },
                .webtransport_session_draining => |draining| {
                    if (draining.session_id == session_id) client_saw_drain = true;
                },
                else => {},
            }
            _ = try client_runner.observe(event);
        }
        clearSessionEvents(allocator, &client_events);

        // Datagrams MUST stay legal after DRAIN and after GOAWAY
        // (draft-16 pins both): answer the drain with one more datagram.
        if (client_saw_drain and !drained_and_datagrammed) {
            try client_wt.sendDatagram("post-drain datagram");
            drained_and_datagrammed = true;
        }

        // A NEW WT CONNECT after the peer's GOAWAY is refused at the H3
        // layer (the transport still has open credit — the deferral
        // window — so this proves the H3 gate does the work).
        if (client_saw_drain and !client_new_connect_refused) {
            try std.testing.expectError(
                error.RequestBlockedByGoaway,
                h3_client.startWebTransport(allocator, .{
                    .authority = "localhost",
                    .path = "/wt-late",
                }),
            );
            client_new_connect_refused = true;
        }
    }

    // End the surviving session: the deferred transport latch engages on
    // the LAST established-session end...
    try client_wt.close(0, "done");
    var settle: u32 = 0;
    while (pair.server_h3.webTransportEstablishedCount() > 0) : (settle += 1) {
        try std.testing.expect(settle < 20_000);
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
    // ...observable as the transport now refusing local opens.
    try std.testing.expectError(error.ShuttingDown, pair.server_h3.quic.openNextUni());
}

test "GOAWAY: with no live WT sessions the transport latch engages immediately and new CONNECTs are refused with no pending residue" {
    const allocator = std.testing.allocator;
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);

    // No sessions exist: sendGoaway must engage the transport latch
    // right away (the pre-deferral behavior, unchanged).
    try pair.server_h3.sendGoaway(pair.server_h3.gracefulGoawayId());
    try std.testing.expectError(error.ShuttingDown, pair.server_h3.quic.openNextUni());

    // Pump the GOAWAY over to the client, then a new WT CONNECT refuses
    // client-side before anything reaches the wire.
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
    var saw_goaway = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_goaway) : (iters += 1) {
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
        for (client_events.items) |event| {
            switch (event) {
                .goaway => saw_goaway = true,
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try std.testing.expectError(
        error.RequestBlockedByGoaway,
        h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = "/wt",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), pair.server_h3.webTransportPendingCount());
    try std.testing.expectEqual(@as(usize, 0), pair.server_h3.webTransportEstablishedCount());
}
