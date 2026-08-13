//! Draft-era negotiation integration tests: one server speaking both
//! the modern draft and the browser era, against clients of each era.
//!
//! The data path is identical across eras — these tests pin the
//! NEGOTIATION layer: newest-common resolution
//! [draft-ietf-webtrans-http3-07 §6], per-connection stamping with
//! sessions inheriting the connection era, flow-control inertness on
//! legacy sessions (modern capsules are unknown types to them), and the
//! era guard on the modern send verbs.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

/// A browser-shaped client: draft-02 bootstrap only, prerequisites
/// advertised (Chrome and Firefox both send all three).
const legacy_client_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_draft02 = true,
};

/// A browser-facing server: modern draft AND the draft-02 era.
const dual_era_server_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
    .wt_draft02 = true,
};

test "era negotiation: a draft-02 client and a dual-era server establish a legacy session; flow capsules are inert on it" {
    const allocator = std.testing.allocator;
    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = legacy_client_settings },
        .{ .settings = dual_era_server_settings },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    // Both sides resolved the connection to the newest COMMON era.
    try std.testing.expectEqual(
        @as(?http3_zig.webtransport.WtDraft, .draft02),
        pair.client_h3.webTransportNegotiatedDraft(),
    );
    try std.testing.expectEqual(
        @as(?http3_zig.webtransport.WtDraft, .draft02),
        pair.server_h3.webTransportNegotiatedDraft(),
    );

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
    var capsule_sent = false;
    var server_saw_unknown = false;
    var server_saw_datagram = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(server_saw_unknown and server_saw_datagram)) : (iters += 1) {
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
                // On a legacy session a modern WT_MAX_DATA is just an
                // unknown capsule type — surfaced byte-exact, never
                // folded into credit.
                .webtransport_unknown_capsule => |unknown| {
                    try std.testing.expectEqual(session_id, unknown.session_id);
                    try std.testing.expectEqual(
                        http3_zig.webtransport.CapsuleType.max_data,
                        unknown.capsule_type,
                    );
                    server_saw_unknown = true;
                },
                .webtransport_credit_granted => return error.CreditFoldedOnLegacySession,
                .webtransport_flow_violated => return error.ViolationOnLegacySession,
                .datagram => |dg| {
                    if (dg.stream_id == session_id and std.mem.eql(u8, dg.payload, "era ping")) {
                        server_saw_datagram = true;
                    }
                },
                else => {},
            }
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        // The era's establishment shape on the wire: the
                        // legacy token and the draft-02 request header
                        // Chrome sends unconditionally.
                        try std.testing.expectEqualStrings("webtransport", request.protocol().?);
                        var saw_draft02_header = false;
                        for (request.headers()) |field| {
                            if (std.mem.eql(u8, field.name, "sec-webtransport-http3-draft02")) {
                                try std.testing.expectEqualStrings("1", field.value);
                                saw_draft02_header = true;
                            }
                        }
                        try std.testing.expect(saw_draft02_header);
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                        // Sessions inherit the connection era — visible
                        // on the established snapshot.
                        try std.testing.expectEqual(
                            http3_zig.webtransport.WtDraft.draft02,
                            (server_wt.?.flowState() orelse return error.MissingFlow).draft,
                        );
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
                    if (!capsule_sent and response.headers().len > 0 and response.webTransportAccepted()) {
                        // Era response header (quiche-server-compatible;
                        // no shipping client validates it — we emit it
                        // for symmetry with what browsers expect to see).
                        var saw_resp_header = false;
                        for (response.headers()) |field| {
                            if (std.mem.eql(u8, field.name, "sec-webtransport-http3-draft")) {
                                try std.testing.expectEqualStrings("draft02", field.value);
                                saw_resp_header = true;
                            }
                        }
                        try std.testing.expect(saw_resp_header);
                        // Datagrams are era-stable and must flow...
                        try client_wt.sendDatagram("era ping");
                        // ...while a modern flow capsule injected raw is
                        // inert on the legacy session (unknown type).
                        var buf: [24]u8 = undefined;
                        const n = try http3_zig.webtransport.encodeMaxData(&buf, 4096);
                        try client_wt.writer.write(buf[0..n]);
                        // And the modern send verbs refuse outright.
                        try std.testing.expectError(
                            error.WebTransportEraUnsupported,
                            client_wt.sendMaxData(4096),
                        );
                        capsule_sent = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // No credit was folded server-side: the session's limits stayed
    // null (legacy sessions never gate on peer credit).
    const snapshot = server_wt.?.flowState() orelse return error.MissingFlow;
    try std.testing.expectEqual(@as(?u64, null), snapshot.peer_max_data);
    try std.testing.expectEqual(http3_zig.webtransport.WtDraft.draft02, snapshot.draft);

    // Unmetered sends: a legacy session never blocks on credit.
    const stream = try client_wt.openUniStream();
    try stream.write("legacy sessions never block on credit");
    try stream.finish();
}

test "era negotiation: a modern-only client against a legacy-only server refuses cleanly" {
    const allocator = std.testing.allocator;
    const modern_client: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };
    const legacy_server: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_draft02 = true,
    };
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = modern_client }, .{ .settings = legacy_server });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    // No common era: clean per-call refusal, no connection error.
    try std.testing.expectEqual(
        @as(?http3_zig.webtransport.WtDraft, null),
        pair.client_h3.webTransportNegotiatedDraft(),
    );
    var h3_client = http3_zig.Client.init(&pair.client_h3);
    try std.testing.expectError(
        error.PeerDidNotEnableWebTransport,
        h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = "/wt",
        }),
    );
}

test "era negotiation: sessions on one connection share the resolved era (same-era invariant)" {
    const allocator = std.testing.allocator;
    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = legacy_client_settings },
        .{ .settings = dual_era_server_settings },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    var wt_a = try h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/a" });
    var wt_b = try h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/b" });

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

    var accepted: usize = 0;
    var handles: [2]?http3_zig.WebTransportServerStream = .{ null, null };
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (accepted < 2) : (iters += 1) {
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
                    if (request.headers().len > 0 and request.isWebTransport()) {
                        const slot: usize = if (request.streamId() == wt_a.sessionId()) 0 else 1;
                        if (handles[slot] == null) {
                            handles[slot] = try h3_server.acceptWebTransport(allocator, request, .{});
                            accepted += 1;
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Mixed-era sessions on one connection are impossible by
    // construction: both sessions carry the connection's era.
    const snap_a = handles[0].?.flowState() orelse return error.MissingFlow;
    const snap_b = handles[1].?.flowState() orelse return error.MissingFlow;
    try std.testing.expectEqual(http3_zig.webtransport.WtDraft.draft02, snap_a.draft);
    try std.testing.expectEqual(snap_a.draft, snap_b.draft);
    _ = &wt_a;
    _ = &wt_b;
}

test "production(): the draft-07 knob advertises exactly the enforced session cap" {
    // Advertisement equals enforcement, structurally: both derive from
    // one option [draft-ietf-webtrans-http3-07 §3.1].
    const config = http3_zig.SessionConfig.production(.{ .enable_webtransport_draft07 = true });
    try std.testing.expectEqual(@as(?u64, 256), config.settings.wt_draft07_max_sessions);
    try std.testing.expectEqual(@as(?usize, 256), config.max_wt_sessions);
    try std.testing.expect(config.settings.enable_connect_protocol);
    try std.testing.expect(config.settings.h3_datagram);

    const custom = http3_zig.SessionConfig.production(.{
        .enable_webtransport_draft07 = true,
        .max_wt_sessions = 8,
    });
    try std.testing.expectEqual(@as(?u64, 8), custom.settings.wt_draft07_max_sessions);
    try std.testing.expectEqual(@as(?usize, 8), custom.max_wt_sessions);

    // Without the era knob the cap is policy-only (nothing advertised).
    const modern = http3_zig.SessionConfig.production(.{
        .enable_webtransport = true,
        .max_wt_sessions = 4,
    });
    try std.testing.expectEqual(@as(?u64, null), modern.settings.wt_draft07_max_sessions);
    try std.testing.expectEqual(@as(?usize, 4), modern.max_wt_sessions);
}

test "session cap: over-cap accept refuses pre-response and the 429 rejection reaches the client" {
    const allocator = std.testing.allocator;
    const wt: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };
    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = wt },
        .{ .settings = wt, .max_wt_sessions = 1 },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);
    var wt_a = try h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/a" });
    var wt_b = try h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/b" });

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

    var first: ?http3_zig.WebTransportServerStream = null;
    var second_rejected = false;
    var client_saw_429 = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_429) : (iters += 1) {
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
                    if (request.headers().len == 0 or !request.isWebTransport()) continue;
                    if (request.streamId() == wt_a.sessionId()) {
                        if (first == null) first = try h3_server.acceptWebTransport(allocator, request, .{});
                    } else if (!second_rejected and first != null) {
                        // The cap refuses BEFORE any response bytes; the
                        // application answers with the polite 429.
                        try std.testing.expectError(
                            error.WebTransportSessionLimitReached,
                            h3_server.acceptWebTransport(allocator, request, .{}),
                        );
                        try h3_server.rejectWebTransport(allocator, request, .{ .status = "429" });
                        second_rejected = true;
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
                    if (response.streamId() == wt_b.sessionId() and response.headers().len > 0) {
                        try std.testing.expect(!response.webTransportAccepted());
                        try std.testing.expectEqualStrings("429", response.status().?);
                        client_saw_429 = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
    // The rejected bootstrap left no session behind on the client.
    try std.testing.expect(
        pair.client_h3.webTransportSessionState(wt_b.sessionId()) == .none,
    );
    try std.testing.expectEqual(@as(usize, 1), pair.server_h3.webTransportEstablishedCount());
    _ = &wt_a;
}

test "draft-07: the peer's advertised session count binds the client before anything reaches the wire" {
    const allocator = std.testing.allocator;
    const d07: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_draft07_max_sessions = 1,
    };
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = d07 }, .{ .settings = d07 });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    try std.testing.expectEqual(
        @as(?http3_zig.webtransport.WtDraft, .draft07),
        pair.client_h3.webTransportNegotiatedDraft(),
    );
    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var wt_a = try h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/a" });
    try std.testing.expectError(
        error.WebTransportSessionLimitReached,
        h3_client.startWebTransport(allocator, .{ .authority = "localhost", .path = "/b" }),
    );
    _ = &wt_a;
}
