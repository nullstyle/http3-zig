//! Multiplexing regression tests: multiple WebTransport sessions on a
//! single QUIC connection.
//!
//! Background: the rest of `webtransport.zig` exercises one session per
//! H3Pair extensively. Multi-session-per-connection is the case we're
//! least confident about, because that's where the dispatch must route
//! peer-opened streams to the correct session via:
//!   - the Session ID varint prefix on uni streams (draft-ietf-webtrans-http3-15 §4.1),
//!   - the parent CONNECT-stream relationship for bidi streams (§4.2),
//!   - the Quarter Stream ID in datagrams (§4.3 / RFC 9297),
//! and per-session flow / DRAIN state must not bleed across sessions.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
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

test "WebTransport: 5 concurrent sessions, peer opens 10 uni streams per session, no cross-session bleed" {
    // Each of 5 client-initiated WT sessions sees 10 server-opened uni
    // streams. Every payload encodes its session index and stream index
    // so the client-side `webtransport_stream_opened` /
    // `webtransport_stream_data` / `webtransport_stream_finished` events
    // can be checked for routing to the right session id, and the
    // payloads can be checked for correct attribution.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const num_sessions: usize = 5;
    const streams_per_session: usize = 10;
    const total_expected_streams: usize = num_sessions * streams_per_session;

    var client_sessions: [num_sessions]http3_zig.WebTransportClientStream = undefined;
    var session_ids: [num_sessions]u64 = undefined;

    // Open all 5 client-side WT bootstraps before pumping. Each one
    // produces a distinct CONNECT stream, hence a distinct session id.
    var paths: [num_sessions][16]u8 = undefined;
    for (0..num_sessions) |i| {
        const path = try std.fmt.bufPrint(&paths[i], "/wt/{d}", .{i});
        client_sessions[i] = try h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = path,
        });
        session_ids[i] = client_sessions[i].sessionId();
    }
    // Sanity: every session id is distinct (per draft §2.3 they are
    // CONNECT request stream ids, which are unique on a connection).
    for (0..num_sessions) |i| {
        for (i + 1..num_sessions) |j| {
            try std.testing.expect(session_ids[i] != session_ids[j]);
        }
    }

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

    // Server-side: one accepted WT handle per session, indexed by
    // session id so we can dispatch the right payload to the right
    // sender when the client request lands.
    var server_wt_by_session: std.AutoHashMapUnmanaged(u64, http3_zig.WebTransportServerStream) = .empty;
    defer server_wt_by_session.deinit(allocator);

    // Per-stream client-side bookkeeping: when the server opens a stream
    // we record (session_id, stream_id) -> received bytes + finished flag.
    const PerStream = struct {
        session_id: u64,
        bytes: std.ArrayList(u8),
        finished: bool,
        opened: bool,
    };
    var streams_by_id: std.AutoHashMapUnmanaged(u64, PerStream) = .empty;
    defer {
        var it = streams_by_id.valueIterator();
        while (it.next()) |entry| entry.bytes.deinit(allocator);
        streams_by_id.deinit(allocator);
    }

    var streams_finished_total: usize = 0;
    var sessions_streamed: [num_sessions]usize = @splat(0);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (streams_finished_total < total_expected_streams) : (iters += 1) {
        try std.testing.expect(iters < 200_000);
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        // Server side: accept incoming WT bootstraps, then for each one
        // open up to `streams_per_session` uni streams carrying a
        // session-distinguishing payload.
        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    const sid = request.streamId();
                    if (request.headers().len > 0 and request.isWebTransport()) {
                        if (!server_wt_by_session.contains(sid)) {
                            const accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                            try server_wt_by_session.put(allocator, sid, accepted);
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        // Once a session is accepted, start opening uni streams on it.
        // We open eagerly across pump iterations so the peer's
        // MAX_STREAMS_UNI = 16 (set by the fixture) can absorb 10
        // per session without saturating in a single tick. Each session
        // opens up to `streams_per_session`.
        for (0..num_sessions) |i| {
            const sid = session_ids[i];
            const wt_ptr = server_wt_by_session.getPtr(sid) orelse continue;
            while (sessions_streamed[i] < streams_per_session) {
                const stream_idx = sessions_streamed[i];
                const stream_id = wt_ptr.openUniStream() catch |err| switch (err) {
                    error.StreamLimitExceeded => break,
                    else => return err,
                };
                var payload_buf: [64]u8 = undefined;
                const payload = try std.fmt.bufPrint(
                    &payload_buf,
                    "session-{d}-stream-{d}",
                    .{ i, stream_idx },
                );
                try wt_ptr.writeStream(stream_id, payload);
                try wt_ptr.finishStream(stream_id);
                sessions_streamed[i] += 1;
            }
        }

        // Client side: collect events. Each `webtransport_stream_opened`
        // must carry a session_id we know about.
        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => {},
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                    // Find which of our sessions this corresponds to.
                    var matched: bool = false;
                    for (session_ids) |s| {
                        if (s == opened.session_id) {
                            matched = true;
                            break;
                        }
                    }
                    try std.testing.expect(matched);
                    const gop = try streams_by_id.getOrPut(allocator, opened.stream_id);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .{
                            .session_id = opened.session_id,
                            .bytes = .empty,
                            .finished = false,
                            .opened = true,
                        };
                    } else {
                        // Two opens for the same stream id would be a routing bug.
                        try std.testing.expect(false);
                    }
                },
                .webtransport_stream_data => |data| {
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, data.kind);
                    const entry = streams_by_id.getPtr(data.stream_id) orelse {
                        // Data before open is a routing bug.
                        return error.UnknownStream;
                    };
                    // Crucially: the data event's session id MUST equal the
                    // open event's session id. Cross-session bleed would
                    // surface here.
                    try std.testing.expectEqual(entry.session_id, data.session_id);
                    try entry.bytes.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    const entry = streams_by_id.getPtr(finished.stream_id) orelse return error.UnknownStream;
                    try std.testing.expectEqual(entry.session_id, finished.session_id);
                    try std.testing.expect(!entry.finished);
                    entry.finished = true;
                    streams_finished_total += 1;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // Verify per-session stream counts and exact payloads.
    var per_session_counts: [num_sessions]usize = @splat(0);
    var it = streams_by_id.valueIterator();
    while (it.next()) |entry| {
        try std.testing.expect(entry.opened);
        try std.testing.expect(entry.finished);
        // Map session id back to the index we created it under.
        var session_idx: ?usize = null;
        for (session_ids, 0..) |s, idx| {
            if (s == entry.session_id) {
                session_idx = idx;
                break;
            }
        }
        try std.testing.expect(session_idx != null);
        const idx = session_idx.?;
        // Payload must start with `session-{idx}-stream-` so we can
        // tell it wasn't routed to a different session.
        var prefix_buf: [32]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "session-{d}-stream-", .{idx});
        try std.testing.expect(std.mem.startsWith(u8, entry.bytes.items, prefix));
        per_session_counts[idx] += 1;
    }
    for (per_session_counts) |c| {
        try std.testing.expectEqual(streams_per_session, c);
    }
    try std.testing.expectEqual(total_expected_streams, streams_by_id.count());
}

test "WebTransport: 3 sessions, one DRAINs while others stay active" {
    // The middle session receives a DRAIN_WEBTRANSPORT_SESSION capsule;
    // its `openUniStream` / `openBidiStream` must fail with
    // `WebTransportSessionDraining`. The other two sessions must still
    // be able to open new streams. This proves DRAIN is per-session
    // bookkeeping in `WTSessionFlowState.received_drain` rather than a
    // connection-wide flag.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const num_sessions: usize = 3;
    var client_sessions: [num_sessions]http3_zig.WebTransportClientStream = undefined;
    var session_ids: [num_sessions]u64 = undefined;

    var paths: [num_sessions][16]u8 = undefined;
    for (0..num_sessions) |i| {
        const path = try std.fmt.bufPrint(&paths[i], "/wt/d{d}", .{i});
        client_sessions[i] = try h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = path,
        });
        session_ids[i] = client_sessions[i].sessionId();
    }

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

    // Pump until all 3 sessions are accepted server-side, then send
    // DRAIN on session index 1, then pump until the client observes
    // DRAIN on session 1's flow state. Track each accepted session.
    var server_wt_by_session: std.AutoHashMapUnmanaged(u64, http3_zig.WebTransportServerStream) = .empty;
    defer server_wt_by_session.deinit(allocator);

    var saw_drain_on_session_1: bool = false;
    var sent_drain: bool = false;
    const drain_index: usize = 1;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_drain_on_session_1) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    const sid = request.streamId();
                    if (request.headers().len > 0 and request.isWebTransport()) {
                        if (!server_wt_by_session.contains(sid)) {
                            const accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                            try server_wt_by_session.put(allocator, sid, accepted);
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (!sent_drain and server_wt_by_session.count() == num_sessions) {
            const sid = session_ids[drain_index];
            const wt_ptr = server_wt_by_session.getPtr(sid).?;
            try wt_ptr.sendDrain();
            sent_drain = true;
        }

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    const sid = response.streamId();
                    if (response.body().len > 0) {
                        // Find which client session this CONNECT stream belongs to.
                        var idx: ?usize = null;
                        for (session_ids, 0..) |s, i| {
                            if (s == sid) {
                                idx = i;
                                break;
                            }
                        }
                        if (idx) |i| {
                            var it = http3_zig.capsule.iter(response.body());
                            while (try it.next()) |decoded| {
                                try client_sessions[i].observeCapsule(decoded.capsule);
                            }
                            if (i == drain_index) {
                                if (client_sessions[i].flowState()) |snap| {
                                    if (snap.received_drain) saw_drain_on_session_1 = true;
                                }
                            }
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // Assertion 1: session 1 (drained) MUST refuse new streams.
    try std.testing.expectError(
        error.WebTransportSessionDraining,
        client_sessions[drain_index].openUniStream(),
    );
    try std.testing.expectError(
        error.WebTransportSessionDraining,
        client_sessions[drain_index].openBidiStream(),
    );

    // Assertion 2: sessions 0 and 2 MUST still be able to open streams.
    // (per-session DRAIN bookkeeping, not connection-wide.)
    for ([_]usize{ 0, 2 }) |i| {
        const flow = client_sessions[i].flowState() orelse return error.MissingFlowState;
        try std.testing.expect(!flow.received_drain);
        // Open one of each kind to prove the gate is open.
        const uni = try client_sessions[i].openUniStream();
        try client_sessions[i].finishStream(uni);
        const bidi = try client_sessions[i].openBidiStream();
        try client_sessions[i].finishStream(bidi);
    }
}

test "WebTransport: 3 sessions, datagrams flow independently" {
    // Each WT session sends 1 datagram with a payload that encodes the
    // session index. The client-side `datagram` events carry the
    // CONNECT stream id (= WT session id, draft §4.3 / RFC 9297) so the
    // application can attribute each payload to its session. We verify
    // exactly 1 datagram per session arrives with the correct payload
    // and stream_id.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    const num_sessions: usize = 3;
    var client_sessions: [num_sessions]http3_zig.WebTransportClientStream = undefined;
    var session_ids: [num_sessions]u64 = undefined;

    var paths: [num_sessions][16]u8 = undefined;
    for (0..num_sessions) |i| {
        const path = try std.fmt.bufPrint(&paths[i], "/wt/g{d}", .{i});
        client_sessions[i] = try h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = path,
        });
        session_ids[i] = client_sessions[i].sessionId();
    }

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

    var server_wt_by_session: std.AutoHashMapUnmanaged(u64, http3_zig.WebTransportServerStream) = .empty;
    defer server_wt_by_session.deinit(allocator);

    var datagrams_sent: usize = 0;
    // Track which session indices we've seen a datagram for.
    var seen_for_session: [num_sessions]bool = @splat(false);
    var datagrams_seen: usize = 0;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (datagrams_seen < num_sessions) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    const sid = request.streamId();
                    if (request.headers().len > 0 and request.isWebTransport()) {
                        if (!server_wt_by_session.contains(sid)) {
                            const accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                            try server_wt_by_session.put(allocator, sid, accepted);
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        // Once all 3 sessions are accepted, send one datagram per
        // session with a session-distinguishing payload.
        if (datagrams_sent == 0 and server_wt_by_session.count() == num_sessions) {
            for (0..num_sessions) |i| {
                const sid = session_ids[i];
                const wt_ptr = server_wt_by_session.getPtr(sid).?;
                var payload_buf: [32]u8 = undefined;
                const payload = try std.fmt.bufPrint(&payload_buf, "datagram-from-session-{d}", .{i});
                try wt_ptr.sendDatagram(payload);
            }
            datagrams_sent = num_sessions;
        }

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => {},
                .datagram => |dg| {
                    // Find which session this datagram belongs to.
                    var idx: ?usize = null;
                    for (session_ids, 0..) |s, i| {
                        if (s == dg.stream_id) {
                            idx = i;
                            break;
                        }
                    }
                    try std.testing.expect(idx != null);
                    const i = idx.?;
                    var expected_buf: [32]u8 = undefined;
                    const expected = try std.fmt.bufPrint(
                        &expected_buf,
                        "datagram-from-session-{d}",
                        .{i},
                    );
                    // Cross-session attribution would surface as a
                    // payload mismatch here.
                    try std.testing.expectEqualStrings(expected, dg.payload);
                    try std.testing.expect(!seen_for_session[i]);
                    seen_for_session[i] = true;
                    datagrams_seen += 1;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    for (seen_for_session) |s| try std.testing.expect(s);
}

test "WebTransport: per-session WT_MAX_STREAMS_UNI applies independently" {
    // Two sessions on the same connection. Server advertises
    // WT_MAX_STREAMS_UNI = 1 to session A and = 8 to session B. Once
    // both limits are observed, the client opens 1 stream on A
    // (success), tries a second on A (must fail with
    // `WebTransportStreamLimitExceeded`), then opens a stream on B
    // (must succeed). This proves the BLOCKED bookkeeping
    // (`flow.local_streams_opened_uni` vs `flow.peer_max_streams_uni`)
    // is per-session — a connection-wide counter would either reject
    // both or accept both.
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);
    var h3_server = http3_zig.Server.init(&pair.server_h3);

    var client_a = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt/a",
    });
    defer client_a.close(0, "done") catch {};
    var client_b = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt/b",
    });
    defer client_b.close(0, "done") catch {};
    const sid_a = client_a.sessionId();
    const sid_b = client_b.sessionId();
    const limit_a: u64 = 1;
    const limit_b: u64 = 8;

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

    var server_wt_by_session: std.AutoHashMapUnmanaged(u64, http3_zig.WebTransportServerStream) = .empty;
    defer server_wt_by_session.deinit(allocator);

    var sent_limits: bool = false;
    var saw_limit_a: bool = false;
    var saw_limit_b: bool = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(saw_limit_a and saw_limit_b)) : (iters += 1) {
        try std.testing.expect(iters < 50_000);
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
                    const sid = request.streamId();
                    if (request.headers().len > 0 and request.isWebTransport()) {
                        if (!server_wt_by_session.contains(sid)) {
                            const accepted = try h3_server.acceptWebTransport(allocator, request, .{});
                            try server_wt_by_session.put(allocator, sid, accepted);
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (!sent_limits and server_wt_by_session.count() == 2) {
            var wt_a = server_wt_by_session.getPtr(sid_a).?;
            try wt_a.sendMaxStreamsUni(limit_a);
            var wt_b = server_wt_by_session.getPtr(sid_b).?;
            try wt_b.sendMaxStreamsUni(limit_b);
            sent_limits = true;
        }

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    const sid = response.streamId();
                    if (response.body().len > 0) {
                        const target: ?*http3_zig.WebTransportClientStream = if (sid == sid_a)
                            &client_a
                        else if (sid == sid_b)
                            &client_b
                        else
                            null;
                        if (target) |wt| {
                            var it = http3_zig.capsule.iter(response.body());
                            while (try it.next()) |decoded| {
                                try wt.observeCapsule(decoded.capsule);
                            }
                            if (wt.flowState()) |snap| {
                                if (sid == sid_a and snap.peer_max_streams_uni == limit_a) saw_limit_a = true;
                                if (sid == sid_b and snap.peer_max_streams_uni == limit_b) saw_limit_b = true;
                            }
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // Now hammer on each session's gate.

    // Session A: limit = 1. First open succeeds, second must fail.
    _ = try client_a.openUniStream();
    try std.testing.expectError(
        error.WebTransportStreamLimitExceeded,
        client_a.openUniStream(),
    );

    // Critically: session B's gate must NOT be affected. With a
    // connection-wide BLOCKED counter we'd see the same error here.
    // Open up to limit_b on B.
    var b_opened: u64 = 0;
    while (b_opened < limit_b) : (b_opened += 1) {
        _ = try client_b.openUniStream();
    }
    // The (limit_b + 1)-th must fail on B itself, proving B's gate is
    // armed at limit_b (not limit_a).
    try std.testing.expectError(
        error.WebTransportStreamLimitExceeded,
        client_b.openUniStream(),
    );

    // And A's flow state should still show only 1 stream opened, with
    // its own limit, not B's.
    const snap_a = client_a.flowState() orelse return error.MissingFlowState;
    try std.testing.expectEqual(@as(u64, 1), snap_a.local_streams_opened_uni);
    try std.testing.expectEqual(@as(?u64, limit_a), snap_a.peer_max_streams_uni);
    const snap_b = client_b.flowState() orelse return error.MissingFlowState;
    try std.testing.expectEqual(limit_b, snap_b.local_streams_opened_uni);
    try std.testing.expectEqual(@as(?u64, limit_b), snap_b.peer_max_streams_uni);
}
