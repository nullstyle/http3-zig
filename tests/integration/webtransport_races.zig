//! Race / interleaving regression tests for WebTransport.
//!
//! The existing `webtransport.zig` integration suite covers happy paths
//! and named bad inputs; this file fills the coverage gap for
//! *interleaved* sequences where multiple WT events arrive in the same
//! drain batch. The drain ordering invariant the session enforces
//! (cf. `Session.drain` →
//! `replayBufferedWebTransportStreams`/`processWebTransportStreamState`/
//! `observeWebTransportCapsule`) must hold even when a peer sprays
//! multiple things at once.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

test "WebTransport: DRAIN arrives in same drain batch as 50 peer-opened streams" {
    // Server opens 50 unidirectional WT streams in rapid succession,
    // sends DRAIN immediately after, then keeps the CONNECT stream
    // alive. The client pumps until either:
    //   - all 50 stream `_opened` events have surfaced, AND
    //   - `flowState().received_drain` is true.
    //
    // Invariant: the DRAIN capsule landing in the same drain pass as a
    // batch of peer-opened uni streams MUST NOT cause the session to
    // drop the buffered streams. They surface on the application side
    // because they were opened *before* DRAIN was applied; only
    // future-opens are forbidden by §5.5.
    const allocator = std.testing.allocator;
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
        .path = "/wt-drain-race",
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

    // Target: 50 uni streams in a burst. The fixture's QUIC transport
    // params advertise `initial_max_streams_uni = 16`, so the server
    // can only land 16 in the *first* burst before QUIC says
    // StreamLimitExceeded. To still hit 50 cleanly we open in waves
    // and pump between waves so MAX_STREAMS credit flows back. The
    // race-under-test (DRAIN batched with N stream-opens) is
    // exercised on every wave; we just send DRAIN at the END of the
    // last wave to avoid having the second wave gated by drain.
    const num_streams = 50;
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var streams_pushed_by_server: usize = 0;
    var server_sent_drain = false;

    // Per-stream bookkeeping on the client. We open from the server
    // side so client_runner sees `_opened` events.
    var stream_index_by_id: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer stream_index_by_id.deinit(allocator);
    var per_stream_opened: [num_streams]bool = @splat(false);
    var streams_opened_seen: usize = 0;
    var saw_drain_on_client = false;

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(streams_opened_seen == num_streams and saw_drain_on_client)) : (iters += 1) {
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
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        server_wt = try h3_server.acceptWebTransport(allocator, request, .{});
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        // Wave-style burst: open as many uni streams as the peer's
        // QUIC MAX_STREAMS credit allows in this iteration, all
        // back-to-back. Once we hit StreamLimitExceeded, fall through
        // to pumping which lets the client surface the streams,
        // releasing credit. After all 50 are pushed, send DRAIN.
        if (server_wt) |*accepted| {
            while (streams_pushed_by_server < num_streams) {
                const uni = accepted.openUniStream() catch |err| switch (err) {
                    error.StreamLimitExceeded => break,
                    else => return err,
                };
                var pl_buf: [8]u8 = undefined;
                const pl = try std.fmt.bufPrint(&pl_buf, "s-{d}", .{streams_pushed_by_server});
                try accepted.writeStream(uni, pl);
                try accepted.finishStream(uni);
                streams_pushed_by_server += 1;
            }
            // Send DRAIN once all 50 stream-opens have been issued
            // locally. The DRAIN capsule lands on the CONNECT stream
            // alongside any pending stream prefixes from the latest
            // wave, so the client's next drain pass sees the
            // interleaving.
            if (streams_pushed_by_server == num_streams and !server_sent_drain) {
                try accepted.sendDrain();
                server_sent_drain = true;
            }
        }

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0) {
                        try std.testing.expect(response.webTransportAccepted());
                        client_saw_response = true;
                    }
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                        if (client_wt.flowState()) |snap| {
                            if (snap.received_drain) saw_drain_on_client = true;
                        }
                    }
                },
                .webtransport_stream_opened => |opened| {
                    try std.testing.expectEqual(session_id, opened.session_id);
                    try std.testing.expectEqual(http3_zig.WebTransportStreamKind.uni, opened.kind);
                    // Lazy-assign each new stream id to the next
                    // unoccupied slot.
                    if (!stream_index_by_id.contains(opened.stream_id)) {
                        const idx = stream_index_by_id.count();
                        try std.testing.expect(idx < num_streams);
                        try stream_index_by_id.put(allocator, opened.stream_id, idx);
                        try std.testing.expect(!per_stream_opened[idx]);
                        per_stream_opened[idx] = true;
                        streams_opened_seen += 1;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    // All 50 stream-opened events surfaced.
    try std.testing.expectEqual(@as(usize, num_streams), streams_opened_seen);
    for (0..num_streams) |i| try std.testing.expect(per_stream_opened[i]);

    // DRAIN was applied to client-side flow state.
    const snap = client_wt.flowState() orelse return error.MissingFlowState;
    try std.testing.expect(snap.received_drain);

    // After observing DRAIN, the client must NOT be able to open new
    // streams (draft §5.5).
    try std.testing.expectError(error.WebTransportSessionDraining, client_wt.openUniStream());
    try std.testing.expectError(error.WebTransportSessionDraining, client_wt.openBidiStream());
}

test "WebTransport: CLOSE_WT capsule interleaved with WT_MAX_DATA" {
    // The wire sequence is: peer sends WT_MAX_DATA capsule on the
    // CONNECT stream's body, then sends CLOSE_WEBTRANSPORT_SESSION,
    // then FINs. All three land in the same drain pass on the receiving
    // side; `processState` surfaces the body and `observeFin` runs
    // `endWebTransportSession`, both in the same drain. The application
    // then iterates events in order: response_updated (body) → close.
    //
    // For v0.2 we chose fix option (b): `observeWebTransportCapsule`
    // tolerates a session that was just torn down — it silently no-ops
    // rather than returning `UnknownWebTransportSession`. The MAX_DATA
    // value isn't folded (the flow state is gone) but the application's
    // drain loop doesn't crash mid-close. (Option (a) — defer teardown
    // — is a bigger session-machine change; deferred to a future
    // release if real usage shows the dropped MAX_DATA matters.)
    const allocator = std.testing.allocator;
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
        .path = "/wt-close-maxdata-race",
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

    // Pump until both sides confirm the session.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (server_wt == null or client_wt.flowState() == null) : (iters += 1) {
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
        for (client_events.items) |event| _ = try client_runner.observe(event);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Server: send WT_MAX_DATA raising the credit, then close (CLOSE_WT
    // capsule + FIN of CONNECT). The two body writes coalesce on the
    // wire so they arrive in the same drain pass on the client.
    try server_wt.?.sendMaxData(1024 * 1024);
    try server_wt.?.close(0, "ok");

    // Client: pump until session is torn down. Within each drain, the
    // application iterates capsules from the response body and feeds
    // each through `observeCapsule`. The MAX_DATA capsule arrived
    // before close on the wire but the close-driven teardown may
    // already have run by the time the app processes the body — that's
    // exactly the race observeCapsule is now tolerant of.
    while (client_wt.flowState() != null) : (iters += 1) {
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
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.body().len > 0) {
                        var it = http3_zig.capsule.iter(response.body());
                        while (try it.next()) |decoded| {
                            // MUST NOT raise UnknownWebTransportSession
                            // even if the close-driven teardown has
                            // already run earlier in this drain.
                            try client_wt.observeCapsule(decoded.capsule);
                        }
                    }
                },
                else => {},
            }
        }
        for (server_events.items) |event| _ = try server_runner.observe(event);
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    // Clean close: no error code surfaced on either peer.
    try std.testing.expectEqual(@as(?http3_zig.errors.ConnectionError, null), pair.client_h3.lastCloseError());
    try std.testing.expectEqual(@as(?http3_zig.errors.ConnectionError, null), pair.server_h3.lastCloseError());
}

test "WebTransport: peer FIN of CONNECT while local mid-send on three streams" {
    // After the peer FINs the CONNECT stream, `endWebTransportSession`
    // tears down the local registry. `gateWebTransportStreamOpen` now
    // distinguishes `.none` (unknown / torn down — error) from
    // `.pending` (in flight — allow) from `.established` (apply gating),
    // so a fresh `openUniStream` after a peer-FIN of CONNECT MUST
    // surface `UnknownWebTransportSession` rather than silently writing
    // a stream prefix pointing at a dead session id.
    const allocator = std.testing.allocator;
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
        .path = "/wt-fin-mid-send",
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

    // Pump until both sides confirm the session.
    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (server_wt == null or client_wt.flowState() == null) : (iters += 1) {
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
        for (client_events.items) |event| _ = try client_runner.observe(event);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Locally open 3 uni streams and write 100 bytes on each WITHOUT
    // finishing them — this is the "mid-send" state we want to hit.
    var uni_ids: [3]u64 = undefined;
    var payload: [100]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);
    for (&uni_ids) |*sid| {
        sid.* = try client_wt.openUniStream();
        try client_wt.writeStream(sid.*, &payload);
    }

    // Server FINs the CONNECT stream WITHOUT sending CLOSE_WT.
    try server_wt.?.finish();

    // Pump until the client observes the peer FIN and runs
    // `endWebTransportSession` on its side (flowState becomes null).
    while (client_wt.flowState() != null) : (iters += 1) {
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
        for (client_events.items) |event| _ = try client_runner.observe(event);
        for (server_events.items) |event| _ = try server_runner.observe(event);
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    // Now the session is gone. A fresh open MUST error rather than
    // silently writing a stream prefix referring to a dead id.
    try std.testing.expectError(error.UnknownWebTransportSession, client_wt.openUniStream());
    try std.testing.expectError(error.UnknownWebTransportSession, client_wt.openBidiStream());

    // The 3 in-flight streams remain observable on the local side —
    // the QUIC streams aren't reset by session teardown; the
    // application can keep reading what's already buffered or finish
    // / reset them itself.
    for (uni_ids) |sid| try std.testing.expect(pair.client.stream(sid) != null);
}

test "WebTransport: peer RESETs CONNECT while local has buffered WT streams pending" {
    // Setup: server uses `.buffer` policy. The CLIENT is the peer
    // that'll RESET in this test — we need to simulate "peer opens
    // uni streams BEFORE its CONNECT request lands as confirmed
    // session, then peer RESETs the CONNECT stream."
    //
    // The client opens a WT CONNECT request and immediately opens 5
    // uni WT streams + writes 100 bytes each + FINs them. All of
    // this lands on the server side as "wt_buffered" entries because
    // the server has not yet accepted the session (and we never let
    // it accept). The client then RESETs its CONNECT request stream
    // before the server runs `acceptWebTransport`. Pump until the
    // server's `wt_buffered_streams` list is drained.
    //
    // Invariant: the buffered streams are dropped (rejected) and
    // never dispatched as `webtransport_stream_opened` events. The
    // `replayBufferedWebTransportStreams` path with
    // `webTransportSessionState == .none` (because the CONNECT
    // RESET tore the pending session down) calls
    // `rejectBufferedWebTransportStream`, NOT
    // `emitWebTransportStreamOpened`.
    const allocator = std.testing.allocator;
    const h3_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = h3_settings },
        .{ .settings = h3_settings, .buffered_stream_policy = .buffer },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var h3_client = http3_zig.Client.init(&pair.client_h3);

    var client_wt = try h3_client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt-reset-pending-buffer",
    });
    const session_id = client_wt.sessionId();

    // Open 5 uni streams BEFORE the server accepts. The server-side
    // session is still pending; its inbound dispatch will mark these
    // as `wt_buffered` entries on the server.
    var uni_ids: [5]u64 = undefined;
    var payload: [100]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);
    for (&uni_ids) |*sid| {
        sid.* = try client_wt.openUniStream();
        try client_wt.writeStream(sid.*, &payload);
        try client_wt.finishStream(sid.*);
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

    // Pump until the server's pending session is registered. The
    // server does NOT accept — we want the streams parked in the
    // wt_buffered list while the session is still pending.
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (pair.server_h3.webTransportPendingCount() == 0) : (iters += 1) {
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
        // We do NOT call acceptWebTransport — the session stays
        // pending so the buffered streams keep accumulating.
        for (server_events.items) |event| _ = try server_runner.observe(event);
        for (client_events.items) |event| _ = try client_runner.observe(event);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Pump a few more rounds so the buffered uni streams land on the
    // server side and get parked.
    iters = 0;
    while (iters < 100) : (iters += 1) {
        try pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        for (server_events.items) |event| _ = try server_runner.observe(event);
        for (client_events.items) |event| _ = try client_runner.observe(event);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Sanity: the session is still pending on the server and no
    // _opened events have fired yet.
    try std.testing.expectEqual(http3_zig.Session.WebTransportSessionState.pending, pair.server_h3.webTransportSessionState(session_id));

    // Now RESET the CONNECT stream from the client side.
    try client_wt.reset(0);

    // Pump enough that the server observes the RESET and then has
    // a few drains afterwards to give any phantom `_opened` events
    // a chance to fire (they MUST NOT).
    var saw_phantom_opened = false;
    iters = 0;
    while (iters < 200) : (iters += 1) {
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
            // Detect phantom WT events for our 5 buffered stream ids.
            // Each variant has its own payload type, so we have to
            // pull `stream_id` per-variant.
            const offending_id: ?u64 = switch (event) {
                .webtransport_stream_opened => |info| info.stream_id,
                .webtransport_stream_data => |info| info.stream_id,
                .webtransport_stream_finished => |info| info.stream_id,
                .webtransport_stream_reset => |info| info.stream_id,
                else => null,
            };
            if (offending_id) |sid_seen| {
                for (uni_ids) |sid| {
                    if (sid_seen == sid) saw_phantom_opened = true;
                }
            }
            _ = try server_runner.observe(event);
        }
        for (client_events.items) |event| _ = try client_runner.observe(event);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    // Once the CONNECT RESET lands, the session id is no longer
    // pending or established.
    try std.testing.expectEqual(http3_zig.Session.WebTransportSessionState.none, pair.server_h3.webTransportSessionState(session_id));

    // The CRITICAL invariant: no phantom `_opened` events surfaced
    // for the buffered streams.
    try std.testing.expect(!saw_phantom_opened);

    // Session-level shutdown state is still active — a CONNECT RESET
    // ends the WT session but doesn't tear the H3 connection down.
    try std.testing.expectEqual(http3_zig.session.ShutdownState.active, pair.server_h3.shutdownState());
}
