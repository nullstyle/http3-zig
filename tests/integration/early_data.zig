//! Wrapper-based 0-RTT HTTP/3 integration test — real packets, real early
//! data (RFC 9114 §7.2.4.2).
//!
//! The other integration files drive an in-process crypto shim that only
//! shuttles CRYPTO bytes between two `quic.Connection`s, so 0-RTT stream
//! data — which rides real 0-RTT packets, not CRYPTO frames — can never
//! flow through them. This file instead drives the public `quic.Client` /
//! `quic.Server` wrappers with real packet pumping, transcribed from the
//! proven quic-zig reference (`tests/e2e/zero_rtt_wrapper.zig`), and layers
//! `http3_zig.Session` on the wrapper connections:
//!
//!   1. EARN — connection 1 completes a normal handshake plus H3 SETTINGS
//!      exchange; `Client.Config.new_session_callback` and the client
//!      session's `peer_settings` event feed `earlydata.TicketBinder`,
//!      which pairs them into the `H3RS` envelope.
//!   2. ACCEPT — connection 2 decodes the envelope, resumes via
//!      `Client.Config.resumption_state`, installs the remembered peer
//!      SETTINGS with `Session.rememberPeerSettings`, and stages the H3
//!      control stream + a GET BEFORE the first `advance()` so both ride
//!      the coalesced ClientHello + 0-RTT flight. The decisive assertion:
//!      the server-side session surfaces the request `headers` event while
//!      its transport handshake is still incomplete — only accepted 0-RTT
//!      can do that.
//!   3. REJECT — the same envelope against a fresh `quic.Server` (fresh
//!      session-ticket keys ⇒ ticket undecryptable ⇒ 0-RTT rejected). The
//!      client drains `Event.early_data{.rejected}`, quic replays the
//!      staged request verbatim at 1-RTT, and NO H3_SETTINGS_ERROR occurs
//!      even though the fresh server's SETTINGS reduce the remembered ones
//!      (§7.2.4.2 ¶7: rejection discards the remembered state).
//!   4. PIN — the settings-identity pin: the original server (same ticket
//!      keys) with `early_data_application_context` re-pointed at a digest
//!      of different SETTINGS. The ticket decrypts, but the RFC 9001
//!      §4.6.1 context digest no longer matches, so 0-RTT is rejected at
//!      the transport — the H3 violation path is never reached.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");
const fixt = @import("_fixtures.zig");

const earlydata = http3_zig.earlydata;
const Settings = http3_zig.settings.Settings;
const Event = http3_zig.session.Event;

const protos = [_][]const u8{"h3"};
const response_body = "early-ok";
const response_fields = [_]http3_zig.FieldLine{
    .{ .name = ":status", .value = "200" },
};

/// Mirrors the reference test's baseline transport parameters.
fn defaultParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}

/// The H3 SETTINGS the ticket is minted under ("settings A"). Deliberately
/// non-default so the rejection scenarios exercise the remembered-vs-actual
/// comparison across a real reduction: a server running defaults would
/// violate these on every axis below if 0-RTT were (incorrectly) treated
/// as accepted.
fn settingsA() Settings {
    return .{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 1 << 14,
    };
}

/// `Client.Config.new_session_callback` trampoline: latch the quic
/// resumption envelope into the `TicketBinder` (bytes are borrowed during
/// the call; the binder copies them out).
fn captureTicket(user_data: ?*anyopaque, resumption_state: []const u8) void {
    const binder: *earlydata.TicketBinder = @ptrCast(@alignCast(user_data.?));
    binder.onSessionTicket(resumption_state) catch {};
}

fn pumpClientToServer(
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    addr: quic.conn.path.Address,
    now_us: u64,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
    }
}

fn pumpServerToClient(
    srv: *quic.Server,
    cli: *quic.Client,
    rx: []u8,
    now_us: u64,
) !void {
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
        }
    }
}

const ResumedParams = struct {
    /// The `H3RS` envelope earned by connection 1.
    envelope: []const u8,
    /// H3 SETTINGS the server-side session on this connection uses.
    settings: Settings,
    addr: quic.conn.path.Address,
    path: []const u8,
    now_base: u64,
};

const ResumedOutcome = struct {
    request_stream_id: u64,
    /// Client-side `Event.early_data` payload (`reason` is static
    /// storage, safe to hold past `clearEvents`).
    early_event: ?http3_zig.session.EarlyDataEvent = null,
    /// Emitted at most once per session — the count proves it.
    early_event_count: u32 = 0,
    /// `Session.earlyDataStatus` snapshot after the exchange completed.
    quic_status: ?quic.EarlyDataStatus = null,
    server_saw_request: bool = false,
    /// True when the server session surfaced the request `headers` event
    /// while its own transport handshake was still incomplete — only
    /// accepted 0-RTT can deliver request bytes that early.
    request_before_server_handshake_done: bool = false,
    /// `FieldEvent.arrived_in_early_data` on the request headers event.
    headers_flag_early: bool = false,
    /// `Session.requestArrivedInEarlyData` sampled at headers time.
    session_flag_early: ?bool = null,
    response_headers_seen: bool = false,
    response_body_ok: bool = false,
    response_finished: bool = false,
    /// `Session.lastCloseError() != null` after the exchange (an
    /// H3_SETTINGS_ERROR close would flip this). Pessimistic default so a
    /// helper bug cannot fake a pass.
    client_h3_closed: bool = true,
    /// Transport `isClosed()` before the deliberate teardown close.
    client_conn_closed: bool = true,
};

/// One resumed connection against `srv`: decode the envelope, connect with
/// `resumption_state`, stage the H3 control stream + a GET before the
/// first `advance()` (so they ride the 0-RTT flight when the server
/// accepts it), pump to completion, then close and reap so the caller's
/// next connection runs against a clean slot table. Whether 0-RTT was
/// accepted or rejected is reported, not asserted — callers own the
/// per-scenario assertions.
fn runResumedExchange(
    allocator: std.mem.Allocator,
    srv: *quic.Server,
    params: ResumedParams,
) !ResumedOutcome {
    const decoded = try earlydata.decode(params.envelope);

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // The wrapper installs the ticket, enables early data on conn and
        // TLS context, and bounds 0-RTT sends by the remembered peer
        // transport parameters — no manual `setEarlyDataEnabled` needed.
        .resumption_state = decoded.quic_resumption_state,
    });
    defer cli.deinit();

    var client_h3 = http3_zig.Session.init(allocator, .client, cli.conn, .{
        .enable_grease = false,
    });
    defer client_h3.deinit();
    // §7.2.4.2 ¶5: comply with the ticket-issuing connection's SETTINGS
    // until the resumed connection's real SETTINGS arrive. Must land
    // before any SETTINGS exchange, so: right after init.
    try client_h3.rememberPeerSettings(decoded.settings);

    // Stage the H3 control stream (client SETTINGS) and the request
    // BEFORE the first advance — only then does the first flight coalesce
    // ClientHello + 0-RTT stream data.
    try client_h3.start();
    const request_fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = params.path },
    };
    const request_stream_id = try client_h3.openRequest(&request_fields);
    try client_h3.finishStream(request_stream_id);
    try cli.conn.advance();

    var out: ResumedOutcome = .{ .request_stream_id = request_stream_id };

    var server_h3: ?http3_zig.Session = null;
    defer if (server_h3) |*sess| sess.deinit();

    var client_events: std.ArrayList(Event) = .empty;
    defer {
        fixt.clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(Event) = .empty;
    defer {
        fixt.clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var rx: [4096]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var body_len: usize = 0;
    var now_us: u64 = params.now_base;

    var iters: u32 = 0;
    while (out.early_event == null or !out.server_saw_request or
        !out.response_headers_seen or !out.response_finished) : (iters += 1)
    {
        try std.testing.expect(iters < 96);

        try pumpClientToServer(&cli, srv, &rx, params.addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}

        // Layer the server-side session on the accepted slot the moment
        // it exists — pre-handshake, so an accepted 0-RTT request is
        // read while the handshake is still in flight.
        if (server_h3 == null and srv.iterator().len > 0) {
            server_h3 = http3_zig.Session.init(allocator, .server, srv.iterator()[0].conn, .{
                .settings = params.settings,
                .enable_grease = false,
            });
            try server_h3.?.start();
        }
        if (server_h3) |*sess| {
            try sess.drain(&server_events);
            for (server_events.items) |event| switch (event) {
                .headers => |h| if (h.kind == .request and !out.server_saw_request) {
                    out.server_saw_request = true;
                    out.request_before_server_handshake_done = !sess.quic.handshakeDone();
                    out.headers_flag_early = h.arrived_in_early_data;
                    out.session_flag_early = sess.requestArrivedInEarlyData(h.stream_id);
                    try sess.sendResponseHeaders(h.stream_id, &response_fields);
                    try sess.sendResponseData(h.stream_id, response_body);
                    try sess.finishStream(h.stream_id);
                },
                else => {},
            };
            fixt.clearSessionEvents(allocator, &server_events);
        }

        try pumpServerToClient(srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        try client_h3.drain(&client_events);
        for (client_events.items) |event| switch (event) {
            .early_data => |ed| {
                out.early_event = ed;
                out.early_event_count += 1;
            },
            .headers => |h| if (h.kind == .response and h.stream_id == request_stream_id) {
                out.response_headers_seen = true;
            },
            .data => |d| if (d.kind == .response and d.stream_id == request_stream_id) {
                const n = @min(d.data.len, body_buf.len - body_len);
                @memcpy(body_buf[body_len..][0..n], d.data[0..n]);
                body_len += n;
            },
            .stream_finished => |f| if (f.stream_id == request_stream_id) {
                out.response_finished = true;
            },
            else => {},
        };
        fixt.clearSessionEvents(allocator, &client_events);

        now_us += 1_000;
    }

    out.response_body_ok = std.mem.eql(u8, body_buf[0..body_len], response_body);
    out.quic_status = client_h3.earlyDataStatus();
    out.client_h3_closed = client_h3.lastCloseError() != null;
    out.client_conn_closed = cli.conn.isClosed();

    // Transport-level teardown + reap so the caller's next connection
    // runs against a clean slot table (mirrors the reference test).
    cli.conn.close(false, 0, "done");
    var close_iters: u32 = 0;
    while (srv.connectionCount() > 0) : (close_iters += 1) {
        try std.testing.expect(close_iters < 32);
        try pumpClientToServer(&cli, srv, &rx, params.addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try pumpServerToClient(srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        _ = srv.reap();
        now_us += 500_000;
    }

    return out;
}

test "0-RTT: H3 ticket capture, early-data accept, rejection recovery, and settings-context pin through the quic wrappers" {
    const allocator = std.testing.allocator;

    // One settings constant, two consumers: the same value feeds the
    // server sessions AND the early-data application context, per the
    // `server.earlyDataApplicationContext` contract.
    var ctx_a_buf: [256]u8 = undefined;
    const ctx_a = try http3_zig.server.earlyDataApplicationContext(&ctx_a_buf, settingsA());

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = fixt.test_cert_pem,
        .tls_key_pem = fixt.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // No anti-replay tracker in-test: every request here is a GET.
        .early_data = .without_replay_protection,
        .early_data_application_context = ctx_a,
    });
    defer srv.deinit();

    var binder = earlydata.TicketBinder.init(allocator);
    defer binder.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };

    // ---- Connection 1 (EARN): normal handshake + H3 SETTINGS exchange;
    // the binder pairs the NewSessionTicket envelope (wrapper callback)
    // with the server's SETTINGS (peer_settings event). ----
    {
        var cli = try quic.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test cert
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = defaultParams(),
            .new_session_callback = captureTicket,
            .new_session_user_data = &binder,
        });
        defer cli.deinit();

        var client_h3 = http3_zig.Session.init(allocator, .client, cli.conn, .{
            .enable_grease = false,
        });
        defer client_h3.deinit();
        var client_started = false;

        var server_h3: ?http3_zig.Session = null;
        defer if (server_h3) |*sess| sess.deinit();

        var client_events: std.ArrayList(Event) = .empty;
        defer {
            fixt.clearSessionEvents(allocator, &client_events);
            client_events.deinit(allocator);
        }
        var server_events: std.ArrayList(Event) = .empty;
        defer {
            fixt.clearSessionEvents(allocator, &server_events);
            server_events.deinit(allocator);
        }

        try cli.conn.advance();
        var now_us: u64 = 1_000;
        var iters: u32 = 0;
        // Keep pumping past handshake completion so the NewSessionTicket
        // flight reaches the client and both binder halves latch.
        while (!binder.ready()) : (iters += 1) {
            try std.testing.expect(iters < 64);

            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            while (srv.drainStatelessResponse()) |_| {}

            if (server_h3 == null and srv.iterator().len > 0 and
                srv.iterator()[0].conn.handshakeDone())
            {
                server_h3 = http3_zig.Session.init(allocator, .server, srv.iterator()[0].conn, .{
                    .settings = settingsA(),
                    .enable_grease = false,
                });
                try server_h3.?.start();
            }
            if (server_h3) |*sess| {
                try sess.drain(&server_events);
                fixt.clearSessionEvents(allocator, &server_events);
            }

            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);

            if (!client_started and cli.conn.handshakeDone()) {
                try client_h3.start();
                client_started = true;
            }
            try client_h3.drain(&client_events);
            for (client_events.items) |event| switch (event) {
                .peer_settings => |s| binder.onPeerSettings(s),
                else => {},
            };
            fixt.clearSessionEvents(allocator, &client_events);

            now_us += 1_000;
        }
        try std.testing.expect(cli.conn.handshakeDone());

        // Close connection 1 and let the server reap it so the resumed
        // connections below run against a clean slot table.
        cli.conn.close(false, 0, "done");
        var close_iters: u32 = 0;
        while (srv.connectionCount() > 0) : (close_iters += 1) {
            try std.testing.expect(close_iters < 32);
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            while (srv.drainStatelessResponse()) |_| {}
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            _ = srv.reap();
            now_us += 500_000;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // The combined H3RS envelope: remembered SETTINGS + quic QZRS bytes.
    const envelope = (try binder.tryEncode(allocator)).?;
    defer allocator.free(envelope);
    {
        const decoded = try earlydata.decode(envelope);
        try std.testing.expect(std.meta.eql(settingsA(), decoded.settings));
    }

    // ---- Connection 2 (ACCEPT): resume against the ticket-issuing
    // server with the request staged pre-advance. ----
    const accept_out = try runResumedExchange(allocator, &srv, .{
        .envelope = envelope,
        .settings = settingsA(),
        .addr = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } },
        .path = "/early",
        .now_base = 60_000_000,
    });
    try std.testing.expect(accept_out.server_saw_request);
    // The decisive check: the request surfaced before the server's
    // handshake completed — real early data, not a fast 1-RTT.
    try std.testing.expect(accept_out.request_before_server_handshake_done);
    try std.testing.expect(accept_out.headers_flag_early);
    try std.testing.expectEqual(@as(?bool, true), accept_out.session_flag_early);
    try std.testing.expectEqual(@as(u32, 1), accept_out.early_event_count);
    try std.testing.expectEqual(
        http3_zig.session.EarlyDataEvent.Status.accepted,
        accept_out.early_event.?.status,
    );
    try std.testing.expectEqualStrings("", accept_out.early_event.?.reason);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, accept_out.quic_status.?);
    try std.testing.expect(accept_out.response_headers_seen);
    try std.testing.expect(accept_out.response_body_ok);
    try std.testing.expect(accept_out.response_finished);
    try std.testing.expect(!accept_out.client_h3_closed);
    try std.testing.expect(!accept_out.client_conn_closed);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // ---- Connection 3 (REJECT): the same envelope against a fresh
    // server — fresh session-ticket keys, so the ticket cannot be
    // decrypted and 0-RTT is rejected (the routine restart scenario).
    // The fresh server runs DEFAULT H3 settings, which reduce every
    // remembered settings-A axis — the §7.2.4.2 ¶7 proof that rejection
    // discards the remembered state instead of raising
    // H3_SETTINGS_ERROR. ----
    var ctx_default_buf: [256]u8 = undefined;
    const ctx_default = try http3_zig.server.earlyDataApplicationContext(&ctx_default_buf, .{});

    var srv2 = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = fixt.test_cert_pem,
        .tls_key_pem = fixt.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .early_data = .without_replay_protection,
        .early_data_application_context = ctx_default,
    });
    defer srv2.deinit();

    const reject_out = try runResumedExchange(allocator, &srv2, .{
        .envelope = envelope,
        .settings = .{},
        .addr = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } },
        .path = "/reject",
        .now_base = 120_000_000,
    });
    try std.testing.expectEqual(@as(u32, 1), reject_out.early_event_count);
    try std.testing.expectEqual(
        http3_zig.session.EarlyDataEvent.Status.rejected,
        reject_out.early_event.?.status,
    );
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, reject_out.quic_status.?);
    // Recovery contract: quic replays the staged request verbatim at
    // 1-RTT and the exchange still completes — with no early-data
    // provenance on the server side, and no H3-level close despite the
    // settings reduction.
    try std.testing.expect(reject_out.server_saw_request);
    try std.testing.expect(!reject_out.request_before_server_handshake_done);
    try std.testing.expect(!reject_out.headers_flag_early);
    try std.testing.expectEqual(@as(?bool, false), reject_out.session_flag_early);
    try std.testing.expect(reject_out.response_headers_seen);
    try std.testing.expect(reject_out.response_body_ok);
    try std.testing.expect(reject_out.response_finished);
    try std.testing.expect(!reject_out.client_h3_closed);
    try std.testing.expect(!reject_out.client_conn_closed);

    // ---- Connection 4 (PIN): settings-identity pin. Same server as the
    // ticket (same session-ticket keys — the ticket itself decrypts),
    // but its early-data application context now digests DEFAULT
    // settings instead of settings A, and its H3 session serves those
    // defaults. `Server.early_data_application_context` is a public
    // wrapper field the accept path re-reads per fresh slot (installed
    // before ClientHello processing), so re-pointing it between
    // connections models a settings change across a deploy. Expected —
    // and asserted — outcome: the RFC 9001 §4.6.1 equality digest
    // differs, so 0-RTT is rejected AT THE TRANSPORT; the session still
    // resumes, the request completes at 1-RTT, and the
    // H3_SETTINGS_ERROR violation path is structurally unreachable. ----
    srv.early_data_application_context = ctx_default;

    const pin_out = try runResumedExchange(allocator, &srv, .{
        .envelope = envelope,
        .settings = .{},
        .addr = .{ .ipv4 = .{ .addr = @splat(0x44), .port = 4444 } },
        .path = "/pin",
        .now_base = 180_000_000,
    });
    try std.testing.expectEqual(@as(u32, 1), pin_out.early_event_count);
    try std.testing.expectEqual(
        http3_zig.session.EarlyDataEvent.Status.rejected,
        pin_out.early_event.?.status,
    );
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, pin_out.quic_status.?);
    try std.testing.expect(pin_out.server_saw_request);
    try std.testing.expect(!pin_out.request_before_server_handshake_done);
    try std.testing.expect(!pin_out.headers_flag_early);
    try std.testing.expectEqual(@as(?bool, false), pin_out.session_flag_early);
    try std.testing.expect(pin_out.response_headers_seen);
    try std.testing.expect(pin_out.response_body_ok);
    try std.testing.expect(pin_out.response_finished);
    try std.testing.expect(!pin_out.client_h3_closed);
    try std.testing.expect(!pin_out.client_conn_closed);
}
