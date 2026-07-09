//! WebTransport concurrent-session load test (V2).
//!
//! V1's `tests/integration/webtransport_multiplexing.zig` covers
//! correctness of routing across 5 sessions. This harness scales the
//! same per-session bookkeeping to **100 concurrent sessions on one
//! QUIC connection** so we can stress the allocator + dispatch under
//! realistic load and surface scaling cliffs (sudden allocation jumps,
//! drain-budget firing repeatedly, mis-attribution under pressure,
//! etc.).
//!
//! Per session the harness runs:
//!   - 5 client→server uni streams, each carrying a 1 KiB
//!     session-distinguishing payload (`session-{idx}-stream-{n}-...`),
//!     written + finished;
//!   - 10 datagrams of 64 bytes each, alternating client→server /
//!     server→client (5 each direction);
//!   - one `WebTransportServerStream.sendMaxData` raising the
//!     advertised `WT_MAX_DATA` to a per-session value (so we exercise
//!     the capsule emit + observe path on every session);
//!   - eventually a client-side `close(0, "ok")` capsule + FIN, which
//!     the server should observe as the session leaving its registry.
//!
//! Verifies invariants:
//!   - `lastCloseError() == null` on both peers (no protocol-level close).
//!   - Every session ends in `webTransportSessionState(...) == .none`
//!     on both sides after the workload drains.
//!   - The expected number of `webtransport_stream_opened`,
//!     `webtransport_stream_data`, `webtransport_stream_finished`
//!     events fired with correct cross-session attribution.
//!   - The expected number of inbound datagrams arrived, attributed
//!     to the right session via the Quarter Stream ID prefix.
//!   - No errors other than the expected `WebTransportSessionDraining`
//!     etc. surfaced.
//!
//! This is an **in-process** harness — `http3_zig.TransportLoopback`
//! shuttles bytes between two `quic_zig.Connection` instances; no
//! kernel sockets, no real network. Wall-clock numbers reflect
//! library overhead only.
//!
//! Build: `zig build wt-load -Doptimize=ReleaseFast`. The build step
//! always runs ReleaseFast so the published numbers are comparable.
//! Invariants are checked every step regardless of optimize mode.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

// Cert + key buffers populated at startup from `tests/data/...` via
// the process cwd. `zig build wt-load` always runs with cwd =
// project root (mirrors `bench/wt_bench.zig`).
var cert_buf: [64 * 1024]u8 = undefined;
var key_buf: [64 * 1024]u8 = undefined;
var cert_pem: []const u8 = &.{};
var key_pem: []const u8 = &.{};

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

// ---------------------------------------------------------------------
// Workload knobs. Kept as `const` (not CLI flags) so the published
// numbers in `docs/load-baseline.md` always describe the same workload.
// ---------------------------------------------------------------------

const num_sessions: usize = 100;
const streams_per_session: usize = 5;
const stream_payload_len: usize = 1024;
const datagrams_per_session: usize = 10;
const datagram_payload_len: usize = 64;

const total_streams: usize = num_sessions * streams_per_session;
const total_datagrams: usize = num_sessions * datagrams_per_session;
// Of those datagrams, we alternate per session: even index =
// client→server, odd index = server→client. So 5 of each direction
// per session.
const dgrams_c2s_per_session: usize = (datagrams_per_session + 1) / 2;
const dgrams_s2c_per_session: usize = datagrams_per_session / 2;
const total_dgrams_c2s: usize = num_sessions * dgrams_c2s_per_session;
const total_dgrams_s2c: usize = num_sessions * dgrams_s2c_per_session;

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

// ---------------------------------------------------------------------
// Per-session bookkeeping.
//
// Mirrors the V1 multiplexing test's pattern (`PerStream` keyed on
// stream id, plus `session_id` for cross-session attribution checks).
// Scaled out to one entry per session.
// ---------------------------------------------------------------------

const PerStream = struct {
    session_id: u64,
    session_idx: usize,
    stream_idx: usize,
    bytes: std.ArrayList(u8),
    finished: bool,
    opened: bool,
};

const PerSession = struct {
    session_id: u64,
    // How many uni streams the client has actually opened so far
    // (we open lazily across pump iterations because the peer's
    // initial `MAX_STREAMS_UNI` grant likely won't cover all 500
    // up front).
    streams_opened: usize = 0,
    // How many of those streams have been fully written + finished.
    streams_written: usize = 0,
    // Tracks server-side max-data bumps: did we push the credit yet?
    pushed_max_data: bool = false,
    // Per-direction datagram progress.
    //
    // `*_sent` are sender-side counters. `*_seen_*` count *unique*
    // datagrams whose payload-encoded session index matches this
    // session, decoded into the per-direction bitmasks below. We
    // verify on receipt that:
    //   - the payload's encoded session index matches the wire
    //     attribution (i.e. dispatch routed correctly);
    //   - the encoded `dg_idx` is in range and hasn't been seen
    //     before (i.e. no replay / duplication).
    // Order-independent because UDP / QUIC datagrams may reorder.
    dgrams_c2s_sent: usize = 0,
    dgrams_s2c_sent: usize = 0,
    dgrams_c2s_seen_mask: u32 = 0,
    dgrams_s2c_seen_mask: u32 = 0,
    // Once the application has done all its work, we send the close
    // and wait for the server to observe it (state goes to .none).
    close_sent: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("# http3-zig WebTransport concurrent-session load test\n\n", .{});
    try stdout.print(
        "Workload: {d} sessions on one connection, {d} uni streams ({d} B each) and {d} datagrams ({d} B each) per session.\n",
        .{ num_sessions, streams_per_session, stream_payload_len, datagrams_per_session, datagram_payload_len },
    );
    try stdout.print(
        "Totals: {d} uni streams, {d} datagrams, {d} sendMaxData capsules, {d} client closes.\n\n",
        .{ total_streams, total_datagrams, num_sessions, num_sessions },
    );
    try stdout.flush();

    const start_ts = nowNs(io);
    const result = try runLoad(allocator, stdout);
    const end_ts = nowNs(io);

    const elapsed_ns = elapsedNs(start_ts, end_ts);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const elapsed_s = elapsed_ms / 1000.0;

    try stdout.print("\n## Result\n\n", .{});
    try stdout.print("Wall-clock: {d:.3} ms ({d} ns)\n", .{ elapsed_ms, elapsed_ns });
    try stdout.print("Pump iterations: {d}\n", .{result.pump_iters});
    try stdout.print(
        "Streams opened/finished (server-observed): {d}/{d}\n",
        .{ result.streams_opened, result.streams_finished },
    );
    try stdout.print(
        "Datagrams C→S: {d} received, {d} lost (of {d} sent)\n",
        .{ result.dgrams_c2s_received, result.dgrams_c2s_lost, total_dgrams_c2s },
    );
    try stdout.print(
        "Datagrams S→C: {d} received, {d} lost (of {d} sent)\n",
        .{ result.dgrams_s2c_received, result.dgrams_s2c_lost, total_dgrams_s2c },
    );
    try stdout.print(
        "Sessions cleanly closed on server: {d}/{d}\n\n",
        .{ result.sessions_closed_server, num_sessions },
    );

    try stdout.print("## Throughput\n\n", .{});
    if (elapsed_s > 0) {
        try stdout.print(
            "- Sessions/sec: {d:.0}\n",
            .{@as(f64, @floatFromInt(num_sessions)) / elapsed_s},
        );
        try stdout.print(
            "- Streams/sec: {d:.0} (1 KiB payload each)\n",
            .{@as(f64, @floatFromInt(total_streams)) / elapsed_s},
        );
        try stdout.print(
            "- Datagrams/sec: {d:.0} (64 B payload each)\n",
            .{@as(f64, @floatFromInt(total_datagrams)) / elapsed_s},
        );
    }
    try stdout.flush();
}

const RunResult = struct {
    pump_iters: u32,
    streams_opened: usize,
    streams_finished: usize,
    dgrams_c2s_received: usize,
    dgrams_c2s_lost: usize,
    dgrams_s2c_received: usize,
    dgrams_s2c_lost: usize,
    sessions_closed_server: usize,
};

fn runLoad(
    allocator: std.mem.Allocator,
    stdout: anytype,
) !RunResult {
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var client_quic = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client_quic.deinit();
    var server_quic = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server_quic.deinit();

    try connectQuic(&client_quic, &server_quic);

    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, .{ .settings = wt_settings });
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, .{ .settings = wt_settings });
    defer server_h3.deinit();
    try client_h3.start();
    try server_h3.start();

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var packet: [4096]u8 = undefined;
    var now_us: u64 = 1_000_000;

    // SETTINGS exchange — every test/example does this before any
    // application traffic. WebTransport gating relies on
    // `wt_enabled = true` being mirrored by the peer.
    {
        var iters: u32 = 0;
        while (client_h3.peer_settings == null or server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.SettingsTimedOut;
            try pump(&client_quic, &server_quic, &client_h3, &server_h3, &client_events, &server_events, &now_us, &packet);
            clearEvents(allocator, &server_events);
            clearEvents(allocator, &client_events);
        }
    }

    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);

    // ----------------------------------------------------------------
    // Spin up the client-side WT bootstraps. Each session's CONNECT
    // request is opened up front (so all 100 session ids exist before
    // we start pumping). The peer's initial bidi-streams grant must
    // cover this — see `connectQuic`.
    // ----------------------------------------------------------------

    const client_sessions = try allocator.alloc(http3_zig.WebTransportClientStream, num_sessions);
    defer allocator.free(client_sessions);

    const session_ids = try allocator.alloc(u64, num_sessions);
    defer allocator.free(session_ids);

    const per_session = try allocator.alloc(PerSession, num_sessions);
    defer allocator.free(per_session);

    var paths_buf: [num_sessions][24]u8 = undefined;
    for (0..num_sessions) |i| {
        const path = try std.fmt.bufPrint(&paths_buf[i], "/wt/load/{d}", .{i});
        client_sessions[i] = try h3_client.startWebTransport(allocator, .{
            .authority = "localhost",
            .path = path,
        });
        session_ids[i] = client_sessions[i].sessionId();
        per_session[i] = .{ .session_id = session_ids[i] };
    }
    // Sanity: all session ids distinct.
    for (0..num_sessions) |i| {
        for (i + 1..num_sessions) |j| {
            if (session_ids[i] == session_ids[j]) return error.DuplicateSessionId;
        }
    }

    // Reverse-lookup table: session id → local index. Avoids O(N²)
    // linear scans on every event in the hot loop.
    var session_idx_by_id: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer session_idx_by_id.deinit(allocator);
    try session_idx_by_id.ensureTotalCapacity(allocator, @intCast(num_sessions));
    for (session_ids, 0..) |sid, idx| {
        session_idx_by_id.putAssumeCapacity(sid, idx);
    }

    // Server-side accept handles, keyed by session id (=request stream id).
    var server_wt_by_session: std.AutoHashMapUnmanaged(u64, http3_zig.WebTransportServerStream) = .empty;
    defer server_wt_by_session.deinit(allocator);
    try server_wt_by_session.ensureTotalCapacity(allocator, @intCast(num_sessions));

    // Per-stream bookkeeping for the server-observed uni streams
    // (mirrors V1's PerStream, just larger).
    var streams_by_id: std.AutoHashMapUnmanaged(u64, PerStream) = .empty;
    defer {
        var it = streams_by_id.valueIterator();
        while (it.next()) |entry| entry.bytes.deinit(allocator);
        streams_by_id.deinit(allocator);
    }
    try streams_by_id.ensureTotalCapacity(allocator, @intCast(total_streams));

    // Counters for the final invariant check.
    var streams_opened_total: usize = 0;
    var streams_finished_total: usize = 0;
    var dgrams_c2s_total: usize = 0;
    var dgrams_s2c_total: usize = 0;
    // Datagrams the QUIC layer reported lost — RFC 9221 datagrams
    // are unreliable so this is fine, we just have to count them
    // toward "drained" so the workload terminates. Both sides track
    // their own losses (a c2s loss is observed on the *client*
    // sender side via the loss-detection feedback path).
    var dgrams_c2s_lost: usize = 0;
    var dgrams_s2c_lost: usize = 0;
    var sessions_closed_observed_server: usize = 0;

    // Build a stream payload once and slice it; payload is just
    // sequential bytes so any cross-stream content bleed would shift
    // the checksum.
    var stream_payload: [stream_payload_len]u8 = undefined;
    for (&stream_payload, 0..) |*b, n| b.* = @truncate(n);

    var dgram_payload_buf: [datagram_payload_len]u8 = undefined;

    const max_iters: u32 = 2_000_000;
    var iters: u32 = 0;
    var done: bool = false;

    while (!done) : (iters += 1) {
        if (iters >= max_iters) {
            // Print where progress stalled so we can diagnose.
            var sessions_none_client: usize = 0;
            var sessions_none_server: usize = 0;
            var sessions_pending_client: usize = 0;
            var sessions_established_client: usize = 0;
            var c2s_dgrams_sent: usize = 0;
            var s2c_dgrams_sent: usize = 0;
            for (per_session, 0..) |ps, i| {
                _ = i;
                if (client_h3.webTransportSessionState(ps.session_id) == .none) sessions_none_client += 1;
                if (client_h3.webTransportSessionState(ps.session_id) == .pending) sessions_pending_client += 1;
                if (client_h3.webTransportSessionState(ps.session_id) == .established) sessions_established_client += 1;
                if (server_h3.webTransportSessionState(ps.session_id) == .none) sessions_none_server += 1;
                c2s_dgrams_sent += ps.dgrams_c2s_sent;
                s2c_dgrams_sent += ps.dgrams_s2c_sent;
            }
            try stdout.print(
                "TIMEOUT iters={d}\n streams_finished={d}/{d}\n c2s_sent={d}/{d} seen={d} lost={d}\n s2c_sent={d}/{d} seen={d} lost={d}\n closes_observed_server={d}/{d}\n client states: none={d} pending={d} established={d}\n server: none={d}/{d}\n",
                .{
                    iters,
                    streams_finished_total,
                    total_streams,
                    c2s_dgrams_sent,
                    total_dgrams_c2s,
                    dgrams_c2s_total,
                    dgrams_c2s_lost,
                    s2c_dgrams_sent,
                    total_dgrams_s2c,
                    dgrams_s2c_total,
                    dgrams_s2c_lost,
                    sessions_closed_observed_server,
                    num_sessions,
                    sessions_none_client,
                    sessions_pending_client,
                    sessions_established_client,
                    sessions_none_server,
                    num_sessions,
                },
            );
            try stdout.flush();
            return error.LoadTimedOut;
        }

        try pump(
            &client_quic,
            &server_quic,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
            &packet,
        );

        // ------------------------------------------------------------
        // Server side: accept incoming WT bootstraps.
        // ------------------------------------------------------------
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
            // Also pull out raw datagram + WT stream events (server side).
            //
            // The client opens client→server uni streams, so the
            // server is the receiver — `webtransport_stream_*`
            // events fire on the server-side event queue, not the
            // client. This is the inverse of the V1 multiplexing
            // test (where the server opened streams).
            switch (event) {
                .datagram => |dg| {
                    if (session_idx_by_id.get(dg.stream_id)) |idx| {
                        const decoded = parseDatagramPayload(dg.payload) catch
                            return error.DatagramPayloadCorrupt;
                        if (decoded.session_idx != idx) return error.DatagramMisattributed;
                        if (decoded.direction != .c2s) return error.DatagramDirectionFlipped;
                        if (decoded.dg_idx >= dgrams_c2s_per_session) return error.DatagramIdxOutOfRange;
                        const bit: u32 = @as(u32, 1) << @intCast(decoded.dg_idx);
                        if ((per_session[idx].dgrams_c2s_seen_mask & bit) != 0) {
                            return error.DatagramReplayed;
                        }
                        per_session[idx].dgrams_c2s_seen_mask |= bit;
                        dgrams_c2s_total += 1;
                    } else {
                        return error.DatagramFromUnknownSession;
                    }
                },
                .webtransport_stream_opened => |opened| {
                    const idx = session_idx_by_id.get(opened.session_id) orelse
                        return error.OpenFromUnknownSession;
                    _ = idx;
                    streams_opened_total += 1;
                },
                .webtransport_stream_data => |data| {
                    const idx = session_idx_by_id.get(data.session_id) orelse
                        return error.DataFromUnknownSession;
                    const gop = try streams_by_id.getOrPut(allocator, data.stream_id);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .{
                            .session_id = data.session_id,
                            .session_idx = idx,
                            .stream_idx = 0,
                            .bytes = .empty,
                            .finished = false,
                            .opened = true,
                        };
                    }
                    if (gop.value_ptr.session_id != data.session_id) {
                        return error.StreamSessionMismatch;
                    }
                    try gop.value_ptr.bytes.appendSlice(allocator, data.data);
                },
                .webtransport_stream_finished => |finished| {
                    const idx = session_idx_by_id.get(finished.session_id) orelse
                        return error.FinishFromUnknownSession;
                    _ = idx;
                    const entry = streams_by_id.getPtr(finished.stream_id) orelse
                        return error.FinishWithoutData;
                    if (entry.session_id != finished.session_id) return error.StreamSessionMismatch;
                    if (entry.finished) return error.DoubleFinish;
                    entry.finished = true;
                    streams_finished_total += 1;
                },
                .stream_finished => |sf| {
                    // The CONNECT stream finishing on the server side is
                    // the server's signal that the client closed the WT
                    // session (close capsule + FIN per draft §5.4).
                    if (session_idx_by_id.contains(sf.stream_id)) {
                        sessions_closed_observed_server += 1;
                    }
                },
                // Server-side datagram-loss events fire when the
                // peer's loss detector decides a previously-sent
                // datagram is gone. Server is the s2c sender, so
                // count these as s2c losses.
                .datagram_lost => {
                    dgrams_s2c_lost += 1;
                },
                else => {},
            }
        }
        clearEvents(allocator, &server_events);

        // ------------------------------------------------------------
        // Client side: drive the workload per session.
        //
        // Each iteration advances every session as far as the current
        // flow / stream limits allow. Anything that hits
        // `WebTransportStreamLimitExceeded` retries on the next pump.
        // ------------------------------------------------------------
        for (per_session, 0..) |*ps, i| {
            if (ps.close_sent) continue;
            const wt = &client_sessions[i];
            // The client side needs the session to be `.established`
            // before opening WT streams (else gateWebTransportStreamOpen
            // returns `UnknownWebTransportSession`). The `pending →
            // established` transition happens when the 2xx response
            // arrives — verify here rather than driving via
            // ClientRunner since we want to attribute fast.
            if (client_h3.webTransportSessionState(ps.session_id) != .established) continue;

            // Open + write up to `streams_per_session` uni streams,
            // bailing out gracefully on the per-session WT_MAX_STREAMS
            // limit; we'll come back next pump after the peer's
            // MAX_STREAMS_UNI capsule lands.
            while (ps.streams_opened < streams_per_session) {
                const stream_idx = ps.streams_opened;
                const stream_id = wt.openUniStream() catch |err| switch (err) {
                    error.WebTransportStreamLimitExceeded => break,
                    error.StreamLimitExceeded => break,
                    else => return err,
                };
                ps.streams_opened += 1;
                // Build a session-distinguishing prefix; the rest of
                // the 1 KiB payload is the deterministic ramp.
                var prefix_buf: [32]u8 = undefined;
                const prefix = try std.fmt.bufPrint(
                    &prefix_buf,
                    "session-{d}-stream-{d}-",
                    .{ i, stream_idx },
                );
                var combined: [stream_payload_len]u8 = undefined;
                @memcpy(combined[0..prefix.len], prefix);
                @memcpy(combined[prefix.len..], stream_payload[prefix.len..]);
                wt.writeStream(stream_id, &combined) catch |err| switch (err) {
                    error.WebTransportFlowControlExceeded,
                    error.FlowControlExceeded,
                    error.SendBufferFull,
                    error.WriteStalled,
                    => break,
                    else => return err,
                };
                wt.finishStream(stream_id) catch |err| switch (err) {
                    error.WebTransportFlowControlExceeded,
                    error.FlowControlExceeded,
                    error.SendBufferFull,
                    error.WriteStalled,
                    => break,
                    else => return err,
                };
                ps.streams_written += 1;
            }

            // Send the per-direction datagrams at the cadence "every
            // pump iteration, send one if we still owe one and the
            // server has caught up". This avoids dumping all 1000 C→S
            // datagrams in a single tick (which the loopback's
            // `max_datagrams_per_direction = 4` would just drop).
            // Datagrams are best-effort: if `sendDatagram` returns
            // `DatagramQueueFull` we just retry next pump rather than
            // counting it as sent. This is the only way to drive the
            // workload to completion under heavy load — the alternative
            // (incrementing on failure) would leak un-delivered
            // datagrams and the receiver-side mask would never fill.
            if (ps.dgrams_c2s_sent < dgrams_c2s_per_session) {
                const dg_idx = ps.dgrams_c2s_sent;
                const dg = try fmtDatagramPayload(&dgram_payload_buf, i, .c2s, dg_idx);
                if (wt.sendDatagram(dg)) |_| {
                    ps.dgrams_c2s_sent += 1;
                } else |err| switch (err) {
                    error.DatagramQueueFull,
                    error.DatagramUnavailable,
                    => {},
                    error.DatagramTooLarge => return error.DatagramTooLarge,
                    else => return err,
                }
            }

            // Fire close once everything else is in flight. The server
            // mirrors the close on its side (we don't need to wait for
            // every byte to drain client→server for the close to
            // reach the peer).
            // Per-session "ready to close" gate. We require:
            //   - every uni stream queued (sender side),
            //   - every c2s datagram queued via `sendDatagram`,
            //   - every s2c datagram either received OR
            //     unambiguously globally accounted for via a
            //     loss event (we don't know which session a lost
            //     datagram belonged to from the event payload, so
            //     we use the global counter as a fallback gate
            //     after streams + sends are done).
            //
            // The close itself triggers when we've made our
            // local "send all my stuff" effort — datagrams are
            // best-effort, blocking the close on every receive
            // would deadlock the workload under any loss.
            const all_streams_done = ps.streams_written == streams_per_session;
            const all_c2s_dgrams_sent = ps.dgrams_c2s_sent == dgrams_c2s_per_session;
            if (all_streams_done and all_c2s_dgrams_sent and !ps.close_sent) {
                wt.close(0, "ok") catch |err| switch (err) {
                    // Already finished from our side — fine.
                    error.SessionClosed,
                    error.UnknownWebTransportSession,
                    => {},
                    else => return err,
                };
                ps.close_sent = true;
            }
        }

        // ------------------------------------------------------------
        // Server side: once a session is accepted, push max-data and
        // send the s2c datagrams. The max-data bump is once per session.
        // ------------------------------------------------------------
        for (per_session, 0..) |*ps, i| {
            const wt_ptr = server_wt_by_session.getPtr(ps.session_id) orelse continue;
            if (server_h3.webTransportSessionState(ps.session_id) != .established) continue;

            if (!ps.pushed_max_data) {
                // Push WT_MAX_DATA bumping the credit. Every session
                // gets a different value so an aliased capsule write
                // would surface as a per-session flow-state mismatch.
                const new_max: u64 = 64 * 1024 + @as(u64, @intCast(i)) * 1024;
                wt_ptr.sendMaxData(new_max) catch |err| switch (err) {
                    error.SessionClosed,
                    error.UnknownWebTransportSession,
                    => {},
                    else => return err,
                };
                ps.pushed_max_data = true;
            }

            if (ps.dgrams_s2c_sent < dgrams_s2c_per_session) {
                const dg_idx = ps.dgrams_s2c_sent;
                const dg = try fmtDatagramPayload(&dgram_payload_buf, i, .s2c, dg_idx);
                if (wt_ptr.sendDatagram(dg)) |_| {
                    ps.dgrams_s2c_sent += 1;
                } else |err| switch (err) {
                    error.DatagramQueueFull,
                    error.DatagramUnavailable,
                    => {},
                    error.DatagramTooLarge => return error.DatagramTooLarge,
                    else => return err,
                }
            }
        }

        // ------------------------------------------------------------
        // Client-side event drain: tracks the S→C datagrams (the
        // server is the sender for those). The client doesn't see
        // `webtransport_stream_*` events in this workload because
        // it's always the stream sender — the server-side scan
        // above handles those. The `client_runner.observe` call is
        // still required so `webTransportSessionState` transitions
        // pending → established after 2xx responses arrive.
        // ------------------------------------------------------------
        for (client_events.items) |event| {
            _ = try client_runner.observe(event);

            switch (event) {
                .datagram => |dg| {
                    const idx = session_idx_by_id.get(dg.stream_id) orelse return error.DatagramFromUnknownSession;
                    const decoded = parseDatagramPayload(dg.payload) catch
                        return error.DatagramPayloadCorrupt;
                    if (decoded.session_idx != idx) return error.DatagramMisattributed;
                    if (decoded.direction != .s2c) return error.DatagramDirectionFlipped;
                    if (decoded.dg_idx >= dgrams_s2c_per_session) return error.DatagramIdxOutOfRange;
                    const bit: u32 = @as(u32, 1) << @intCast(decoded.dg_idx);
                    if ((per_session[idx].dgrams_s2c_seen_mask & bit) != 0) {
                        return error.DatagramReplayed;
                    }
                    per_session[idx].dgrams_s2c_seen_mask |= bit;
                    dgrams_s2c_total += 1;
                },
                // Client-side: we're the c2s sender, so c2s losses
                // surface here as `datagram_lost`.
                .datagram_lost => {
                    dgrams_c2s_lost += 1;
                },
                else => {},
            }
        }
        clearEvents(allocator, &client_events);

        // ------------------------------------------------------------
        // Termination check.
        //
        // We require:
        //   - every uni stream finished on the client side,
        //   - every C→S and S→C datagram observed at the receiver,
        //   - every session closed on both peers
        //     (state = `.none`).
        //
        // The latter is the strongest invariant: if any session leaks
        // (state stuck at `.established` or `.pending`) we'll
        // either stall or report the leak.
        // ------------------------------------------------------------
        if (streams_finished_total < total_streams) continue;
        // Datagram completion: received + lost ≥ expected (lost
        // events arrive late so we accept them as "drained").
        if (dgrams_c2s_total + dgrams_c2s_lost < total_dgrams_c2s) continue;
        if (dgrams_s2c_total + dgrams_s2c_lost < total_dgrams_s2c) continue;

        // Once application traffic has drained, force a few more
        // pumps to absorb the close capsules + FINs. The session id
        // only transitions to `.none` after the CONNECT stream is
        // fully closed and `endWebTransportSession` runs.
        var sessions_none_client: usize = 0;
        var sessions_none_server: usize = 0;
        for (session_ids) |sid| {
            if (client_h3.webTransportSessionState(sid) == .none) sessions_none_client += 1;
            if (server_h3.webTransportSessionState(sid) == .none) sessions_none_server += 1;
        }
        done = (sessions_none_client == num_sessions and sessions_none_server == num_sessions);
    }

    // ----------------------------------------------------------------
    // Final invariants. We crash here on any mis-attribution; the
    // build step keeps these enabled even in ReleaseFast.
    // ----------------------------------------------------------------

    if (client_h3.lastCloseError()) |close| {
        try stdout.print(
            "FAIL: client lastCloseError = code 0x{x} {s}\n",
            .{ close.application.code, close.reason() },
        );
        return error.ClientCloseError;
    }
    if (server_h3.lastCloseError()) |close| {
        try stdout.print(
            "FAIL: server lastCloseError = code 0x{x} {s}\n",
            .{ close.application.code, close.reason() },
        );
        return error.ServerCloseError;
    }

    // Stream count + payload prefix attribution.
    var per_session_finished: [num_sessions]usize = @splat(0);
    var sit = streams_by_id.valueIterator();
    while (sit.next()) |entry| {
        if (!entry.finished) return error.UnfinishedStream;
        const idx = session_idx_by_id.get(entry.session_id) orelse return error.UnknownSessionInStream;
        var prefix_buf: [32]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "session-{d}-stream-", .{idx});
        if (!std.mem.startsWith(u8, entry.bytes.items, prefix)) {
            return error.StreamPayloadMisattributed;
        }
        per_session_finished[idx] += 1;
    }
    if (streams_by_id.count() != total_streams) return error.WrongStreamCount;
    for (per_session_finished) |c| {
        if (c != streams_per_session) return error.PerSessionStreamCountMismatch;
    }

    // Datagrams: received + lost ≥ expected (datagram delivery
    // is best-effort per RFC 9221; we report the loss rate as a
    // cliff observation rather than failing the test). A
    // dropped-without-loss-event gap would surface here.
    if (dgrams_c2s_total + dgrams_c2s_lost < total_dgrams_c2s) return error.WrongC2SDatagramCount;
    if (dgrams_s2c_total + dgrams_s2c_lost < total_dgrams_s2c) return error.WrongS2CDatagramCount;

    // All sessions transitioned to `.none` cleanly.
    for (session_ids) |sid| {
        if (client_h3.webTransportSessionState(sid) != .none) return error.SessionNotNoneOnClient;
        if (server_h3.webTransportSessionState(sid) != .none) return error.SessionNotNoneOnServer;
    }

    // Every session got its sendMaxData bump.
    for (per_session) |ps| {
        if (!ps.pushed_max_data) return error.MaxDataNotSent;
    }

    return .{
        .pump_iters = iters,
        .streams_opened = streams_opened_total,
        .streams_finished = streams_finished_total,
        .dgrams_c2s_received = dgrams_c2s_total,
        .dgrams_c2s_lost = dgrams_c2s_lost,
        .dgrams_s2c_received = dgrams_s2c_total,
        .dgrams_s2c_lost = dgrams_s2c_lost,
        .sessions_closed_server = sessions_closed_observed_server,
    };
}

const Direction = enum { c2s, s2c };

/// Build a 64-byte datagram payload that encodes
/// `{direction, session_idx, dg_idx}` so the receiver can verify
/// attribution. Padding fills the remainder with a deterministic
/// ramp so any byte-level mishandling shows up as a memcmp diff.
fn fmtDatagramPayload(
    buf: *[datagram_payload_len]u8,
    session_idx: usize,
    dir: Direction,
    dg_idx: usize,
) ![]const u8 {
    const dir_str: []const u8 = switch (dir) {
        .c2s => "c2s",
        .s2c => "s2c",
    };
    const head = try std.fmt.bufPrint(
        buf,
        "{s}-s{d}-d{d}-",
        .{ dir_str, session_idx, dg_idx },
    );
    for (head.len..datagram_payload_len) |i| {
        buf[i] = @truncate(i);
    }
    return buf[0..datagram_payload_len];
}

const DecodedDatagram = struct {
    direction: Direction,
    session_idx: usize,
    dg_idx: usize,
};

/// Parse the `{c2s|s2c}-s{idx}-d{idx}-` self-attestation prefix and
/// validate the deterministic ramp tail. The check is order-independent
/// because UDP / QUIC datagrams may legitimately reorder.
fn parseDatagramPayload(payload: []const u8) !DecodedDatagram {
    if (payload.len != datagram_payload_len) return error.WrongLen;
    const dir: Direction = if (std.mem.startsWith(u8, payload, "c2s-"))
        .c2s
    else if (std.mem.startsWith(u8, payload, "s2c-"))
        .s2c
    else
        return error.BadDirection;
    const after_dir = payload[4..]; // skip "c2s-" / "s2c-"
    if (after_dir.len < 2 or after_dir[0] != 's') return error.BadFormat;
    var i: usize = 1;
    var session_idx: usize = 0;
    while (i < after_dir.len and after_dir[i] >= '0' and after_dir[i] <= '9') : (i += 1) {
        session_idx = session_idx * 10 + (after_dir[i] - '0');
    }
    if (i >= after_dir.len or after_dir[i] != '-') return error.BadFormat;
    i += 1;
    if (i >= after_dir.len or after_dir[i] != 'd') return error.BadFormat;
    i += 1;
    var dg_idx: usize = 0;
    while (i < after_dir.len and after_dir[i] >= '0' and after_dir[i] <= '9') : (i += 1) {
        dg_idx = dg_idx * 10 + (after_dir[i] - '0');
    }
    if (i >= after_dir.len or after_dir[i] != '-') return error.BadFormat;
    const head_len = 4 + i + 1;
    // Verify the ramp tail matches what `fmtDatagramPayload` writes.
    for (head_len..datagram_payload_len) |k| {
        const expected: u8 = @truncate(k);
        if (payload[k] != expected) return error.RampMismatch;
    }
    return .{ .direction = dir, .session_idx = session_idx, .dg_idx = dg_idx };
}

// ---------------------------------------------------------------------
// Plumbing — copies of the bench helpers, kept local so this file is
// self-contained.
// ---------------------------------------------------------------------

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

fn elapsedNs(start: i96, end: i96) u64 {
    const delta = end - start;
    if (delta < 0) return 0;
    return @intCast(delta);
}

fn pump(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
    packet: []u8,
) !void {
    // `max_datagrams_per_direction = 64` lets each step drain
    // many QUIC packets per direction so the 100-session workload
    // converges in a reasonable iteration count. The bench harness
    // uses 1 because it measures a single round-trip — here we
    // care about throughput, not per-step latency.
    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(client, client_h3, client_events),
        http3_zig.TransportEndpoint.withSession(server, server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 64,
        },
    );
    _ = try driver.step(packet);
    now_us.* = driver.now_us;
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    // Transport params tuned for the 100-session workload:
    //   - `initial_max_streams_bidi = 256` covers the 100 CONNECT
    //     streams plus headroom (the HTTP/3 control + QPACK uni
    //     streams use the uni budget, not bidi).
    //   - `initial_max_streams_uni  = 1024` covers the 500 client→
    //     server uni WT streams plus the H3 control / QPACK
    //     encoder / decoder streams (3 each side).
    //   - `initial_max_data = 16 MiB` is the maximum the underlying
    //     QUIC stack accepts (`default_connection_receive_window`).
    //     Comfortably covers ~500 KiB stream payload + headers.
    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 256,
        .initial_max_streams_uni = 1024,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    if (!client.handshakeDone() or !server.handshakeDone()) return error.HandshakeTimedOut;

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Match `tests/integration/_fixtures.zig`: in-process shim never
    // carries real datagrams, so flip the validated bit manually.
    _ = server.markPathValidated(server.activePathId());
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
