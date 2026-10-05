//! External WebTransport interop server harness.
//!
//! Brings up an http3-zig WebTransport server on a real UDP socket
//! and runs an echo loop that:
//!
//!   * accepts a WebTransport `CONNECT` (`:protocol = webtransport`),
//!   * echoes inbound datagrams back to the peer,
//!   * surfaces inbound peer-opened unidirectional WT streams via
//!     `webtransport_stream_data` events and echoes the payload on a
//!     server-initiated unidirectional WT stream while the session is open,
//!   * serves any number of QUIC connections at once (`quic.Server`
//!     routes by connection ID; Firefox opens two per origin),
//!   * stays running until `--max-sessions` sessions have completed
//!     across all connections (default 1) or `--max-lifetime-ms` runs
//!     out. A closed connection does not end the run: another one may
//!     still be on its way.
//!
//! Used by `.github/workflows/wt-interop-self-test.yml` as the peer
//! the existing `external-wt-client` / `wt-interop-matrix` runners
//! exercise. The loop is quic's foreign-loop shape: our own UDP
//! socket (so READY can report an ephemeral port), `quic.Server.feed`,
//! one `http3_zig.Session` per accepted slot (on `Slot.user_data`,
//! freed by the will-close hook), then `tick` and a per-slot
//! `pollDatagram` drain.
//!
//! Exit codes:
//!   * 0 — the server completed `max_sessions` sessions, or its
//!         lifetime ran out (harness drivers read the OBSERVED lines,
//!         not the exit code, to judge a run).
//!   * 1 — a session ended in a protocol error.
//!   * 2 — setup / network error (cert load, socket bind, ...).

const std = @import("std");
const quic = @import("quic");
const http3_zig = @import("http3_zig");

const Net = std.Io.net;

const Options = struct {
    listen: []const u8 = "127.0.0.1:0",
    cert: []const u8 = "tests/data/test_cert.pem",
    key: []const u8 = "tests/data/test_key.pem",
    /// Number of WebTransport sessions to accept before the server
    /// exits. Set to 0 to run until killed.
    max_sessions: u64 = 1,
    /// Wallclock cap on the server's lifetime, in milliseconds.
    /// Defends against a stuck client wedging the harness in CI.
    max_lifetime_ms: u64 = 30_000,
    /// Comma-separated draft eras to advertise: any of
    /// `modern`,`draft07`,`draft02`. Browsers need `draft02`; the
    /// matrix's foreign servers speak `modern`.
    eras: []const u8 = "modern",
};

const Category = enum { protocol, setup };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const options = parseArgs(init, allocator) catch |err| {
        std.debug.print("external_wt server: argument parse failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };

    runServer(allocator, io, options) catch |err| {
        const category = classifyError(err);
        std.debug.print(
            "external_wt server: harness failed with {s} ({s})\n",
            .{ @errorName(err), @tagName(category) },
        );
        std.process.exit(switch (category) {
            .protocol => 1,
            .setup => 2,
        });
    };
}

/// Transport parameters every accepted connection advertises. The
/// connection-ID parameters are filled in by `quic.Server`.
fn transportParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 128,
        .initial_max_streams_uni = 128,
        .max_udp_payload_size = 65527, // RFC default — Chrome sends 1250-byte
        // Initials (quiche kDefaultMaxPacketSize); the old 1200 pin made the
        // transport close before the handshake, the exact bug class the
        // client-side harness fixed once before.
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
    };
}

/// The HTTP/3 session configuration of every accepted connection.
fn sessionConfig(options: Options) http3_zig.session.Config {
    const era_modern = std.mem.indexOf(u8, options.eras, "modern") != null;
    const era_draft07 = std.mem.indexOf(u8, options.eras, "draft07") != null;
    const era_draft02 = std.mem.indexOf(u8, options.eras, "draft02") != null;
    // Advertisement equals enforcement: the draft-07 SETTINGS value and
    // the enforced cap both come from --max-sessions (min 1).
    const draft07_cap: u64 = @max(options.max_sessions, 1);
    return .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 4,
            .max_field_section_size = 16 * 1024 * 1024,
            .enable_connect_protocol = true,
            .h3_datagram = true,
            .wt_enabled = era_modern,
            .wt_draft02 = era_draft02,
            .wt_draft07_max_sessions = if (era_draft07) @as(?u64, draft07_cap) else null,
        },
        .max_wt_sessions = if (era_draft07) @as(?usize, @intCast(draft07_cap)) else null,
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 16 * 1024 * 1024,
        .max_data_frame_payload = 16 * 1024,
    };
}

/// Monotonic microseconds: one clock for `feed`, `tick`, `pollDatagram`
/// and the harness's own deadlines.
fn nowUs(io: std.Io) u64 {
    const ns = std.Io.Clock.awake.now(io).nanoseconds;
    return @intCast(@divTrunc(@max(ns, 0), std.time.ns_per_us));
}

fn runServer(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const listen_addr = try Net.IpAddress.parseLiteral(options.listen);
    const sock = try Net.IpAddress.bind(&listen_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    var cert_buf: [16 * 1024]u8 = undefined;
    var key_buf: [16 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, options.cert, &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, options.key, &key_buf);

    var harness: Harness = .{
        .allocator = allocator,
        .session_config = sessionConfig(options),
        .max_sessions = options.max_sessions,
    };

    // `quic.Server` demultiplexes by connection ID, so a peer may open
    // several connections: Firefox opens two to one origin, and the
    // single-`Connection` loop this replaced answered only one of them
    // (and re-aimed its replies at whichever address sent last).
    const alpn = [_][]const u8{"h3"};
    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = cert_pem,
        .tls_key_pem = key_pem,
        .alpn_protocols = &alpn,
        .transport_params = transportParams(),
        .on_connection_will_close = Harness.onConnectionWillClose,
        .on_connection_will_close_user_data = &harness,
    });
    // `deinit` runs the will-close hook for every live slot, which
    // releases each connection's HTTP/3 state before its connection.
    defer server.deinit();

    // Everything goes to stderr: on current Zig master the buffered
    // stdout writer flushes at its own logical offset (pwrite
    // semantics), which CLOBBERS interleaved stderr bytes when both are
    // redirected to one log file — the READY/EXIT lines were observed
    // partially overwriting OBSERVED lines. std.debug.print is
    // append-consistent; harness drivers capture with `2>&1` anyway.
    std.debug.print("READY {d}\n", .{sock.address.getPort()});

    const start_us = nowUs(io);
    const lifetime_us: u64 = options.max_lifetime_ms * 1_000;
    var rx: [64 * 1024]u8 = undefined;
    var tx: [64 * 1024]u8 = undefined;
    var iteration: u64 = 0;

    while (true) : (iteration += 1) {
        var now_us = nowUs(io);
        if (now_us - start_us > lifetime_us) {
            std.debug.print("EXIT lifetime {d}ms exceeded\n", .{options.max_lifetime_ms});
            break;
        }
        if (harness.isDone(now_us)) break;

        const maybe_msg = sock.receiveTimeout(io, &rx, .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(5),
                .clock = .awake,
            },
        }) catch |err| switch (quic.transport.classifyReceiveError(err)) {
            .tolerate => null,
            .fatal => return err,
        };

        now_us = nowUs(io);
        if (maybe_msg) |msg| {
            // A datagram the server cannot place (or that does not
            // authenticate) is dropped inside `feed`; an error here is
            // per-datagram, never a reason to stop serving.
            _ = server.feed(msg.data, quic.transport.udp_batch.ipAddressToPathAddress(msg.from), now_us) catch |err| {
                std.debug.print("OBSERVED datagram dropped by feed: {s}\n", .{@errorName(err)});
            };
            while (server.drainStatelessResponse()) |response| {
                const dst = quic.transport.udp_server.pathAddressToIpAddress(response.dst) orelse continue;
                sendTolerant(io, sock, dst, response.slice()) catch |err| return err;
            }
        }

        // HTTP/3 per connection: read events first, then tick, then
        // drain the outbox (quic's foreign-loop order: the stream GC in
        // `tick` must not reap data the application has not read).
        for (server.iterator()) |slot| {
            const state = harness.ensureState(slot) catch |err| {
                std.debug.print("OBSERVED connection state failed conn={d}: {s}\n", .{ slot.slot_id, @errorName(err) });
                continue;
            };
            harness.pump(state, now_us) catch |err| {
                std.debug.print("OBSERVED session error conn={d}: {s}\n", .{ state.slot_id, @errorName(err) });
                state.session.close(http3_zig.protocol.ErrorCode.internal_error, "");
            };
        }
        for (server.iterator()) |slot| {
            if (slot.conn.closeState() == .closed) continue;
            slot.conn.tick(now_us) catch {};
            while (slot.conn.pollDatagram(&tx, now_us) catch null) |out| {
                const to = out.to orelse slot.peer_addr orelse continue;
                const dst = quic.transport.udp_server.pathAddressToIpAddress(to) orelse continue;
                try sendTolerant(io, sock, dst, tx[0..out.len]);
            }
        }
        if (iteration % 64 == 0) _ = server.reap();
    }

    std.debug.print(
        "EXIT sessions={d}/{d} connections={d}\n",
        .{ harness.sessions_completed, options.max_sessions, harness.connections_accepted },
    );
}

/// Peer-provoked send faults (ICMP-fed ConnectionRefused/reset,
/// oversize) drop the datagram: loss recovery retransmits, and a dead
/// peer is reaped by the idle timeout. Local faults propagate.
fn sendTolerant(io: std.Io, sock: anytype, dst: Net.IpAddress, bytes: []const u8) !void {
    sock.send(io, &dst, bytes) catch |err| switch (quic.transport.classifySendError(err)) {
        .tolerate => {},
        // The loop's own task was cancelled: return so it exits.
        .canceled, .fatal => return err,
    };
}

/// One accepted QUIC connection's HTTP/3 state, hung off
/// `Slot.user_data` on first sight and freed by the will-close hook.
const ConnState = struct {
    session: http3_zig.Session,
    facade: http3_zig.Server,
    endpoint: http3_zig.TransportEndpoint,
    events: std.ArrayList(http3_zig.session.Event),
    runner: http3_zig.ServerRunner,
    accepted: std.AutoHashMapUnmanaged(u64, AcceptedSession) = .empty,
    slot_id: u64,
};

const AcceptedSession = struct {
    wt: http3_zig.WebTransportServerStream,
    completed: bool = false,
};

const Harness = struct {
    const completion_drain_us: u64 = 1_000_000;

    allocator: std.mem.Allocator,
    session_config: http3_zig.session.Config,
    /// Sessions to complete, across all connections, before exiting.
    max_sessions: u64,
    sessions_completed: u64 = 0,
    completed_at_us: ?u64 = null,
    connections_accepted: u64 = 0,

    fn isDone(self: *const Harness, now_us: u64) bool {
        if (self.max_sessions == 0) return false;
        if (self.sessions_completed < self.max_sessions) return false;
        const completed_at = self.completed_at_us orelse return false;
        return now_us - completed_at >= completion_drain_us;
    }

    fn noteCompleted(self: *Harness, now_us: u64) void {
        self.sessions_completed += 1;
        if (self.max_sessions != 0 and
            self.sessions_completed >= self.max_sessions and
            self.completed_at_us == null)
        {
            self.completed_at_us = now_us;
        }
    }

    fn stateOf(slot: *quic.Server.Slot) ?*ConnState {
        const ptr = slot.user_data orelse return null;
        return @ptrCast(@alignCast(ptr));
    }

    fn ensureState(self: *Harness, slot: *quic.Server.Slot) !*ConnState {
        if (stateOf(slot)) |state| return state;
        const state = try self.allocator.create(ConnState);
        errdefer self.allocator.destroy(state);
        state.* = .{
            .session = http3_zig.Session.init(self.allocator, .server, slot.conn, self.session_config),
            .facade = undefined,
            .endpoint = undefined,
            .events = .empty,
            .runner = http3_zig.ServerRunner.init(self.allocator),
            .slot_id = slot.slot_id,
        };
        // The facade and endpoint point into the heap ConnState: wire
        // them only once it is at its final address.
        state.facade = http3_zig.Server.init(&state.session);
        state.endpoint = http3_zig.TransportEndpoint.withSession(slot.conn, &state.session, &state.events);
        slot.user_data = state;
        self.connections_accepted += 1;
        std.debug.print("OBSERVED connection accepted conn={d}\n", .{state.slot_id});
        return state;
    }

    /// `quic.Server.Config.on_connection_will_close`: runs in `reap` and
    /// in `Server.deinit` while `slot.conn` is still valid — the last
    /// safe place to release the session that borrows it.
    fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
        const self: *Harness = @ptrCast(@alignCast(ctx.?));
        const state = stateOf(slot) orelse return;
        state.session.clearEvents(&state.events);
        state.events.deinit(self.allocator);
        state.accepted.deinit(self.allocator);
        state.runner.deinit();
        state.session.deinit();
        self.allocator.destroy(state);
        slot.user_data = null;
    }

    fn pump(self: *Harness, state: *ConnState, now_us: u64) !void {
        // Drains the session (auto-starting it on first use).
        _ = try state.endpoint.drainSession();
        defer _ = state.endpoint.clearEvents();
        for (state.events.items) |event| try self.observe(state, event, now_us);
    }

    fn observe(self: *Harness, state: *ConnState, event: http3_zig.session.Event, now_us: u64) !void {
        // The runner classifies HTTP/3 frame events; WebTransport-
        // specific stream events fall through as `.ignored` from the
        // tracker's perspective, so we inspect them on the raw event
        // first.
        switch (event) {
            // Proves the handshake finished and the peer's control
            // stream parsed; a browser that closes before this line
            // failed below HTTP/3 or on its first frames.
            .peer_settings => |ps| {
                std.debug.print("OBSERVED peer settings conn={d} enable_connect_protocol={} h3_datagram={}\n", .{
                    state.slot_id,
                    ps.enable_connect_protocol,
                    ps.h3_datagram,
                });
            },
            .webtransport_stream_data => |data| {
                std.debug.print(
                    "OBSERVED wt stream data session={d} stream={d} kind={s} bytes={d}\n",
                    .{ data.session_id, data.stream_id, @tagName(data.kind), data.data.len },
                );
                try echoUni(state, data.session_id, data.data);
            },
            .webtransport_stream_finished => |finished| {
                std.debug.print(
                    "OBSERVED wt stream finished session={d} stream={d}\n",
                    .{ finished.session_id, finished.stream_id },
                );
            },
            .webtransport_stream_reset => |reset| {
                std.debug.print(
                    "OBSERVED wt stream reset session={d} stream={d} code={d}\n",
                    .{ reset.session_id, reset.stream_id, reset.error_code },
                );
            },
            .webtransport_flow_violated => |v| {
                std.debug.print(
                    "OBSERVED wt flow violated session={d} stream={d} kind={s} limit={d}\n",
                    .{ v.session_id, v.stream_id, @tagName(v.kind), v.limit },
                );
            },
            .datagram => |dg| {
                if (state.accepted.getPtr(dg.stream_id)) |entry| {
                    var wt = entry.wt;
                    try wt.sendDatagram(dg.payload);
                    entry.wt = wt;
                    std.debug.print("OBSERVED wt datagram echo session={d} bytes={d}\n", .{ dg.stream_id, dg.payload.len });
                }
            },
            else => {},
        }

        switch (event) {
            // Browsers end sessions with CLOSE_WEBTRANSPORT_SESSION; the
            // native fold surfaces it (and tears the session down) the
            // moment it arrives — count completion here so a peer whose
            // FIN trails (or never lands cleanly) still completes.
            .webtransport_session_closed => |closed| {
                if (state.accepted.getPtr(closed.session_id)) |entry| {
                    if (!entry.completed) {
                        entry.completed = true;
                        self.noteCompleted(now_us);
                    }
                    std.debug.print("OBSERVED wt session closed session={d} how={s} total={d}\n", .{
                        closed.session_id,
                        @tagName(closed.how),
                        self.sessions_completed,
                    });
                }
            },
            else => {},
        }
        switch (try state.runner.observe(event)) {
            .request_updated, .request_complete => |request_state| {
                const request = request_state.reader();
                if (!state.accepted.contains(request.streamId()) and request.headers().len > 0 and request.isWebTransport()) {
                    const wt = try state.facade.acceptWebTransport(self.allocator, request, .{});
                    try state.accepted.put(self.allocator, request.streamId(), .{ .wt = wt });
                    std.debug.print("OBSERVED wt accepted session={d} era={s} conn={d}\n", .{
                        request.streamId(),
                        @tagName(state.session.webTransportNegotiatedDraft() orelse .draft16),
                        state.slot_id,
                    });
                }
                if (request.complete()) {
                    if (state.accepted.getPtr(request.streamId())) |entry| {
                        if (!entry.completed) {
                            var wt = entry.wt;
                            try wt.finish();
                            entry.wt = wt;
                            entry.completed = true;
                            self.noteCompleted(now_us);
                        }
                        std.debug.print("OBSERVED wt session done session={d} total={d}\n", .{ request.streamId(), self.sessions_completed });
                    }
                }
            },
            .connection_closed => |closed| {
                std.debug.print(
                    "OBSERVED connection close source={s} space={s} code={d} reason={s} conn={d}\n",
                    .{
                        @tagName(closed.source),
                        @tagName(closed.error_space),
                        closed.error_code,
                        closed.reason,
                        state.slot_id,
                    },
                );
            },
            else => {},
        }
    }

    fn echoUni(state: *ConnState, session_id: u64, payload: []const u8) !void {
        const entry = state.accepted.getPtr(session_id) orelse return;
        if (entry.completed) {
            std.debug.print("OBSERVED wt stream echo skipped session={d} reason=session-complete\n", .{session_id});
            return;
        }
        var wt = entry.wt;
        const stream = try wt.openUniStream();
        try stream.write(payload);
        try stream.finish();
        entry.wt = wt;
    }
};

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--listen")) {
            options.listen = args.next() orelse return error.MissingListenAddress;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            options.cert = args.next() orelse return error.MissingCertPath;
        } else if (std.mem.eql(u8, arg, "--key")) {
            options.key = args.next() orelse return error.MissingKeyPath;
        } else if (std.mem.eql(u8, arg, "--max-sessions")) {
            options.max_sessions = try std.fmt.parseInt(u64, args.next() orelse return error.MissingSessionCount, 10);
        } else if (std.mem.eql(u8, arg, "--max-lifetime-ms")) {
            options.max_lifetime_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingLifetime, 10);
        } else if (std.mem.eql(u8, arg, "--eras")) {
            options.eras = args.next() orelse return error.MissingEras;
        } else {
            return error.UnknownArgument;
        }
    }
    return options;
}

fn clearEvents(allocator: std.mem.Allocator, events: *std.ArrayList(http3_zig.session.Event)) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn classifyError(err: anyerror) Category {
    return switch (err) {
        error.AddressInUse,
        error.AddressNotAvailable,
        error.PermissionDenied,
        error.AccessDenied,
        error.FileNotFound,
        error.MissingListenAddress,
        error.MissingCertPath,
        error.MissingKeyPath,
        error.MissingSessionCount,
        error.MissingLifetime,
        error.UnknownArgument,
        => .setup,
        else => .protocol,
    };
}
