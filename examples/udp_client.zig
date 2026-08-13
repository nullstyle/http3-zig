//! UDP client — the real-socket HTTP/3 client example, paired with
//! `udp_server.zig`.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/http3-zig-udp-server &
//! ./zig-out/bin/http3-zig-udp-client --insecure [target] [--sni host] [--path /] \
//!     [--session-cache <path>] [--qlog <dir>]
//! ```
//!
//! The shape to copy for your own client:
//!
//!  1. `quic.Client.connect` builds the TLS context (system trust
//!     store by default; `--insecure` maps to `insecure_skip_verify`
//!     for the demo server's self-signed cert — never set that against
//!     an untrusted network) and a ready-to-tick `Connection`.
//!  2. `http3_zig.Session` + `Client` facade + `ClientRunner` ride on
//!     `client.conn`; `TransportEndpoint.withSession` keeps the H3
//!     drain order in one place.
//!  3. `quic.transport.runUdpClient` owns the socket and the
//!     advance/receive/tick loop; ALL application logic lives in the
//!     `on_iteration` hook, on the loop thread.
//!  4. Without a stored ticket the request is sent only after
//!     `handshakeDone()`. With `--session-cache <path>` the client does
//!     0-RTT (RFC 9114 §7.2.4.2): the first run earns a session ticket
//!     (`earlydata.TicketBinder` pairs the quic resumption envelope
//!     with the server's SETTINGS into an `H3RS` file), and later runs
//!     resume from it — staging the GET BEFORE the first `advance()` so
//!     it rides the 0-RTT flight coalesced with the ClientHello.
//!
//! Flow: send `GET <path>` (staged in 0-RTT, or after the handshake),
//! assemble the response with `ClientRunner`, print status + body,
//! close cleanly with H3_NO_ERROR (which exits the loop).

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");

const earlydata = http3_zig.earlydata;

pub const default_target = "127.0.0.1:4433";

/// Cap on the stored `H3RS` envelope size — a resumption envelope is a
/// ticket plus settings, so anything bigger than this is not ours.
const max_session_cache_bytes = 64 * 1024;

const Options = struct {
    target: []const u8 = default_target,
    sni: []const u8 = "localhost",
    path: []const u8 = "/",
    insecure: bool = false,
    /// `H3RS` envelope file for 0-RTT: read to resume, written after
    /// every fetch that captured a fresh ticket. Null = 1-RTT only.
    session_cache: ?[]const u8 = null,
    /// `--qlog <dir>`: stream this connection's qlog trace into
    /// `<dir>/client-<timestamp>.sqlog` (JSON-SEQ; loads in qvis).
    qlog_dir: ?[]const u8 = null,
};

/// Transport parameters this client advertises. Same H3-suitable shape
/// as the interop client: enough uni-stream credit for the peer's
/// control + QPACK streams, and a large `max_udp_payload_size` receive
/// limit (the RFC 9000 default) so the server's coalesced handshake
/// datagrams are not dropped as too large — 1200 is the RFC minimum
/// send floor, not a good receive limit.
fn transportParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .active_connection_id_limit = 8,
        .max_udp_payload_size = 65527,
        .max_datagram_frame_size = 1200,
    };
}

/// `quic.Client.Config.new_session_callback` trampoline: latch the quic
/// resumption envelope into the `TicketBinder` (the bytes are borrowed
/// only for the duration of the call; the binder copies them out).
fn captureTicket(user_data: ?*anyopaque, resumption_state: []const u8) void {
    const binder: *earlydata.TicketBinder = @ptrCast(@alignCast(user_data.?));
    binder.onSessionTicket(resumption_state) catch {};
}

/// The client's whole application: a small state machine advanced once
/// per loop iteration by `onIteration`.
const FetchFlow = struct {
    allocator: std.mem.Allocator,
    session: *http3_zig.Session,
    h3_client: *http3_zig.Client,
    runner: *http3_zig.ClientRunner,
    endpoint: *http3_zig.TransportEndpoint,
    authority: []const u8,
    path: []const u8,
    /// Give-up deadline on the loop's monotonic clock (microseconds
    /// since loop start). Erroring out stops `runUdpClient` and
    /// propagates to the caller.
    deadline_us: u64,
    /// Non-null with `--session-cache`: latches the peer SETTINGS half
    /// of the `H3RS` envelope (the ticket half arrives via
    /// `captureTicket` on the transport's callback).
    binder: ?*earlydata.TicketBinder = null,
    /// Pre-set true when the request was staged in the 0-RTT flight.
    request_sent: bool = false,
    /// One transport-stats line per connection, once the handshake is up.
    stats_logged: bool = false,
    /// Set once the response completes; body/status stay owned by the
    /// runner, so `run` can validate them after the loop exits.
    response: ?*http3_zig.ResponseState = null,
    done: bool = false,

    /// `transport.RunUdpClientOptions.on_iteration` — fires once per
    /// loop iteration on the loop thread, after inbound datagrams are
    /// handled and the clock ticked; anything queued here ships on the
    /// very next outbox drain.
    pub fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        const flow: *FetchFlow = @ptrCast(@alignCast(ctx.?));
        if (flow.done) return;
        if (now_us > flow.deadline_us) return error.RequestTimedOut;

        // 1-RTT path: wait for the handshake before opening the request
        // stream. (The session's drain consumes `pollEvent`, so the
        // latched `handshakeDone()` query is the signal to use here, not
        // the one-shot event.) The 0-RTT path staged the request before
        // the first advance instead, so this gate never fires there.
        if (!flow.request_sent) {
            if (!client.conn.handshakeDone()) return;
            const request = try flow.h3_client.request(flow.allocator, .{
                .authority = flow.authority,
                .path = flow.path,
            });
            flow.request_sent = true;
            std.debug.print(
                "[client] handshake established; sent GET {s} on stream {d}\n",
                .{ flow.path, request.stream_id },
            );
        }

        // One-line transport snapshot after handshake completion.
        // `TransportEndpoint.transportStats` (= `Session.transportStats`
        // = `quic.Connection.stats`) is a by-value copy — safe to hold
        // across drains and teardown. It is the transport-reality
        // complement to the H3-level `metrics()` counters: RTT and cwnd
        // here are the live active-path estimates the real network
        // produced.
        if (!flow.stats_logged and client.conn.handshakeDone()) {
            flow.stats_logged = true;
            const stats = flow.endpoint.transportStats();
            std.debug.print(
                "[client] transport: srtt={d}us cwnd={d} bytes_sent={d} bytes_received={d}\n",
                .{ stats.smoothed_rtt_us, stats.cwnd, stats.bytes_sent, stats.bytes_received },
            );
        }

        // Drain H3 events (auto-starts the session) and assemble the
        // response through the runner.
        _ = try flow.endpoint.drainSession();
        for (flow.endpoint.events.?.items) |event| {
            switch (try flow.runner.observe(event)) {
                .response_complete => |response| {
                    if (flow.response == null) flow.response = response;
                },
                // Capture half of the ticket flow: the server's SETTINGS
                // are what a future 0-RTT run must comply with (§7.2.4.2
                // ¶5), so they go into the envelope beside the ticket.
                .settings => |settings| if (flow.binder) |binder| binder.onPeerSettings(settings),
                // At-most-once 0-RTT disposition. On rejection nothing is
                // required of us: quic replays the staged request
                // verbatim at 1-RTT and the remembered settings are
                // discarded (§7.2.4.2 ¶7).
                .early_data => |early| switch (early.status) {
                    .accepted => std.debug.print("[client] 0-RTT accepted\n", .{}),
                    .rejected => std.debug.print(
                        "[client] 0-RTT rejected ({s}); request completed at 1-RTT\n",
                        .{early.reason},
                    ),
                },
                .goaway => |id| std.debug.print("[client] goaway observed (id={d})\n", .{id}),
                .connection_closed => |closed| {
                    std.debug.print(
                        "[client] connection closed early (source={s} code={d})\n",
                        .{ @tagName(closed.source), closed.error_code },
                    );
                    return error.ConnectionClosedEarly;
                },
                else => {},
            }
        }
        _ = flow.endpoint.clearEvents();

        if (flow.response) |response| {
            const reader = response.reader();
            std.debug.print("[client] status={s}\n", .{reader.status() orelse ""});
            std.debug.print("[client] body={s}", .{reader.body()});
            // Clean H3-level close (H3_NO_ERROR maps to a QUIC
            // application CONNECTION_CLOSE); `runUdpClient` exits on
            // its own once the connection latches closed.
            flow.session.close(http3_zig.protocol.ErrorCode.no_error, "done");
            flow.done = true;
        }
    }
};

/// Run one GET round-trip against `target`. Returns an error if the
/// exchange fails, the status is not 200, `timeout_us` elapses, or (when
/// non-null) the body does not equal `expect_body`. Factored out of
/// `main` so `udp_smoke.zig` can drive the identical flow in-process.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    timeout_us: u64,
    expect_body: ?[]const u8,
) !void {
    const alpn = [_][]const u8{"h3"};

    // 0-RTT capture half (any run with `--session-cache`): the binder
    // pairs the quic NewSessionTicket envelope with the server's
    // SETTINGS, in whichever order they arrive, into the `H3RS`
    // envelope persisted below.
    var binder = earlydata.TicketBinder.init(allocator);
    defer binder.deinit();

    // 0-RTT resume half: a stored envelope means this run can stage the
    // GET in the first flight. `decode` borrows from `stored`, so the
    // buffer stays alive for the whole run.
    var stored: ?[]u8 = null;
    defer if (stored) |bytes| allocator.free(bytes);
    var resumed: ?earlydata.Decoded = null;
    if (options.session_cache) |path| {
        if (std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_session_cache_bytes))) |bytes| {
            stored = bytes;
            resumed = try earlydata.decode(bytes);
        } else |err| switch (err) {
            // First run against this cache path: no ticket yet — do a
            // normal 1-RTT fetch and earn one below.
            error.FileNotFound => {},
            else => return err,
        }
    }

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = options.sni,
        .alpn_protocols = &alpn,
        .transport_params = transportParams(),
        // Default posture verifies against the system trust store;
        // `--insecure` opts out for the demo server's self-signed cert.
        .insecure_skip_verify = options.insecure,
        // Resumption: the wrapper installs the ticket, enables early
        // data, and bounds 0-RTT sends by the remembered peer transport
        // parameters — no manual `setEarlyDataEnabled` needed.
        .resumption_state = if (resumed) |decoded| decoded.quic_resumption_state else null,
        // Ticket capture: servers may issue fresh NewSessionTickets on
        // every connection (including resumed ones); latest wins.
        .new_session_callback = if (options.session_cache != null) captureTicket else null,
        .new_session_user_data = if (options.session_cache != null) @as(?*anyopaque, &binder) else null,
        // Transport tuning (docs/embedding-guide.md "Transport
        // Tuning"). Since quic 0.11 the defaults are the deployment
        // posture — CUBIC + pacing + HyStart++ — so this demo sets
        // nothing; the levers, shown at their defaults:
        // .congestion_control = .cubic, // .bbr = BBRv3 opt-in; .new_reno = pre-0.11 rollback
        // .enable_pacing = true, // false restores pre-0.11 burst timing exactly
        // .enable_hystart = true, // false restores plain RFC 9002 slow start
    });
    defer client.deinit();

    var session = http3_zig.Session.init(
        allocator,
        .client,
        client.conn,
        http3_zig.SessionConfig.production(.{}),
    );
    defer session.deinit();
    // §7.2.4.2 ¶5: comply with the ticket-issuing connection's SETTINGS
    // until the resumed connection's real SETTINGS arrive. Must land
    // before any SETTINGS exchange, so: right after init.
    if (resumed) |decoded| try session.rememberPeerSettings(decoded.settings);

    // `--qlog`: stream this connection's qlog events into
    // `<dir>/client-<timestamp>.sqlog` via quic's own JSON-SEQ writer
    // (`quic.qlog.Writer`, qlog 0.4) — its `callback` is installed
    // through the same `setQuicQlogCallback` passthrough any embedder
    // uses, and per-packet events are opted in with the
    // `setQlogPacketEvents` passthrough (high-volume; right for a demo
    // trace, off by default in production). Installed BEFORE start/
    // advance: since quic 0.12 `connection_started` fires at install
    // time (the first moment a sink exists), so the whole handshake
    // lands in the trace.
    var qlog_file: ?std.Io.File = null;
    defer if (qlog_file) |file| file.close(io);
    var qlog_writer: ?quic.qlog.Writer = null;
    defer if (qlog_writer) |*writer| {
        // Uninstall first so nothing later in teardown can call into a
        // dead writer; closing the file above flushes the trace.
        session.setQuicQlogCallback(null, null);
        writer.deinit();
    };
    if (options.qlog_dir) |dir| {
        try std.Io.Dir.cwd().createDirPath(io, dir);
        const stamp = std.Io.Timestamp.now(io, .real).toMilliseconds();
        const qlog_path = try std.fmt.allocPrint(allocator, "{s}/client-{d}.sqlog", .{ dir, stamp });
        defer allocator.free(qlog_path);
        qlog_file = try std.Io.Dir.cwd().createFile(io, qlog_path, .{});
        qlog_writer = try quic.qlog.Writer.init(allocator, io, qlog_file.?, .{
            .vantage_point = .client,
            .title = "http3-zig-udp-client",
        });
        session.setQuicQlogCallback(quic.qlog.Writer.callback, &qlog_writer.?);
        session.setQlogPacketEvents(true);
        std.debug.print("[client] qlog trace -> {s} (JSON-SEQ .sqlog; loads in qvis)\n", .{qlog_path});
    }

    var h3_client = http3_zig.Client.init(&session);
    var runner = http3_zig.ClientRunner.init(allocator);
    defer runner.deinit();

    var events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        session.clearEvents(&events);
        events.deinit(allocator);
    }
    var endpoint = http3_zig.TransportEndpoint.withSession(client.conn, &session, &events);

    // 0-RTT staging: the H3 control stream (SETTINGS) and the request
    // must be queued BEFORE the first `advance()` — only then does the
    // first flight coalesce ClientHello + 0-RTT stream data. Stage only
    // idempotent requests here: transport anti-replay protects the
    // connection, not your application semantics (RFC 9470 territory).
    var request_staged = false;
    if (resumed != null) {
        try session.start();
        const request = try h3_client.request(allocator, .{
            .authority = options.sni,
            .path = options.path,
        });
        request_staged = true;
        std.debug.print(
            "[client] resuming session; staged GET {s} on stream {d} in the 0-RTT flight\n",
            .{ options.path, request.stream_id },
        );
    }

    // Client bootstrap: run the handshake state machine once so the
    // first ClientHello is queued for the wire — on a real network
    // there is no inbound packet to bootstrap from (`Client.connect`
    // defers this so 0-RTT data could be staged first, as above).
    // `runUdpClient` performs the same call itself, so this is
    // redundant here, but it is THE step an open-coded client loop must
    // not forget; loopback examples rely on the in-process peer shim
    // instead.
    try endpoint.advance();

    std.debug.print(
        "[client] connecting to {s} (SNI {s}, ALPN h3, verify={s})\n",
        .{ options.target, options.sni, if (options.insecure) "insecure" else "system" },
    );

    var flow: FetchFlow = .{
        .allocator = allocator,
        .session = &session,
        .h3_client = &h3_client,
        .runner = &runner,
        .endpoint = &endpoint,
        .authority = options.sni,
        .path = options.path,
        .deadline_us = timeout_us,
        .binder = if (options.session_cache != null) &binder else null,
        .request_sent = request_staged,
    };
    try quic.transport.runUdpClient(&client, .{
        .target = options.target,
        .io = io,
        // Demo posture, same as the server: run unprivileged.
        .tune_socket = false,
        // Batched-datapath levers (0.11+ defaults shown; see
        // docs/embedding-guide.md "Transport Tuning"):
        // .max_datagrams_per_iteration = 16, // ingress batch per iteration; 1 = historical behavior
        // .max_send_batch_datagrams = 64, // egress batch per sendMany (sendmmsg on Linux)
        // .enable_gso = true, // Linux UDP generic segmentation offload; no effect elsewhere
        // .enable_gro = true, // Linux UDP generic receive offload; no effect elsewhere
        .on_iteration = FetchFlow.onIteration,
        .on_iteration_ctx = &flow,
    });

    // The loop can also exit on handshake failure or a server-initiated
    // close — only a completed flow means the GET happened.
    if (!flow.done) return error.RequestIncomplete;
    const reader = flow.response.?.reader();
    if (!std.mem.eql(u8, reader.status() orelse "", "200")) return error.UnexpectedStatus;
    if (expect_body) |expected| {
        if (!std.mem.eql(u8, reader.body(), expected)) return error.UnexpectedBody;
    }

    // Persist the fresh `H3RS` envelope, overwriting any previous one —
    // the embedder owns the origin-keyed store, and a flat file per
    // target is the simplest correct one.
    if (options.session_cache) |path| {
        if (try binder.tryEncode(allocator)) |envelope| {
            defer allocator.free(envelope);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = envelope });
            std.debug.print("[client] session cache written to {s} ({d} bytes)\n", .{ path, envelope.len });
        } else {
            // A 0-RTT exchange can complete before a fresh ticket
            // arrives; the stored envelope (if any) stays as-is.
            std.debug.print("[client] no fresh session ticket captured; cache unchanged\n", .{});
        }
    }

    std.debug.print("[client] closed cleanly\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // program name

    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--insecure")) {
            options.insecure = true;
        } else if (std.mem.eql(u8, arg, "--sni")) {
            options.sni = args.next() orelse return error.MissingSni;
        } else if (std.mem.eql(u8, arg, "--path")) {
            options.path = args.next() orelse return error.MissingPath;
        } else if (std.mem.eql(u8, arg, "--session-cache")) {
            options.session_cache = args.next() orelse return error.MissingSessionCachePath;
        } else if (std.mem.eql(u8, arg, "--qlog")) {
            options.qlog_dir = args.next() orelse return error.MissingQlogDir;
        } else {
            options.target = arg;
        }
    }

    try run(allocator, io, options, 15 * std.time.us_per_s, null);
}
