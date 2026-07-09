//! UDP client — the real-socket HTTP/3 client example, paired with
//! `udp_server.zig`.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/http3-zig-udp-server &
//! ./zig-out/bin/http3-zig-udp-client --insecure [target] [--sni host] [--path /]
//! ```
//!
//! The shape to copy for your own client:
//!
//!  1. `quic_zig.Client.connect` builds the TLS context (system trust
//!     store by default; `--insecure` maps to `insecure_skip_verify`
//!     for the demo server's self-signed cert — never set that against
//!     an untrusted network) and a ready-to-tick `Connection`.
//!  2. `http3_zig.Session` + `Client` facade + `ClientRunner` ride on
//!     `client.conn`; `TransportEndpoint.withSession` keeps the H3
//!     drain order in one place.
//!  3. `quic_zig.transport.runUdpClient` owns the socket and the
//!     advance/receive/tick loop; ALL application logic lives in the
//!     `on_iteration` hook, on the loop thread.
//!  4. The request is sent only after `handshakeDone()` — http3-zig has
//!     no blessed 0-RTT request path yet, so sending H3 requests before
//!     the handshake is established is undefined.
//!
//! Flow: wait for the handshake, send `GET <path>`, assemble the
//! response with `ClientRunner`, print status + body, close cleanly
//! with H3_NO_ERROR (which exits the loop).

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

pub const default_target = "127.0.0.1:4433";

const Options = struct {
    target: []const u8 = default_target,
    sni: []const u8 = "localhost",
    path: []const u8 = "/",
    insecure: bool = false,
};

/// Transport parameters this client advertises. Same H3-suitable shape
/// as the interop client: enough uni-stream credit for the peer's
/// control + QPACK streams, and a large `max_udp_payload_size` receive
/// limit (the RFC 9000 default) so the server's coalesced handshake
/// datagrams are not dropped as too large — 1200 is the RFC minimum
/// send floor, not a good receive limit.
fn transportParams() quic_zig.tls.TransportParams {
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
    request_sent: bool = false,
    /// Set once the response completes; body/status stay owned by the
    /// runner, so `run` can validate them after the loop exits.
    response: ?*http3_zig.ResponseState = null,
    done: bool = false,

    /// `transport.RunUdpClientOptions.on_iteration` — fires once per
    /// loop iteration on the loop thread, after inbound datagrams are
    /// handled and the clock ticked; anything queued here ships on the
    /// very next outbox drain.
    pub fn onIteration(ctx: ?*anyopaque, client: *quic_zig.Client, now_us: u64) anyerror!void {
        const flow: *FetchFlow = @ptrCast(@alignCast(ctx.?));
        if (flow.done) return;
        if (now_us > flow.deadline_us) return error.RequestTimedOut;

        // No blessed H3 0-RTT/early-data request path exists yet: wait
        // for 1-RTT before opening the request stream. (The session's
        // drain consumes `pollEvent`, so the latched `handshakeDone()`
        // query is the signal to use here, not the one-shot event.)
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

        // Drain H3 events (auto-starts the session) and assemble the
        // response through the runner.
        _ = try flow.endpoint.drainSession();
        for (flow.endpoint.events.?.items) |event| {
            switch (try flow.runner.observe(event)) {
                .response_complete => |response| {
                    if (flow.response == null) flow.response = response;
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

    var client = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = options.sni,
        .alpn_protocols = &alpn,
        .transport_params = transportParams(),
        // Default posture verifies against the system trust store;
        // `--insecure` opts out for the demo server's self-signed cert.
        .insecure_skip_verify = options.insecure,
    });
    defer client.deinit();

    var session = http3_zig.Session.init(
        allocator,
        .client,
        client.conn,
        http3_zig.SessionConfig.production(.{}),
    );
    defer session.deinit();

    var h3_client = http3_zig.Client.init(&session);
    var runner = http3_zig.ClientRunner.init(allocator);
    defer runner.deinit();

    var events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        session.clearEvents(&events);
        events.deinit(allocator);
    }
    var endpoint = http3_zig.TransportEndpoint.withSession(client.conn, &session, &events);

    // Client bootstrap: run the handshake state machine once so the
    // first ClientHello is queued for the wire — on a real network
    // there is no inbound packet to bootstrap from (`Client.connect`
    // defers this so 0-RTT data could be staged first). `runUdpClient`
    // performs the same call itself, so this is redundant here, but it
    // is THE step an open-coded client loop must not forget; loopback
    // examples rely on the in-process peer shim instead.
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
    };
    try quic_zig.transport.runUdpClient(&client, .{
        .target = options.target,
        .io = io,
        // Demo posture, same as the server: run unprivileged.
        .tune_socket = false,
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
        } else {
            options.target = arg;
        }
    }

    try run(allocator, io, options, 15 * std.time.us_per_s, null);
}
