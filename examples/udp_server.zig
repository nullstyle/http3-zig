//! UDP server — the production HTTP/3 server skeleton.
//!
//! One real UDP socket, many concurrent QUIC connections, one
//! `http3_zig.Session` per connection:
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/http3-zig-udp-server                # listens on 127.0.0.1:4433
//! ./zig-out/bin/http3-zig-udp-client --insecure     # GETs / against it
//! ```
//!
//! The shape to copy for your own server:
//!
//!  1. `quic_zig.Server.init` owns TLS, accept/demux, Retry, and the
//!     connection table. This example uses the auto-built TLS path
//!     (`tls_cert_pem`/`tls_key_pem` + `.alpn_protocols = &.{"h3"}`):
//!     it produces the same TLS-1.3-only / ALPN-pinned context that
//!     `http3_zig.server.initTlsContext` builds, the Server owns its
//!     lifetime, and `Server.replaceTlsContext` rotation works.
//!     (`Config.tls_context_override` also accepts a context built by
//!     `http3_zig.server.initTlsContext` — use that only when you need
//!     TLS behavior the auto-built path doesn't expose, e.g. keylog or
//!     session-ticket callbacks; the override context's lifetime then
//!     stays yours.)
//!  2. `quic_zig.transport.runUdpServer` owns the socket and the
//!     receive/tick/drain loop on a monotonic clock. ALL application
//!     logic lives in the `on_iteration` hook — the one place where
//!     touching a loop-owned `Server` is safe (no internal locking;
//!     the hook runs on the loop thread, after ingest and before the
//!     outbox drain, so responses ship the same iteration).
//!  3. Per-connection HTTP/3 state (Session + facade + runner + event
//!     list + TransportEndpoint) hangs off `Slot.user_data`, created on
//!     first sight of a slot and released in
//!     `Config.on_connection_will_close`.
//!  4. Teardown is ordered: the will-close hook runs inside `reap`
//!     while `slot.conn` is still valid, which is exactly what makes it
//!     safe for the `Session` (which borrows `slot.conn`) to deinit
//!     there — and never later. This ordering is what makes reap safe.
//!  5. Graceful shutdown is two-phase: SIGINT starts an HTTP/3 GOAWAY
//!     drain (`sendGoaway(gracefulGoawayId())` per session, pump until
//!     `openRequestStreamCount() == 0` or a drain deadline), and only
//!     then flips the loop's shutdown flag so `runUdpServer` queues
//!     CONNECTION_CLOSE on every slot and drains its own grace window.
//!
//! Serving model: requests are assembled with `ServerRunner` (owned
//! request lifecycle state that survives the drain batch) — the blessed
//! shape for whole-request handlers. Applications that stream uploads
//! or enforce their own body budgets classify raw events instead
//! (`http3_zig.RequestEvent.from(event)`; see
//! `examples/bounded_body_sink.zig`). Routing is application space and
//! kept as a visible branch on the request path in `serveRequest`.

const std = @import("std");
const builtin = @import("builtin");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

/// Self-signed localhost certificate + key (PEM). Test fixtures copied
/// from `tests/data/` so this module (rooted at `examples/`) can
/// `@embedFile` them. Localhost demos only — a real deployment supplies
/// its own PEM pair and clients verify against real roots.
pub const cert_pem = @embedFile("support/test_cert.pem");
pub const key_pem = @embedFile("support/test_key.pem");

/// Default address the udp_server/udp_client pair rendezvous on.
pub const default_addr = "127.0.0.1:4433";

/// Body served for `GET /` — exported so `udp_smoke.zig` can assert the
/// exact bytes round-tripped.
pub const index_body =
    "<!doctype html>\n" ++
    "<html><head><title>http3-zig</title></head>\n" ++
    "<body><h1>hello from http3-zig</h1>\n" ++
    "<p>served over HTTP/3 by examples/udp_server.zig</p></body></html>\n";

pub const not_found_body = "not found\n";

/// How long the GOAWAY drain waits for in-flight requests before the
/// loop-level shutdown (CONNECTION_CLOSE) starts anyway.
const drain_grace_us: u64 = 3 * std.time.us_per_s;

/// Transport parameters advertised to every accepted connection.
/// Sized for HTTP/3: enough uni-stream credit for the peer's control +
/// QPACK encoder/decoder streams (>= 3), a healthy bidi budget for
/// request streams, and a non-zero `max_datagram_frame_size` so the
/// RFC 9297 HTTP/3 DATAGRAM extension path stays open (costs nothing
/// for plain request/response).
fn transportParams() quic_zig.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 128,
        .initial_max_streams_uni = 16,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
    };
}

/// Per-connection application state, allocated on the first sight of a
/// slot, hung off `Slot.user_data`, and freed in
/// `onConnectionWillClose`. quic_zig never reads or frees `user_data`;
/// the will-close hook is the last safe place to release it.
const ConnState = struct {
    /// HTTP/3 session over the slot's `*quic_zig.Connection`.
    /// `SessionConfig.production(.{})` is the deployment posture — the
    /// bare `.{}` defaults are a compatibility posture with unbounded
    /// buffers.
    session: http3_zig.Session,
    /// Facade for respond/goaway/reset over the session.
    facade: http3_zig.Server,
    /// Owned request lifecycle assembly (headers + body + terminal
    /// state that outlives the drain batch).
    runner: http3_zig.ServerRunner,
    /// Drained-event storage; payloads are owned by the drainer and
    /// released with the session-bound `clearEvents`.
    events: std.ArrayList(http3_zig.Event),
    /// Keeps the repeated QUIC/H3 step order in one place. The loop
    /// already owns handle/tick/poll for the slot; the hook only uses
    /// `drainSession` / `clearEvents`.
    endpoint: http3_zig.TransportEndpoint,
    /// Copied from `slot.slot_id` for log lines.
    slot_id: u64,
    /// One GOAWAY per session during the drain phase.
    goaway_sent: bool = false,
    /// Tiny per-connection counter, reported at close.
    requests_served: u32 = 0,
};

fn connState(slot: *quic_zig.Server.Slot) ?*ConnState {
    const ptr = slot.user_data orelse return null;
    return @ptrCast(@alignCast(ptr));
}

/// Application context threaded through both hooks as an opaque
/// pointer.
pub const App = struct {
    allocator: std.mem.Allocator,
    /// Flipped by SIGINT (or the smoke harness): starts the HTTP/3
    /// GOAWAY drain.
    request_shutdown: *const std.atomic.Value(bool),
    /// Handed to `runUdpServer` as its `shutdown_flag`; the hook flips
    /// it once the GOAWAY drain completes (or its deadline expires) so
    /// the loop queues CONNECTION_CLOSE and runs its own grace window.
    loop_shutdown: *std.atomic.Value(bool),
    drain_started: bool = false,
    drain_deadline_us: u64 = 0,

    /// `transport.RunUdpOptions.on_iteration` — fires once per loop
    /// iteration on the loop thread. `now_us` is the loop's monotonic
    /// clock (microseconds since loop start): the same domain every
    /// `handle`/`tick`/`poll` call and `OpenRequestStream.last_event_us`
    /// use. Embedders that open-code the loop instead of using
    /// `runUdpServer` size their poll/sleep timeout with
    /// `quic_zig.Server.nextTimerDeadline(now_us)` (per-connection:
    /// `Connection.nextTimerDeadline`) rather than sleeping a fixed
    /// interval — that keeps PTO/loss timers firing on schedule without
    /// busy-spinning.
    pub fn onIteration(ctx: ?*anyopaque, server: *quic_zig.Server, now_us: u64) anyerror!void {
        const app: *App = @ptrCast(@alignCast(ctx.?));

        // Shutdown phase 1: SIGINT observed -> start the HTTP/3 drain.
        if (!app.drain_started and app.request_shutdown.load(.acquire)) {
            app.drain_started = true;
            app.drain_deadline_us = now_us +| drain_grace_us;
            std.debug.print("[server] shutdown requested; draining in-flight requests\n", .{});
        }

        for (server.iterator()) |slot| {
            // Per-connection state on first sight. The slot was created
            // by `feed` when the first Initial arrived; everything H3
            // hangs off `slot.user_data` from here on.
            const state = app.ensureState(slot) catch |err| {
                std.debug.print(
                    "[server] conn {d}: state init failed: {s}\n",
                    .{ slot.slot_id, @errorName(err) },
                );
                continue;
            };

            // Shutdown phase 1, per session: GOAWAY at the
            // session-derived "covers nothing new" id (RFC 9114 §5.2).
            // In-flight requests keep draining below.
            if (app.drain_started and !state.goaway_sent) {
                state.session.sendGoaway(state.session.gracefulGoawayId()) catch {};
                state.goaway_sent = true;
            }

            // Drain + serve. Per-connection failures close that
            // connection, never the whole server.
            app.pumpSlot(state) catch |err| {
                std.debug.print(
                    "[server] conn {d}: session error: {s}\n",
                    .{ state.slot_id, @errorName(err) },
                );
                state.session.close(http3_zig.protocol.ErrorCode.internal_error, "");
            };
        }

        // Shutdown phase 2: every request admitted before the GOAWAYs
        // has finished (session-derived, no app-side stream map) or the
        // drain deadline passed -> hand shutdown to the loop.
        if (app.drain_started and !app.loop_shutdown.load(.acquire)) {
            var open_requests: usize = 0;
            for (server.iterator()) |slot| {
                if (connState(slot)) |state| {
                    open_requests += state.session.openRequestStreamCount();
                }
            }
            if (open_requests == 0 or now_us >= app.drain_deadline_us) {
                std.debug.print(
                    "[server] drain complete ({d} open request(s)); closing connections\n",
                    .{open_requests},
                );
                app.loop_shutdown.store(true, .release);
            }
        }
    }

    /// `Server.Config.on_connection_will_close` — runs inside `reap`
    /// for each closed slot while `slot.conn` / `slot.user_data` are
    /// still valid. THE ordered-teardown pattern: the `Session` borrows
    /// `slot.conn`, so this hook — before reap destroys the connection —
    /// is the last safe place to deinit it. Doing it here (and nowhere
    /// else) is what makes reap safe. Events are cleared with the
    /// session-bound `clearEvents` first (payloads were cloned from the
    /// session's allocator), then the session, then the state itself.
    pub fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic_zig.Server.Slot) void {
        const app: *App = @ptrCast(@alignCast(ctx.?));
        const state = connState(slot) orelse return;
        std.debug.print(
            "[server] conn {d}: reaped after {d} request(s)\n",
            .{ state.slot_id, state.requests_served },
        );
        state.session.clearEvents(&state.events);
        state.events.deinit(app.allocator);
        state.runner.deinit();
        state.session.deinit();
        app.allocator.destroy(state);
        slot.user_data = null;
    }

    fn ensureState(app: *App, slot: *quic_zig.Server.Slot) !*ConnState {
        if (connState(slot)) |state| return state;
        const state = try app.allocator.create(ConnState);
        errdefer app.allocator.destroy(state);
        state.* = .{
            .session = http3_zig.Session.init(
                app.allocator,
                .server,
                slot.conn,
                http3_zig.SessionConfig.production(.{}),
            ),
            .facade = undefined,
            .runner = http3_zig.ServerRunner.init(app.allocator),
            .events = .empty,
            .endpoint = undefined,
            .slot_id = slot.slot_id,
        };
        // Facade + endpoint hold pointers into the heap ConnState, so
        // they are wired up only after the struct is at its final
        // address.
        state.facade = http3_zig.Server.init(&state.session);
        state.endpoint = http3_zig.TransportEndpoint.withSession(
            slot.conn,
            &state.session,
            &state.events,
        );
        slot.user_data = state;
        std.debug.print("[server] conn {d}: accepted\n", .{state.slot_id});
        return state;
    }

    /// Drain the H3 session (auto-starts it), assemble requests through
    /// the runner, serve completed ones, release event payloads.
    fn pumpSlot(app: *App, state: *ConnState) !void {
        _ = try state.endpoint.drainSession();
        for (state.events.items) |event| {
            switch (try state.runner.observe(event)) {
                .request_complete => |request| try app.serveRequest(state, request),
                .connection_closed => |closed| std.debug.print(
                    "[server] conn {d}: close observed (source={s} code={d})\n",
                    .{ state.slot_id, @tagName(closed.source), closed.error_code },
                ),
                else => {},
            }
        }
        _ = state.endpoint.clearEvents();
    }

    fn serveRequest(
        app: *App,
        state: *ConnState,
        request: *const http3_zig.RequestState,
    ) !void {
        // Reset/rejected exchanges have no response to write.
        if (request.reset != null or request.rejected != null) return;
        if (!request.complete or request.headers == null) return;

        const method = request.method() orelse "GET";
        const path = request.path() orelse "/";

        // Routing is application space — keep it a visible branch on
        // the request path.
        var status: []const u8 = undefined;
        var body: []const u8 = undefined;
        if (std.mem.eql(u8, path, "/")) {
            status = "200";
            body = index_body;
        } else {
            status = "404";
            body = not_found_body;
        }

        const response_headers = [_]http3_zig.FieldLine{
            .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        };
        _ = try state.facade.respond(app.allocator, request.stream_id, .{
            .status = status,
            .headers = &response_headers,
            .body = body,
        });
        state.requests_served += 1;
        std.debug.print(
            "[server] conn {d}: {s} {s} -> {s} ({d} bytes)\n",
            .{ state.slot_id, method, path, status, body.len },
        );
    }
};

/// Run the HTTP/3 server until `request_shutdown` flips and the GOAWAY
/// drain completes (or the loop fails). Factored out of `main` so
/// `udp_smoke.zig` can drive the identical loop on a background thread.
pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    request_shutdown: *const std.atomic.Value(bool),
) !void {
    var loop_shutdown = std.atomic.Value(bool).init(false);
    var app: App = .{
        .allocator = allocator,
        .request_shutdown = request_shutdown,
        .loop_shutdown = &loop_shutdown,
    };
    const alpn = [_][]const u8{"h3"};

    var server = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = cert_pem,
        .tls_key_pem = key_pem,
        .alpn_protocols = &alpn,
        .transport_params = transportParams(),
        .on_connection_will_close = App.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
    });
    defer server.deinit();

    std.debug.print("[server] HTTP/3 server listening on {s} (ALPN h3)\n", .{listen});

    try quic_zig.transport.runUdpServer(&server, .{
        .listen = listen,
        .io = io,
        .shutdown_flag = &loop_shutdown,
        // Demo posture: skip the SO_RCVBUF/SO_SNDBUF bump so the
        // example runs unprivileged everywhere. Production servers
        // should leave `tune_socket = true` (the default).
        .tune_socket = false,
        .on_iteration = App.onIteration,
        .on_iteration_ctx = &app,
    });

    std.debug.print("[server] shut down cleanly\n", .{});
}

// -- SIGINT -> shutdown flag ------------------------------------------------

var sigint_flag = std.atomic.Value(bool).init(false);

fn onSigInt(_: std.posix.SIG) callconv(.c) void {
    sigint_flag.store(true, .release);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // program name
    const listen = args.next() orelse default_addr;

    if (builtin.os.tag != .windows) {
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = onSigInt },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &act, null);
        std.debug.print("[server] Ctrl-C to shut down gracefully (GOAWAY drain)\n", .{});
    }

    try serve(allocator, io, listen, &sigint_flag);
}
