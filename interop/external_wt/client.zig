//! External WebTransport interop client harness.
//!
//! Sister to `interop/external_h3/client.zig`. Drives http3-zig as a
//! WebTransport client against a third-party server (quiche, aioquic,
//! Chromium origin trial, native_messaging, ...). Reads the target URL
//! from the `WT_INTEROP_URL` environment variable. If the variable is
//! unset, the harness exits cleanly with a "skipped" status so this
//! binary can be wired into CI without requiring a peer to be present.
//!
//! Flow exercised on the wire (mirrors `examples/loopback_wt.zig`):
//!
//!   1. UDP socket bind + QUIC handshake.
//!   2. SETTINGS exchange with WebTransport advertised
//!      (enable_connect_protocol + h3_datagram + wt_enabled).
//!   3. Extended CONNECT for `:protocol = webtransport` against the URL's
//!      authority/path.
//!   4. Wait for a 2xx response on the CONNECT stream.
//!   5. Send a single datagram and one client-initiated unidirectional
//!      WebTransport stream.
//!   6. Send `CLOSE_WEBTRANSPORT_SESSION` and finish the CONNECT stream.
//!
//! Exit codes:
//!   * 0 — success (handshake landed, datagram + uni stream sent, close OK)
//!         or skipped (no `WT_INTEROP_URL` set).
//!   * 1 — protocol failure observed against the peer.
//!   * 2 — setup / network failure (URL parse, DNS, socket bind, ...).
//!
//! TLS verification follows the existing `external_h3` harness: defaults
//! to `.none` for interop testing. Pass `--verify-system` to flip back to
//! the platform trust store if the peer's cert chains correctly.

const std = @import("std");
const boringssl = @import("boringssl");
const quic_zig = @import("quic_zig");
const http3_zig = @import("http3_zig");

const Net = std.Io.net;

/// Reason the harness terminates without running the protocol exchange.
const SkipReason = enum {
    no_url,
};

/// Top-level error category used to map errors onto exit codes.
const Category = enum { protocol, setup };

const initial_dcid = [_]u8{ 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
const local_scid = [_]u8{ 0xc3, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

const datagram_payload = "hello-from-http3-zig";
const uni_payload = "hello-uni";
const close_code: u32 = 0x0;
const close_reason: []const u8 = "bye";

const env_var = "WT_INTEROP_URL";

const Options = struct {
    url: []const u8,
    local: []const u8 = "0.0.0.0:0",
    /// Optional override for the SNI / `:authority`. Defaults to the URL host.
    sni: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    /// Pump bound. Mirrors `external_h3/client.zig` defaults but bumped a
    /// little to give a roundtrip + close room over a real network.
    max_time_ms: u64 = 30_000,
    max_iterations: u32 = 100_000,
    verify: boringssl.tls.VerifyMode = .none,
};

const ParsedUrl = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const url = init.environ_map.get(env_var) orelse {
        try printSkip(io, .no_url);
        std.process.exit(0);
    };

    const cli = parseArgs(init, allocator) catch |err| {
        std.debug.print("external_wt: argument parse failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };

    var options = cli;
    options.url = url;

    runHarness(allocator, io, options) catch |err| {
        const category = classifyError(err);
        std.debug.print(
            "external_wt: harness failed with {s} ({s})\n",
            .{ @errorName(err), @tagName(category) },
        );
        std.process.exit(switch (category) {
            .protocol => 1,
            .setup => 2,
        });
    };
}

fn runHarness(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const parsed = parseUrl(options.url) catch |err| {
        std.debug.print("external_wt: invalid {s}=\"{s}\": {s}\n", .{ env_var, options.url, @errorName(err) });
        return error.InvalidUrl;
    };
    if (!std.mem.eql(u8, parsed.scheme, "https")) {
        std.debug.print(
            "external_wt: only https:// URLs are supported (got \"{s}\")\n",
            .{parsed.scheme},
        );
        return error.UnsupportedScheme;
    }

    const sni_bytes = options.sni orelse parsed.host;
    const authority = options.authority orelse parsed.host;

    std.debug.print(
        "external_wt: target={s}://{s}:{d}{s} (sni=\"{s}\", authority=\"{s}\")\n",
        .{ parsed.scheme, parsed.host, parsed.port, parsed.path, sni_bytes, authority },
    );

    const remote_addr = try resolveHost(io, parsed.host, parsed.port);
    const local_addr = try Net.IpAddress.parseLiteral(options.local);
    const sock = try Net.IpAddress.bind(&local_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    const sni_z = try allocator.dupeZ(u8, sni_bytes);
    defer allocator.free(sni_z);

    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = options.verify });
    defer client_tls.deinit();

    var conn = try quic_zig.Connection.initClient(allocator, client_tls, sni_z);
    defer conn.deinit();
    try conn.bind();

    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&initial_dcid);
    try conn.setLocalScid(&local_scid);
    try conn.setTransportParams(.{
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .initial_max_streams_uni = 16,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
    });

    var h3 = http3_zig.Session.init(allocator, .client, &conn, .{
        .settings = .{
            .qpack_max_table_capacity = 256,
            .qpack_blocked_streams = 4,
            .h3_datagram = true,
            .enable_connect_protocol = true,
            .wt_enabled = true,
        },
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 16 * 1024 * 1024,
        .max_data_frame_payload = 16 * 1024,
    });
    defer h3.deinit();

    try h3.start();

    var h3_client = http3_zig.Client.init(&h3);
    var runner = http3_zig.ClientRunner.init(allocator);
    defer runner.deinit();

    var events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &events);
        events.deinit(allocator);
    }

    var endpoint = http3_zig.TransportEndpoint.withSession(&conn, &h3, &events);

    var rx: [64 * 1024]u8 = undefined;
    var tx: [4096]u8 = undefined;

    var now_us: u64 = 1_000_000;
    const deadline_us = now_us + options.max_time_ms * 1000;
    var iters: u32 = 0;

    // Phase 1: pump until SETTINGS arrive in both directions.
    std.debug.print("external_wt: phase 1 — waiting for SETTINGS exchange\n", .{});
    while (h3.peer_settings == null) : (iters += 1) {
        if (now_us >= deadline_us or iters >= options.max_iterations) return error.SettingsExchangeTimedOut;
        try pumpOnce(allocator, io, &endpoint, &events, sock, remote_addr, &rx, &tx, now_us);
        try endpoint.tick(now_us);
        clearEvents(allocator, &events);
        now_us += http3_zig.driver.default_step_us;
    }
    if (!http3_zig.webtransport.peerEnabled(h3.peer_settings.?)) {
        std.debug.print("external_wt: peer SETTINGS do not advertise WebTransport\n", .{});
        return error.PeerDidNotEnableWebTransport;
    }
    std.debug.print("external_wt: phase 1 done — peer advertises WebTransport\n", .{});

    // Phase 2: open the WT CONNECT.
    var wt = try h3_client.startWebTransport(allocator, .{
        .scheme = "https",
        .authority = authority,
        .path = parsed.path,
    });
    const session_id = wt.sessionId();
    std.debug.print(
        "external_wt: phase 2 — opened CONNECT (stream_id={d}, authority=\"{s}\", path=\"{s}\")\n",
        .{ session_id, authority, parsed.path },
    );

    // Phase 3: drive the response, run the data exchange, send CLOSE.
    var saw_response = false;
    var sent_data = false;
    var sent_close = false;
    var saw_finish = false;

    while (!saw_finish) : (iters += 1) {
        if (now_us >= deadline_us or iters >= options.max_iterations) return error.HarnessTimedOut;
        if (conn.isClosed()) {
            std.debug.print("external_wt: connection closed before harness completed\n", .{});
            return error.ConnectionClosedEarly;
        }

        try pumpOnce(allocator, io, &endpoint, &events, sock, remote_addr, &rx, &tx, now_us);

        for (events.items) |event| {
            const observation = try runner.observe(event);
            switch (observation) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.streamId() != session_id) continue;
                    if (!saw_response and response.headers().len > 0) {
                        const status = response.status() orelse "";
                        if (response.webTransportAccepted()) {
                            std.debug.print(
                                "external_wt: phase 3 — WebTransport accepted (status={s})\n",
                                .{status},
                            );
                            saw_response = true;
                        } else {
                            std.debug.print(
                                "external_wt: peer rejected WebTransport CONNECT (status={s})\n",
                                .{status},
                            );
                            return error.WebTransportRejected;
                        }
                    }
                    if (observation == .response_complete and response.streamId() == session_id) {
                        saw_finish = true;
                    }
                },
                .datagram => |dgram| {
                    if (dgram.stream_id == session_id) {
                        std.debug.print(
                            "external_wt: phase 3 — received datagram (len={d})\n",
                            .{dgram.payload.len},
                        );
                    }
                },
                .connection_closed => |closed| {
                    std.debug.print(
                        "external_wt: peer closed connection (error_code=0x{x})\n",
                        .{closed.error_code},
                    );
                    return error.PeerClosedConnection;
                },
                else => {},
            }
        }
        clearEvents(allocator, &events);

        // Once the peer accepts the CONNECT, push our datagram + uni
        // stream payload, then send CLOSE in a follow-up loop iteration
        // so the data has a chance to flush first.
        if (saw_response and !sent_data) {
            try wt.sendDatagram(datagram_payload);
            std.debug.print(
                "external_wt: phase 3 — sent datagram (len={d})\n",
                .{datagram_payload.len},
            );

            const uni_id = try wt.openUniStream();
            try wt.writeStream(uni_id, uni_payload);
            try wt.finishStream(uni_id);
            std.debug.print(
                "external_wt: phase 3 — opened uni stream id={d}, payload=\"{s}\"\n",
                .{ uni_id, uni_payload },
            );
            sent_data = true;
        }

        if (sent_data and !sent_close) {
            try wt.close(close_code, close_reason);
            std.debug.print(
                "external_wt: phase 3 — sent CLOSE_WEBTRANSPORT_SESSION (code=0x{x}, reason=\"{s}\")\n",
                .{ close_code, close_reason },
            );
            sent_close = true;
        }

        try endpoint.tick(now_us);
        now_us += http3_zig.driver.default_step_us;

        // Once we've sent CLOSE the CONNECT stream's response_complete
        // observation flips `saw_finish` and the loop unwinds. If the
        // peer is unresponsive we still fall through to the deadline /
        // iteration bound checks at the top of the loop.
    }

    std.debug.print("external_wt: success — handshake + datagram + uni stream + close all flushed\n", .{});
}

fn pumpOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: *http3_zig.TransportEndpoint,
    events: *std.ArrayList(http3_zig.session.Event),
    sock: anytype,
    peer: Net.IpAddress,
    rx: []u8,
    tx: []u8,
    now_us: u64,
) !void {
    _ = allocator;
    _ = events;
    _ = try endpoint.drainSession();

    const Sink = struct {
        socket: @TypeOf(sock),
        io: std.Io,
        peer: Net.IpAddress,

        pub fn send(self: *@This(), bytes: []const u8) !void {
            try self.socket.send(self.io, &self.peer, bytes);
        }
    };

    var sink = Sink{ .socket = sock, .io = io, .peer = peer };
    _ = try endpoint.flush(tx, now_us, &sink);

    const maybe_msg = sock.receiveTimeout(io, rx, .{
        .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(5),
            .clock = .awake,
        },
    }) catch |err| switch (err) {
        error.Timeout => null,
        else => return err,
    };
    if (maybe_msg) |msg| {
        try endpoint.handle(msg.data, null, now_us);
    }
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn parseUrl(text: []const u8) !ParsedUrl {
    const uri = try std.Uri.parse(text);
    const host_component = uri.host orelse return error.UrlMissingHost;
    const host = switch (host_component) {
        .raw, .percent_encoded => |bytes| bytes,
    };
    if (host.len == 0) return error.UrlMissingHost;

    const default_port: u16 = if (std.mem.eql(u8, uri.scheme, "https")) 443 else 0;
    const port = uri.port orelse default_port;
    if (port == 0) return error.UrlMissingPort;

    const path = blk: {
        if (uri.path.isEmpty()) break :blk "/";
        break :blk switch (uri.path) {
            .raw, .percent_encoded => |bytes| bytes,
        };
    };

    return .{
        .scheme = uri.scheme,
        .host = host,
        .port = port,
        .path = path,
    };
}

fn resolveHost(io: std.Io, host: []const u8, port: u16) !Net.IpAddress {
    if (Net.IpAddress.parse(host, port)) |addr| return addr else |_| {}

    // Strip a trailing dot if the URL author wrote a fully-qualified name
    // — `HostName.validate` allows it but `HostName.lookup` is happier
    // working with the canonical form.
    const validated = Net.HostName.init(host) catch |err| {
        std.debug.print(
            "external_wt: \"{s}\" is neither an IP literal nor a valid hostname: {s}\n",
            .{ host, @errorName(err) },
        );
        return error.InvalidHost;
    };

    var lookup_buffer: [32]Net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(Net.HostName.LookupResult) = .init(&lookup_buffer);
    var future = io.async(Net.HostName.lookup, .{ validated, io, &lookup_queue, .{ .port = port } });
    defer future.cancel(io) catch {};

    var first: ?Net.IpAddress = null;
    while (lookup_queue.getOne(io)) |result| {
        switch (result) {
            .address => |addr| {
                if (first == null) first = addr;
            },
            .canonical_name => continue,
        }
    } else |err| switch (err) {
        error.Canceled => return err,
        error.Closed => {
            future.await(io) catch |lookup_err| {
                std.debug.print("external_wt: DNS lookup for \"{s}\" failed: {s}\n", .{ host, @errorName(lookup_err) });
                return error.DnsLookupFailed;
            };
        },
    }

    return first orelse error.NoDnsAddresses;
}

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    var options: Options = .{ .url = "" };
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--local")) {
            options.local = args.next() orelse return error.MissingLocalAddress;
        } else if (std.mem.eql(u8, arg, "--sni")) {
            options.sni = args.next() orelse return error.MissingSni;
        } else if (std.mem.eql(u8, arg, "--authority")) {
            options.authority = args.next() orelse return error.MissingAuthority;
        } else if (std.mem.eql(u8, arg, "--max-time-ms")) {
            options.max_time_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingTimeout, 10);
        } else if (std.mem.eql(u8, arg, "--max-iterations")) {
            options.max_iterations = try std.fmt.parseInt(u32, args.next() orelse return error.MissingIterations, 10);
        } else if (std.mem.eql(u8, arg, "--verify-system")) {
            options.verify = .system;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            options.verify = .none;
        } else {
            std.debug.print("external_wt: unknown argument \"{s}\"\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return options;
}

fn classifyError(err: anyerror) Category {
    return switch (err) {
        // Setup / network class — argument parsing, DNS, socket bring-up.
        error.InvalidUrl,
        error.UnsupportedScheme,
        error.UrlMissingHost,
        error.UrlMissingPort,
        error.InvalidHost,
        error.DnsLookupFailed,
        error.NoDnsAddresses,
        error.MissingLocalAddress,
        error.MissingSni,
        error.MissingAuthority,
        error.MissingTimeout,
        error.MissingIterations,
        error.UnknownArgument,
        error.OutOfMemory,
        => .setup,
        else => .protocol,
    };
}

fn printSkip(io: std.Io, reason: SkipReason) !void {
    var stdout_buf: [512]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    switch (reason) {
        .no_url => try stdout.print(
            "external_wt: SKIP — set {s}=https://host:port/path to run against a peer\n",
            .{env_var},
        ),
    }
    try stdout.flush();
}
