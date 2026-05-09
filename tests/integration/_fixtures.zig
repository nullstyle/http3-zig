//! Shared helpers for the integration test files in this directory.
//!
//! These were originally inlined at the top of `tests/root.zig`. When that
//! file grew past 4000 lines we split the tests across the per-feature
//! files in `tests/integration/` and pulled the helpers here.
//!
//! The test runner package boundary is `tests/` (entry point is
//! `tests/root.zig`), so `@embedFile("../data/test_cert.pem")` resolves to
//! `tests/data/test_cert.pem` from this file.

const std = @import("std");
const boringssl = @import("boringssl");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

pub const test_cert_pem = @embedFile("../data/test_cert.pem");
pub const test_key_pem = @embedFile("../data/test_key.pem");

pub const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
pub const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

pub fn discardKeylog(line: []const u8) void {
    _ = line;
}

pub fn handshake(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

pub fn initConnectedQuic(
    allocator: std.mem.Allocator,
    client_tls: anytype,
    server_tls: anytype,
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
) !void {
    client.* = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    errdefer client.deinit();
    server.* = try quic_zig.Connection.initServer(allocator, server_tls);
    errdefer server.deinit();

    // Surface CONNECTION_CLOSE reason phrases in the integration tests
    // so close-event assertions can verify them. quic_zig's hardening
    // default redacts the reason on the wire (hardening guide §9 / §12);
    // tests opt in to the visible form.
    client.reveal_close_reason_on_wire = true;
    server.reveal_close_reason_on_wire = true;

    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(client, server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // The `handshake` helper completes TLS through an in-process
    // outbox→inbox shim instead of real datagrams (see
    // `Connection.advance` and `shuttleOutboxToPeer` in quic-zig). On the
    // wire, RFC 9000 §8.1 / §8.1.4 promise that a server's primary path
    // is implicitly validated by receipt of an authenticated Handshake
    // packet from the client (`conn_recv_packet_handlers.zig` flips the
    // validated bit there). Bypassing the wire skips that flip, leaving
    // the server's path unvalidated with a 3*bytes_received anti-amp
    // budget of 0 — which silently drops outgoing CONNECTION_CLOSE
    // (RFC 9000 §10) and any other server-initiated 1-RTT bytes that
    // run before the client's first packet lands. Mark it validated
    // here so the fixture matches the post-handshake state real
    // datagrams would have produced. The client's primary path is
    // already validated in `Connection.initClient` per §8.1 (the
    // client picked the destination address itself).
    _ = server.markPathValidated(server.activePathId());
}

pub fn clearSessionEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

pub fn pumpH3(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
) !void {
    var pkt: [2048]u8 = undefined;
    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(client, client_h3, client_events),
        http3_zig.TransportEndpoint.withSession(server, server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 1,
        },
    );
    _ = try driver.step(&pkt);
    now_us.* = driver.now_us;
}

pub fn pumpUntilH3Error(
    allocator: std.mem.Allocator,
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
    expected: anyerror,
) !void {
    var iters: u32 = 0;
    while (iters < 20_000) : (iters += 1) {
        pumpH3(
            client,
            server,
            client_h3,
            server_h3,
            client_events,
            server_events,
            now_us,
        ) catch |err| {
            if (err != expected) return err;
            return;
        };
        clearSessionEvents(allocator, client_events);
        clearSessionEvents(allocator, server_events);
    }
    return error.ExpectedH3ErrorNotFound;
}

pub fn writeFrame(conn: *quic_zig.Connection, stream_id: u64, frame: http3_zig.Frame) !void {
    var buf: [4096]u8 = undefined;
    const n = try http3_zig.frame.encode(&buf, frame);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn writeQpackEncoderInstruction(
    conn: *quic_zig.Connection,
    stream_id: u64,
    instruction: http3_zig.QpackEncoderInstruction,
) !void {
    var buf: [512]u8 = undefined;
    const n = try http3_zig.qpack.instructions.encodeEncoderInstruction(&buf, instruction);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn writeStreamType(conn: *quic_zig.Connection, stream_id: u64, stream_type: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try quic_zig.wire.varint.encode(&buf, stream_type);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn writeVarint(conn: *quic_zig.Connection, stream_id: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try quic_zig.wire.varint.encode(&buf, value);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn openUniWithType(conn: *quic_zig.Connection, stream_id: u64, stream_type: u64) !void {
    _ = try conn.openUni(stream_id);
    try writeStreamType(conn, stream_id, stream_type);
}

pub fn writeHeadersFrame(conn: *quic_zig.Connection, stream_id: u64, fields: []const http3_zig.FieldLine) !void {
    var block: [2048]u8 = undefined;
    const block_n = try http3_zig.qpack.encodeFieldSection(&block, fields);
    try writeFrame(conn, stream_id, .{ .headers = block[0..block_n] });
}

pub fn writePushPromiseFrame(
    conn: *quic_zig.Connection,
    stream_id: u64,
    push_id: u64,
    fields: []const http3_zig.FieldLine,
) !void {
    var block: [2048]u8 = undefined;
    const block_n = try http3_zig.qpack.encodeFieldSection(&block, fields);
    try writeFrame(conn, stream_id, .{
        .push_promise = .{
            .push_id = push_id,
            .field_section = block[0..block_n],
        },
    });
}

pub fn expectLastCloseCode(session: *const http3_zig.Session, code: u64) !void {
    const close = session.lastCloseError() orelse return error.MissingCloseError;
    try std.testing.expectEqual(code, close.application.code);
}

pub fn fieldValue(fields: []const http3_zig.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

pub const H3Pair = struct {
    client_tls: boringssl.tls.Context,
    server_tls: boringssl.tls.Context,
    client: quic_zig.Connection,
    server: quic_zig.Connection,
    client_h3: http3_zig.Session,
    server_h3: http3_zig.Session,

    pub fn initStarted(
        self: *H3Pair,
        allocator: std.mem.Allocator,
        client_config: http3_zig.session.Config,
        server_config: http3_zig.session.Config,
    ) !void {
        self.client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
        errdefer self.client_tls.deinit();

        self.server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
        errdefer self.server_tls.deinit();

        try initConnectedQuic(allocator, self.client_tls, self.server_tls, &self.client, &self.server);
        errdefer {
            self.server.deinit();
            self.client.deinit();
        }

        self.client_h3 = http3_zig.Session.init(allocator, .client, &self.client, client_config);
        errdefer self.client_h3.deinit();

        self.server_h3 = http3_zig.Session.init(allocator, .server, &self.server, server_config);
        errdefer self.server_h3.deinit();

        try self.client_h3.start();
        try self.server_h3.start();
    }

    pub fn deinit(self: *H3Pair) void {
        self.server_h3.deinit();
        self.client_h3.deinit();
        self.server.deinit();
        self.client.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
    }
};

pub fn expectPairH3Error(allocator: std.mem.Allocator, pair: *H3Pair, expected: anyerror) !void {
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

    var now_us: u64 = 1_000_000;
    try pumpUntilH3Error(
        allocator,
        &pair.client,
        &pair.server,
        &pair.client_h3,
        &pair.server_h3,
        &client_events,
        &server_events,
        &now_us,
        expected,
    );
}

pub fn exchangePairSettings(allocator: std.mem.Allocator, pair: *H3Pair) !void {
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

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (pair.client_h3.peer_settings == null or pair.server_h3.peer_settings == null) : (iters += 1) {
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
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
}

pub fn openGetAndAwaitServerHeaders(
    allocator: std.mem.Allocator,
    pair: *H3Pair,
    h3_client: *http3_zig.Client,
) !u64 {
    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
    });
    const stream_id = request.stream_id;
    try request.finish();

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

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (iters < 20_000) : (iters += 1) {
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
                .request_updated => |request_state| {
                    if (request_state.reader().headers().len > 0) return stream_id;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    return error.ExpectedRequestHeaders;
}

pub fn sendRawH3Datagram(conn: *quic_zig.Connection, stream_id: u64, payload: []const u8) !void {
    var buf: [2048]u8 = undefined;
    const n = try http3_zig.datagram.encode(&buf, stream_id, payload);
    try conn.sendDatagram(buf[0..n]);
}
