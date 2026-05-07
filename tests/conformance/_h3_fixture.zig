//! Shared HTTP/3 conformance fixture.
//!
//! Mirrors the in-process loopback pattern from `tests/root.zig` and exposes
//! a small, conformance-focused surface so the streams and session suites can
//! drive `null3.Session` without touching `tests/root.zig`. Every helper
//! exists to expose an observable HTTP/3 behaviour for assertions: we always
//! pump the loopback driver until the next change in close state, error, or
//! event queue rather than counting "iterations".
//!
//! The conformance tests use these helpers to inject crafted bytes onto the
//! peer's view of one of `null3.Session`'s critical or request streams and
//! then assert the resulting CONNECTION_CLOSE error code, mirroring the
//! exact code path real implementations exercise on the wire.

const std = @import("std");
const boringssl = @import("boringssl");
const null3 = @import("null3");
const nullq = @import("nullq");

pub const test_cert_pem = @embedFile("../data/test_cert.pem");
pub const test_key_pem = @embedFile("../data/test_key.pem");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

fn handshake(client: *nullq.Connection, server: *nullq.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

fn initConnectedQuic(
    allocator: std.mem.Allocator,
    client_tls: anytype,
    server_tls: anytype,
    client: *nullq.Connection,
    server: *nullq.Connection,
) !void {
    client.* = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    errdefer client.deinit();
    server.* = try nullq.Connection.initServer(allocator, server_tls);
    errdefer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    const tp: nullq.tls.TransportParams = .{
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
}

pub fn clearSessionEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(null3.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn pumpStep(
    client: *nullq.Connection,
    server: *nullq.Connection,
    client_h3: *null3.Session,
    server_h3: *null3.Session,
    client_events: *std.ArrayList(null3.session.Event),
    server_events: *std.ArrayList(null3.session.Event),
    now_us: *u64,
) !void {
    var pkt: [2048]u8 = undefined;
    var driver = null3.TransportLoopback.init(
        null3.TransportEndpoint.withSession(client, client_h3, client_events),
        null3.TransportEndpoint.withSession(server, server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 1,
        },
    );
    _ = try driver.step(&pkt);
    now_us.* = driver.now_us;
}

pub const H3Pair = struct {
    client_tls: boringssl.tls.Context,
    server_tls: boringssl.tls.Context,
    client: nullq.Connection,
    server: nullq.Connection,
    client_h3: null3.Session,
    server_h3: null3.Session,

    pub fn initStarted(
        self: *H3Pair,
        allocator: std.mem.Allocator,
        client_config: null3.session.Config,
        server_config: null3.session.Config,
    ) !void {
        self.client_tls = try null3.client.initTlsContext(.{ .verify = .none });
        errdefer self.client_tls.deinit();

        self.server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
        errdefer self.server_tls.deinit();

        try initConnectedQuic(allocator, self.client_tls, self.server_tls, &self.client, &self.server);
        errdefer {
            self.server.deinit();
            self.client.deinit();
        }

        self.client_h3 = null3.Session.init(allocator, .client, &self.client, client_config);
        errdefer self.client_h3.deinit();

        self.server_h3 = null3.Session.init(allocator, .server, &self.server, server_config);
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

/// Pump the loopback driver until either side raises the expected error.
/// The returned event lists are emptied between iterations so the budget
/// stays bounded — the suite asserts the post-condition (close code, state)
/// after this returns, not the intermediate event stream.
pub fn expectPairH3Error(
    allocator: std.mem.Allocator,
    pair: *H3Pair,
    expected: anyerror,
) !void {
    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (iters < 20_000) : (iters += 1) {
        pumpStep(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ) catch |err| {
            if (err != expected) return err;
            return;
        };
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    return error.ExpectedH3ErrorNotFound;
}

/// Pump until both sessions have observed each other's SETTINGS.
pub fn exchangePairSettings(allocator: std.mem.Allocator, pair: *H3Pair) !void {
    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (pair.client_h3.peer_settings == null or pair.server_h3.peer_settings == null) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpStep(
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

/// Pump for a bounded number of iterations without expecting an error. Used
/// to deliver crafted control-stream frames after `exchangePairSettings`.
pub fn pumpQuiet(
    allocator: std.mem.Allocator,
    pair: *H3Pair,
    iters_max: u32,
) !void {
    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (iters < iters_max) : (iters += 1) {
        try pumpStep(
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

pub fn writeFrame(conn: *nullq.Connection, stream_id: u64, frame: null3.Frame) !void {
    var buf: [4096]u8 = undefined;
    const n = try null3.frame.encode(&buf, frame);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn writeStreamType(conn: *nullq.Connection, stream_id: u64, stream_type: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try nullq.wire.varint.encode(&buf, stream_type);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn writeVarint(conn: *nullq.Connection, stream_id: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try nullq.wire.varint.encode(&buf, value);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

pub fn openUniWithType(conn: *nullq.Connection, stream_id: u64, stream_type: u64) !void {
    _ = try conn.openUni(stream_id);
    try writeStreamType(conn, stream_id, stream_type);
}

pub fn writeRawBytes(conn: *nullq.Connection, stream_id: u64, bytes: []const u8) !void {
    _ = try conn.streamWrite(stream_id, bytes);
}

pub fn expectLastCloseCode(session: *const null3.Session, code: u64) !void {
    const close = session.lastCloseError() orelse return error.MissingCloseError;
    try std.testing.expectEqual(code, close.application.code);
}

pub fn writeQpackEncoderInstruction(
    conn: *nullq.Connection,
    stream_id: u64,
    instruction: null3.QpackEncoderInstruction,
) !void {
    var buf: [512]u8 = undefined;
    const n = try null3.qpack.instructions.encodeEncoderInstruction(&buf, instruction);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}
