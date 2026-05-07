const std = @import("std");
const boringssl = @import("boringssl");
const fuzz_codecs = @import("null3_fuzz_codecs");
const null3 = @import("null3");
const nullq = @import("nullq");

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

fn discardKeylog(line: []const u8) void {
    _ = line;
}

test "TLS context helpers accept keylog callbacks" {
    var client_tls = try null3.client.initTlsContext(.{
        .verify = .none,
        .keylog_callback = discardKeylog,
    });
    defer client_tls.deinit();

    var server_tls = try null3.server.initTlsContext(.{
        .keylog_callback = discardKeylog,
    }, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
}

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

fn clearSessionEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(null3.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn pumpH3(
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

fn pumpUntilH3Error(
    allocator: std.mem.Allocator,
    client: *nullq.Connection,
    server: *nullq.Connection,
    client_h3: *null3.Session,
    server_h3: *null3.Session,
    client_events: *std.ArrayList(null3.session.Event),
    server_events: *std.ArrayList(null3.session.Event),
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

fn writeFrame(conn: *nullq.Connection, stream_id: u64, frame: null3.Frame) !void {
    var buf: [4096]u8 = undefined;
    const n = try null3.frame.encode(&buf, frame);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

fn writeQpackEncoderInstruction(
    conn: *nullq.Connection,
    stream_id: u64,
    instruction: null3.QpackEncoderInstruction,
) !void {
    var buf: [512]u8 = undefined;
    const n = try null3.qpack.instructions.encodeEncoderInstruction(&buf, instruction);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

fn writeStreamType(conn: *nullq.Connection, stream_id: u64, stream_type: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try nullq.wire.varint.encode(&buf, stream_type);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

fn writeVarint(conn: *nullq.Connection, stream_id: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    const n = try nullq.wire.varint.encode(&buf, value);
    _ = try conn.streamWrite(stream_id, buf[0..n]);
}

fn openUniWithType(conn: *nullq.Connection, stream_id: u64, stream_type: u64) !void {
    _ = try conn.openUni(stream_id);
    try writeStreamType(conn, stream_id, stream_type);
}

fn writeHeadersFrame(conn: *nullq.Connection, stream_id: u64, fields: []const null3.FieldLine) !void {
    var block: [2048]u8 = undefined;
    const block_n = try null3.qpack.encodeFieldSection(&block, fields);
    try writeFrame(conn, stream_id, .{ .headers = block[0..block_n] });
}

fn writePushPromiseFrame(
    conn: *nullq.Connection,
    stream_id: u64,
    push_id: u64,
    fields: []const null3.FieldLine,
) !void {
    var block: [2048]u8 = undefined;
    const block_n = try null3.qpack.encodeFieldSection(&block, fields);
    try writeFrame(conn, stream_id, .{
        .push_promise = .{
            .push_id = push_id,
            .field_section = block[0..block_n],
        },
    });
}

fn expectLastCloseCode(session: *const null3.Session, code: u64) !void {
    const close = session.lastCloseError() orelse return error.MissingCloseError;
    try std.testing.expectEqual(code, close.application.code);
}

fn fieldValue(fields: []const null3.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

const H3Pair = struct {
    client_tls: boringssl.tls.Context,
    server_tls: boringssl.tls.Context,
    client: nullq.Connection,
    server: nullq.Connection,
    client_h3: null3.Session,
    server_h3: null3.Session,

    fn initStarted(
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

    fn deinit(self: *H3Pair) void {
        self.server_h3.deinit();
        self.client_h3.deinit();
        self.server.deinit();
        self.client.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
    }
};

fn expectPairH3Error(allocator: std.mem.Allocator, pair: *H3Pair, expected: anyerror) !void {
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

fn exchangePairSettings(allocator: std.mem.Allocator, pair: *H3Pair) !void {
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

fn openGetAndAwaitServerHeaders(
    allocator: std.mem.Allocator,
    pair: *H3Pair,
    h3_client: *null3.Client,
) !u64 {
    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
    });
    const stream_id = request.stream_id;
    try request.finish();

    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

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

test "codec fuzz target names parse" {
    try std.testing.expectEqual(@as(?fuzz_codecs.Target, .all), fuzz_codecs.targetFromName("all"));
    for (fuzz_codecs.concrete_targets) |target| {
        try std.testing.expectEqual(@as(?fuzz_codecs.Target, target), fuzz_codecs.targetFromName(fuzz_codecs.targetName(target)));
    }
    try std.testing.expectEqual(@as(?fuzz_codecs.Target, .qpack_integer), fuzz_codecs.targetFromName("qpack_integer"));
    try std.testing.expect(fuzz_codecs.targetFromName("not-a-target") == null);
}

test "codec fuzz harness smoke corpus" {
    const allocator = std.testing.allocator;
    for (fuzz_codecs.smokeInputs()) |input| {
        try fuzz_codecs.runTarget(allocator, .all, input);
    }
}

test "codec fuzz harness accepts representative valid encodings" {
    const allocator = std.testing.allocator;
    var buf: [512]u8 = undefined;

    const frame_n = try null3.frame.encode(&buf, .{ .data = "hello" });
    try fuzz_codecs.runTarget(allocator, .frame, buf[0..frame_n]);

    const settings_n = try (null3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    }).encode(&buf);
    try fuzz_codecs.runTarget(allocator, .settings, buf[0..settings_n]);

    const capsule_n = try null3.capsule.encodeDatagram(&buf, "payload");
    try fuzz_codecs.runTarget(allocator, .capsule, buf[0..capsule_n]);

    const datagram_n = try null3.datagram.encodeWithContext(&buf, 4, 7, "payload");
    try fuzz_codecs.runTarget(allocator, .datagram, buf[0..datagram_n]);

    const masque_path = try null3.masque.allocConnectUdpPath(allocator, .{
        .authority = "proxy.example",
        .target_host = "example.com",
        .target_port = 443,
    });
    defer allocator.free(masque_path);
    try fuzz_codecs.runTarget(allocator, .masque, masque_path);
    const masque_udp_n = try null3.masque.encodeUdpPayload(&buf, "udp");
    try fuzz_codecs.runTarget(allocator, .masque, buf[0..masque_udp_n]);

    const integer_n = try null3.qpack.integer.encode(&buf, 5, 0, 1337);
    try fuzz_codecs.runTarget(allocator, .qpack_integer, buf[0..integer_n]);

    const huffman_n = try null3.qpack.huffman.encode(&buf, "www.example.com");
    try fuzz_codecs.runTarget(allocator, .qpack_huffman, buf[0..huffman_n]);

    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-null3-fuzz", .value = "ok" },
    };
    const static_section_n = try null3.qpack.encodeFieldSection(&buf, &fields);
    try fuzz_codecs.runTarget(allocator, .qpack_field_static, buf[0..static_section_n]);
    try fuzz_codecs.runTarget(allocator, .qpack_field_literal, buf[0..static_section_n]);

    var table = null3.DynamicTable.init(allocator, 0);
    defer table.deinit();
    const dynamic_section_n = try null3.qpack.encodeDynamicFieldSection(&buf, &table, &fields);
    try fuzz_codecs.runTarget(allocator, .qpack_field_dynamic, buf[0..dynamic_section_n]);

    const encoder_instruction_n = try null3.qpack.instructions.encodeEncoderInstruction(&buf, .{ .set_capacity = 0 });
    try fuzz_codecs.runTarget(allocator, .qpack_encoder_instruction, buf[0..encoder_instruction_n]);

    const decoder_instruction_n = try null3.qpack.instructions.encodeDecoderInstruction(&buf, .{ .insert_count_increment = 1 });
    try fuzz_codecs.runTarget(allocator, .qpack_decoder_instruction, buf[0..decoder_instruction_n]);

    const websocket_n = try null3.websocket.frame.encodeText(&buf, "hello", .{
        .mask = true,
        .masking_key = .{ 1, 2, 3, 4 },
    });
    try fuzz_codecs.runTarget(allocator, .websocket_frame, buf[0..websocket_n]);
    try fuzz_codecs.runTarget(allocator, .websocket_message, buf[0..websocket_n]);
}

fn sendRawH3Datagram(conn: *nullq.Connection, stream_id: u64, payload: []const u8) !void {
    var buf: [2048]u8 = undefined;
    const n = try null3.datagram.encode(&buf, stream_id, payload);
    try conn.sendDatagram(buf[0..n]);
}

test "HTTP/3 SETTINGS frame round-trip" {
    const s: null3.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 1 << 20,
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    var buf: [128]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{ .settings = s });
    const d = try null3.frame.decode(buf[0..n]);
    try std.testing.expectEqual(n, d.bytes_read);
    switch (d.frame) {
        .settings => |got| {
            try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
            try std.testing.expectEqual(@as(u64, 8), got.qpack_blocked_streams);
            try std.testing.expectEqual(@as(?u64, 1 << 20), got.max_field_section_size);
            try std.testing.expect(got.enable_connect_protocol);
            try std.testing.expect(got.h3_datagram);
        },
        else => return error.TestExpectedEqual,
    }
}

test "SETTINGS decoder rejects duplicate reserved and invalid values" {
    const varint = nullq.wire.varint;

    var duplicate: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(duplicate[pos..], null3.protocol.SettingId.h3_datagram);
    pos += try varint.encode(duplicate[pos..], 1);
    pos += try varint.encode(duplicate[pos..], null3.protocol.SettingId.h3_datagram);
    pos += try varint.encode(duplicate[pos..], 1);
    try std.testing.expectError(error.DuplicateSetting, null3.Settings.decode(duplicate[0..pos]));

    var invalid_bool: [8]u8 = undefined;
    pos = 0;
    pos += try varint.encode(invalid_bool[pos..], null3.protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(invalid_bool[pos..], 2);
    try std.testing.expectError(error.InvalidSettingValue, null3.Settings.decode(invalid_bool[0..pos]));

    var reserved: [8]u8 = undefined;
    pos = 0;
    pos += try varint.encode(reserved[pos..], 0x02);
    pos += try varint.encode(reserved[pos..], 1);
    try std.testing.expectError(error.ReservedSetting, null3.Settings.decode(reserved[0..pos]));
}

test "literal QPACK field section validates as request headers" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "user-agent", .value = "null3-test" },
    };
    var block: [512]u8 = undefined;
    const n = try null3.qpack.encodeLiteralFieldSection(&block, &fields);
    const decoded = try null3.qpack.decodeLiteralFieldSection(std.testing.allocator, block[0..n]);
    defer null3.qpack.freeFieldSection(std.testing.allocator, decoded);

    try null3.headers.validateRequest(decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("example.com", decoded[3].value);
}

test "static QPACK field section uses indexed representation" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/search" },
    };
    var block: [128]u8 = undefined;
    var literal_block: [128]u8 = undefined;
    const n = try null3.qpack.encodeFieldSection(&block, &fields);
    const literal_n = try null3.qpack.encodeLiteralFieldSection(&literal_block, &fields);
    try std.testing.expect(n < literal_n);

    const decoded = try null3.qpack.decodeFieldSection(std.testing.allocator, block[0..n]);
    defer null3.qpack.freeFieldSection(std.testing.allocator, decoded);
    try null3.headers.validateRequest(decoded);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("/search", decoded[2].value);
}

test "extended CONNECT header validation requires opt-in" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/socket" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };

    try std.testing.expectError(error.ExtendedConnectNotEnabled, null3.headers.validateRequest(&fields));
    try null3.headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
    try std.testing.expectEqualStrings("websocket", null3.headers.requestProtocol(&fields).?);
    try std.testing.expect(null3.headers.isExtendedConnect(&fields));

    const bad_method = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/socket" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        error.InvalidPseudoHeader,
        null3.headers.validateRequestWithOptions(&bad_method, .{ .enable_connect_protocol = true }),
    );
}

test "header validation rejects malformed pseudo headers and connection fields" {
    const pseudo_after_regular = [_]null3.FieldLine{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(error.PseudoHeaderAfterRegular, null3.headers.validateRequest(&pseudo_after_regular));

    const duplicate_method = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(error.DuplicatePseudoHeader, null3.headers.validateRequest(&duplicate_method));

    const missing_path = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, null3.headers.validateRequest(&missing_path));

    const uppercase = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "User-Agent", .value = "bad" },
    };
    try std.testing.expectError(error.UppercaseFieldName, null3.headers.validateRequest(&uppercase));

    const connection_specific = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    try std.testing.expectError(error.ConnectionSpecificField, null3.headers.validateRequest(&connection_specific));

    const bad_trailer = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expectError(error.InvalidPseudoHeader, null3.headers.validateTrailers(&bad_trailer));

    const response_without_status = [_]null3.FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, null3.headers.validateResponse(&response_without_status));
}

test "capsule and context datagram codecs round-trip" {
    var context_buf: [64]u8 = undefined;
    const context_len = try null3.datagram.encodeContextPayload(&context_buf, 42, "ctx");
    const context = try null3.datagram.decodeContextPayload(context_buf[0..context_len]);
    try std.testing.expectEqual(@as(u64, 42), context.context_id);
    try std.testing.expectEqualStrings("ctx", context.payload);

    var capsule_buf: [64]u8 = undefined;
    const capsule_len = try null3.capsule.encodeDatagram(&capsule_buf, context_buf[0..context_len]);
    const capsule = try null3.capsule.decode(capsule_buf[0..capsule_len]);
    try std.testing.expect(capsule.capsule.isDatagram());
    const capsule_context = try null3.datagram.decodeContextPayload(capsule.capsule.value);
    try std.testing.expectEqual(@as(u64, 42), capsule_context.context_id);
    try std.testing.expectEqualStrings("ctx", capsule_context.payload);

    var iter = null3.capsule.iter(capsule_buf[0..capsule_len]);
    try std.testing.expect((try iter.next()) != null);
    try std.testing.expect((try iter.next()) == null);
}

test "capsule decoder rejects truncated capsule payloads" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try nullq.wire.varint.encode(buf[pos..], null3.capsule.Type.datagram);
    pos += try nullq.wire.varint.encode(buf[pos..], 4);
    buf[pos] = 'x';
    pos += 1;
    try std.testing.expectError(error.InsufficientBytes, null3.capsule.decode(buf[0..pos]));
}

test "PRIORITY_UPDATE request frame round-trip" {
    var buf: [64]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=3, i",
        },
    });
    const d = try null3.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqualStrings("u=3, i", p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "priority parser and stream frame validator" {
    const p = try null3.Priority.parse("u=1, i");
    try std.testing.expectEqual(@as(u3, 1), p.urgency);
    try std.testing.expect(p.incremental);

    var validator = null3.stream.FrameValidator.init(.control);
    try validator.observe(null3.protocol.FrameType.settings);
    try validator.observe(null3.protocol.FrameType.priority_update_request);
    try std.testing.expectError(
        null3.stream.FrameValidationError.FrameUnexpected,
        validator.observe(null3.protocol.FrameType.headers),
    );
}

test "priority field helpers surface request and response priorities" {
    var request_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=0, i" },
    };
    var request_state = null3.RequestState{
        .stream_id = 0,
        .headers = &request_headers,
    };
    const request_priority = (try request_state.reader().priority()).?;
    try std.testing.expectEqual(@as(u3, 0), request_priority.urgency);
    try std.testing.expect(request_priority.incremental);

    var response_headers = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "Priority", .value = "u=6" },
    };
    var response_state = null3.ResponseState{
        .stream_id = 0,
        .headers = &response_headers,
    };
    const response_priority = (try response_state.reader().priority()).?;
    try std.testing.expectEqual(@as(u3, 6), response_priority.urgency);
    try std.testing.expect(!response_priority.incremental);
}

test "client PRIORITY_UPDATE for request reaches server state" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);

    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/priority",
    });
    const request_stream_id = request.stream_id;
    try request.updatePriority(.{ .urgency = 1, .incremental = true });

    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

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

    var saw_priority = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_priority) : (iters += 1) {
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
                .priority_update => |update| {
                    saw_priority = true;
                    switch (update.target) {
                        .request_stream => |stream_id| try std.testing.expectEqual(request_stream_id, stream_id),
                        else => return error.TestExpectedEqual,
                    }
                    try std.testing.expectEqual(@as(u3, 1), update.priority.urgency);
                    try std.testing.expect(update.priority.incremental);
                    try std.testing.expectEqualStrings("u=1, i", update.priority_field_value);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const stored = h3_server.priorityForRequest(request_stream_id).?;
    try std.testing.expectEqual(@as(u3, 1), stored.urgency);
    try std.testing.expect(stored.incremental);
    try std.testing.expectEqual(@as(u64, 1), h3_client.metrics().priority_updates_sent);
    try std.testing.expectEqual(@as(u64, 1), h3_server.metrics().priority_updates_received);
}

test "client PRIORITY_UPDATE for push reaches server state" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/priority.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });

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

    var sent_update = false;
    var saw_priority = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_priority) : (iters += 1) {
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

        if (!sent_update) {
            for (client_events.items) |event| {
                const response_event = h3_client.classify(event) orelse continue;
                switch (response_event) {
                    .push_promise => |promise| {
                        try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                        try h3_client.sendPriorityUpdateForPush(0, .{ .urgency = 0 });
                        sent_update = true;
                    },
                    else => {},
                }
            }
        }

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .priority_update => |update| {
                    saw_priority = true;
                    switch (update.target) {
                        .push => |push_id| try std.testing.expectEqual(@as(u64, 0), push_id),
                        else => return error.TestExpectedEqual,
                    }
                    try std.testing.expectEqual(@as(u3, 0), update.priority.urgency);
                    try std.testing.expect(!update.priority.incremental);
                    try std.testing.expectEqualStrings("u=0", update.priority_field_value);
                },
                else => {},
            }
        }

        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const stored = h3_server.priorityForPush(0).?;
    try std.testing.expectEqual(@as(u3, 0), stored.urgency);
    try std.testing.expect(!stored.incremental);
}

test "PRIORITY_UPDATE rejects invalid request stream targets" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 2,
            .priority_field_value = "u=1",
        },
    });

    try expectPairH3Error(allocator, &pair, error.InvalidPriorityTarget);
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.id_error);
}

test "PRIORITY_UPDATE rejects server senders" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=1",
        },
    });

    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "PRIORITY_UPDATE rejects invalid Priority field values" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=9",
        },
    });

    try expectPairH3Error(allocator, &pair, error.InvalidUrgency);
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.general_protocol_error);
}

test "message encoder and decoder handles response body and trailers" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "server-timing", .value = "app;dur=1" },
    };

    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = null3.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &fields);
    pos += try enc.encodeData(bytes[pos..], "ok");
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);

    var dec = null3.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(null3.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }

    try dec.observeBytes(std.testing.allocator, bytes[0..pos], &events);
    try dec.finish();
    try std.testing.expectEqual(@as(usize, 3), events.items.len);
    switch (events.items[0]) {
        .headers => |h| try std.testing.expectEqualStrings("200", h[0].value),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[1]) {
        .data => |body| try std.testing.expectEqualStrings("ok", body),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[2]) {
        .trailers => |t| try std.testing.expectEqualStrings("app;dur=1", t[0].value),
        else => return error.TestExpectedEqual,
    }
}

test "message decoder rejects DATA before HEADERS" {
    var buf: [32]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{ .data = "nope" });
    const d = try null3.frame.decode(buf[0..n]);
    var dec = null3.MessageDecoder.init(.request, .{});
    try std.testing.expectError(
        null3.message.Error.DataBeforeHeaders,
        dec.observe(std.testing.allocator, d.frame),
    );
}

test "message codec rejects oversized headers and DATA after trailers" {
    var oversized = null3.MessageDecoder.init(.response, .{ .max_field_section_size = 1 });
    try std.testing.expectError(
        error.HeaderSectionTooLarge,
        oversized.observe(std.testing.allocator, .{ .headers = "too-large" }),
    );

    const headers = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    var bytes: [256]u8 = undefined;
    var pos: usize = 0;
    var enc = null3.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &headers);
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);
    pos += try null3.frame.encode(bytes[pos..], .{ .data = "late" });

    var dec = null3.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(null3.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.DataAfterTrailers,
        dec.observeBytes(std.testing.allocator, bytes[0..pos], &events),
    );
}

test "client and server facades classify session events" {
    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const response_fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "204" },
    };

    const request_headers: null3.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .request,
        .fields = @constCast(&request_fields),
    } };
    try std.testing.expect(null3.client.ResponseEvent.from(request_headers) == null);
    switch (null3.server.RequestEvent.from(request_headers).?) {
        .headers => |headers| {
            try std.testing.expectEqual(@as(u64, 0), headers.stream_id);
            try std.testing.expectEqualStrings("GET", headers.fields[0].value);
        },
        else => return error.TestExpectedEqual,
    }

    const response_headers: null3.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .response,
        .fields = @constCast(&response_fields),
    } };
    try std.testing.expect(null3.server.RequestEvent.from(response_headers) == null);
    switch (null3.client.ResponseEvent.from(response_headers).?) {
        .headers => |headers| try std.testing.expectEqualStrings("204", headers.fields[0].value),
        else => return error.TestExpectedEqual,
    }

    const request_data: null3.session.Event = .{ .data = .{
        .stream_id = 0,
        .kind = .request,
        .data = @constCast("body"),
    } };
    switch (null3.server.RequestEvent.from(request_data).?) {
        .data => |data| try std.testing.expectEqualStrings("body", data.bytes),
        else => return error.TestExpectedEqual,
    }

    const rejected: null3.session.Event = .{ .request_rejected = .{
        .stream_id = 4,
        .error_code = null3.protocol.ErrorCode.request_rejected,
    } };
    switch (null3.server.RequestEvent.from(rejected).?) {
        .rejected => |event| {
            try std.testing.expectEqual(@as(u64, 4), event.stream_id);
            try std.testing.expectEqual(null3.protocol.ErrorCode.request_rejected, event.error_code);
        },
        else => return error.TestExpectedEqual,
    }

    const flow_blocked: null3.session.Event = .{ .flow_blocked = .{
        .source = .local,
        .kind = .streams,
        .limit = 0,
        .bidi = true,
    } };
    switch (null3.client.ResponseEvent.from(flow_blocked).?) {
        .flow_blocked => |event| {
            try std.testing.expectEqual(null3.FlowBlockedSource.local, event.source);
            try std.testing.expectEqual(null3.FlowBlockedKind.streams, event.kind);
            try std.testing.expectEqual(@as(?bool, true), event.bidi);
        },
        else => return error.TestExpectedEqual,
    }
    switch (null3.server.RequestEvent.from(flow_blocked).?) {
        .flow_blocked => |event| {
            try std.testing.expectEqual(null3.FlowBlockedSource.local, event.source);
            try std.testing.expectEqual(null3.FlowBlockedKind.streams, event.kind);
            try std.testing.expectEqual(@as(u64, 0), event.limit);
        },
        else => return error.TestExpectedEqual,
    }

    const connection_ids_needed: null3.session.Event = .{ .connection_ids_needed = .{
        .path_id = 0,
        .reason = .retired,
        .active_count = 1,
        .active_limit = 2,
        .issue_budget = 1,
        .next_sequence_number = 3,
    } };
    switch (null3.client.ResponseEvent.from(connection_ids_needed).?) {
        .connection_ids_needed => |event| {
            try std.testing.expectEqual(@as(u32, 0), event.path_id);
            try std.testing.expectEqual(@as(usize, 1), event.issue_budget);
        },
        else => return error.TestExpectedEqual,
    }
    switch (null3.server.RequestEvent.from(connection_ids_needed).?) {
        .connection_ids_needed => |event| {
            try std.testing.expectEqual(@as(usize, 2), event.active_limit);
            try std.testing.expectEqual(@as(u64, 3), event.next_sequence_number);
        },
        else => return error.TestExpectedEqual,
    }
}

test "request tracker owns server request lifecycle" {
    const allocator = std.testing.allocator;
    var tracker = null3.RequestTracker.init(allocator);
    defer tracker.deinit();

    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/tracked" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    _ = try tracker.observe(.{ .headers = .{
        .stream_id = 0,
        .fields = @constCast(&request_fields),
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "hello",
    } });
    _ = try tracker.observe(.{ .trailers = .{
        .stream_id = 0,
        .fields = @constCast(&trailers),
    } });
    const state = (try tracker.observe(.{ .finished = .{ .stream_id = 0 } })).?;

    try std.testing.expectEqual(@as(u64, 0), state.stream_id);
    try std.testing.expectEqualStrings("/tracked", state.headerFields()[2].value);
    try std.testing.expectEqualStrings("hello", state.bodyBytes());
    try std.testing.expectEqualStrings("ok", state.trailerFields()[0].value);
    try std.testing.expect(state.complete);

    const reader = state.reader();
    try std.testing.expectEqual(@as(u64, 0), reader.streamId());
    try std.testing.expectEqualStrings("POST", reader.method().?);
    try std.testing.expectEqualStrings("https", reader.scheme().?);
    try std.testing.expectEqualStrings("localhost", reader.authority().?);
    try std.testing.expectEqualStrings("/tracked", reader.path().?);
    try std.testing.expectEqualStrings("hello", reader.body());
    try std.testing.expect(reader.complete());

    const removed = tracker.remove(0).?;
    defer {
        removed.deinit(allocator);
        allocator.destroy(removed);
    }
    try std.testing.expect(tracker.get(0) == null);
}

test "request tracker enforces body budget" {
    const allocator = std.testing.allocator;
    var tracker = null3.RequestTracker.initWithConfig(allocator, .{ .max_body_bytes = 5 });
    defer tracker.deinit();

    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "hel",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "lo",
    } });
    try std.testing.expectError(error.BodyTooLarge, tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "!",
    } }));

    const state = tracker.get(0).?;
    try std.testing.expectEqualStrings("hello", state.bodyBytes());
}

test "response tracker owns client response lifecycle" {
    const allocator = std.testing.allocator;
    var tracker = null3.ResponseTracker.init(allocator);
    defer tracker.deinit();

    const response_fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "server-timing", .value = "app;dur=1" },
    };

    _ = try tracker.observe(.{ .headers = .{
        .stream_id = 0,
        .fields = @constCast(&response_fields),
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "po",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "ng",
    } });
    _ = try tracker.observe(.{ .trailers = .{
        .stream_id = 0,
        .fields = @constCast(&trailers),
    } });
    const state = (try tracker.observe(.{ .finished = .{ .stream_id = 0 } })).?;

    const reader = state.reader();
    try std.testing.expectEqual(@as(u64, 0), reader.streamId());
    try std.testing.expectEqualStrings("200", reader.status().?);
    try std.testing.expectEqualStrings("pong", reader.body());
    try std.testing.expectEqualStrings("app;dur=1", reader.trailers()[0].value);
    try std.testing.expect(reader.complete());

    const removed = tracker.remove(0).?;
    defer {
        removed.deinit(allocator);
        allocator.destroy(removed);
    }
    try std.testing.expect(tracker.get(0) == null);
}

test "response tracker enforces body budget" {
    const allocator = std.testing.allocator;
    var tracker = null3.ResponseTracker.initWithConfig(allocator, .{ .max_body_bytes = 4 });
    defer tracker.deinit();

    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "po",
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "ng",
    } });
    try std.testing.expectError(error.BodyTooLarge, tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "!",
    } }));

    const state = tracker.get(0).?;
    try std.testing.expectEqualStrings("pong", state.bodyBytes());
}

test "server runner classifies and tracks request batches" {
    const allocator = std.testing.allocator;
    var runner = null3.ServerRunner.init(allocator);
    defer runner.deinit();

    var fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/runner" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var body = [_]u8{ 'o', 'k' };
    const events = [_]null3.session.Event{
        .{ .peer_settings = .{ .h3_datagram = true } },
        .{ .datagram_acked = .{
            .id = 7,
            .len = 13,
        } },
        .{ .datagram_lost = .{
            .id = 8,
            .len = 21,
        } },
        .{ .flow_blocked = .{
            .source = .peer,
            .kind = .stream_data,
            .limit = 64,
            .stream_id = 0,
        } },
        .{ .headers = .{
            .stream_id = 0,
            .kind = null3.message.Kind.request,
            .fields = &fields,
        } },
        .{ .data = .{
            .stream_id = 0,
            .kind = null3.message.Kind.request,
            .data = &body,
        } },
        .{ .stream_finished = .{
            .stream_id = 0,
            .kind = null3.message.Kind.request,
        } },
    };
    var completed: std.ArrayList(*null3.RequestState) = .empty;
    defer completed.deinit(allocator);

    const stats = try runner.observeBatch(&events, &completed);
    try std.testing.expectEqual(@as(usize, 7), stats.observed);
    try std.testing.expectEqual(@as(usize, 1), stats.settings);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_acks);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_losses);
    try std.testing.expectEqual(@as(usize, 1), stats.flow_blocked);
    try std.testing.expectEqual(@as(usize, 2), stats.state_updates);
    try std.testing.expectEqual(@as(usize, 1), stats.completions);
    try std.testing.expectEqual(@as(usize, 1), completed.items.len);
    try std.testing.expect(runner.peer_settings.?.h3_datagram);

    const request = completed.items[0].reader();
    try std.testing.expectEqual(@as(u64, 0), request.streamId());
    try std.testing.expect(request.complete());
    try std.testing.expectEqualStrings("POST", request.method().?);
    try std.testing.expectEqualStrings("/runner", request.path().?);
    try std.testing.expectEqualStrings("ok", request.body());
}

test "client runner classifies and tracks response batches" {
    const allocator = std.testing.allocator;
    var runner = null3.ClientRunner.init(allocator);
    defer runner.deinit();

    var fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-runner", .value = "yes" },
    };
    var body = [_]u8{ 'd', 'o', 'n', 'e' };
    const events = [_]null3.session.Event{
        .{ .datagram_acked = .{
            .id = 3,
            .len = 9,
        } },
        .{ .datagram_lost = .{
            .id = 4,
            .len = 11,
        } },
        .{ .flow_blocked = .{
            .source = .local,
            .kind = .data,
            .limit = 128,
        } },
        .{ .headers = .{
            .stream_id = 0,
            .kind = null3.message.Kind.response,
            .fields = &fields,
        } },
        .{ .data = .{
            .stream_id = 0,
            .kind = null3.message.Kind.response,
            .data = &body,
        } },
        .{ .stream_finished = .{
            .stream_id = 0,
            .kind = null3.message.Kind.response,
        } },
        .{ .goaway = 4 },
    };
    var completed: std.ArrayList(*null3.ResponseState) = .empty;
    defer completed.deinit(allocator);

    const stats = try runner.observeBatch(&events, &completed);
    try std.testing.expectEqual(@as(usize, 7), stats.observed);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_acks);
    try std.testing.expectEqual(@as(usize, 1), stats.datagram_losses);
    try std.testing.expectEqual(@as(usize, 1), stats.flow_blocked);
    try std.testing.expectEqual(@as(usize, 2), stats.state_updates);
    try std.testing.expectEqual(@as(usize, 1), stats.completions);
    try std.testing.expectEqual(@as(usize, 1), stats.goaways);
    try std.testing.expectEqual(@as(?u64, 4), runner.last_goaway);
    try std.testing.expectEqual(@as(usize, 1), completed.items.len);

    const response = completed.items[0].reader();
    try std.testing.expectEqual(@as(u64, 0), response.streamId());
    try std.testing.expect(response.complete());
    try std.testing.expectEqualStrings("204", response.status().?);
    try std.testing.expectEqualStrings("done", response.body());
}

test "runners pass body budgets to lifecycle trackers" {
    const allocator = std.testing.allocator;

    var client_runner = null3.ClientRunner.initWithConfig(allocator, .{
        .response_tracker = .{ .max_body_bytes = 2 },
    });
    defer client_runner.deinit();
    try std.testing.expectError(error.BodyTooLarge, client_runner.observeResponseEvent(.{ .data = .{
        .stream_id = 0,
        .bytes = "abc",
    } }));

    var server_runner = null3.ServerRunner.initWithConfig(allocator, .{
        .request_tracker = .{ .max_body_bytes = 2 },
    });
    defer server_runner.deinit();
    try std.testing.expectError(error.BodyTooLarge, server_runner.observeRequestEvent(.{ .data = .{
        .stream_id = 0,
        .bytes = "abc",
    } }));
}

test "session negotiates and surfaces extended CONNECT requests" {
    const allocator = std.testing.allocator;

    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try null3.server.initTlsContext(
        .{},
        test_cert_pem,
        test_key_pem,
    );
    defer server_tls.deinit();

    var client: nullq.Connection = undefined;
    var server: nullq.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    const h3_settings: null3.Settings = .{ .enable_connect_protocol = true };
    var client_h3 = null3.Session.init(allocator, .client, &client, .{
        .settings = h3_settings,
    });
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{
        .settings = h3_settings,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = null3.Client.init(&client_h3);

    try std.testing.expectError(
        null3.session.Error.MissingSettings,
        h3_client.startRequest(allocator, .{
            .method = "CONNECT",
            .authority = "localhost",
            .path = "/socket",
            .connect_protocol = "websocket",
        }),
    );

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

    var client_saw_settings = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_settings) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    try std.testing.expect(settings.enable_connect_protocol);
                    client_saw_settings = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    var writer = try h3_client.startRequest(allocator, .{
        .method = "CONNECT",
        .authority = "localhost",
        .path = "/socket",
        .connect_protocol = "websocket",
    });
    const stream_id = writer.stream_id;
    try writer.finish();

    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();
    var completed: std.ArrayList(*null3.RequestState) = .empty;
    defer completed.deinit(allocator);

    iters = 0;
    while (completed.items.len == 0) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        _ = try server_runner.observeBatch(server_events.items, &completed);
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const request = completed.items[0].reader();
    try std.testing.expectEqual(stream_id, request.streamId());
    try std.testing.expect(request.complete());
    try std.testing.expect(request.isExtendedConnect());
    try std.testing.expectEqualStrings("CONNECT", request.method().?);
    try std.testing.expectEqualStrings("/socket", request.path().?);
    try std.testing.expectEqualStrings("websocket", request.protocol().?);
}

test "WebSocket helper requires negotiated Extended CONNECT support" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    try std.testing.expectError(
        error.ExtendedConnectNotEnabled,
        h3_client.startWebSocket(allocator, .{
            .authority = "localhost",
            .path = "/chat",
        }),
    );
}

test "WebSocket over HTTP/3 helper opens tunnel and streams bytes" {
    const allocator = std.testing.allocator;
    const h3_settings: null3.Settings = .{ .enable_connect_protocol = true };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);

    var client_ws = try h3_client.startWebSocket(allocator, .{
        .authority = "localhost",
        .path = "/chat",
    });
    const stream_id = client_ws.streamId();
    try client_ws.writeMessage(.text, "ping", .{ 1, 2, 3, 4 });
    try client_ws.finishSend();

    var client_runner = null3.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

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

    var accepted = false;
    var server_complete = false;
    var client_complete = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!(accepted and server_complete and client_complete)) : (iters += 1) {
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
                    if (!accepted and request.headers().len > 0) {
                        try std.testing.expectEqual(stream_id, request.streamId());
                        try std.testing.expect(request.isExtendedConnect());
                        try std.testing.expect(request.isWebSocket());
                        try std.testing.expectEqualStrings("CONNECT", request.method().?);
                        try std.testing.expectEqualStrings("/chat", request.path().?);
                        try std.testing.expectEqualStrings(null3.websocket.protocol_token, request.protocol().?);

                        var server_ws = try h3_server.acceptWebSocket(allocator, request, .{});
                        try server_ws.writeMessage(.text, "pong");
                        try server_ws.finishSend();
                        accepted = true;
                    }

                    if (!server_complete and request.complete()) {
                        var decoder = null3.websocket.message.Decoder.init(allocator, .{
                            .frame = .{ .mask_policy = .required },
                        });
                        defer decoder.deinit();
                        try decoder.push(request.body());
                        const ws_event = (try decoder.next()).?;
                        defer ws_event.deinit(allocator);
                        switch (ws_event) {
                            .text => |payload| try std.testing.expectEqualStrings("ping", payload),
                            else => return error.UnexpectedWebSocketEvent,
                        }
                        try std.testing.expect((try decoder.next()) == null);
                        server_complete = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.headers().len > 0) {
                        try std.testing.expect(response.webSocketAccepted());
                        try std.testing.expectEqualStrings("200", response.status().?);
                    }

                    if (!client_complete and response.complete()) {
                        var decoder = null3.websocket.message.Decoder.init(allocator, .{
                            .frame = .{ .mask_policy = .forbidden },
                        });
                        defer decoder.deinit();
                        try decoder.push(response.body());
                        const ws_event = (try decoder.next()).?;
                        defer ws_event.deinit(allocator);
                        switch (ws_event) {
                            .text => |payload| try std.testing.expectEqualStrings("pong", payload),
                            else => return error.UnexpectedWebSocketEvent,
                        }
                        try std.testing.expect((try decoder.next()) == null);
                        client_complete = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "CONNECT-UDP helper opens MASQUE tunnel and exchanges UDP payloads" {
    const allocator = std.testing.allocator;
    const h3_settings: null3.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .settings = h3_settings }, .{ .settings = h3_settings });
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);

    var client_udp = try h3_client.startConnectUdp(allocator, .{
        .authority = "proxy.example",
        .target_host = "example.com",
        .target_port = 443,
    });
    const stream_id = client_udp.streamId();

    var client_runner = null3.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

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

    var server_udp: ?null3.ConnectUdpServerStream = null;
    var client_udp_receiver = null3.MasqueConnectUdpReceiver.init();
    var server_udp_receiver = null3.MasqueConnectUdpReceiver.init();
    var accepted = false;
    var client_saw_response = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!accepted or !client_saw_response) : (iters += 1) {
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
                .request_updated => |request_state| {
                    const request = request_state.reader();
                    if (!accepted and request.headers().len > 0) {
                        try std.testing.expectEqual(stream_id, request.streamId());
                        try std.testing.expect(request.isExtendedConnect());
                        try std.testing.expect(request.isConnectUdp());
                        try std.testing.expect(request.capsuleProtocolEnabled());
                        try std.testing.expectEqualStrings("CONNECT", request.method().?);
                        try std.testing.expectEqualStrings(null3.masque.connect_udp_protocol, request.protocol().?);

                        const target = try request.connectUdpTarget(allocator);
                        defer target.deinit(allocator);
                        try std.testing.expectEqualStrings("example.com", target.host);
                        try std.testing.expectEqual(@as(u16, 443), target.port);

                        server_udp = try h3_server.acceptConnectUdp(allocator, request, .{});
                        accepted = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated => |response_state| {
                    const response = response_state.reader();
                    if (response.headers().len > 0) {
                        try std.testing.expect(response.connectUdpAccepted());
                        try std.testing.expect(response.capsuleProtocolEnabled());
                        try std.testing.expectEqualStrings("200", response.status().?);
                        client_saw_response = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    const tracked_client_datagram_id = try client_udp.sendUdpTracked("client-packet");
    try client_udp.sendUdpCapsule("client-capsule");
    if (server_udp) |*udp| {
        try udp.sendUdp("server-packet");
        try udp.sendUdpCapsule("server-capsule");
    } else {
        return error.MissingConnectUdpStream;
    }

    var server_saw_udp = false;
    var client_saw_udp = false;
    var server_saw_capsule = false;
    var client_saw_capsule = false;
    var client_saw_ack = false;
    iters = 0;
    while (!server_saw_udp or !client_saw_udp or !server_saw_capsule or !client_saw_capsule or !client_saw_ack) : (iters += 1) {
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
                .datagram => |datagram| {
                    server_saw_udp = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    switch (datagram.connectUdp(&server_udp_receiver)) {
                        .udp_payload => |payload| try std.testing.expectEqualStrings("client-packet", payload),
                        else => return error.UnexpectedConnectUdpDisposition,
                    }
                },
                .request_updated => |request_state| {
                    const request = request_state.reader();
                    if (request.body().len > 0) {
                        server_saw_capsule = true;
                        const decoded_capsule = try null3.capsule.decode(request.body());
                        try std.testing.expect(decoded_capsule.capsule.isDatagram());
                        switch (server_udp_receiver.classifyCapsule(decoded_capsule.capsule)) {
                            .udp_payload => |payload| try std.testing.expectEqualStrings("client-capsule", payload),
                            else => return error.UnexpectedConnectUdpDisposition,
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .datagram => |datagram| {
                    client_saw_udp = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    switch (datagram.connectUdp(&client_udp_receiver)) {
                        .udp_payload => |payload| try std.testing.expectEqualStrings("server-packet", payload),
                        else => return error.UnexpectedConnectUdpDisposition,
                    }
                },
                .datagram_acked => |acked| {
                    if (acked.id == tracked_client_datagram_id) client_saw_ack = true;
                },
                .response_updated => |response_state| {
                    const response = response_state.reader();
                    if (response.body().len > 0) {
                        client_saw_capsule = true;
                        const decoded_capsule = try null3.capsule.decode(response.body());
                        try std.testing.expect(decoded_capsule.capsule.isDatagram());
                        switch (client_udp_receiver.classifyCapsule(decoded_capsule.capsule)) {
                            .udp_payload => |payload| try std.testing.expectEqualStrings("server-capsule", payload),
                            else => return error.UnexpectedConnectUdpDisposition,
                        }
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "server push sends PUSH_PROMISE and push stream response" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);

    var request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/",
    });
    const request_stream_id = request.stream_id;
    try request.finish();

    var server_runner = null3.ServerRunner.init(allocator);
    defer server_runner.deinit();

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

    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var push_started = false;
    var push_stream_id: ?u64 = null;
    var saw_push_promise = false;
    var saw_push_stream = false;
    var saw_push_headers = false;
    var saw_push_data = false;
    var saw_push_finished = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_push_promise or !saw_push_stream or !saw_push_headers or !saw_push_data or !saw_push_finished) : (iters += 1) {
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
                .request_updated => |request_state| {
                    const reader = request_state.reader();
                    if (!push_started and reader.headers().len > 0) {
                        try std.testing.expectEqual(request_stream_id, reader.streamId());
                        var push = try h3_server.startPush(allocator, reader.streamId(), .{
                            .promise_headers = &promised_headers,
                            .response = .{
                                .status = "200",
                                .headers = &[_]null3.FieldLine{
                                    .{ .name = "content-type", .value = "text/css" },
                                },
                            },
                        });
                        push_stream_id = push.stream_id;
                        try push.write("body { color: #111; }");
                        try push.finish();
                        push_started = true;
                    }
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .push_promise => |promise| {
                    saw_push_promise = true;
                    try std.testing.expectEqual(request_stream_id, promise.stream_id);
                    try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                    try std.testing.expectEqualStrings("/style.css", fieldValue(promise.fields, ":path").?);
                },
                .push_stream => |push| {
                    saw_push_stream = true;
                    try std.testing.expectEqual(@as(u64, 0), push.push_id);
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, push.stream_id);
                },
                .push_headers => |headers| {
                    saw_push_headers = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, headers.stream_id);
                    try std.testing.expectEqualStrings("200", fieldValue(headers.fields, ":status").?);
                },
                .push_data => |data| {
                    saw_push_data = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, data.stream_id);
                    try std.testing.expectEqualStrings("body { color: #111; }", data.bytes);
                },
                .push_finished => |finished| {
                    saw_push_finished = true;
                    if (push_stream_id) |expected| try std.testing.expectEqual(expected, finished.stream_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "server push helpers build and validate same-authority cacheable promises" {
    const allocator = std.testing.allocator;

    var request_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var request_state = null3.RequestState{
        .stream_id = 0,
        .headers = &request_headers,
    };
    const request = request_state.reader();

    const built = try null3.server.allocPushPromiseFields(allocator, request, .{
        .path = "/style.css",
        .headers = &[_]null3.FieldLine{
            .{ .name = "accept", .value = "text/css" },
        },
    });
    defer allocator.free(built);
    try std.testing.expectEqualStrings("GET", fieldValue(built, ":method").?);
    try std.testing.expectEqualStrings("https", fieldValue(built, ":scheme").?);
    try std.testing.expectEqualStrings("example.com", fieldValue(built, ":authority").?);
    try std.testing.expectEqualStrings("/style.css", fieldValue(built, ":path").?);
    try null3.server.validatePushPromisePolicy(request, built, .{});

    const cross_authority = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "cdn.example.com" },
    };
    try std.testing.expectError(
        error.CrossAuthorityPush,
        null3.server.validatePushPromisePolicy(request, &cross_authority, .{}),
    );
    try null3.server.validatePushPromisePolicy(request, &cross_authority, .{
        .require_same_authority = false,
    });

    const post_promise = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/mutate" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(
        error.UncacheablePushMethod,
        null3.server.validatePushPromisePolicy(request, &post_promise, .{}),
    );

    const extended_connect = [_]null3.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/tunnel" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        error.ExtendedConnectPush,
        null3.server.validatePushPromisePolicy(request, &extended_connect, .{
            .require_cacheable_method = false,
        }),
    );
}

test "client pushed response tracker assembles promised response lifecycle" {
    const allocator = std.testing.allocator;

    var promise_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var promise_block: [128]u8 = undefined;
    const promise_block_n = try null3.qpack.encodeFieldSection(&promise_block, &promise_fields);
    var response_headers = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/css" },
    };
    var response_trailers = [_]null3.FieldLine{
        .{ .name = "x-push-complete", .value = "yes" },
    };

    var tracker = null3.PushedResponseTracker.initWithConfig(allocator, .{
        .max_body_bytes = 64,
        .max_promise_field_section_bytes = 128,
    });
    defer tracker.deinit();

    const promised = (try tracker.observe(.{ .push_promise = .{
        .stream_id = 0,
        .push_id = 7,
        .field_section = promise_block[0..promise_block_n],
        .fields = &promise_fields,
    } })).?;
    try std.testing.expectEqual(@as(u64, 7), promised.push_id);
    try std.testing.expectEqual(@as(usize, 1), promised.requestStreamIds().len);
    try std.testing.expectEqual(@as(u64, 0), promised.requestStreamIds()[0]);

    try std.testing.expectEqualStrings("/style.css", fieldValue(promised.reader().promiseFields(), ":path").?);

    _ = try tracker.observe(.{ .push_stream = .{ .stream_id = 14, .push_id = 7 } });
    _ = try tracker.observe(.{ .push_headers = .{ .stream_id = 14, .fields = &response_headers } });
    _ = try tracker.observe(.{ .push_data = .{ .stream_id = 14, .bytes = "body { color: #111; }" } });
    _ = try tracker.observe(.{ .push_trailers = .{ .stream_id = 14, .fields = &response_trailers } });
    const completed = (try tracker.observe(.{ .push_finished = .{ .stream_id = 14 } })).?;

    const by_stream = tracker.getByStream(14).?;
    try std.testing.expectEqual(completed, by_stream);
    const reader = completed.reader();
    try std.testing.expectEqual(@as(?u64, 14), reader.streamId());
    try std.testing.expectEqualStrings("200", reader.status().?);
    try std.testing.expectEqualStrings("body { color: #111; }", reader.body());
    try std.testing.expectEqualStrings("yes", fieldValue(reader.trailers(), "x-push-complete").?);
    try std.testing.expect(reader.complete());
    try std.testing.expect(!reader.cancelled());

    var runner = null3.ClientRunner.init(allocator);
    defer runner.deinit();
    _ = try runner.observeResponseEvent(.{ .push_promise = .{
        .stream_id = 0,
        .push_id = 9,
        .field_section = promise_block[0..promise_block_n],
        .fields = &promise_fields,
    } });
    switch (try runner.observeResponseEvent(.{ .push_stream = .{ .stream_id = 18, .push_id = 9 } })) {
        .pushed_response_updated => |pushed| try std.testing.expectEqual(@as(u64, 9), pushed.push_id),
        else => return error.ExpectedPushedResponseUpdate,
    }
    _ = try runner.observeResponseEvent(.{ .push_headers = .{ .stream_id = 18, .fields = &response_headers } });
    _ = try runner.observeResponseEvent(.{ .push_data = .{ .stream_id = 18, .bytes = "ok" } });
    switch (try runner.observeResponseEvent(.{ .push_finished = .{ .stream_id = 18 } })) {
        .pushed_response_complete => |pushed| {
            try std.testing.expectEqual(@as(u64, 9), pushed.push_id);
            try std.testing.expectEqualStrings("ok", pushed.bodyBytes());
        },
        else => return error.ExpectedPushedResponseCompletion,
    }
    try std.testing.expect(runner.getPushedResponse(9).?.complete);
    try std.testing.expectEqual(runner.getPushedResponse(9).?, runner.getPushedResponseByStream(18).?);
}

test "server push requires client MAX_PUSH_ID opt-in" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_server = null3.Server.init(&pair.server_h3);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(
        error.PushNotEnabled,
        h3_server.startPush(allocator, 0, .{
            .promise_headers = &promised_headers,
            .response = .{},
        }),
    );
}

test "server push enforces advertised MAX_PUSH_ID limit" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try std.testing.expectError(
        error.PushLimitExceeded,
        h3_server.startPush(allocator, request_stream_id, .{
            .promise_headers = &promised_headers,
            .response = .{ .status = "200" },
        }),
    );
}

test "client CANCEL_PUSH reaches server" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try h3_client.cancelPush(0);

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

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);

        clearSessionEvents(allocator, &client_events);
    }
}

test "server CANCEL_PUSH reaches client" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });
    try h3_server.cancelPush(0);

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

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "session rejects CANCEL_PUSH for unpromised push IDs" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .cancel_push = 0 });

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects CANCEL_PUSH above advertised MAX_PUSH_ID" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .cancel_push = 1 });

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects push streams above advertised MAX_PUSH_ID" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try openUniWithType(&pair.server, 7, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 7, 1);

    try expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects duplicate push stream IDs" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

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

    try openUniWithType(&pair.server, 7, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 7, 0);

    var now_us: u64 = 1_000_000;
    var saw_push = false;
    var iters: u32 = 0;
    while (!saw_push) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);
        for (client_events.items) |event| {
            switch (event) {
                .push_stream => |push| {
                    saw_push = true;
                    try std.testing.expectEqual(@as(u64, 0), push.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try openUniWithType(&pair.server, 11, null3.protocol.StreamType.push);
    try writeVarint(&pair.server, 11, 0);

    try pumpUntilH3Error(
        allocator,
        &pair.client,
        &pair.server,
        &pair.client_h3,
        &pair.server_h3,
        &client_events,
        &server_events,
        &now_us,
        error.InvalidPushId,
    );
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session accepts duplicate PUSH_PROMISE with identical fields" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    const first_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const second_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    try writePushPromiseFrame(&pair.server, first_stream_id, 0, &promised_headers);
    try writePushPromiseFrame(&pair.server, second_stream_id, 0, &promised_headers);

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

    var promises: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (promises < 2) : (iters += 1) {
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
        clearSessionEvents(allocator, &server_events);
        for (client_events.items) |event| {
            switch (event) {
                .push_promise => |promise| {
                    promises += 1;
                    try std.testing.expectEqual(@as(u64, 0), promise.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }
}

test "session rejects duplicate PUSH_PROMISE with inconsistent fields" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 1 }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    const first_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const second_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const conflicting_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/script.js" },
        .{ .name = ":authority", .value = "example.com" },
    };

    try writePushPromiseFrame(&pair.server, first_stream_id, 0, &promised_headers);
    try writePushPromiseFrame(&pair.server, second_stream_id, 0, &conflicting_headers);

    try expectPairH3Error(allocator, &pair, error.InconsistentPushPromise);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.message_error);
}

test "client push policy auto-cancels promised resources" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{
        .max_push_id = 0,
        .push_policy = .cancel_promises,
    }, .{});
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    var h3_server = null3.Server.init(&pair.server_h3);
    const request_stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    const promised_headers = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/style.css" },
        .{ .name = ":authority", .value = "example.com" },
    };

    _ = try h3_server.startPush(allocator, request_stream_id, .{
        .promise_headers = &promised_headers,
        .response = .{ .status = "200" },
    });

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

    var saw_cancel = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_cancel) : (iters += 1) {
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
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .cancel_push => |cancel| {
                    saw_cancel = true;
                    try std.testing.expectEqual(@as(u64, 0), cancel.push_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
    }
}

test "session rejects duplicate peer SETTINGS" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .settings = .{} });

    try expectPairH3Error(allocator, &pair, error.DuplicateSettings);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    // RFC 9114 §7.2.4 ¶3: a second SETTINGS frame is H3_FRAME_UNEXPECTED.
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "session rejects DATA on control streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .data = "bad-control-data" });
    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "session rejects SETTINGS on request streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try writeFrame(&pair.client, stream_id, .{ .settings = .{} });
    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "session rejects GOAWAY on request streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try writeFrame(&pair.client, stream_id, .{ .goaway = 0 });
    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "session rejects CANCEL_PUSH on request streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try writeFrame(&pair.client, stream_id, .{ .cancel_push = 0 });
    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.frame_unexpected);
}

test "session closes on invalid peer GOAWAY ids" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 1 });
    try expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session closes on increasing peer GOAWAY ids" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 4 });
    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 8 });
    try expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, null3.protocol.ErrorCode.id_error);
}

test "session rejects duplicate peer control streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try openUniWithType(&pair.client, 6, null3.protocol.StreamType.control);
    try expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.stream_creation_error);
}

test "session rejects duplicate peer QPACK encoder streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    try openUniWithType(&pair.client, 14, null3.protocol.StreamType.qpack_encoder);
    try expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.stream_creation_error);
}

test "session rejects peer QPACK capacity above advertised limit" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{
            .settings = .{ .qpack_max_table_capacity = 64 },
            .open_qpack_streams = true,
        },
    );
    defer pair.deinit();

    try writeQpackEncoderInstruction(
        &pair.client,
        pair.client_h3.qpack_encoder_stream_id.?,
        .{ .set_capacity = 128 },
    );
    try expectPairH3Error(allocator, &pair, error.CapacityTooLarge);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.qpack_decompression_failed);
}

test "session rejects peer QPACK insert larger than dynamic table capacity" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{
            .settings = .{ .qpack_max_table_capacity = 64 },
            .open_qpack_streams = true,
        },
    );
    defer pair.deinit();

    try writeQpackEncoderInstruction(
        &pair.client,
        pair.client_h3.qpack_encoder_stream_id.?,
        .{ .set_capacity = 64 },
    );
    try writeQpackEncoderInstruction(
        &pair.client,
        pair.client_h3.qpack_encoder_stream_id.?,
        .{ .insert_literal = .{
            .name = "x-overflow-name",
            .value = "this-value-is-too-large-for-a-sixty-four-byte-qpack-entry",
        } },
    );
    try expectPairH3Error(allocator, &pair, error.EntryTooLarge);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.qpack_decompression_failed);
}

test "session rejects invalid peer QPACK decoder feedback" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    _ = try pair.client.streamWrite(pair.client_h3.qpack_decoder_stream_id.?, &.{0});
    try expectPairH3Error(allocator, &pair, error.InsertCountIncrementZero);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.qpack_decoder_stream_error);
}

test "session rejects push streams sent to servers" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try openUniWithType(&pair.client, 6, null3.protocol.StreamType.push);
    try expectPairH3Error(allocator, &pair, error.UnexpectedStream);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.stream_creation_error);
}

test "session surfaces nullq flow blocked events" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    pair.client.peer_max_streams_bidi = 0;

    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try std.testing.expectError(error.StreamLimitExceeded, pair.client_h3.openRequest(&fields));

    var events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &events);
        events.deinit(allocator);
    }
    try pair.client_h3.drain(&events);

    var saw_flow_blocked = false;
    for (events.items) |event| {
        switch (event) {
            .flow_blocked => |blocked| {
                saw_flow_blocked = true;
                try std.testing.expectEqual(null3.FlowBlockedSource.local, blocked.source);
                try std.testing.expectEqual(null3.FlowBlockedKind.streams, blocked.kind);
                try std.testing.expectEqual(@as(u64, 0), blocked.limit);
                try std.testing.expectEqual(@as(?bool, true), blocked.bidi);
                try std.testing.expectEqual(@as(?u64, null), blocked.stream_id);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_flow_blocked);
}

test "session exposes send buffer state and enforces configured cap" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .max_stream_send_buffered = 256 },
        .{},
    );
    defer pair.deinit();

    var h3_client = null3.Client.init(&pair.client_h3);
    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/buffered",
    });

    const before = try writer.sendState();
    try std.testing.expectEqual(writer.stream_id, before.stream_id);
    try std.testing.expect(before.written_bytes > 0);
    try std.testing.expectEqual(@as(u64, 0), before.acked_bytes);
    try std.testing.expectEqual(before.written_bytes, before.buffered_bytes);
    try std.testing.expect(before.has_pending);
    try std.testing.expect(!before.overLimit(256));

    var body: [512]u8 = @splat('x');
    try std.testing.expect(!try writer.canWrite(body.len));
    try std.testing.expectError(error.SendBufferFull, writer.write(&body));

    const after = try writer.sendState();
    try std.testing.expectEqual(before.written_bytes, after.written_bytes);
    try std.testing.expectEqual(before.buffered_bytes, after.buffered_bytes);
}

test "session enforces drain event count budget" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .max_events_per_drain = 0 },
        .{},
    );
    defer pair.deinit();

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
    try std.testing.expectError(
        error.EventQueueFull,
        pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ),
    );
    try std.testing.expect(pair.client_h3.shutdownState() != .closed);
}

test "session enforces drain event payload budget" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{},
        .{
            .settings = .{ .h3_datagram = true },
            .max_event_payload_size = 1,
        },
    );
    defer pair.deinit();

    try sendRawH3Datagram(&pair.client, 0, "xx");

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

    var saw_budget_error = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_budget_error) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        pumpH3(
            &pair.client,
            &pair.server,
            &pair.client_h3,
            &pair.server_h3,
            &client_events,
            &server_events,
            &now_us,
        ) catch |err| {
            try std.testing.expectEqual(error.EventPayloadTooLarge, err);
            saw_budget_error = true;
        };
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }
    try std.testing.expect(pair.server_h3.shutdownState() != .closed);
}

test "session rejects disabled DATAGRAM sends after SETTINGS" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    try std.testing.expectError(error.DatagramNotEnabled, pair.client_h3.sendDatagram(0, "disabled"));
}

test "session rejects oversized DATAGRAM sends" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    var payload: [1200]u8 = @splat('x');
    try std.testing.expectError(error.DatagramTooLarge, pair.client_h3.sendDatagram(0, &payload));
}

test "session closes on received DATAGRAM when local setting disabled" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try sendRawH3Datagram(&pair.client, 0, "unexpected");
    try expectPairH3Error(allocator, &pair, error.DatagramNotEnabled);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.settings_error);
}

test "session closes malformed DATAGRAM payload with H3_DATAGRAM_ERROR" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();

    try pair.client.sendDatagram(&.{});
    try expectPairH3Error(allocator, &pair, error.InsufficientBytes);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.datagram_error);
}

test "session closes when peer control stream is closed" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try pair.client.streamFinish(pair.client_h3.control_stream_id.?);

    try expectPairH3Error(allocator, &pair, error.ClosedCriticalStream);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.closed_critical_stream);
}

test "session rejects malformed request pseudo headers" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const bad_fields = [_]null3.FieldLine{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &bad_fields);

    try expectPairH3Error(allocator, &pair, error.PseudoHeaderAfterRegular);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.message_error);
}

test "session enforces max field section size on decoded request headers" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{
        .settings = .{ .max_field_section_size = 4 },
        .max_field_section_size = 4,
    });
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var block: [512]u8 = undefined;
    const block_n = try null3.qpack.encodeFieldSection(&block, &fields);
    try std.testing.expect(block_n > 4);
    try writeFrame(&pair.client, stream_id, .{ .headers = block[0..block_n] });

    try expectPairH3Error(allocator, &pair, error.HeaderSectionTooLarge);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.message_error);
}

test "session enforces decoded field-line count budget" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{
        .max_field_lines = 3,
    });
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &fields);

    try expectPairH3Error(allocator, &pair, error.TooManyFieldLines);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.message_error);
}

test "production session config supports ordinary request flow" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        null3.SessionConfig.production(.{}),
        null3.SessionConfig.production(.{}),
    );
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    var h3_client = null3.Client.init(&pair.client_h3);
    const stream_id = try openGetAndAwaitServerHeaders(allocator, &pair, &h3_client);
    try std.testing.expectEqual(@as(u64, 0), stream_id);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), pair.client_h3.peer_settings.?.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 4096), pair.client_h3.peer_settings.?.qpack_max_table_capacity);
}

test "production session config advertises limits and enforces caps" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(
        allocator,
        null3.SessionConfig.production(.{}),
        null3.SessionConfig.production(.{
            .max_field_lines = 3,
        }),
    );
    defer pair.deinit();

    try exchangePairSettings(allocator, &pair);
    try std.testing.expectEqual(@as(?u64, 64 * 1024), pair.client_h3.peer_settings.?.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 4096), pair.client_h3.peer_settings.?.qpack_max_table_capacity);

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &fields);

    try expectPairH3Error(allocator, &pair, error.TooManyFieldLines);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, null3.protocol.ErrorCode.message_error);
}

test "session exchanges HTTP/3 request and response over nullq streams" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

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

    try handshake(&client, &server);
    try std.testing.expectEqualStrings("h3", client.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("h3", server.inner.alpnSelected().?);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    const h3_settings: null3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 1 << 20,
    };
    var client_h3 = null3.Session.init(allocator, .client, &client, .{
        .settings = h3_settings,
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = null3.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 1 << 20,
    });
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{
        .settings = h3_settings,
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = null3.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 1 << 20,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = null3.Client.init(&client_h3);
    var h3_server = null3.Server.init(&server_h3);
    var request_tracker = null3.RequestTracker.init(allocator);
    defer request_tracker.deinit();
    var response_tracker = null3.ResponseTracker.init(allocator);
    defer response_tracker.deinit();

    const request_headers = [_]null3.FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    var request_writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/echo",
        .headers = &request_headers,
    });
    const request_stream_id = request_writer.stream_id;
    try request_writer.write("pi");
    try request_writer.write("ng");
    try request_writer.finish();

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
    var client_saw_settings = false;
    var server_saw_settings = false;
    var server_saw_request_headers = false;
    var server_saw_request_body = false;
    var server_saw_request_finish = false;
    var response_sent = false;
    var client_saw_response_headers = false;
    var client_saw_dynamic_response_header = false;
    var client_saw_response_body = false;
    var client_saw_response_finish = false;
    var client_saw_goaway = false;
    var client_applied_dynamic_qpack = false;
    var server_saw_qpack_ack = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (!client_saw_response_finish or !client_saw_goaway or !server_saw_qpack_ack) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        if (client_h3.qpack_decoder_table.insert_count > 0) {
            client_applied_dynamic_qpack = true;
        }
        if (server_h3.qpack_encoder_table.insert_count > 0 and
            server_h3.qpack_encoder_state.referenceCount(0) == 0 and
            server_h3.qpack_encoder_state.known_received_count > 0)
        {
            server_saw_qpack_ack = true;
        }

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    server_saw_settings = true;
                    try std.testing.expectEqual(@as(?u64, 1 << 20), settings.max_field_section_size);
                },
                else => {
                    const request_state = (try request_tracker.observe(request_event)) orelse continue;
                    const request_reader = request_state.reader();
                    try std.testing.expectEqual(request_stream_id, request_state.stream_id);
                    if (request_reader.headers().len > 0) {
                        server_saw_request_headers = true;
                        try std.testing.expectEqualStrings("POST", request_reader.method().?);
                        try std.testing.expectEqualStrings("/echo", request_reader.path().?);
                    }
                    if (request_reader.body().len > 0) {
                        const body = request_reader.body();
                        try std.testing.expect(body.len <= "ping".len);
                        try std.testing.expectEqualStrings("ping"[0..body.len], body);
                        if (std.mem.eql(u8, body, "ping")) server_saw_request_body = true;
                    }
                    if (request_reader.complete()) server_saw_request_finish = true;
                },
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (!response_sent and server_saw_settings and server_saw_request_headers and server_saw_request_body and server_saw_request_finish) {
            const response_fields = [_]null3.FieldLine{
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "x-dyn", .value = "one" },
            };
            var response_writer = try h3_server.startResponse(allocator, request_stream_id, .{
                .status = "200",
                .headers = &response_fields,
            });
            try response_writer.write("po");
            try response_writer.write("ng");
            try response_writer.finish();
            try h3_server.goaway(request_stream_id + 4);
            response_sent = true;
        }

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    client_saw_settings = true;
                    try std.testing.expectEqual(@as(?u64, 1 << 20), settings.max_field_section_size);
                },
                .goaway => |id| {
                    client_saw_goaway = true;
                    try std.testing.expectEqual(request_stream_id + 4, id);
                },
                else => {
                    const response_state = (try response_tracker.observe(response_event)) orelse continue;
                    const response_reader = response_state.reader();
                    try std.testing.expectEqual(request_stream_id, response_reader.streamId());
                    if (response_reader.headers().len > 0) {
                        client_saw_response_headers = true;
                        try std.testing.expectEqualStrings("200", response_reader.status().?);
                        for (response_reader.headers()) |field| {
                            if (std.mem.eql(u8, field.name, "x-dyn") and
                                std.mem.eql(u8, field.value, "one"))
                            {
                                client_saw_dynamic_response_header = true;
                            }
                        }
                    }
                    if (response_reader.body().len > 0) {
                        const body = response_reader.body();
                        try std.testing.expect(body.len <= "pong".len);
                        try std.testing.expectEqualStrings("pong"[0..body.len], body);
                        if (std.mem.eql(u8, body, "pong")) client_saw_response_body = true;
                    }
                    if (response_reader.complete()) client_saw_response_finish = true;
                },
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(client_saw_settings);
    try std.testing.expect(server_saw_settings);
    try std.testing.expect(server_saw_request_headers);
    try std.testing.expect(server_saw_request_body);
    try std.testing.expect(server_saw_request_finish);
    try std.testing.expect(response_sent);
    try std.testing.expect(client_saw_response_headers);
    try std.testing.expect(client_saw_dynamic_response_header);
    try std.testing.expect(client_saw_response_body);
    try std.testing.expect(client_saw_response_finish);
    try std.testing.expect(client_saw_goaway);
    try std.testing.expect(client_applied_dynamic_qpack);
    try std.testing.expect(server_saw_qpack_ack);
    try std.testing.expectEqual(null3.session.ShutdownState.draining, client_h3.shutdownState());
    try std.testing.expectEqual(null3.session.ShutdownState.draining, server_h3.shutdownState());

    try std.testing.expectError(
        null3.session.Error.RequestBlockedByGoaway,
        h3_client.request(allocator, .{
            .method = "POST",
            .authority = "localhost",
            .path = "/echo",
            .headers = &request_headers,
        }),
    );

    const ignored_stream_id = request_stream_id + 4;
    _ = try client.openBidi(ignored_stream_id);
    var ignored_encoder = null3.MessageEncoder.init(.request, .{});
    const ignored_request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var ignored_bytes: [512]u8 = undefined;
    var ignored_len: usize = 0;
    ignored_len += try ignored_encoder.encodeHeaders(ignored_bytes[ignored_len..], &ignored_request_fields);
    ignored_len += try ignored_encoder.encodeData(ignored_bytes[ignored_len..], "late");
    _ = try client.streamWrite(ignored_stream_id, ignored_bytes[0..ignored_len]);
    try client.streamFinish(ignored_stream_id);

    var server_saw_rejection = false;
    iters = 0;
    while (!server_saw_rejection) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .rejected => |rejected| {
                    server_saw_rejection = true;
                    try std.testing.expectEqual(ignored_stream_id, rejected.stream_id);
                    try std.testing.expectEqual(null3.protocol.ErrorCode.request_rejected, rejected.error_code);
                    const info = rejected.errorInfo();
                    try std.testing.expectEqual(null3.ErrorSource.local, info.source);
                    try std.testing.expectEqual(null3.ErrorCategory.request, info.application.category);
                    try std.testing.expectEqual(null3.ErrorScope.stream, info.application.default_scope);
                },
                .headers => |headers| {
                    try std.testing.expect(headers.stream_id != ignored_stream_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}

test "session exchanges HTTP/3 datagrams over nullq datagram frames" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: nullq.Connection = undefined;
    var server: nullq.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    const h3_settings: null3.Settings = .{ .h3_datagram = true };
    var client_h3 = null3.Session.init(allocator, .client, &client, .{
        .settings = h3_settings,
    });
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{
        .settings = h3_settings,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = null3.Client.init(&client_h3);
    var h3_server = null3.Server.init(&server_h3);

    try std.testing.expectError(
        null3.session.Error.MissingSettings,
        h3_client.sendDatagram(0, "too-soon"),
    );

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

    var client_saw_settings = false;
    var server_saw_settings = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!client_saw_settings or !server_saw_settings) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    try std.testing.expect(settings.h3_datagram);
                    client_saw_settings = true;
                },
                else => {},
            }
        }
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    try std.testing.expect(settings.h3_datagram);
                    server_saw_settings = true;
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    var writer = try h3_client.startRequest(allocator, .{
        .method = "CONNECT",
        .authority = "localhost",
        .path = "/datagram",
    });
    const stream_id = writer.stream_id;
    const tracked_client_datagram_id = try writer.datagramTracked("from-client");

    var server_saw_datagram = false;
    var client_saw_datagram_ack = false;
    iters = 0;
    while (!server_saw_datagram or !client_saw_datagram_ack) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .datagram => |datagram| {
                    server_saw_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    try std.testing.expectEqualStrings("from-client", datagram.payload);
                    try std.testing.expect(!datagram.arrived_in_early_data);
                },
                else => {},
            }
        }
        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .datagram_acked => |acked| {
                    client_saw_datagram_ack = true;
                    try std.testing.expectEqual(tracked_client_datagram_id, acked.id);
                    try std.testing.expect(acked.len >= "from-client".len);
                    try std.testing.expectEqual(@as(u32, 0), acked.path_id);
                    try std.testing.expect(!acked.arrived_in_early_data);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.datagramWithContext(7, "ctx-client");

    var server_saw_context_datagram = false;
    iters = 0;
    while (!server_saw_context_datagram) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .datagram => |datagram| {
                    server_saw_context_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    const context = try datagram.context();
                    try std.testing.expectEqual(@as(u64, 7), context.context_id);
                    try std.testing.expectEqualStrings("ctx-client", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const tracked_server_datagram_id = try h3_server.sendDatagramTracked(stream_id, "from-server");

    var client_saw_datagram = false;
    var server_saw_datagram_ack = false;
    iters = 0;
    while (!client_saw_datagram or !server_saw_datagram_ack) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .datagram => |datagram| {
                    client_saw_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    try std.testing.expectEqualStrings("from-server", datagram.payload);
                    try std.testing.expect(!datagram.arrived_in_early_data);
                },
                else => {},
            }
        }
        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .datagram_acked => |acked| {
                    server_saw_datagram_ack = true;
                    try std.testing.expectEqual(tracked_server_datagram_id, acked.id);
                    try std.testing.expect(acked.len >= "from-server".len);
                    try std.testing.expectEqual(@as(u32, 0), acked.path_id);
                    try std.testing.expect(!acked.arrived_in_early_data);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try h3_server.sendDatagramWithContext(stream_id, 9, "ctx-server");

    var client_saw_context_datagram = false;
    iters = 0;
    while (!client_saw_context_datagram) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .datagram => |datagram| {
                    client_saw_context_datagram = true;
                    try std.testing.expectEqual(stream_id, datagram.stream_id);
                    const context = try datagram.context();
                    try std.testing.expectEqual(@as(u64, 9), context.context_id);
                    try std.testing.expectEqualStrings("ctx-server", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try writer.datagramContextCapsule(11, "capsule-client");

    var server_saw_datagram_capsule = false;
    iters = 0;
    while (!server_saw_datagram_capsule) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .data => |data| {
                    server_saw_datagram_capsule = true;
                    const decoded_capsule = try data.capsule();
                    try std.testing.expect(decoded_capsule.capsule.isDatagram());
                    const context = try null3.datagram.decodeContextPayload(decoded_capsule.capsule.value);
                    try std.testing.expectEqual(@as(u64, 11), context.context_id);
                    try std.testing.expectEqualStrings("capsule-client", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    const capsule_headers = [_]null3.FieldLine{
        .{ .name = "capsule-protocol", .value = "?1" },
    };
    var response_writer = try h3_server.startResponse(allocator, stream_id, .{
        .status = "200",
        .headers = &capsule_headers,
    });
    try response_writer.datagramContextCapsule(13, "capsule-server");

    var client_saw_datagram_capsule = false;
    iters = 0;
    while (!client_saw_datagram_capsule) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .data => |data| {
                    client_saw_datagram_capsule = true;
                    const decoded_capsule = try data.capsule();
                    try std.testing.expect(decoded_capsule.capsule.isDatagram());
                    const context = try null3.datagram.decodeContextPayload(decoded_capsule.capsule.value);
                    try std.testing.expectEqual(@as(u64, 13), context.context_id);
                    try std.testing.expectEqualStrings("capsule-server", context.payload);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try std.testing.expectError(
        error.InvalidDatagramStream,
        h3_client.sendDatagram(stream_id + 1, "bad stream"),
    );
}

test "session surfaces nullq connection close events" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: nullq.Connection = undefined;
    var server: nullq.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = null3.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();

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

    server_h3.close(null3.protocol.ErrorCode.no_error, "server shutdown");
    try server_h3.drain(&server_events);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, server_h3.shutdownState());
    try std.testing.expectEqual(@as(usize, 1), server_events.items.len);
    switch (server_events.items[0]) {
        .connection_closed => |closed| {
            try std.testing.expectEqual(nullq.CloseSource.local, closed.source);
            try std.testing.expectEqual(nullq.CloseErrorSpace.application, closed.error_space);
            try std.testing.expectEqual(null3.protocol.ErrorCode.no_error, closed.error_code);
            try std.testing.expectEqualStrings("server shutdown", closed.reason);
            try std.testing.expectEqualStrings("H3_NO_ERROR", closed.application.?.name);
        },
        else => return error.TestExpectedEqual,
    }
    clearSessionEvents(allocator, &server_events);

    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    var client_saw_close = false;
    while (!client_saw_close) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (client_events.items) |event| {
            switch (event) {
                .connection_closed => |closed| {
                    client_saw_close = true;
                    try std.testing.expectEqual(nullq.CloseSource.peer, closed.source);
                    try std.testing.expectEqual(nullq.CloseErrorSpace.application, closed.error_space);
                    try std.testing.expectEqual(null3.protocol.ErrorCode.no_error, closed.error_code);
                    try std.testing.expectEqualStrings("server shutdown", closed.reason);
                    try std.testing.expectEqualStrings("H3_NO_ERROR", closed.application.?.name);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
        clearSessionEvents(allocator, &server_events);
    }

    try std.testing.expectEqual(null3.session.ShutdownState.draining, client_h3.shutdownState());
}

test "client send-side reset is surfaced as server request reset" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: nullq.Connection = undefined;
    var server: nullq.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = null3.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();
    var h3_client = null3.Client.init(&client_h3);
    var h3_server = null3.Server.init(&server_h3);

    var writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/reset-me",
    });
    const request_stream_id = writer.stream_id;
    try writer.write("partial body");

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
    while (server.stream(request_stream_id) == null) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }

    try writer.reset(null3.protocol.ErrorCode.request_cancelled);

    iters = 0;
    var server_saw_reset = false;
    while (!server_saw_reset) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .reset => |reset| {
                    server_saw_reset = true;
                    try std.testing.expectEqual(request_stream_id, reset.stream_id);
                    try std.testing.expectEqual(null3.protocol.ErrorCode.request_cancelled, reset.error_code);
                    try std.testing.expect(reset.final_size > 0);
                    const info = reset.errorInfo();
                    try std.testing.expectEqual(null3.ErrorSource.peer, info.source);
                    try std.testing.expectEqual(null3.ErrorCategory.request, info.application.category);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}

test "server send-side reset is surfaced as client response reset" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client: nullq.Connection = undefined;
    var server: nullq.Connection = undefined;
    try initConnectedQuic(allocator, client_tls, server_tls, &client, &server);
    defer client.deinit();
    defer server.deinit();

    var client_h3 = null3.Session.init(allocator, .client, &client, .{});
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{});
    defer server_h3.deinit();
    var h3_client = null3.Client.init(&client_h3);
    var h3_server = null3.Server.init(&server_h3);
    var request_tracker = null3.RequestTracker.init(allocator);
    defer request_tracker.deinit();

    const request = try h3_client.request(allocator, .{
        .method = "GET",
        .authority = "localhost",
        .path = "/server-reset",
    });

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
    var response_reset_sent = false;
    var client_saw_reset = false;
    while (!client_saw_reset) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            const request_state = (try request_tracker.observe(request_event)) orelse continue;
            if (!response_reset_sent and request_state.headers != null and request_state.complete) {
                var response_writer = try h3_server.startResponse(allocator, request.stream_id, .{
                    .status = "503",
                });
                try response_writer.write("not today");
                try response_writer.reset(null3.protocol.ErrorCode.internal_error);
                response_reset_sent = true;
            }
        }
        clearSessionEvents(allocator, &server_events);

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .reset => |reset| {
                    client_saw_reset = true;
                    try std.testing.expectEqual(request.stream_id, reset.stream_id);
                    try std.testing.expectEqual(null3.protocol.ErrorCode.internal_error, reset.error_code);
                    try std.testing.expect(reset.final_size > 0);
                    const info = reset.errorInfo();
                    try std.testing.expectEqual(null3.ErrorSource.peer, info.source);
                    try std.testing.expectEqual(null3.ErrorCategory.internal, info.application.category);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(response_reset_sent);
}
