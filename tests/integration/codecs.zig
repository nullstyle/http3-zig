const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fuzz_codecs = @import("http3_zig_fuzz_codecs");
const fixt = @import("_fixtures.zig");

// Aliases — pulls in only the helpers this file's tests reference. It's
// fine to over-alias; unused aliases compile away.
const test_cert_pem = fixt.test_cert_pem;
const test_key_pem = fixt.test_key_pem;
const ClientCid = fixt.ClientCid;
const ServerCid = fixt.ServerCid;
const discardKeylog = fixt.discardKeylog;
const handshake = fixt.handshake;
const initConnectedQuic = fixt.initConnectedQuic;
const clearSessionEvents = fixt.clearSessionEvents;
const pumpH3 = fixt.pumpH3;
const pumpUntilH3Error = fixt.pumpUntilH3Error;
const writeFrame = fixt.writeFrame;
const writeQpackEncoderInstruction = fixt.writeQpackEncoderInstruction;
const writeStreamType = fixt.writeStreamType;
const writeVarint = fixt.writeVarint;
const openUniWithType = fixt.openUniWithType;
const writeHeadersFrame = fixt.writeHeadersFrame;
const writePushPromiseFrame = fixt.writePushPromiseFrame;
const expectLastCloseCode = fixt.expectLastCloseCode;
const fieldValue = fixt.fieldValue;
const H3Pair = fixt.H3Pair;
const expectPairH3Error = fixt.expectPairH3Error;
const exchangePairSettings = fixt.exchangePairSettings;
const openGetAndAwaitServerHeaders = fixt.openGetAndAwaitServerHeaders;
const sendRawH3Datagram = fixt.sendRawH3Datagram;

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

    const frame_n = try http3_zig.frame.encode(&buf, .{ .data = "hello" });
    try fuzz_codecs.runTarget(allocator, .frame, buf[0..frame_n]);

    const settings_n = try (http3_zig.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    }).encode(&buf);
    try fuzz_codecs.runTarget(allocator, .settings, buf[0..settings_n]);

    const capsule_n = try http3_zig.capsule.encodeDatagram(&buf, "payload");
    try fuzz_codecs.runTarget(allocator, .capsule, buf[0..capsule_n]);

    const datagram_n = try http3_zig.datagram.encodeWithContext(&buf, 4, 7, "payload");
    try fuzz_codecs.runTarget(allocator, .datagram, buf[0..datagram_n]);

    const masque_path = try http3_zig.masque.allocConnectUdpPath(allocator, .{
        .authority = "proxy.example",
        .target_host = "example.com",
        .target_port = 443,
    });
    defer allocator.free(masque_path);
    try fuzz_codecs.runTarget(allocator, .masque, masque_path);
    const masque_udp_n = try http3_zig.masque.encodeUdpPayload(&buf, "udp");
    try fuzz_codecs.runTarget(allocator, .masque, buf[0..masque_udp_n]);

    const integer_n = try http3_zig.qpack.integer.encode(&buf, 5, 0, 1337);
    try fuzz_codecs.runTarget(allocator, .qpack_integer, buf[0..integer_n]);

    const huffman_n = try http3_zig.qpack.huffman.encode(&buf, "www.example.com");
    try fuzz_codecs.runTarget(allocator, .qpack_huffman, buf[0..huffman_n]);

    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-http3-zig-fuzz", .value = "ok" },
    };
    const static_section_n = try http3_zig.qpack.encodeFieldSection(&buf, &fields);
    try fuzz_codecs.runTarget(allocator, .qpack_field_static, buf[0..static_section_n]);
    try fuzz_codecs.runTarget(allocator, .qpack_field_literal, buf[0..static_section_n]);

    var table = http3_zig.DynamicTable.init(allocator, 0);
    defer table.deinit();
    const dynamic_section_n = try http3_zig.qpack.encodeDynamicFieldSection(&buf, &table, &fields);
    try fuzz_codecs.runTarget(allocator, .qpack_field_dynamic, buf[0..dynamic_section_n]);

    const encoder_instruction_n = try http3_zig.qpack.instructions.encodeEncoderInstruction(&buf, .{ .set_capacity = 0 });
    try fuzz_codecs.runTarget(allocator, .qpack_encoder_instruction, buf[0..encoder_instruction_n]);

    const decoder_instruction_n = try http3_zig.qpack.instructions.encodeDecoderInstruction(&buf, .{ .insert_count_increment = 1 });
    try fuzz_codecs.runTarget(allocator, .qpack_decoder_instruction, buf[0..decoder_instruction_n]);

    const websocket_n = try http3_zig.websocket.frame.encodeText(&buf, "hello", .{
        .mask = true,
        .masking_key = .{ 1, 2, 3, 4 },
    });
    try fuzz_codecs.runTarget(allocator, .websocket_frame, buf[0..websocket_n]);
    try fuzz_codecs.runTarget(allocator, .websocket_message, buf[0..websocket_n]);
}
test "HTTP/3 SETTINGS frame round-trip" {
    const s: http3_zig.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 1 << 20,
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    var buf: [128]u8 = undefined;
    const n = try http3_zig.frame.encode(&buf, .{ .settings = s });
    const d = try http3_zig.frame.decode(buf[0..n]);
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
    const varint = quic_zig.wire.varint;

    var duplicate: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(duplicate[pos..], http3_zig.protocol.SettingId.h3_datagram);
    pos += try varint.encode(duplicate[pos..], 1);
    pos += try varint.encode(duplicate[pos..], http3_zig.protocol.SettingId.h3_datagram);
    pos += try varint.encode(duplicate[pos..], 1);
    try std.testing.expectError(error.DuplicateSetting, http3_zig.Settings.decode(duplicate[0..pos]));

    var invalid_bool: [8]u8 = undefined;
    pos = 0;
    pos += try varint.encode(invalid_bool[pos..], http3_zig.protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(invalid_bool[pos..], 2);
    try std.testing.expectError(error.InvalidSettingValue, http3_zig.Settings.decode(invalid_bool[0..pos]));

    var reserved: [8]u8 = undefined;
    pos = 0;
    pos += try varint.encode(reserved[pos..], 0x02);
    pos += try varint.encode(reserved[pos..], 1);
    try std.testing.expectError(error.ReservedSetting, http3_zig.Settings.decode(reserved[0..pos]));
}

test "literal QPACK field section validates as request headers" {
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "user-agent", .value = "http3-zig-test" },
    };
    var block: [512]u8 = undefined;
    const n = try http3_zig.qpack.encodeLiteralFieldSection(&block, &fields);
    const decoded = try http3_zig.qpack.decodeLiteralFieldSection(std.testing.allocator, block[0..n]);
    defer http3_zig.qpack.freeFieldSection(std.testing.allocator, decoded);

    try http3_zig.headers.validateRequest(decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("example.com", decoded[3].value);
}

test "static QPACK field section uses indexed representation" {
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/search" },
    };
    var block: [128]u8 = undefined;
    var literal_block: [128]u8 = undefined;
    const n = try http3_zig.qpack.encodeFieldSection(&block, &fields);
    const literal_n = try http3_zig.qpack.encodeLiteralFieldSection(&literal_block, &fields);
    try std.testing.expect(n < literal_n);

    const decoded = try http3_zig.qpack.decodeFieldSection(std.testing.allocator, block[0..n]);
    defer http3_zig.qpack.freeFieldSection(std.testing.allocator, decoded);
    try http3_zig.headers.validateRequest(decoded);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("/search", decoded[2].value);
}

test "extended CONNECT header validation requires opt-in" {
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/socket" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };

    try std.testing.expectError(error.ExtendedConnectNotEnabled, http3_zig.headers.validateRequest(&fields));
    try http3_zig.headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
    try std.testing.expectEqualStrings("websocket", http3_zig.headers.requestProtocol(&fields).?);
    try std.testing.expect(http3_zig.headers.isExtendedConnect(&fields));

    const bad_method = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/socket" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        error.InvalidPseudoHeader,
        http3_zig.headers.validateRequestWithOptions(&bad_method, .{ .enable_connect_protocol = true }),
    );
}

test "header validation rejects malformed pseudo headers and connection fields" {
    const pseudo_after_regular = [_]http3_zig.FieldLine{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(error.PseudoHeaderAfterRegular, http3_zig.headers.validateRequest(&pseudo_after_regular));

    const duplicate_method = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(error.DuplicatePseudoHeader, http3_zig.headers.validateRequest(&duplicate_method));

    const missing_path = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, http3_zig.headers.validateRequest(&missing_path));

    const uppercase = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "User-Agent", .value = "bad" },
    };
    try std.testing.expectError(error.UppercaseFieldName, http3_zig.headers.validateRequest(&uppercase));

    const connection_specific = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    try std.testing.expectError(error.ConnectionSpecificField, http3_zig.headers.validateRequest(&connection_specific));

    const bad_trailer = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expectError(error.InvalidPseudoHeader, http3_zig.headers.validateTrailers(&bad_trailer));

    const response_without_status = [_]http3_zig.FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, http3_zig.headers.validateResponse(&response_without_status));
}

test "capsule and context datagram codecs round-trip" {
    var context_buf: [64]u8 = undefined;
    const context_len = try http3_zig.datagram.encodeContextPayload(&context_buf, 42, "ctx");
    const context = try http3_zig.datagram.decodeContextPayload(context_buf[0..context_len]);
    try std.testing.expectEqual(@as(u64, 42), context.context_id);
    try std.testing.expectEqualStrings("ctx", context.payload);

    var capsule_buf: [64]u8 = undefined;
    const capsule_len = try http3_zig.capsule.encodeDatagram(&capsule_buf, context_buf[0..context_len]);
    const capsule = try http3_zig.capsule.decode(capsule_buf[0..capsule_len]);
    try std.testing.expect(capsule.capsule.isDatagram());
    const capsule_context = try http3_zig.datagram.decodeContextPayload(capsule.capsule.value);
    try std.testing.expectEqual(@as(u64, 42), capsule_context.context_id);
    try std.testing.expectEqualStrings("ctx", capsule_context.payload);

    var iter = http3_zig.capsule.iter(capsule_buf[0..capsule_len]);
    try std.testing.expect((try iter.next()) != null);
    try std.testing.expect((try iter.next()) == null);
}

test "capsule decoder rejects truncated capsule payloads" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try quic_zig.wire.varint.encode(buf[pos..], http3_zig.capsule.Type.datagram);
    pos += try quic_zig.wire.varint.encode(buf[pos..], 4);
    buf[pos] = 'x';
    pos += 1;
    try std.testing.expectError(error.InsufficientBytes, http3_zig.capsule.decode(buf[0..pos]));
}

test "PRIORITY_UPDATE request frame round-trip" {
    var buf: [64]u8 = undefined;
    const n = try http3_zig.frame.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=3, i",
        },
    });
    const d = try http3_zig.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqualStrings("u=3, i", p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "priority parser and stream frame validator" {
    const p = try http3_zig.Priority.parse("u=1, i");
    try std.testing.expectEqual(@as(u3, 1), p.urgency);
    try std.testing.expect(p.incremental);

    var validator = http3_zig.stream.FrameValidator.init(.control);
    try validator.observe(http3_zig.protocol.FrameType.settings);
    try validator.observe(http3_zig.protocol.FrameType.priority_update_request);
    try std.testing.expectError(
        http3_zig.stream.FrameValidationError.FrameUnexpected,
        validator.observe(http3_zig.protocol.FrameType.headers),
    );
}

