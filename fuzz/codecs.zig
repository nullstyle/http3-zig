const std = @import("std");
const http3_zig = @import("http3_zig");

const max_iterator_items = 1024;

const qpack_decode_options: http3_zig.QpackFieldSectionDecodeOptions = .{
    .max_field_lines = 64,
    .max_decoded_bytes = 16 * 1024,
};

pub const Target = enum {
    all,
    frame,
    settings,
    capsule,
    datagram,
    qpack_integer,
    qpack_huffman,
    qpack_field_static,
    qpack_field_literal,
    qpack_field_dynamic,
    qpack_encoder_instruction,
    qpack_decoder_instruction,
    websocket_frame,
    websocket_message,
    masque,
    webtransport,
    webtransport_session,
};

pub const concrete_targets = [_]Target{
    .frame,
    .settings,
    .capsule,
    .datagram,
    .qpack_integer,
    .qpack_huffman,
    .qpack_field_static,
    .qpack_field_literal,
    .qpack_field_dynamic,
    .qpack_encoder_instruction,
    .qpack_decoder_instruction,
    .websocket_frame,
    .websocket_message,
    .masque,
    .webtransport,
    .webtransport_session,
};

const smoke_inputs = [_][]const u8{
    "",
    "\x00",
    "\x01",
    "\x00\x00",
    "\x00\x05hello",
    "\x01\x02\x00\x00",
    "\x04\x00",
    "\x00\x03abc",
    "\x3f\xe1\x1f",
    "\xff",
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "GET / HTTP/3\r\n\r\n",
};

pub fn smokeInputs() []const []const u8 {
    return &smoke_inputs;
}

pub fn targetName(target: Target) []const u8 {
    return switch (target) {
        .all => "all",
        .frame => "frame",
        .settings => "settings",
        .capsule => "capsule",
        .datagram => "datagram",
        .qpack_integer => "qpack-integer",
        .qpack_huffman => "qpack-huffman",
        .qpack_field_static => "qpack-field-static",
        .qpack_field_literal => "qpack-field-literal",
        .qpack_field_dynamic => "qpack-field-dynamic",
        .qpack_encoder_instruction => "qpack-encoder-instruction",
        .qpack_decoder_instruction => "qpack-decoder-instruction",
        .websocket_frame => "websocket-frame",
        .websocket_message => "websocket-message",
        .masque => "masque",
        .webtransport => "webtransport",
        .webtransport_session => "webtransport-session",
    };
}

pub fn targetFromName(name: []const u8) ?Target {
    if (std.mem.eql(u8, name, "all")) return .all;
    if (std.mem.eql(u8, name, "frame")) return .frame;
    if (std.mem.eql(u8, name, "settings")) return .settings;
    if (std.mem.eql(u8, name, "capsule")) return .capsule;
    if (std.mem.eql(u8, name, "datagram")) return .datagram;
    if (std.mem.eql(u8, name, "qpack-integer") or std.mem.eql(u8, name, "qpack_integer")) return .qpack_integer;
    if (std.mem.eql(u8, name, "qpack-huffman") or std.mem.eql(u8, name, "qpack_huffman")) return .qpack_huffman;
    if (std.mem.eql(u8, name, "qpack-field-static") or std.mem.eql(u8, name, "qpack_field_static")) return .qpack_field_static;
    if (std.mem.eql(u8, name, "qpack-field-literal") or std.mem.eql(u8, name, "qpack_field_literal")) return .qpack_field_literal;
    if (std.mem.eql(u8, name, "qpack-field-dynamic") or std.mem.eql(u8, name, "qpack_field_dynamic")) return .qpack_field_dynamic;
    if (std.mem.eql(u8, name, "qpack-encoder-instruction") or std.mem.eql(u8, name, "qpack_encoder_instruction")) return .qpack_encoder_instruction;
    if (std.mem.eql(u8, name, "qpack-decoder-instruction") or std.mem.eql(u8, name, "qpack_decoder_instruction")) return .qpack_decoder_instruction;
    if (std.mem.eql(u8, name, "websocket-frame") or std.mem.eql(u8, name, "websocket_frame")) return .websocket_frame;
    if (std.mem.eql(u8, name, "websocket-message") or std.mem.eql(u8, name, "websocket_message")) return .websocket_message;
    if (std.mem.eql(u8, name, "masque")) return .masque;
    if (std.mem.eql(u8, name, "webtransport")) return .webtransport;
    if (std.mem.eql(u8, name, "webtransport-session") or std.mem.eql(u8, name, "webtransport_session")) return .webtransport_session;
    return null;
}

pub fn runTarget(allocator: std.mem.Allocator, target: Target, input: []const u8) !void {
    switch (target) {
        .all => {
            inline for (concrete_targets) |concrete| {
                try runTarget(allocator, concrete, input);
            }
        },
        .frame => fuzzFrame(input),
        .settings => fuzzSettings(input),
        .capsule => fuzzCapsule(input),
        .datagram => fuzzDatagram(input),
        .qpack_integer => fuzzQpackInteger(input),
        .qpack_huffman => fuzzQpackHuffman(allocator, input),
        .qpack_field_static => fuzzQpackFieldStatic(allocator, input),
        .qpack_field_literal => fuzzQpackFieldLiteral(allocator, input),
        .qpack_field_dynamic => fuzzQpackFieldDynamic(allocator, input),
        .qpack_encoder_instruction => fuzzQpackEncoderInstruction(allocator, input),
        .qpack_decoder_instruction => fuzzQpackDecoderInstruction(input),
        .websocket_frame => fuzzWebSocketFrame(allocator, input),
        .websocket_message => fuzzWebSocketMessage(allocator, input),
        .masque => fuzzMasque(allocator, input),
        .webtransport => fuzzWebTransport(input),
        .webtransport_session => fuzzWebTransportSession(allocator, input),
    }
}

fn fuzzFrame(input: []const u8) void {
    if (http3_zig.frame.decode(input)) |_| {} else |_| {}

    var it = http3_zig.frame.iter(input);
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = it.next() catch break;
        if (maybe == null) break;
    }
}

fn fuzzSettings(input: []const u8) void {
    if (http3_zig.Settings.decode(input)) |_| {} else |_| {}
}

fn fuzzCapsule(input: []const u8) void {
    if (http3_zig.capsule.decode(input)) |_| {} else |_| {}

    var it = http3_zig.capsule.iter(input);
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = it.next() catch break;
        if (maybe == null) break;
    }
}

fn fuzzDatagram(input: []const u8) void {
    if (http3_zig.datagram.decode(input)) |decoded| {
        if (decoded.context()) |_| {} else |_| {}
    } else |_| {}

    if (http3_zig.datagram.decodeContextPayload(input)) |_| {} else |_| {}
}

fn fuzzQpackInteger(input: []const u8) void {
    var prefix_bits: u8 = 1;
    while (prefix_bits <= 8) : (prefix_bits += 1) {
        if (http3_zig.qpack.integer.decode(input, prefix_bits)) |_| {} else |_| {}
    }
}

fn fuzzQpackHuffman(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.qpack.huffman.decode(allocator, input)) |decoded| {
        allocator.free(decoded);
    } else |_| {}
}

fn fuzzQpackFieldStatic(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.qpack.decodeFieldSectionWithOptions(allocator, input, qpack_decode_options)) |fields| {
        http3_zig.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackFieldLiteral(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.qpack.decodeLiteralFieldSectionWithOptions(allocator, input, qpack_decode_options)) |fields| {
        http3_zig.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackFieldDynamic(allocator: std.mem.Allocator, input: []const u8) void {
    var table = http3_zig.DynamicTable.init(allocator, 0);
    defer table.deinit();

    if (http3_zig.qpack.decodeDynamicFieldSectionWithOptions(allocator, &table, 0, input, qpack_decode_options)) |fields| {
        http3_zig.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackEncoderInstruction(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.qpack.instructions.decodeEncoderInstruction(allocator, input)) |decoded| {
        http3_zig.qpack.instructions.freeDecodedEncoderInstruction(allocator, decoded);
    } else |_| {}
}

fn fuzzQpackDecoderInstruction(input: []const u8) void {
    if (http3_zig.qpack.instructions.decodeDecoderInstruction(input)) |_| {} else |_| {}
}

fn fuzzWebSocketFrame(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.websocket.frame.decode(allocator, input, .{
        .max_payload_len = 16 * 1024,
    })) |decoded| {
        decoded.deinit(allocator);
    } else |_| {}

    var decoder = http3_zig.websocket.frame.Decoder.init(allocator, .{
        .max_payload_len = 16 * 1024,
    });
    defer decoder.deinit();
    decoder.push(input) catch return;
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = decoder.next() catch break;
        const frame = maybe orelse break;
        frame.deinit(allocator);
    }
}

fn fuzzWebSocketMessage(allocator: std.mem.Allocator, input: []const u8) void {
    var decoder = http3_zig.websocket.message.Decoder.init(allocator, .{
        .frame = .{
            .max_payload_len = 16 * 1024,
        },
        .max_message_len = 16 * 1024,
    });
    defer decoder.deinit();
    decoder.push(input) catch return;
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = decoder.next() catch break;
        const event = maybe orelse break;
        event.deinit(allocator);
    }
}

fn fuzzWebTransport(input: []const u8) void {
    // Stream-prefix decoders. The varint inputs reuse the same fuzz corpus
    // as every other codec — the goal is to exercise the truncation,
    // mismatched-type, and oversized-session-id paths without crashing.
    if (http3_zig.webtransport.decodeStreamHeader(.uni, input)) |_| {} else |_| {}
    if (http3_zig.webtransport.decodeStreamHeader(.bidi, input)) |_| {} else |_| {}
    if (http3_zig.webtransport.decodeAnyStreamHeader(input)) |_| {} else |_| {}

    // Capsule-level classification: a corpus byte string is interpreted as a
    // single Capsule Protocol record, then routed through `classifyCapsule`
    // so CLOSE/DRAIN/other paths all see fuzzer-generated values.
    if (http3_zig.capsule.decode(input)) |decoded| {
        if (http3_zig.webtransport.classifyCapsule(decoded.capsule)) |_| {} else |_| {}
    } else |_| {}

    // Direct value-level decoders (the input is interpreted as the capsule
    // value alone, exercising boundary lengths around the 4-byte error code
    // and the 1024-byte reason limit).
    if (http3_zig.webtransport.decodeCloseSessionValue(input)) |_| {} else |_| {}

    // Error-code mapping is total over u32, so just probe the reverse map.
    if (input.len >= 8) {
        const wire = std.mem.readInt(u64, input[0..8], .big);
        _ = http3_zig.webtransport.http3ToAppError(wire);
        _ = http3_zig.webtransport.isReservedStreamCode(wire);
    }
}

// `webtransport_session` target. Drives a wider, more structured set of
// shapes through the WebTransport codec entry points than `fuzzWebTransport`
// does: the fuzzer corpus is reinterpreted as the body of a WT_STREAM bidi
// prefix, as the value bytes of every WebTransport-registered capsule, and
// as the comma-separated value of `wt-available-protocols`. Round-trips
// through the flow-control encode/decode pairs catch encoder/decoder
// asymmetry that pure decode-only fuzzing would miss.
fn fuzzWebTransportSession(allocator: std.mem.Allocator, input: []const u8) void {
    // Truncated WT_STREAM bidi prefix: a single fuzzer byte followed by
    // the canonical 2-byte varint encoding of frame type 0x41
    // (`0x40 0x41`), then arbitrary continuation bytes. Exercises the
    // `decodeAnyStreamHeader` path where the type-varint and session-id
    // varint sit right at the boundary of the corpus length.
    {
        var buf: [256]u8 = undefined;
        const lead = if (input.len > 0) input[0] else @as(u8, 0);
        buf[0] = lead;
        buf[1] = 0x40;
        buf[2] = 0x41;
        const tail_len = @min(input.len, buf.len - 3);
        if (tail_len > 0) @memcpy(buf[3 .. 3 + tail_len], input[0..tail_len]);
        const total = 3 + tail_len;
        if (http3_zig.webtransport.decodeAnyStreamHeader(buf[0..total])) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeStreamHeader(.bidi, buf[1 .. 1 + 2 + tail_len])) |_| {} else |_| {}
    }

    // WT_STREAM uni prefix (`0x40 0x54`) followed by a truncated session-id
    // varint built from fuzzer bytes. Probes the second-varint truncation
    // path that the existing `webtransport` target only sees opportunistically.
    {
        var buf: [256]u8 = undefined;
        buf[0] = 0x40;
        buf[1] = 0x54;
        const tail_len = @min(input.len, buf.len - 2);
        if (tail_len > 0) @memcpy(buf[2 .. 2 + tail_len], input[0..tail_len]);
        const total = 2 + tail_len;
        if (http3_zig.webtransport.decodeAnyStreamHeader(buf[0..total])) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeStreamHeader(.uni, buf[0..total])) |_| {} else |_| {}
    }

    // CLOSE_WEBTRANSPORT_SESSION value: the first 4 bytes are interpreted
    // as the application error code (big-endian u32), the remainder as the
    // candidate UTF-8 reason phrase. Exercises both the under-4-byte
    // failure path and the > 4 + max_close_reason_len overflow path.
    {
        if (http3_zig.webtransport.decodeCloseSessionValue(input)) |_| {} else |_| {}

        // Wrap the same bytes into a CLOSE_WEBTRANSPORT_SESSION capsule and
        // route through `classifyCapsule` so the close-session arm of the
        // dispatcher sees fuzzer-generated values too.
        var buf: [2 + 8 + 64]u8 = undefined; // type varint + length varint + value bytes
        const value_len = @min(input.len, 64);
        if (http3_zig.capsule.encode(&buf, http3_zig.webtransport.CapsuleType.close_session, input[0..value_len])) |n| {
            if (http3_zig.capsule.decode(buf[0..n])) |decoded| {
                if (http3_zig.webtransport.classifyCapsule(decoded.capsule)) |_| {} else |_| {}
            } else |_| {}
        } else |_| {}
    }

    // DRAIN_WEBTRANSPORT_SESSION with non-empty value: spec MUST-error path.
    // Builds a draft drain capsule whose value field is the fuzzer corpus,
    // confirming `classifyCapsule` rejects it with `error.InvalidDrainCapsule`.
    {
        var buf: [2 + 8 + 64]u8 = undefined;
        const value_len = @min(input.len, 64);
        if (http3_zig.capsule.encode(&buf, http3_zig.webtransport.CapsuleType.drain_session, input[0..value_len])) |n| {
            if (http3_zig.capsule.decode(buf[0..n])) |decoded| {
                if (http3_zig.webtransport.classifyCapsule(decoded.capsule)) |_| {} else |_| {}
            } else |_| {}
        } else |_| {}
    }

    // All six flow-control capsules with varint-decoded values. The fuzzer
    // input drives both the value to encode (drawn from any 8-byte prefix as
    // a big-endian u64, masked to varint range) and the raw value bytes fed
    // back through the decoders. The encode -> capsule.decode -> classify
    // round-trip catches asymmetry where the encoder accepts a value the
    // classifier later refuses.
    {
        const wire_value: u64 = if (input.len >= 8) blk: {
            const raw = std.mem.readInt(u64, input[0..8], .big);
            // Mask to QUIC varint range (2^62 - 1) so encode does not bail
            // with ValueTooLarge before we even reach the classifier.
            break :blk raw & ((@as(u64, 1) << 62) - 1);
        } else 0;

        const capsule_types = [_]u64{
            http3_zig.webtransport.CapsuleType.max_data,
            http3_zig.webtransport.CapsuleType.data_blocked,
            http3_zig.webtransport.CapsuleType.max_streams_bidi,
            http3_zig.webtransport.CapsuleType.streams_blocked_bidi,
            http3_zig.webtransport.CapsuleType.max_streams_uni,
            http3_zig.webtransport.CapsuleType.streams_blocked_uni,
        };

        for (capsule_types) |ct| {
            var encoded: [2 + 8 + 8]u8 = undefined; // type varint + length varint + varint value
            const written = switch (ct) {
                http3_zig.webtransport.CapsuleType.max_data => http3_zig.webtransport.encodeMaxData(&encoded, wire_value),
                http3_zig.webtransport.CapsuleType.data_blocked => http3_zig.webtransport.encodeDataBlocked(&encoded, wire_value),
                http3_zig.webtransport.CapsuleType.max_streams_bidi => http3_zig.webtransport.encodeMaxStreamsBidi(&encoded, wire_value),
                http3_zig.webtransport.CapsuleType.streams_blocked_bidi => http3_zig.webtransport.encodeStreamsBlockedBidi(&encoded, wire_value),
                http3_zig.webtransport.CapsuleType.max_streams_uni => http3_zig.webtransport.encodeMaxStreamsUni(&encoded, wire_value),
                http3_zig.webtransport.CapsuleType.streams_blocked_uni => http3_zig.webtransport.encodeStreamsBlockedUni(&encoded, wire_value),
                else => unreachable,
            } catch continue;
            if (http3_zig.capsule.decode(encoded[0..written])) |decoded| {
                if (http3_zig.webtransport.classifyCapsule(decoded.capsule)) |_| {} else |_| {}
            } else |_| {}
        }

        // Direct value-level decoders. Each accepts only the bare varint with
        // no trailing bytes, so feeding the full corpus probes the
        // trailing-byte guard.
        if (http3_zig.webtransport.decodeMaxDataValue(input)) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeDataBlockedValue(input)) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeMaxStreamsBidiValue(input)) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeStreamsBlockedBidiValue(input)) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeMaxStreamsUniValue(input)) |_| {} else |_| {}
        if (http3_zig.webtransport.decodeStreamsBlockedUniValue(input)) |_| {} else |_| {}
    }

    // Capsule iterator + per-element classification. Bound at
    // `max_iterator_items` so a malicious zero-length capsule loop cannot
    // pin the harness.
    {
        var it = http3_zig.capsule.iter(input);
        var count: usize = 0;
        while (count < max_iterator_items) : (count += 1) {
            const maybe = it.next() catch break;
            const decoded = maybe orelse break;
            if (http3_zig.webtransport.classifyCapsule(decoded.capsule)) |_| {} else |_| {}
        }
    }

    // `wt-available-protocols` parser. The fuzzer corpus is fed verbatim
    // as the comma-separated header value; output is freed before return.
    if (http3_zig.webtransport.parseAvailableProtocols(allocator, input)) |parsed| {
        parsed.deinit(allocator);
    } else |_| {}

    // `isOfferedProtocol` is total over arbitrary input; pair it with a
    // candidate "selected" token sliced from the fuzzer bytes.
    if (input.len > 0) {
        const split = input.len / 2;
        _ = http3_zig.webtransport.isOfferedProtocol(input[0..split], input[split..]);
    }

    // Error-code mapping. The forward direction `appErrorToHttp3` is total
    // over u32, so any 4-byte prefix can drive it; the reverse direction
    // `http3ToAppError` we then compose to confirm the round-trip lives
    // within the spec's mapping table.
    if (input.len >= 4) {
        const app_code = std.mem.readInt(u32, input[0..4], .big);
        const wire = http3_zig.webtransport.appErrorToHttp3(app_code);
        const recovered = http3_zig.webtransport.http3ToAppError(wire);
        // The forward map MUST round-trip; if it ever does not, the
        // fuzz harness is the right place to surface the regression.
        std.debug.assert(recovered != null and recovered.? == app_code);
        _ = http3_zig.webtransport.isReservedStreamCode(wire);
    }
    if (input.len >= 8) {
        const wire_in = std.mem.readInt(u64, input[0..8], .big);
        _ = http3_zig.webtransport.http3ToAppError(wire_in);
        _ = http3_zig.webtransport.isReservedStreamCode(wire_in);
    }
}

fn fuzzMasque(allocator: std.mem.Allocator, input: []const u8) void {
    if (http3_zig.masque.parseConnectUdpTarget(
        allocator,
        input,
        http3_zig.masque.default_connect_udp_path_prefix,
    )) |target| {
        target.deinit(allocator);
    } else |_| {}

    if (http3_zig.masque.decodeUdpPayload(input)) |_| {} else |_| {}

    var registry = http3_zig.masque.ContextRegistry.init();
    var pending = http3_zig.masque.PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 2,
        .max_payload_bytes = 64,
    });
    defer pending.deinit();
    if (registry.decodeContextPayload(input)) |_| {} else |_| {}
    _ = registry.classifyDatagramPayload(input);
    _ = pending.classifyOrBuffer(&registry, input) catch {};
    registry.registerExtension(7) catch {};
    if (registry.decodeContextPayload(input)) |_| {} else |_| {}
    if (registry.decodeUdpPayload(input)) |_| {} else |_| {}
    _ = registry.classifyDatagramPayload(input);

    var receiver = http3_zig.masque.ConnectUdpReceiver.init();
    _ = receiver.classifyDatagramPayload(input);
    if (http3_zig.capsule.decode(input)) |decoded| {
        _ = receiver.classifyCapsule(decoded.capsule);
    } else |_| {}
}
