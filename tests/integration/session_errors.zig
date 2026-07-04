const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
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

test "session rejects duplicate peer SETTINGS" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .settings = .{} });

    try expectPairH3Error(allocator, &pair, error.DuplicateSettings);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    // RFC 9114 §7.2.4 ¶3: a second SETTINGS frame is H3_FRAME_UNEXPECTED.
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
}

test "session rejects DATA on control streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{ .data = "bad-control-data" });
    try expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
}

test "sending GOAWAY drives quic-zig transport-level graceful shutdown" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    try std.testing.expect(!pair.server.gracefulShutdownActive());

    // Server GOAWAY(0): stop processing new requests. This must engage the
    // transport-level graceful shutdown, not just the H3-layer draining flag.
    try pair.server_h3.sendGoaway(0);

    try std.testing.expect(pair.server.gracefulShutdownActive());
    // New local stream opens are now refused at the transport with
    // ShuttingDown (MAX_STREAMS credit is also withheld from the peer).
    try std.testing.expectError(error.ShuttingDown, pair.server.openNextUni());
    try std.testing.expectError(error.ShuttingDown, pair.server.openNextBidi());
}

test "session rejects an oversized HEADERS declared length before buffering the payload [DoS]" {
    const allocator = std.testing.allocator;

    // Server enforces a 64 KiB field-section cap. Pre-0.4-hardening this cap
    // only fired AFTER the whole HEADERS payload was reassembled, so a peer
    // could pin up to the QUIC stream window in rx first. The cap must now be
    // enforced on the DECLARED length, before any payload arrives.
    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{ .max_field_section_size = 65536 });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    // Raw frame header only: HEADERS type + a declared length far above the
    // cap, and NO payload bytes at all. Early rejection must still fire.
    try writeVarint(&pair.client, stream_id, http3_zig.protocol.FrameType.headers);
    try writeVarint(&pair.client, stream_id, 200_000);

    try expectPairH3Error(allocator, &pair, error.HeaderSectionTooLarge);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.message_error);
}

test "session rejects an oversized non-DATA frame via max_incoming_frame_length [DoS]" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{ .max_incoming_frame_length = 131072 });
    defer pair.deinit();
    try exchangePairSettings(allocator, &pair);

    // A GREASE/unknown frame type (0x1f*0 + 0x21) on the peer control stream,
    // declaring a length above the general non-DATA cap. Unknown control
    // frames are normally ignored, but the size cap fires on the declared
    // length before the frame is processed.
    const control = pair.client_h3.control_stream_id.?;
    try writeVarint(&pair.client, control, 0x21);
    try writeVarint(&pair.client, control, 200_000);

    try expectPairH3Error(allocator, &pair, error.FrameTooLong);
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.excess_load);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.frame_unexpected);
}

test "session closes on invalid peer GOAWAY ids" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 1 });
    try expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, http3_zig.protocol.ErrorCode.id_error);
}

test "session closes on increasing peer GOAWAY ids" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 4 });
    try writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{ .goaway = 8 });
    try expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try expectLastCloseCode(&pair.client_h3, http3_zig.protocol.ErrorCode.id_error);
}

test "session rejects duplicate peer control streams" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try openUniWithType(&pair.client, 6, http3_zig.protocol.StreamType.control);
    try expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.stream_creation_error);
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

    try openUniWithType(&pair.client, 14, http3_zig.protocol.StreamType.qpack_encoder);
    try expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.stream_creation_error);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.qpack_decompression_failed);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.qpack_decompression_failed);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.qpack_decoder_stream_error);
}

test "session rejects push streams sent to servers" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try openUniWithType(&pair.client, 6, http3_zig.protocol.StreamType.push);
    try expectPairH3Error(allocator, &pair, error.UnexpectedStream);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.stream_creation_error);
}

test "session surfaces quic_zig flow blocked events" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    pair.client.peer_max_streams_bidi = 0;

    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try std.testing.expectError(error.StreamLimitExceeded, pair.client_h3.openRequest(&fields));

    var events: std.ArrayList(http3_zig.session.Event) = .empty;
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
                try std.testing.expectEqual(http3_zig.FlowBlockedSource.local, blocked.source);
                try std.testing.expectEqual(http3_zig.FlowBlockedKind.streams, blocked.kind);
                try std.testing.expectEqual(@as(u64, 0), blocked.limit);
                try std.testing.expectEqual(@as(?bool, true), blocked.bidi);
                try std.testing.expectEqual(@as(?u64, null), blocked.stream_id);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_flow_blocked);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.settings_error);
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
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.datagram_error);
}

test "session closes when peer control stream is closed" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try pair.client.streamFinish(pair.client_h3.control_stream_id.?);

    try expectPairH3Error(allocator, &pair, error.ClosedCriticalStream);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.closed_critical_stream);
}

test "session rejects malformed request pseudo headers" {
    const allocator = std.testing.allocator;

    var pair: H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    const bad_fields = [_]http3_zig.FieldLine{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &bad_fields);

    try expectPairH3Error(allocator, &pair, error.PseudoHeaderAfterRegular);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.message_error);
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
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var block: [512]u8 = undefined;
    const block_n = try http3_zig.qpack.encodeFieldSection(&block, &fields);
    try std.testing.expect(block_n > 4);
    try writeFrame(&pair.client, stream_id, .{ .headers = block[0..block_n] });

    try expectPairH3Error(allocator, &pair, error.HeaderSectionTooLarge);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.message_error);
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
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try writeHeadersFrame(&pair.client, stream_id, &fields);

    try expectPairH3Error(allocator, &pair, error.TooManyFieldLines);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try expectLastCloseCode(&pair.server_h3, http3_zig.protocol.ErrorCode.message_error);
}
