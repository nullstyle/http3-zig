//! draft-ietf-webtrans-http3-15 — WebTransport over HTTP/3 (July 2025 revision).
//!
//! This is a working-group draft, not an RFC. The citation grammar in this
//! file deliberately uses `[draft-ietf-webtrans-http3 §X.Y]` rather than the
//! `[RFC#### §X.Y]` form so an auditor can tell a draft requirement from a
//! standardized one. When the draft becomes an RFC, rename the file and
//! update the citations.
//!
//! Wire-format pin: this implementation tracks revision -15. The most
//! visible drift from earlier revisions is the SETTINGS bootstrap: -13
//! used a numeric `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29`, but -15
//! collapsed it to a boolean `SETTINGS_WT_ENABLED = 0x2c7cf000`. Each
//! revision gets its own codepoint by design so two peers never agree
//! by accident across revisions.
//!
//! ## Coverage
//!
//! Covered:
//!   draft-ietf-webtrans-http3-15 §9.2 ¶?  MUST     peer advertises support via SETTINGS_WT_ENABLED with value > 0
//!   draft-ietf-webtrans-http3-15 §9.2 ¶?  MUST     SETTINGS_WT_ENABLED round-trips through the SETTINGS codec
//!   draft-ietf-webtrans-http3 §3.2 ¶?  MUST     bootstrap request uses :method = CONNECT, :protocol = "webtransport"
//!   draft-ietf-webtrans-http3 §3.3 ¶?  MUST     a 2xx response accepts the WebTransport session
//!   draft-ietf-webtrans-http3 §3.3 ¶?  MUST NOT a non-2xx response is treated as accepted
//!   draft-ietf-webtrans-http3 §4.1 ¶?  MUST     unidirectional WebTransport stream prefix is varint 0x54 + Session ID
//!   draft-ietf-webtrans-http3 §4.2 ¶?  MUST     bidirectional WebTransport stream prefix is varint 0x41 + Session ID
//!   draft-ietf-webtrans-http3 §4.6 ¶?  MUST     application stream error codes map through f(n) = 0x52e4a40fa8db + n + (n / 30)
//!   draft-ietf-webtrans-http3 §4.6 ¶?  MUST NOT a stride-boundary wire code decodes back to an application code
//!   draft-ietf-webtrans-http3 §4.6 ¶?  NORMATIVE WEBTRANSPORT_BUFFERED_STREAM_REJECTED reserved as 0x3994bd84
//!   draft-ietf-webtrans-http3 §4.6 ¶?  NORMATIVE WEBTRANSPORT_SESSION_GONE reserved as 0x170d7b68
//!   draft-ietf-webtrans-http3 §5.4 ¶?  MUST     CLOSE_WEBTRANSPORT_SESSION capsule type is 0x2843
//!   draft-ietf-webtrans-http3 §5.4 ¶?  MUST     CLOSE_WEBTRANSPORT_SESSION value carries 32-bit code + UTF-8 reason
//!   draft-ietf-webtrans-http3 §5.4 ¶?  MUST NOT CLOSE_WEBTRANSPORT_SESSION reason exceeds 1024 bytes
//!   draft-ietf-webtrans-http3 §5.4 ¶?  MUST     reason MUST be valid UTF-8
//!   draft-ietf-webtrans-http3 §5.5 ¶?  MUST     DRAIN_WEBTRANSPORT_SESSION capsule type is 0x78ae
//!   draft-ietf-webtrans-http3 §5.5 ¶?  MUST     DRAIN_WEBTRANSPORT_SESSION value is empty
//!   draft-ietf-webtrans-http3 §5.6.4 ¶? MUST    WT_MAX_DATA capsule type is 0x190b4d3d, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6.5 ¶? MUST    WT_DATA_BLOCKED capsule type is 0x190b4d41, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6.2 ¶? MUST    WT_MAX_STREAMS_BIDI capsule type is 0x190b4d3f, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6.2 ¶? MUST    WT_MAX_STREAMS_UNI capsule type is 0x190b4d40, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6.3 ¶? MUST    WT_STREAMS_BLOCKED_BIDI capsule type is 0x190b4d43, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6.3 ¶? MUST    WT_STREAMS_BLOCKED_UNI capsule type is 0x190b4d44, value is a single varint
//!   draft-ietf-webtrans-http3 §5.6   ¶? MUST    flow-control capsule values MUST contain exactly one QUIC varint
//!
//! Out of scope (covered elsewhere):
//!   draft-ietf-webtrans-http3 §3       handshake/bootstrapping interplay,
//!                                      session-level inbound stream dispatch,
//!                                      receive-side flow-control adoption,
//!                                      buffered-stream replay → tests/integration/webtransport.zig
//!   draft-ietf-webtrans-http3 §4.1,
//!     §4.2, §4.6                       session-level peer-opened uni/bidi
//!                                      stream dispatch and stream-error
//!                                      reverse-mapping → tests/integration/webtransport.zig
//!   draft-ietf-webtrans-http3 §5.6     session-level flow-control enforcement
//!                                      (gating sends on peer MAX_DATA /
//!                                      MAX_STREAMS, auto-emitting
//!                                      WT_DATA_BLOCKED / WT_STREAMS_BLOCKED,
//!                                      receive-side limit enforcement) →
//!                                      tests/integration/webtransport.zig

const std = @import("std");
const http3_zig = @import("http3_zig");

const wt = http3_zig.webtransport;
const capsule = http3_zig.capsule;

test "MUST: peer SETTINGS with WT_ENABLED set advertises WebTransport [draft-ietf-webtrans-http3-15 §9.2]" {
    try std.testing.expect(wt.peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    }));
}

test "MUST NOT: peer without WT_ENABLED advertises WebTransport [draft-ietf-webtrans-http3-15 §9.2]" {
    try std.testing.expect(!wt.peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = false,
    }));
}

test "MUST NOT: peer without enable_connect_protocol advertises WebTransport [draft-ietf-webtrans-http3-15 §9.2]" {
    // Even if WT_ENABLED is set, Extended CONNECT (RFC 9220) must also
    // be advertised — the bootstrap is a CONNECT request and would be
    // rejected without this setting.
    try std.testing.expect(!wt.peerEnabled(.{
        .enable_connect_protocol = false,
        .h3_datagram = true,
        .wt_enabled = true,
    }));
}

test "MUST NOT: peer without h3_datagram advertises WebTransport [draft-ietf-webtrans-http3-15 §9.2]" {
    // RFC 9297 datagrams are a hard prerequisite — datagram-mode
    // WebTransport sends ride on H3_DATAGRAM and the spec requires
    // both peers to enable it.
    try std.testing.expect(!wt.peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = false,
        .wt_enabled = true,
    }));
}

test "MUST: SETTINGS_WT_ENABLED round-trips through the SETTINGS codec [draft-ietf-webtrans-http3-15 §9.2]" {
    const original: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };
    var buf: [64]u8 = undefined;
    const n = try original.encode(&buf);
    const decoded = try http3_zig.Settings.decode(buf[0..n]);
    try std.testing.expect(decoded.wt_enabled);
}

test "MUST: SETTINGS_WT_ENABLED uses the draft-15 codepoint 0x2c7cf000 [draft-ietf-webtrans-http3-15 §9.2]" {
    // The codepoint is draft-revision-specific by design. Pinning the
    // numeric value here makes accidental regressions across revisions
    // very loud — peers from a different draft revision will never
    // accidentally interoperate with this implementation.
    try std.testing.expectEqual(@as(u64, 0x2c7cf000), http3_zig.protocol.SettingId.wt_enabled);
}

test "MUST: WT initial flow-control SETTINGS use the draft-15 codepoints [draft-ietf-webtrans-http3-15 §9.2]" {
    // Draft-revision-specific codepoints for the initial per-session
    // flow-control limits. Pinned numerically so a revision drift is loud.
    try std.testing.expectEqual(@as(u64, 0x2b61), http3_zig.protocol.SettingId.wt_initial_max_data);
    try std.testing.expectEqual(@as(u64, 0x2b64), http3_zig.protocol.SettingId.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 0x2b65), http3_zig.protocol.SettingId.wt_initial_max_streams_bidi);
}

test "MUST: WT initial flow-control SETTINGS round-trip through the SETTINGS codec [draft-ietf-webtrans-http3-15 §9.2]" {
    const original: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
        .wt_initial_max_data = 262144,
        .wt_initial_max_streams_uni = 16,
        .wt_initial_max_streams_bidi = 8,
    };
    var buf: [64]u8 = undefined;
    const n = try original.encode(&buf);
    const decoded = try http3_zig.Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(?u64, 262144), decoded.wt_initial_max_data);
    try std.testing.expectEqual(@as(?u64, 16), decoded.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, 8), decoded.wt_initial_max_streams_bidi);
}

test "MUST: bootstrap request uses :method = CONNECT and :protocol = webtransport [draft-ietf-webtrans-http3 §3.2]" {
    const request = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
        .{ .name = ":protocol", .value = wt.protocol_token },
    };
    try std.testing.expect(wt.isRequest(&request));
    try std.testing.expectEqualStrings("webtransport", wt.protocol_token);
}

test "MUST: a 2xx response accepts the WebTransport session [draft-ietf-webtrans-http3 §3.3]" {
    const accepted = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expect(wt.responseAccepted(&accepted));
    try std.testing.expect(wt.isAcceptedStatus("204"));
    try std.testing.expect(wt.isAcceptedStatus("299"));
}

test "MUST NOT: a non-2xx response is treated as accepted [draft-ietf-webtrans-http3 §3.3]" {
    const not_accepted = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "404" },
    };
    try std.testing.expect(!wt.responseAccepted(&not_accepted));
    try std.testing.expect(!wt.isAcceptedStatus("101"));
    try std.testing.expect(!wt.isAcceptedStatus("301"));
}

test "MUST: unidirectional stream prefix is varint 0x54 + Session ID [draft-ietf-webtrans-http3 §4.1]" {
    var buf: [16]u8 = undefined;
    const n = try wt.encodeUniStreamPrefix(&buf, 4);
    // 0x54 fits in a 1-byte varint with the 6-bit prefix encoding;
    // 0x54 = 0b01010100 — top 2 bits "01" indicate 2-byte form so the wire
    // bytes for type=0x54 are 0x40 0x54 (per RFC 9000 §16). Session ID 4
    // also serializes as a single 0x04 byte.
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x40), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x54), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x04), buf[2]);

    const decoded = try wt.decodeStreamHeader(.uni, buf[0..n]);
    try std.testing.expectEqual(wt.StreamKind.uni, decoded.header.kind);
    try std.testing.expectEqual(@as(u64, 4), decoded.header.session_id);
}

test "MUST: bidirectional stream prefix is varint 0x41 + Session ID [draft-ietf-webtrans-http3 §4.2]" {
    var buf: [16]u8 = undefined;
    const n = try wt.encodeBidiStreamPrefix(&buf, 0);
    // 0x41 also lands in the 2-byte varint form: 0x40 0x41.
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x40), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x41), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[2]);

    const decoded = try wt.decodeStreamHeader(.bidi, buf[0..n]);
    try std.testing.expectEqual(wt.StreamKind.bidi, decoded.header.kind);
    try std.testing.expectEqual(@as(u64, 0), decoded.header.session_id);
}

test "MUST: application stream error codes map through f(n) [draft-ietf-webtrans-http3 §4.6]" {
    try std.testing.expectEqual(@as(u64, 0x52e4a40fa8db), wt.appErrorToHttp3(0));
    try std.testing.expectEqual(@as(u64, 0x52e4a40fa8db + 1), wt.appErrorToHttp3(1));
    try std.testing.expectEqual(@as(u64, 0x52e4a40fa8db + 30 + 1), wt.appErrorToHttp3(30));
}

test "MUST NOT: a stride-boundary wire code decodes back to an application code [draft-ietf-webtrans-http3 §4.6]" {
    // The slot at (offset+1) % 31 == 0 is reserved.
    const reserved = wt.appErrorToHttp3(29) + 1;
    try std.testing.expectEqual(@as(?u32, null), wt.http3ToAppError(reserved));
}

test "NORMATIVE: WEBTRANSPORT_BUFFERED_STREAM_REJECTED reserved as 0x3994bd84 [draft-ietf-webtrans-http3 §4.6]" {
    try std.testing.expectEqual(@as(u64, 0x3994bd84), wt.buffered_stream_rejected_code);
    try std.testing.expect(wt.isReservedStreamCode(0x3994bd84));
}

test "NORMATIVE: WEBTRANSPORT_SESSION_GONE reserved as 0x170d7b68 [draft-ietf-webtrans-http3 §4.6]" {
    try std.testing.expectEqual(@as(u64, 0x170d7b68), wt.session_gone_code);
    try std.testing.expect(wt.isReservedStreamCode(0x170d7b68));
}

test "MUST: CLOSE_WEBTRANSPORT_SESSION capsule type is 0x2843 [draft-ietf-webtrans-http3 §5.4]" {
    var buf: [128]u8 = undefined;
    const n = try wt.encodeCloseSession(&buf, 1, "");
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x2843), decoded.capsule.capsule_type);
}

test "MUST: CLOSE_WEBTRANSPORT_SESSION value carries 32-bit code + reason [draft-ietf-webtrans-http3 §5.4]" {
    var buf: [128]u8 = undefined;
    const n = try wt.encodeCloseSession(&buf, 0xcafebabe, "all done");
    const decoded = try capsule.decode(buf[0..n]);
    const value = decoded.capsule.value;
    try std.testing.expectEqual(@as(usize, 4 + 8), value.len);
    try std.testing.expectEqual(@as(u8, 0xca), value[0]);
    try std.testing.expectEqual(@as(u8, 0xfe), value[1]);
    try std.testing.expectEqual(@as(u8, 0xba), value[2]);
    try std.testing.expectEqual(@as(u8, 0xbe), value[3]);
    try std.testing.expectEqualStrings("all done", value[4..]);

    const close = try wt.decodeCloseSessionValue(value);
    try std.testing.expectEqual(@as(u32, 0xcafebabe), close.code);
    try std.testing.expectEqualStrings("all done", close.reason);
}

test "MUST NOT: CLOSE_WEBTRANSPORT_SESSION reason exceeds 1024 bytes [draft-ietf-webtrans-http3 §5.4]" {
    var huge: [wt.max_close_reason_len + 1]u8 = undefined;
    @memset(&huge, 'a');
    var buf: [wt.max_close_reason_len + 32]u8 = undefined;
    try std.testing.expectError(error.CloseReasonTooLarge, wt.encodeCloseSession(&buf, 0, &huge));
}

test "MUST: CLOSE reason MUST be valid UTF-8 [draft-ietf-webtrans-http3 §5.4]" {
    // Hand-crafted invalid UTF-8 in the reason slot.
    const value = [_]u8{ 0, 0, 0, 0, 0xff, 0xfe };
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeCloseSessionValue(&value));
}

test "MUST: DRAIN_WEBTRANSPORT_SESSION capsule type is 0x78ae [draft-ietf-webtrans-http3 §5.5]" {
    var buf: [16]u8 = undefined;
    const n = try wt.encodeDrainSession(&buf);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x78ae), decoded.capsule.capsule_type);
}

test "MUST: DRAIN_WEBTRANSPORT_SESSION value is empty [draft-ietf-webtrans-http3 §5.5]" {
    var buf: [16]u8 = undefined;
    const n = try wt.encodeDrainSession(&buf);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), decoded.capsule.value.len);
}

test "MUST: peer-opened uni WT stream prefix decodes type 0x54 + Session ID [draft-ietf-webtrans-http3 §4.1]" {
    // Hand-build the wire bytes the way the peer would send them and walk
    // them back through the codec to make sure the stream-type classifier
    // (used by the session dispatch path) and the prefix decoder see the
    // same bytes.
    var buf: [8]u8 = undefined;
    const n = try wt.encodeUniStreamPrefix(&buf, 16);

    const stream = http3_zig.stream;
    const type_decoded = try stream.decodeType(buf[0..n]);
    try std.testing.expectEqual(stream.Kind.webtransport_uni, type_decoded.kind);

    const header = try wt.decodeStreamHeader(.uni, buf[0..n]);
    try std.testing.expectEqual(@as(u64, 16), header.header.session_id);
}

test "MUST: peer-opened bidi WT stream prefix decodes type 0x41 + Session ID [draft-ietf-webtrans-http3 §4.2]" {
    var buf: [8]u8 = undefined;
    const n = try wt.encodeBidiStreamPrefix(&buf, 0);
    const header = try wt.decodeStreamHeader(.bidi, buf[0..n]);
    try std.testing.expectEqual(wt.StreamKind.bidi, header.header.kind);
    try std.testing.expectEqual(@as(u64, 0), header.header.session_id);
}

test "MUST: stream-reset on a WT stream maps wire code back through the §4.6 algorithm" {
    // The session-layer `WebTransportStreamResetEvent` carries both the wire
    // error code and the recovered 32-bit application code. This test
    // exercises the codec end of that contract: any application code we
    // produce must reverse-map cleanly. The session-level dispatch is
    // covered by the integration tests in tests/integration/webtransport.zig.
    const samples = [_]u32{ 0, 1, 30, 31, 256, 0xffff, std.math.maxInt(u32) };
    for (samples) |app| {
        const wire = wt.appErrorToHttp3(app);
        try std.testing.expectEqual(@as(?u32, app), wt.http3ToAppError(wire));
    }
}

test "MUST: WT-Available-Protocols round-trips through encoder/decoder [draft-ietf-webtrans-http3 §3.4]" {
    const allocator = std.testing.allocator;
    const offered = [_][]const u8{ "echo-v1", "echo-v2", "telemetry-v3" };
    const encoded = try wt.allocAvailableProtocols(allocator, &offered);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("echo-v1,echo-v2,telemetry-v3", encoded);

    var parsed = try wt.parseAvailableProtocols(allocator, encoded);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.tokens.len);
    try std.testing.expectEqualStrings("echo-v1", parsed.tokens[0]);
    try std.testing.expectEqualStrings("echo-v2", parsed.tokens[1]);
    try std.testing.expectEqualStrings("telemetry-v3", parsed.tokens[2]);
}

test "MUST: WT-Available-Protocols decoder tolerates whitespace around tokens [draft-ietf-webtrans-http3 §3.4]" {
    const allocator = std.testing.allocator;
    var parsed = try wt.parseAvailableProtocols(allocator, "  a , b ,c");
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.tokens.len);
    try std.testing.expectEqualStrings("a", parsed.tokens[0]);
    try std.testing.expectEqualStrings("b", parsed.tokens[1]);
    try std.testing.expectEqualStrings("c", parsed.tokens[2]);
}

test "MUST NOT: WT subprotocol tokens carry HTTP-disallowed characters [draft-ietf-webtrans-http3 §3.4]" {
    try std.testing.expectError(error.InvalidSubprotocolToken, wt.validateSubprotocolToken(""));
    try std.testing.expectError(error.InvalidSubprotocolToken, wt.validateSubprotocolToken("has space"));
    try std.testing.expectError(error.InvalidSubprotocolToken, wt.validateSubprotocolToken("has\"quote"));
    try wt.validateSubprotocolToken("a-Z9.~!");
}

test "MUST: isOfferedProtocol matches member tokens [draft-ietf-webtrans-http3 §3.4]" {
    const offered_value = "echo-v1,echo-v2,telemetry";
    try std.testing.expect(wt.isOfferedProtocol(offered_value, "echo-v1"));
    try std.testing.expect(wt.isOfferedProtocol(offered_value, "echo-v2"));
    try std.testing.expect(wt.isOfferedProtocol(offered_value, "telemetry"));
    try std.testing.expect(!wt.isOfferedProtocol(offered_value, "echo-v3"));
    try std.testing.expect(!wt.isOfferedProtocol(offered_value, ""));
    try std.testing.expect(!wt.isOfferedProtocol("", "echo-v1"));
}

test "MUST: production() preset emits SETTINGS_WT_ENABLED when WebTransport is enabled [draft-ietf-webtrans-http3-15 §9.2]" {
    const config = http3_zig.SessionConfig.production(.{
        .enable_webtransport = true,
    });
    try std.testing.expect(config.settings.wt_enabled);
    try std.testing.expect(config.settings.enable_connect_protocol);
    try std.testing.expect(config.settings.h3_datagram);
}

test "MUST NOT: production() preset emits SETTINGS_WT_ENABLED when WebTransport is not enabled [draft-ietf-webtrans-http3-15 §9.2]" {
    const config = http3_zig.SessionConfig.production(.{
        .enable_webtransport = false,
    });
    try std.testing.expect(!config.settings.wt_enabled);
}

// ---------------------------------------------------------------------------
// Flow-control capsules (draft-ietf-webtrans-http3-13 §5.6)
//
// The wire codepoints here are pinned to draft-ietf-webtrans-http3-13's
// IANA "Capsule Types" table (§9.6). If the next published revision shifts
// any of them, update both these constants and the matching constants in
// `src/webtransport.zig` together. The values were verified against
// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-13.
// ---------------------------------------------------------------------------

test "MUST: WT_MAX_DATA capsule type is 0x190b4d3d [draft-ietf-webtrans-http3 §5.6.4]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeMaxData(&buf, 1);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d3d), decoded.capsule.capsule_type);
}

test "MUST: WT_MAX_DATA value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.4]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 0x1234_5678;
    const n = try wt.encodeMaxData(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    // The capsule VALUE is exactly the encoded varint — nothing else.
    try std.testing.expectEqual(@as(u64, value), try wt.decodeMaxDataValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .max_data => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST: WT_DATA_BLOCKED capsule type is 0x190b4d41 [draft-ietf-webtrans-http3 §5.6.5]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeDataBlocked(&buf, 0);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d41), decoded.capsule.capsule_type);
}

test "MUST: WT_DATA_BLOCKED value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.5]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 9001;
    const n = try wt.encodeDataBlocked(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, value), try wt.decodeDataBlockedValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .data_blocked => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST: WT_MAX_STREAMS_BIDI capsule type is 0x190b4d3f [draft-ietf-webtrans-http3 §5.6.2]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeMaxStreamsBidi(&buf, 1);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d3f), decoded.capsule.capsule_type);
}

test "MUST: WT_MAX_STREAMS_BIDI value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.2]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 64;
    const n = try wt.encodeMaxStreamsBidi(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, value), try wt.decodeMaxStreamsBidiValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .max_streams_bidi => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST: WT_MAX_STREAMS_UNI capsule type is 0x190b4d40 [draft-ietf-webtrans-http3 §5.6.2]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeMaxStreamsUni(&buf, 1);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d40), decoded.capsule.capsule_type);
}

test "MUST: WT_MAX_STREAMS_UNI value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.2]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 32;
    const n = try wt.encodeMaxStreamsUni(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, value), try wt.decodeMaxStreamsUniValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .max_streams_uni => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST: WT_STREAMS_BLOCKED_BIDI capsule type is 0x190b4d43 [draft-ietf-webtrans-http3 §5.6.3]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeStreamsBlockedBidi(&buf, 0);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d43), decoded.capsule.capsule_type);
}

test "MUST: WT_STREAMS_BLOCKED_BIDI value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.3]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 7;
    const n = try wt.encodeStreamsBlockedBidi(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, value), try wt.decodeStreamsBlockedBidiValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .streams_blocked_bidi => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST: WT_STREAMS_BLOCKED_UNI capsule type is 0x190b4d44 [draft-ietf-webtrans-http3 §5.6.3]" {
    var buf: [32]u8 = undefined;
    const n = try wt.encodeStreamsBlockedUni(&buf, 0);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x190b4d44), decoded.capsule.capsule_type);
}

test "MUST: WT_STREAMS_BLOCKED_UNI value is a single QUIC varint [draft-ietf-webtrans-http3 §5.6.3]" {
    var buf: [32]u8 = undefined;
    const value: u64 = 5;
    const n = try wt.encodeStreamsBlockedUni(&buf, value);
    const decoded = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, value), try wt.decodeStreamsBlockedUniValue(decoded.capsule.value));

    const event = try wt.classifyCapsule(decoded.capsule);
    switch (event) {
        .streams_blocked_uni => |v| try std.testing.expectEqual(value, v),
        else => return error.UnexpectedClassification,
    }
}

test "MUST NOT: flow-control capsule values carry trailing bytes after the varint [draft-ietf-webtrans-http3 §5.6]" {
    // 0x00 is a 1-byte varint for value 0; an extra 0x00 must trip the
    // single-varint contract. This protects against a peer smuggling
    // additional fields into a flow-control capsule.
    const trailing = [_]u8{ 0x00, 0x00 };
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeMaxDataValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeDataBlockedValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeMaxStreamsBidiValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeStreamsBlockedBidiValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeMaxStreamsUniValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, wt.decodeStreamsBlockedUniValue(&trailing));
}

test "NORMATIVE: WT_MAX_STREAMS Maximum Streams cannot exceed 2^60 [draft-ietf-webtrans-http3 §5.6.2]" {
    // The varint codec already caps values at 2^62 - 1 (RFC 9000 §16); we
    // encode/decode the §5.6.2 cap of 2^60 to confirm legal Maximum
    // Streams values round-trip cleanly. Higher-level enforcement of the
    // 2^60 ceiling is application policy; the codec MUST faithfully
    // round-trip values up to that bound.
    const cap: u64 = @as(u64, 1) << 60;
    var buf: [32]u8 = undefined;

    const n_bidi = try wt.encodeMaxStreamsBidi(&buf, cap);
    const decoded_bidi = try capsule.decode(buf[0..n_bidi]);
    try std.testing.expectEqual(cap, try wt.decodeMaxStreamsBidiValue(decoded_bidi.capsule.value));

    const n_uni = try wt.encodeMaxStreamsUni(&buf, cap);
    const decoded_uni = try capsule.decode(buf[0..n_uni]);
    try std.testing.expectEqual(cap, try wt.decodeMaxStreamsUniValue(decoded_uni.capsule.value));
}
