//! RFC 9114 §7.2.4 — SETTINGS frame payload codec.
//!
//! The SETTINGS frame is a sequence of `(identifier, value)` pairs,
//! each member encoded as a QUIC variable-length integer (RFC 9000
//! §16). Identifiers are drawn from the §7.2.4.1 / §11.2.2 registry,
//! and parsing rules in §7.2.4 ¶5 require that a duplicate identifier
//! be treated as H3_SETTINGS_ERROR. Identifiers in the HTTP/2
//! reservation set (§7.2.4.1 ¶8) MUST NOT be sent and MUST be rejected
//! when received. nullq surfaces the codec as `null3.settings.Settings`.
//!
//! Cross-reference: RFC 9220 §3 (`SETTINGS_ENABLE_CONNECT_PROTOCOL`)
//! and RFC 9297 §2.1 (`SETTINGS_H3_DATAGRAM`) define their own
//! identifiers that share this codec; their boolean-domain rules are
//! exercised at the wire layer here, while their semantic effect lives
//! in higher-layer suites.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §7.2.4   ¶1   MUST     SETTINGS payload is a sequence of varint pairs
//!   RFC9114 §7.2.4   ¶3   NORMATIVE encoder emits each (id, value) pair using minimum varint form
//!   RFC9114 §7.2.4   ¶5   MUST     reject a SETTINGS payload that repeats the same identifier
//!   RFC9114 §7.2.4.1 ¶8   MUST NOT honour HTTP/2 reserved SETTINGS IDs (0x00, 0x02–0x05)
//!   RFC9114 §7.2.4.1 ¶7   NORMATIVE ignore unknown / GREASE setting identifiers on receive
//!   RFC9114 §7.2.4   ¶?   NORMATIVE QPACK_MAX_TABLE_CAPACITY default value is 0
//!   RFC9114 §7.2.4   ¶?   NORMATIVE QPACK_BLOCKED_STREAMS default value is 0
//!   RFC9114 §7.2.4.1 ¶3   NORMATIVE MAX_FIELD_SECTION_SIZE absent ⇒ unlimited (encoded as null)
//!   RFC9220 §3       ¶3   MUST     ENABLE_CONNECT_PROTOCOL value MUST be 0 or 1; reject 2+
//!   RFC9297 §2.1     ¶2   MUST     H3_DATAGRAM value MUST be 0 or 1; reject 2+
//!   RFC9114 §7.2.4   ¶3   NORMATIVE encode/decode round-trips a non-zero value for every defined ID
//!   RFC9114 §7.2.4   ¶3   NORMATIVE encoder emits exactly the `encodedLen` byte count
//!   RFC9114 §7.2.4   ¶1   MUST NOT accept a SETTINGS payload truncated mid-pair
//!
//! Visible debt:
//!   RFC9114 §7.2.4.1 ¶8   MUST NOT serialise a reserved-HTTP/2 setting on the encoder side
//!     — the current `Settings` struct only stores defined IDs, so the
//!       encoder can't physically emit a reserved ID. See skip_ test below.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.4   ¶2   SETTINGS-handshake state machine (first frame on
//!                          control stream, peer-side rejection of late SETTINGS,
//!                          GOAWAY interaction)                       → rfc9114_session.zig
//!   RFC9114 §6.2.1   ¶2   SETTINGS uniqueness across the lifetime of the control
//!                          stream                                    → rfc9114_session.zig
//!   RFC9114 §7.2.4.1 ¶3   semantic enforcement of MAX_FIELD_SECTION_SIZE on receive
//!                          (HEADERS rejection)                       → rfc9114_messages.zig

const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");

const settings_mod = null3.settings;
const protocol = null3.protocol;
const varint = nullq.wire.varint;

// ---------------------------------------------------------------- §7.2.4 default values

test "NORMATIVE default value of SETTINGS_QPACK_MAX_TABLE_CAPACITY is 0 [RFC9114 §7.2.4 ¶3]" {
    // §7.2.4 ¶3: "Each parameter has a default value, which the
    // recipient SHOULD use if the SETTINGS frame is not received or
    // does not include that parameter." For QPACK_MAX_TABLE_CAPACITY,
    // RFC 9204 §5 fixes the default at 0 (encoder MUST NOT use the
    // dynamic table). nullq's struct default reflects that.
    const s: settings_mod.Settings = .{};
    try std.testing.expectEqual(@as(u64, 0), s.qpack_max_table_capacity);
}

test "NORMATIVE default value of SETTINGS_QPACK_BLOCKED_STREAMS is 0 [RFC9204 §5 ¶3]" {
    // RFC 9204 §5 ¶3: "QPACK_BLOCKED_STREAMS ... default 0." Encoder
    // MUST NOT cause a decoder to block when this default is in
    // effect.
    const s: settings_mod.Settings = .{};
    try std.testing.expectEqual(@as(u64, 0), s.qpack_blocked_streams);
}

test "NORMATIVE default of SETTINGS_MAX_FIELD_SECTION_SIZE is unlimited (absent on the wire) [RFC9114 §7.2.4.1 ¶3]" {
    // §7.2.4.1 ¶3: "SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): The
    // default value is unlimited." nullq encodes "unlimited" as a
    // missing entry (null optional in the struct), not as a sentinel
    // value, so the field is omitted from the wire.
    const s: settings_mod.Settings = .{};
    try std.testing.expectEqual(@as(?u64, null), s.max_field_section_size);

    // Encoder must not emit the identifier when the field is null.
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    // Decode the resulting payload and confirm 0x06 is not present.
    var pos: usize = 0;
    while (pos < n) {
        const id_d = try varint.decode(buf[pos..]);
        pos += id_d.bytes_read;
        const val_d = try varint.decode(buf[pos..]);
        pos += val_d.bytes_read;
        try std.testing.expect(id_d.value != protocol.SettingId.max_field_section_size);
    }
}

test "NORMATIVE default of SETTINGS_ENABLE_CONNECT_PROTOCOL is false (absent on the wire) [RFC9220 §3 ¶3]" {
    // RFC 9220 §3 ¶3: "If the value of ENABLE_CONNECT_PROTOCOL is set
    // to 1, the server MUST NOT reject an Extended CONNECT request
    // ... If the value is set to 0 or omitted, the server MUST close
    // the stream." Default is therefore 0/false; absent on the wire.
    const s: settings_mod.Settings = .{};
    try std.testing.expect(!s.enable_connect_protocol);

    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    var pos: usize = 0;
    while (pos < n) {
        const id_d = try varint.decode(buf[pos..]);
        pos += id_d.bytes_read;
        const val_d = try varint.decode(buf[pos..]);
        pos += val_d.bytes_read;
        try std.testing.expect(id_d.value != protocol.SettingId.enable_connect_protocol);
    }
}

test "NORMATIVE default of SETTINGS_H3_DATAGRAM is false (absent on the wire) [RFC9297 §2.1 ¶2]" {
    // RFC 9297 §2.1 ¶2: "An endpoint that has either sent or received
    // a SETTINGS_H3_DATAGRAM value of 1 ... A value of 0 indicates ..."
    // Default is therefore 0/false; absent on the wire.
    const s: settings_mod.Settings = .{};
    try std.testing.expect(!s.h3_datagram);

    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    var pos: usize = 0;
    while (pos < n) {
        const id_d = try varint.decode(buf[pos..]);
        pos += id_d.bytes_read;
        const val_d = try varint.decode(buf[pos..]);
        pos += val_d.bytes_read;
        try std.testing.expect(id_d.value != protocol.SettingId.h3_datagram);
    }
}

// ---------------------------------------------------------------- §7.2.4 wire format

test "MUST encode each SETTINGS entry as a varint identifier followed by a varint value [RFC9114 §7.2.4 ¶1]" {
    // §7.2.4 ¶1 / Figure 8: "Setting { Identifier (i), Value (i) }" —
    // both fields are QUIC variable-length integers.
    const s: settings_mod.Settings = .{
        .qpack_max_table_capacity = 4096,
    };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);

    // First pair must be the identifier (1 byte for 0x01) + value (2 bytes for 4096).
    const id_d = try varint.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, protocol.SettingId.qpack_max_table_capacity), id_d.value);
    const val_d = try varint.decode(buf[id_d.bytes_read..n]);
    try std.testing.expectEqual(@as(u64, 4096), val_d.value);

    // QPACK_BLOCKED_STREAMS is also emitted (default 0); confirm the
    // codec walks past the first pair to a second pair.
    try std.testing.expect(@as(usize, id_d.bytes_read) + val_d.bytes_read < n);
}

test "MUST report an `encodedLen` that matches the `encode` byte count [RFC9114 §7.2.4 ¶1]" {
    // The encode function must agree with `encodedLen` so callers can
    // size their buffers up front (the SETTINGS frame envelope needs
    // the payload length as a varint before encoding the payload).
    const s: settings_mod.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 16,
        .max_field_section_size = 65536,
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);
    try std.testing.expectEqual(s.encodedLen(), n);
}

// ---------------------------------------------------------------- §7.2.4.1 defined identifiers

test "MUST round-trip a non-zero SETTINGS_QPACK_MAX_TABLE_CAPACITY value [RFC9204 §5 ¶3]" {
    // RFC 9204 §5: setting carries the maximum QPACK dynamic table
    // size in bytes. Round-trip a non-default value.
    const s: settings_mod.Settings = .{ .qpack_max_table_capacity = 65535 };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 65535), got.qpack_max_table_capacity);
}

test "MUST round-trip a non-zero SETTINGS_QPACK_BLOCKED_STREAMS value [RFC9204 §5 ¶3]" {
    const s: settings_mod.Settings = .{ .qpack_blocked_streams = 100 };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 100), got.qpack_blocked_streams);
}

test "MUST round-trip a non-zero SETTINGS_MAX_FIELD_SECTION_SIZE value [RFC9114 §7.2.4.1 ¶3]" {
    // §7.2.4.1 ¶3 carries the maximum size of header sections in
    // bytes (RFC 9113 §6.5.2 semantics inherited).
    const s: settings_mod.Settings = .{ .max_field_section_size = 16384 };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(?u64, 16384), got.max_field_section_size);
}

test "MUST round-trip SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 as `true` [RFC9220 §3 ¶3]" {
    // RFC 9220 §3 ¶3: ENABLE_CONNECT_PROTOCOL=1 turns on Extended
    // CONNECT for HTTP/3.
    const s: settings_mod.Settings = .{ .enable_connect_protocol = true };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(got.enable_connect_protocol);
}

test "MUST round-trip SETTINGS_H3_DATAGRAM = 1 as `true` [RFC9297 §2.1 ¶2]" {
    // RFC 9297 §2.1 ¶2: H3_DATAGRAM=1 enables HTTP/3 Datagrams on the
    // connection.
    const s: settings_mod.Settings = .{ .h3_datagram = true };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(got.h3_datagram);
}

// ---------------------------------------------------------------- §7.2.4 ¶5 duplicate-identifier rule

test "MUST reject a SETTINGS payload that repeats the QPACK_MAX_TABLE_CAPACITY identifier [RFC9114 §7.2.4 ¶5]" {
    // §7.2.4 ¶5: "An implementation MUST ignore any parameter with an
    // identifier it does not understand. A SETTINGS frame MUST NOT
    // include the same identifier twice. Receipt of a duplicate
    // setting MUST be treated as a connection error of type
    // H3_SETTINGS_ERROR." nullq surfaces this as `DuplicateSetting`.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 4096);
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 8192);

    try std.testing.expectError(
        settings_mod.Error.DuplicateSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject a SETTINGS payload that repeats the QPACK_BLOCKED_STREAMS identifier [RFC9114 §7.2.4 ¶5]" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_blocked_streams);
    pos += try varint.encode(buf[pos..], 1);
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_blocked_streams);
    pos += try varint.encode(buf[pos..], 2);

    try std.testing.expectError(
        settings_mod.Error.DuplicateSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject a SETTINGS payload that repeats the MAX_FIELD_SECTION_SIZE identifier [RFC9114 §7.2.4 ¶5]" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.max_field_section_size);
    pos += try varint.encode(buf[pos..], 1024);
    pos += try varint.encode(buf[pos..], protocol.SettingId.max_field_section_size);
    pos += try varint.encode(buf[pos..], 2048);

    try std.testing.expectError(
        settings_mod.Error.DuplicateSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject a SETTINGS payload that repeats the ENABLE_CONNECT_PROTOCOL identifier [RFC9114 §7.2.4 ¶5]" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(buf[pos..], 1);
    pos += try varint.encode(buf[pos..], protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(buf[pos..], 1);

    try std.testing.expectError(
        settings_mod.Error.DuplicateSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject a SETTINGS payload that repeats the H3_DATAGRAM identifier [RFC9114 §7.2.4 ¶5]" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 1);
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 1);

    try std.testing.expectError(
        settings_mod.Error.DuplicateSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

// ---------------------------------------------------------------- §7.2.4.1 ¶8 reserved HTTP/2 IDs

test "MUST NOT accept a SETTINGS payload containing reserved HTTP/2 ID 0x02 [RFC9114 §7.2.4.1 ¶8]" {
    // §7.2.4.1 ¶8: "Setting identifiers that were defined in HTTP/2
    // where there is no corresponding HTTP/3 setting have also been
    // reserved (Section 11.2.2). These reserved settings MUST NOT be
    // sent, and their receipt MUST be treated as a connection error
    // of type H3_SETTINGS_ERROR." 0x02 = HTTP/2 SETTINGS_HEADER_TABLE_SIZE.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x02);
    pos += try varint.encode(buf[pos..], 0);

    try std.testing.expectError(
        settings_mod.Error.ReservedSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST NOT accept a SETTINGS payload containing reserved HTTP/2 ID 0x03 [RFC9114 §7.2.4.1 ¶8]" {
    // 0x03 = HTTP/2 SETTINGS_ENABLE_PUSH; reserved in HTTP/3 because
    // server push uses different mechanics (§7.2.5).
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x03);
    pos += try varint.encode(buf[pos..], 0);

    try std.testing.expectError(
        settings_mod.Error.ReservedSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST NOT accept a SETTINGS payload containing reserved HTTP/2 ID 0x04 [RFC9114 §7.2.4.1 ¶8]" {
    // 0x04 = HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x04);
    pos += try varint.encode(buf[pos..], 100);

    try std.testing.expectError(
        settings_mod.Error.ReservedSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST NOT accept a SETTINGS payload containing reserved HTTP/2 ID 0x05 [RFC9114 §7.2.4.1 ¶8]" {
    // 0x05 = HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x05);
    pos += try varint.encode(buf[pos..], 65535);

    try std.testing.expectError(
        settings_mod.Error.ReservedSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST NOT accept a SETTINGS payload containing reserved-zero ID 0x00 [RFC9114 §7.2.4.1 ¶8]" {
    // The codec groups 0x00 with the HTTP/2 reservation set so it is
    // rejected identically.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0);
    pos += try varint.encode(buf[pos..], 0);

    try std.testing.expectError(
        settings_mod.Error.ReservedSetting,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "skip_MUST NOT serialise a reserved HTTP/2 setting on the encoder side [RFC9114 §7.2.4.1 ¶8]" {
    // §7.2.4.1 ¶8 prohibits sending reserved IDs on the wire. The
    // current `Settings` struct only stores the IDs nullq defines
    // (0x01, 0x06, 0x07, 0x08, 0x33), so the encoder is *physically
    // incapable* of emitting a reserved ID — but there is no negative
    // test today for "I tried to emit one and was told no". Worth
    // adding once an unknown-ID raw passthrough lands on the encoder.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §7.2.4.1 ¶7 unknown / GREASE IDs

test "NORMATIVE ignore an unknown identifier on receive (GREASE-style tolerance) [RFC9114 §7.2.4.1 ¶7]" {
    // §7.2.4.1 ¶7: "Setting identifiers of the format `0x1f * N + 0x21`
    // ... are reserved to exercise the requirement that unknown
    // identifiers be ignored." More generally, §7.2.4 ¶5 requires
    // "An implementation MUST ignore any parameter with an identifier
    // it does not understand." nullq must skip the entry without
    // raising an error.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 4096);
    // Inject a GREASE identifier with N=1: 0x1f*1+0x21 = 0x40.
    pos += try varint.encode(buf[pos..], 0x40);
    pos += try varint.encode(buf[pos..], 0xdeadbeef);

    const got = try settings_mod.Settings.decode(buf[0..pos]);
    try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
}

test "NORMATIVE ignore an unknown identifier sandwiched between defined IDs [RFC9114 §7.2.4 ¶5]" {
    // §7.2.4 ¶5 again: ignore unknown identifiers, but still apply the
    // surrounding defined IDs.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 1024);
    // GREASE N=2: 0x1f*2+0x21 = 0x5f.
    pos += try varint.encode(buf[pos..], 0x5f);
    pos += try varint.encode(buf[pos..], 0xfeedface);
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 1);

    const got = try settings_mod.Settings.decode(buf[0..pos]);
    try std.testing.expectEqual(@as(u64, 1024), got.qpack_max_table_capacity);
    try std.testing.expect(got.h3_datagram);
}

test "NORMATIVE accept an unknown identifier carrying a varint value at every length boundary [RFC9114 §7.2.4 ¶5]" {
    // The §7.2.4 grammar accepts any QUIC varint (1, 2, 4, or 8
    // bytes). The decoder must walk past such a value without
    // rejecting it just because it didn't recognise the identifier.
    const lengths = [_]u64{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30 };
    for (lengths) |v| {
        var buf: [24]u8 = undefined;
        var pos: usize = 0;
        // GREASE N=3 → 0x7e (1-byte ID).
        pos += try varint.encode(buf[pos..], 0x7e);
        pos += try varint.encode(buf[pos..], v);
        const got = try settings_mod.Settings.decode(buf[0..pos]);
        // Defined IDs were untouched by the unknown-id payload.
        try std.testing.expectEqual(@as(u64, 0), got.qpack_max_table_capacity);
        try std.testing.expectEqual(@as(?u64, null), got.max_field_section_size);
    }
}

// ---------------------------------------------------------------- §7.2.4.1 boolean-domain settings

test "MUST reject SETTINGS_ENABLE_CONNECT_PROTOCOL = 2 as out of domain [RFC9220 §3 ¶3]" {
    // RFC 9220 §3 ¶3: the setting carries a boolean (0 or 1). A value
    // outside that domain is malformed; nullq raises
    // `InvalidSettingValue`.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(buf[pos..], 2);

    try std.testing.expectError(
        settings_mod.Error.InvalidSettingValue,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject SETTINGS_ENABLE_CONNECT_PROTOCOL value at u62 ceiling [RFC9220 §3 ¶3]" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(buf[pos..], (1 << 62) - 1);

    try std.testing.expectError(
        settings_mod.Error.InvalidSettingValue,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST reject SETTINGS_H3_DATAGRAM = 2 as out of domain [RFC9297 §2.1 ¶2]" {
    // RFC 9297 §2.1 ¶2: "An endpoint that has either sent or received
    // a SETTINGS_H3_DATAGRAM value of 1..." — the codec rejects any
    // other non-zero value.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 2);

    try std.testing.expectError(
        settings_mod.Error.InvalidSettingValue,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

test "MUST accept SETTINGS_H3_DATAGRAM = 0 as the disabled state [RFC9297 §2.1 ¶2]" {
    // Symmetric: 0 is in the boolean domain.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 0);

    const got = try settings_mod.Settings.decode(buf[0..pos]);
    try std.testing.expect(!got.h3_datagram);
}

test "MUST accept SETTINGS_ENABLE_CONNECT_PROTOCOL = 0 as the disabled state [RFC9220 §3 ¶3]" {
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.enable_connect_protocol);
    pos += try varint.encode(buf[pos..], 0);

    const got = try settings_mod.Settings.decode(buf[0..pos]);
    try std.testing.expect(!got.enable_connect_protocol);
}

// ---------------------------------------------------------------- §7.2.4 truncation guards

test "MUST NOT accept a SETTINGS payload truncated mid-identifier [RFC9114 §7.2.4 ¶1]" {
    // §7.2.4 ¶1 says identifier and value are both varints. A
    // multi-byte varint truncated to its first byte must surface as
    // InsufficientBytes, not as a successful 0-byte read.
    // 0x40 declares a 2-byte varint but only 1 byte is provided.
    const truncated = [_]u8{0x40};
    try std.testing.expectError(
        settings_mod.Error.InsufficientBytes,
        settings_mod.Settings.decode(&truncated),
    );
}

test "MUST NOT accept a SETTINGS payload truncated between identifier and value [RFC9114 §7.2.4 ¶1]" {
    // Identifier present (single byte 0x06 = max_field_section_size)
    // but no value byte follows — empty buffer for the value's varint.
    const truncated = [_]u8{0x06};
    try std.testing.expectError(
        settings_mod.Error.InsufficientBytes,
        settings_mod.Settings.decode(&truncated),
    );
}

test "MUST NOT accept a SETTINGS payload truncated mid-value [RFC9114 §7.2.4 ¶1]" {
    // Identifier 0x06, value-length declares 2-byte form (0x40) but
    // only 1 of the 2 bytes is present.
    const truncated = [_]u8{ 0x06, 0x40 };
    try std.testing.expectError(
        settings_mod.Error.InsufficientBytes,
        settings_mod.Settings.decode(&truncated),
    );
}

// ---------------------------------------------------------------- §7.2.4 round-trip

test "NORMATIVE encode→decode preserves all five defined settings simultaneously [RFC9114 §7.2.4 ¶3]" {
    // Encode all five identifiers nullq supports, decode, confirm
    // identity. Belt-and-suspenders for the multi-identifier scan.
    const original: settings_mod.Settings = .{
        .qpack_max_table_capacity = 8192,
        .qpack_blocked_streams = 32,
        .max_field_section_size = 0x10000,
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    var buf: [64]u8 = undefined;
    const n = try original.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);

    try std.testing.expectEqual(original.qpack_max_table_capacity, got.qpack_max_table_capacity);
    try std.testing.expectEqual(original.qpack_blocked_streams, got.qpack_blocked_streams);
    try std.testing.expectEqual(original.max_field_section_size, got.max_field_section_size);
    try std.testing.expectEqual(original.enable_connect_protocol, got.enable_connect_protocol);
    try std.testing.expectEqual(original.h3_datagram, got.h3_datagram);
}

test "NORMATIVE accept an empty SETTINGS payload (no entries) [RFC9114 §7.2.4 ¶3]" {
    // §7.2.4 ¶3: "Each parameter has a default value... if the
    // SETTINGS frame is not received or does not include that
    // parameter." Implication: zero entries is a valid SETTINGS
    // payload — every default applies.
    const got = try settings_mod.Settings.decode("");
    try std.testing.expectEqual(@as(u64, 0), got.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 0), got.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, null), got.max_field_section_size);
    try std.testing.expect(!got.enable_connect_protocol);
    try std.testing.expect(!got.h3_datagram);
}

test "NORMATIVE accept SETTINGS payload containing only an unknown identifier [RFC9114 §7.2.4 ¶5]" {
    // §7.2.4 ¶5 again — unknown identifiers MUST be ignored, even
    // when they are the only entry in the payload.
    var buf: [8]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x40); // GREASE
    pos += try varint.encode(buf[pos..], 99);
    const got = try settings_mod.Settings.decode(buf[0..pos]);

    // Result should be an all-defaults Settings.
    try std.testing.expectEqual(@as(u64, 0), got.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 0), got.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, null), got.max_field_section_size);
    try std.testing.expect(!got.enable_connect_protocol);
    try std.testing.expect(!got.h3_datagram);
}

test "NORMATIVE encode picks the minimum varint form for every emitted identifier [RFC9000 §16 ¶6]" {
    // RFC 9000 §16 ¶6 (cross-cutting): "The encoded form for an
    // integer can be larger than the minimum size required..."
    // Convention is "encoder picks minimum"; nullq follows that.
    // The encoder always emits QPACK_MAX_TABLE_CAPACITY (id=0x01)
    // and QPACK_BLOCKED_STREAMS (id=0x07) plus any boolean settings
    // that are true; every identifier here fits in 1 varint byte.
    const s: settings_mod.Settings = .{ .h3_datagram = true };
    var buf: [16]u8 = undefined;
    const n = try s.encode(&buf);
    // Walk the emitted entries and confirm every identifier and
    // every value uses a 1-byte varint (top bits 00).
    var pos: usize = 0;
    while (pos < n) {
        try std.testing.expectEqual(@as(u8, 0x00), buf[pos] & 0xc0);
        const id_d = try varint.decode(buf[pos..]);
        pos += id_d.bytes_read;
        try std.testing.expectEqual(@as(u8, 0x00), buf[pos] & 0xc0);
        const val_d = try varint.decode(buf[pos..]);
        pos += val_d.bytes_read;
    }
    try std.testing.expectEqual(@as(usize, n), pos);
}

test "NORMATIVE encode picks the minimum varint form for a value that crosses a length boundary [RFC9000 §16 ¶6]" {
    // 16384 = 2^14, the smallest value that requires the 4-byte
    // varint form. The encoder must emit length 4 (top 2 bits = 10).
    const s: settings_mod.Settings = .{ .max_field_section_size = 16384 };
    var buf: [16]u8 = undefined;
    const n = try s.encode(&buf);
    // Locate the 0x06 identifier byte.
    var pos: usize = 0;
    while (pos < n) {
        const id_d = try varint.decode(buf[pos..]);
        pos += id_d.bytes_read;
        if (id_d.value == protocol.SettingId.max_field_section_size) {
            // Inspect the value byte: top 2 bits must be 10 (4-byte form).
            try std.testing.expectEqual(@as(u8, 0x80), buf[pos] & 0xc0);
            return;
        }
        const val_d = try varint.decode(buf[pos..]);
        pos += val_d.bytes_read;
    }
    return error.TestExpectedEqual;
}
