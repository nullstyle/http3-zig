//! RFC 9114 §7.2 — HTTP/3 frame definitions.
//!
//! Every HTTP/3 frame on the wire is `Type (i) Length (i) Payload (..)`,
//! both Type and Length encoded as QUIC variable-length integers. This
//! suite covers the codec for each defined frame: DATA, HEADERS,
//! CANCEL_PUSH, SETTINGS-envelope (the payload is exercised by
//! `rfc9114_settings.zig`), PUSH_PROMISE, GOAWAY, MAX_PUSH_ID, and the
//! RFC 9218 §7.2 PRIORITY_UPDATE pair. Unknown / GREASE / reserved-HTTP/2
//! IDs are exercised at the wire level here too.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §7.1   ¶1   MUST     every frame begins Type (i) Length (i) Payload
//!   RFC9114 §7.1   ¶3   MUST NOT accept a frame whose declared Length exceeds the buffer
//!   RFC9114 §7.2.1 ¶2   NORMATIVE DATA frame body is the unframed payload
//!   RFC9114 §7.2.1 ¶?   MUST     DATA frame round-trip is byte-exact
//!   RFC9114 §7.2.2 ¶1   NORMATIVE HEADERS frame body carries the QPACK field section
//!   RFC9114 §7.2.2 ¶?   MUST     HEADERS frame round-trip is byte-exact
//!   RFC9114 §7.2.3 ¶1   MUST     CANCEL_PUSH carries a single Push ID varint
//!   RFC9114 §7.2.3 ¶?   MUST NOT accept CANCEL_PUSH with trailing garbage
//!   RFC9114 §7.2.5 ¶1   MUST     PUSH_PROMISE carries Push ID varint then Encoded Field Section
//!   RFC9114 §7.2.5 ¶?   MUST     PUSH_PROMISE round-trips push_id and field_section verbatim
//!   RFC9114 §7.2.6 ¶1   MUST     GOAWAY carries a single Stream/Push ID varint
//!   RFC9114 §7.2.6 ¶?   MUST NOT accept GOAWAY with trailing garbage
//!   RFC9114 §7.2.7 ¶1   MUST     MAX_PUSH_ID carries a single Push ID varint
//!   RFC9114 §7.2.7 ¶?   MUST NOT accept MAX_PUSH_ID with trailing garbage
//!   RFC9114 §7.2.8 ¶1   MUST     ignore unknown frame types per §9
//!   RFC9114 §7.2.8 ¶3   MUST     reserve frame-type IDs of the form 0x1f*N+0x21 for greasing
//!   RFC9114 §7.2.4 ¶2   MUST     SETTINGS payload is opaque to the frame-envelope codec (parsed by Settings.decode)
//!   RFC9218 §7.2   ¶3   MUST     PRIORITY_UPDATE Request is type 0xF0700, carries Element ID + Priority Field Value
//!   RFC9218 §7.2   ¶3   MUST     PRIORITY_UPDATE Push is type 0xF0701, carries Element ID + Priority Field Value
//!   RFC9114 §7.1   ¶1   NORMATIVE iterator walks concatenated frames in order
//!
//! Visible debt:
//!   none — the empty-payload PUSH_PROMISE and varint upper-bound paths are
//!   exercised below as `InsufficientBytes` (the decoder surfaces both via
//!   varint).
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.1 ¶?  declared Length > 2^62-1 — `nullq.wire.varint`
//!     enforces the upper bound; the explicit-cap test lives in
//!     `nullq/tests/conformance/rfc9000_varint.zig`.
//!   RFC9114 §7.2.4    SETTINGS payload codec                       → rfc9114_settings.zig
//!   RFC9114 §6.2      stream-context placement (DATA only on req)  → rfc9114_streams.zig
//!   RFC9114 §4        message-level malformed-pseudo-header rules  → rfc9114_messages.zig
//!   RFC9114 §8.1      error-code escalation semantics              → rfc9114_errors.zig
//!   RFC9218 §4–§6     Priority Field Value semantics               → rfc9218_priority.zig

const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");

const frame_mod = null3.frame;
const protocol = null3.protocol;
const varint = nullq.wire.varint;

// ---------------------------------------------------------------- §7.1 frame envelope

test "MUST encode every frame as `Type (i) Length (i) Payload` [RFC9114 §7.1 ¶1]" {
    // §7.1 ¶1: "All frames have the following format: Frame { Type
    // (i), Length (i), Frame Payload (..), }". DATA with type 0x00
    // gives the simplest byte layout to assert.
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .data = "abc" });

    // Type byte 0 = 0x00 (1-byte varint).
    const type_d = try varint.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, protocol.FrameType.data), type_d.value);
    // Length follows.
    const length_d = try varint.decode(buf[type_d.bytes_read..n]);
    try std.testing.expectEqual(@as(u64, 3), length_d.value);
    // Payload is verbatim.
    const start = type_d.bytes_read + length_d.bytes_read;
    try std.testing.expectEqualSlices(u8, "abc", buf[start..n]);
}

test "MUST NOT accept a frame whose declared Length exceeds the available buffer [RFC9114 §7.1 ¶3]" {
    // §7.1 ¶3: "If a frame is incomplete or larger than what is
    // remaining in the QUIC stream's current readable bytes, the
    // implementation MUST treat the [...]" — at the codec layer this
    // surfaces as InsufficientBytes when the Length declares more
    // bytes than the slice contains.
    // type=0x00, length=0x10 (16 bytes), but only 0 bytes follow.
    const truncated = [_]u8{ 0x00, 0x10 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&truncated),
    );
}

test "MUST NOT accept a frame truncated mid-Type varint [RFC9114 §7.1 ¶1]" {
    // 0x40 declares the 2-byte varint form for the Type field, but
    // only one byte is present.
    const truncated = [_]u8{0x40};
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&truncated),
    );
}

test "MUST NOT accept a frame truncated mid-Length varint [RFC9114 §7.1 ¶1]" {
    // type=0x00, length declares 2-byte form (0x40) but only 1 byte
    // is present.
    const truncated = [_]u8{ 0x00, 0x40 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&truncated),
    );
}

test "MUST NOT accept a frame whose Length refers to bytes past the slice boundary [RFC9114 §7.1 ¶3]" {
    // type=0x01 (HEADERS), length=0x05, only 3 payload bytes follow.
    const truncated = [_]u8{ 0x01, 0x05, 'a', 'b', 'c' };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&truncated),
    );
}

// ---------------------------------------------------------------- §7.2.1 DATA

test "NORMATIVE DATA frame body is the unframed payload [RFC9114 §7.2.1 ¶2]" {
    // §7.2.1 ¶2: "DATA frames convey arbitrary, variable-length
    // sequences of bytes associated with HTTP request or response
    // content." The codec MUST hand the raw bytes back unchanged.
    const payload = "Hello, HTTP/3";
    var buf: [32]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .data = payload });
    const d = try frame_mod.decode(buf[0..n]);
    try std.testing.expectEqual(n, d.bytes_read);
    switch (d.frame) {
        .data => |bytes| try std.testing.expectEqualSlices(u8, payload, bytes),
        else => return error.TestExpectedEqual,
    }
}

test "NORMATIVE DATA frame admits a zero-length payload [RFC9114 §7.2.1 ¶2]" {
    // §7.2.1 ¶2 places no minimum on the payload length. A zero-byte
    // DATA frame is legal.
    var buf: [4]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .data = "" });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .data => |bytes| try std.testing.expectEqual(@as(usize, 0), bytes.len),
        else => return error.TestExpectedEqual,
    }
}

test "MUST emit the DATA frame with type ID 0x00 on the wire [RFC9114 §7.2.1 ¶1]" {
    // The encoder MUST stamp the registry-assigned ID. Keep this
    // distinct from the protocol-constant test in
    // rfc9114_protocol.zig: that one asserts the table value, this
    // one asserts the codec output.
    var buf: [4]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .data = "x" });
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
}

// ---------------------------------------------------------------- §7.2.2 HEADERS

test "NORMATIVE HEADERS frame body carries the QPACK field section verbatim [RFC9114 §7.2.2 ¶1]" {
    // §7.2.2 ¶1: "The HEADERS frame is used to carry an HTTP field
    // section that is encoded using QPACK." The frame envelope is
    // QPACK-agnostic; round-trip MUST preserve the bytes.
    const opaque_field_section = [_]u8{ 0x00, 0x00, 0xc0, 0xd1 };
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .headers = &opaque_field_section });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .headers => |bytes| try std.testing.expectEqualSlices(u8, &opaque_field_section, bytes),
        else => return error.TestExpectedEqual,
    }
}

test "MUST emit the HEADERS frame with type ID 0x01 on the wire [RFC9114 §7.2.2 ¶1]" {
    var buf: [8]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .headers = "x" });
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "NORMATIVE HEADERS frame admits a zero-length field section [RFC9114 §7.2.2 ¶1]" {
    // The §7.2.2 grammar places no minimum; trailers can yield an
    // empty HEADERS frame in practice.
    var buf: [4]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .headers = "" });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .headers => |bytes| try std.testing.expectEqual(@as(usize, 0), bytes.len),
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- §7.2.3 CANCEL_PUSH

test "MUST encode CANCEL_PUSH with type ID 0x03 and a single Push ID varint [RFC9114 §7.2.3 ¶1]" {
    // §7.2.3 ¶1 / Figure 6: "CANCEL_PUSH Frame { Push ID (i) }".
    var buf: [8]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .cancel_push = 7 });
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);
    // length byte = 1 (one varint byte for Push ID = 7).
    try std.testing.expectEqual(@as(u8, 0x01), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x07), buf[2]);
    _ = n;
}

test "MUST round-trip the Push ID carried by CANCEL_PUSH [RFC9114 §7.2.3 ¶1]" {
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .cancel_push = 0x4000 });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .cancel_push => |id| try std.testing.expectEqual(@as(u64, 0x4000), id),
        else => return error.TestExpectedEqual,
    }
}

test "MUST NOT accept a CANCEL_PUSH frame with trailing garbage after the Push ID [RFC9114 §7.2.3 ¶1]" {
    // §7.2.3 grammar declares exactly one Push ID varint; any
    // trailing bytes are malformed. type=0x03, length=0x02, payload =
    // varint Push ID (1 byte) + extra byte.
    const malformed = [_]u8{ 0x03, 0x02, 0x07, 0xff };
    try std.testing.expectError(
        frame_mod.Error.InvalidFramePayload,
        frame_mod.decode(&malformed),
    );
}

test "MUST NOT accept a CANCEL_PUSH frame with empty payload [RFC9114 §7.2.3 ¶1]" {
    // The Push ID varint is required; a zero-length payload has none.
    const malformed = [_]u8{ 0x03, 0x00 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&malformed),
    );
}

// ---------------------------------------------------------------- §7.2.4 SETTINGS envelope

test "MUST emit the SETTINGS frame with type ID 0x04 on the wire [RFC9114 §7.2.4 ¶1]" {
    // §7.2.4 ¶1 fixes the SETTINGS type ID at 0x04. The frame
    // envelope test sits here; the payload contents are exercised
    // exhaustively in rfc9114_settings.zig.
    const s: null3.Settings = .{ .qpack_max_table_capacity = 100 };
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .settings = s });
    try std.testing.expectEqual(@as(u8, 0x04), buf[0]);
    _ = n;
}

test "MUST round-trip a SETTINGS payload through the frame envelope [RFC9114 §7.2.4 ¶1]" {
    // The frame envelope is opaque to the SETTINGS payload; once
    // encoded and decoded as a frame, the payload codec parses it
    // back to the same struct.
    const s: null3.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 16,
        .max_field_section_size = 65536,
        .h3_datagram = true,
    };
    var buf: [64]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .settings = s });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .settings => |got| {
            try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
            try std.testing.expectEqual(@as(u64, 16), got.qpack_blocked_streams);
            try std.testing.expectEqual(@as(?u64, 65536), got.max_field_section_size);
            try std.testing.expect(got.h3_datagram);
        },
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- §7.2.5 PUSH_PROMISE

test "MUST encode PUSH_PROMISE with type ID 0x05 [RFC9114 §7.2.5 ¶1]" {
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .push_promise = .{ .push_id = 1, .field_section = "" } });
    try std.testing.expectEqual(@as(u8, 0x05), buf[0]);
    _ = n;
}

test "MUST round-trip the Push ID and Encoded Field Section carried by PUSH_PROMISE [RFC9114 §7.2.5 ¶1]" {
    // §7.2.5 ¶1 / Figure 7: "PUSH_PROMISE Frame { Push ID (i),
    // Encoded Field Section (..) }".
    const opaque_field_section = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    var buf: [32]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .push_promise = .{
            .push_id = 42,
            .field_section = &opaque_field_section,
        },
    });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .push_promise => |p| {
            try std.testing.expectEqual(@as(u64, 42), p.push_id);
            try std.testing.expectEqualSlices(u8, &opaque_field_section, p.field_section);
        },
        else => return error.TestExpectedEqual,
    }
}

test "MUST accept a PUSH_PROMISE frame whose Field Section is zero bytes [RFC9114 §7.2.5 ¶1]" {
    // §7.2.5 ¶1 allows the Encoded Field Section to be empty (only
    // the Push ID is required). nullq's codec MUST round-trip this.
    var buf: [8]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .push_promise = .{ .push_id = 9, .field_section = "" } });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .push_promise => |p| {
            try std.testing.expectEqual(@as(u64, 9), p.push_id);
            try std.testing.expectEqual(@as(usize, 0), p.field_section.len);
        },
        else => return error.TestExpectedEqual,
    }
}

test "MUST NOT accept a PUSH_PROMISE frame with empty payload (missing Push ID) [RFC9114 §7.2.5 ¶1]" {
    // type=0x05, length=0 — Push ID is required.
    const malformed = [_]u8{ 0x05, 0x00 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&malformed),
    );
}

// ---------------------------------------------------------------- §7.2.6 GOAWAY

test "MUST encode GOAWAY with type ID 0x07 and a single Stream/Push ID varint [RFC9114 §7.2.6 ¶1]" {
    // §7.2.6 ¶1 / Figure 9: "GOAWAY Frame { Stream ID/Push ID (i) }".
    var buf: [8]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .goaway = 0 });
    try std.testing.expectEqual(@as(u8, 0x07), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x01), buf[1]); // length = 1
    try std.testing.expectEqual(@as(u8, 0x00), buf[2]); // Stream ID = 0
    _ = n;
}

test "MUST round-trip the Stream/Push ID carried by GOAWAY [RFC9114 §7.2.6 ¶1]" {
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .goaway = 0x4000 });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .goaway => |id| try std.testing.expectEqual(@as(u64, 0x4000), id),
        else => return error.TestExpectedEqual,
    }
}

test "MUST NOT accept a GOAWAY frame with trailing garbage after the ID [RFC9114 §7.2.6 ¶1]" {
    // §7.2.6 grammar declares exactly one varint; any trailing bytes
    // are malformed.
    const malformed = [_]u8{ 0x07, 0x02, 0x00, 0xff };
    try std.testing.expectError(
        frame_mod.Error.InvalidFramePayload,
        frame_mod.decode(&malformed),
    );
}

test "MUST NOT accept a GOAWAY frame with empty payload [RFC9114 §7.2.6 ¶1]" {
    const malformed = [_]u8{ 0x07, 0x00 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&malformed),
    );
}

// ---------------------------------------------------------------- §7.2.7 MAX_PUSH_ID

test "MUST encode MAX_PUSH_ID with type ID 0x0d and a single Push ID varint [RFC9114 §7.2.7 ¶1]" {
    // §7.2.7 ¶1 / Figure 10: "MAX_PUSH_ID Frame { Push ID (i) }".
    var buf: [8]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .max_push_id = 5 });
    try std.testing.expectEqual(@as(u8, 0x0d), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x01), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x05), buf[2]);
    _ = n;
}

test "MUST round-trip the Push ID carried by MAX_PUSH_ID [RFC9114 §7.2.7 ¶1]" {
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{ .max_push_id = 0x10000 });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .max_push_id => |id| try std.testing.expectEqual(@as(u64, 0x10000), id),
        else => return error.TestExpectedEqual,
    }
}

test "MUST NOT accept a MAX_PUSH_ID frame with trailing garbage [RFC9114 §7.2.7 ¶1]" {
    const malformed = [_]u8{ 0x0d, 0x02, 0x00, 0xff };
    try std.testing.expectError(
        frame_mod.Error.InvalidFramePayload,
        frame_mod.decode(&malformed),
    );
}

test "MUST NOT accept a MAX_PUSH_ID frame with empty payload [RFC9114 §7.2.7 ¶1]" {
    const malformed = [_]u8{ 0x0d, 0x00 };
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        frame_mod.decode(&malformed),
    );
}

// ---------------------------------------------------------------- §7.2.8 reserved / unknown frames

test "MUST decode a frame with an unknown type as `unknown` [RFC9114 §9 ¶?]" {
    // §9 (cross-cutting reserved-extension paragraph) and §7.2.8: a
    // receiver "MUST ignore" unknown frame types. The codec's
    // contract is to surface them as the `unknown` variant — the
    // receive-side gating that triggers H3_FRAME_UNEXPECTED for
    // wrong-context frames lives in stream.zig and rfc9114_streams.zig.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x4242);
    pos += try varint.encode(buf[pos..], 4);
    @memcpy(buf[pos .. pos + 4], "data");
    pos += 4;

    const d = try frame_mod.decode(buf[0..pos]);
    switch (d.frame) {
        .unknown => |u| {
            try std.testing.expectEqual(@as(u64, 0x4242), u.frame_type);
            try std.testing.expectEqualSlices(u8, "data", u.payload);
        },
        else => return error.TestExpectedEqual,
    }
}

test "MUST decode a GREASE-formatted frame type as `unknown` [RFC9114 §7.2.8 ¶3]" {
    // §7.2.8 ¶3: "Frame types of the format `0x1f * N + 0x21` for
    // non-negative integer values of N are reserved to exercise the
    // requirement that unknown types be ignored." The codec hands
    // these through the same `unknown` variant. N=1 → 0x40.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x40);
    pos += try varint.encode(buf[pos..], 0);

    const d = try frame_mod.decode(buf[0..pos]);
    switch (d.frame) {
        .unknown => |u| try std.testing.expectEqual(@as(u64, 0x40), u.frame_type),
        else => return error.TestExpectedEqual,
    }
}

test "MUST decode a reserved HTTP/2 frame type (0x02 PRIORITY) as `unknown` at the codec layer [RFC9114 §7.2.8 ¶2]" {
    // §7.2.8 ¶2: HTTP/2 IDs 0x02, 0x06, 0x08, 0x09 are reserved. The
    // wire codec surfaces them as `unknown`; the receive-side gate
    // that maps that to H3_FRAME_UNEXPECTED lives in stream.zig and
    // is exercised in rfc9114_streams.zig — keep that distinct.
    var buf: [4]u8 = undefined;
    buf[0] = 0x02; // type
    buf[1] = 0x00; // length

    const d = try frame_mod.decode(buf[0..2]);
    switch (d.frame) {
        .unknown => |u| try std.testing.expectEqual(@as(u64, 0x02), u.frame_type),
        else => return error.TestExpectedEqual,
    }
}

test "MUST round-trip an Unknown frame's payload bytes verbatim [RFC9114 §9 ¶?]" {
    // The encoder offers an `unknown` constructor that mirrors
    // decoded `unknown` frames — useful for forwarding GREASE on the
    // sender side. Round-trip MUST preserve frame_type and payload.
    const payload = "opaque-extension-bytes";
    var buf: [64]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .unknown = .{ .frame_type = 0x40, .payload = payload },
    });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .unknown => |u| {
            try std.testing.expectEqual(@as(u64, 0x40), u.frame_type);
            try std.testing.expectEqualSlices(u8, payload, u.payload);
        },
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- RFC 9218 §7.2 PRIORITY_UPDATE

test "MUST encode PRIORITY_UPDATE Request with type ID 0xF0700 [RFC9218 §7.2 ¶3]" {
    // RFC 9218 §7.2 ¶3 / Figure 4: PRIORITY_UPDATE Frame Type 0xF0700
    // (request). Since 0xF0700 > 2^14, it lands in the 4-byte varint
    // form on the wire (top bits 10).
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=3",
        },
    });
    // First byte top 2 bits = 10 (4-byte varint form).
    try std.testing.expectEqual(@as(u8, 0x80), buf[0] & 0xc0);
    const t = try varint.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0xF0700), t.value);
}

test "MUST encode PRIORITY_UPDATE Push with type ID 0xF0701 [RFC9218 §7.2 ¶3]" {
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .priority_update_push = .{
            .prioritized_element_id = 1,
            .priority_field_value = "u=5",
        },
    });
    const t = try varint.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0xF0701), t.value);
}

test "MUST round-trip the Element ID and Priority Field Value carried by PRIORITY_UPDATE Request [RFC9218 §7.2 ¶3]" {
    // RFC 9218 §7.2 ¶3 / Figure 4: "PRIORITY_UPDATE Frame {
    //   Prioritized Element ID (i), Priority Field Value (..) }".
    // The Priority Field Value is opaque at the codec layer — its
    // structured-field grammar is exercised in rfc9218_priority.zig.
    const pfv = "u=2, i";
    var buf: [32]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0x40,
            .priority_field_value = pfv,
        },
    });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0x40), p.prioritized_element_id);
            try std.testing.expectEqualSlices(u8, pfv, p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "MUST round-trip the Element ID and Priority Field Value carried by PRIORITY_UPDATE Push [RFC9218 §7.2 ¶3]" {
    const pfv = "u=7";
    var buf: [32]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .priority_update_push = .{
            .prioritized_element_id = 5,
            .priority_field_value = pfv,
        },
    });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_push => |p| {
            try std.testing.expectEqual(@as(u64, 5), p.prioritized_element_id);
            try std.testing.expectEqualSlices(u8, pfv, p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "NORMATIVE PRIORITY_UPDATE Request admits a zero-byte Priority Field Value [RFC9218 §7.2 ¶3]" {
    // §7.2 ¶3 places no minimum on the Priority Field Value — an
    // empty value selects the default urgency / non-incremental.
    var buf: [16]u8 = undefined;
    const n = try frame_mod.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "",
        },
    });
    const d = try frame_mod.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqual(@as(usize, 0), p.priority_field_value.len);
        },
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- §7.1 frame iterator

test "NORMATIVE frame iterator walks consecutive frames in order [RFC9114 §7.1 ¶1]" {
    // §7.1 ¶1 implies a stream of concatenated `Type | Length |
    // Payload` triples. The iterator yields them in their original
    // order without buffering across frames.
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .headers = "h" });
    pos += try frame_mod.encode(buf[pos..], .{ .data = "d" });
    pos += try frame_mod.encode(buf[pos..], .{ .max_push_id = 4 });

    var it = frame_mod.iter(buf[0..pos]);
    const f1 = (try it.next()).?;
    try std.testing.expect(f1.frame == .headers);
    const f2 = (try it.next()).?;
    try std.testing.expect(f2.frame == .data);
    const f3 = (try it.next()).?;
    try std.testing.expect(f3.frame == .max_push_id);
    try std.testing.expectEqual(@as(?frame_mod.Decoded, null), try it.next());
}

test "NORMATIVE frame iterator surfaces a parse error on a corrupt frame mid-stream [RFC9114 §7.1 ¶3]" {
    // After one valid frame, append a frame whose Length lies — the
    // iterator MUST return the error rather than swallow it.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .data = "d" });
    // type=0x00 (DATA), length=0x10, but only 0 bytes follow.
    buf[pos] = 0x00;
    buf[pos + 1] = 0x10;
    pos += 2;

    var it = frame_mod.iter(buf[0..pos]);
    const ok = (try it.next()).?;
    try std.testing.expect(ok.frame == .data);
    try std.testing.expectError(
        nullq.wire.varint.Error.InsufficientBytes,
        it.next(),
    );
}

// ---------------------------------------------------------------- §7.1 frameType / payloadLen / encodedLen helpers

test "MUST report the correct frameType for every defined frame variant [RFC9114 §7.2 ¶1]" {
    // Cover every variant the public API exposes so a future
    // refactor that drops a case is caught here. Spot-check against
    // the §7.2 IANA-assigned IDs.
    try std.testing.expectEqual(@as(u64, 0x00), frame_mod.frameType(.{ .data = "" }));
    try std.testing.expectEqual(@as(u64, 0x01), frame_mod.frameType(.{ .headers = "" }));
    try std.testing.expectEqual(@as(u64, 0x03), frame_mod.frameType(.{ .cancel_push = 0 }));
    try std.testing.expectEqual(@as(u64, 0x04), frame_mod.frameType(.{ .settings = .{} }));
    try std.testing.expectEqual(@as(u64, 0x05), frame_mod.frameType(.{ .push_promise = .{ .push_id = 0, .field_section = "" } }));
    try std.testing.expectEqual(@as(u64, 0x07), frame_mod.frameType(.{ .goaway = 0 }));
    try std.testing.expectEqual(@as(u64, 0x0d), frame_mod.frameType(.{ .max_push_id = 0 }));
    try std.testing.expectEqual(@as(u64, 0xF0700), frame_mod.frameType(.{
        .priority_update_request = .{ .prioritized_element_id = 0, .priority_field_value = "" },
    }));
    try std.testing.expectEqual(@as(u64, 0xF0701), frame_mod.frameType(.{
        .priority_update_push = .{ .prioritized_element_id = 0, .priority_field_value = "" },
    }));
    try std.testing.expectEqual(@as(u64, 0x42), frame_mod.frameType(.{
        .unknown = .{ .frame_type = 0x42, .payload = "" },
    }));
}

test "NORMATIVE encodedLen agrees with the byte count produced by encode [RFC9114 §7.1 ¶1]" {
    // Ensures sender-side preallocation logic is sound for every
    // frame variant the public API exposes.
    const cases = [_]frame_mod.Frame{
        .{ .data = "abc" },
        .{ .headers = "" },
        .{ .cancel_push = 0x4000 },
        .{ .settings = .{ .qpack_max_table_capacity = 100 } },
        .{ .push_promise = .{ .push_id = 9, .field_section = "fs" } },
        .{ .goaway = 0 },
        .{ .max_push_id = 1 },
        .{
            .priority_update_request = .{
                .prioritized_element_id = 0,
                .priority_field_value = "u=3",
            },
        },
        .{
            .priority_update_push = .{
                .prioritized_element_id = 0,
                .priority_field_value = "",
            },
        },
        .{ .unknown = .{ .frame_type = 0x40, .payload = "x" } },
    };
    for (cases) |f| {
        var buf: [128]u8 = undefined;
        const n = try frame_mod.encode(&buf, f);
        try std.testing.expectEqual(frame_mod.encodedLen(f), n);
    }
}
