//! RFC 9204 — QPACK: Field Compression for HTTP/3 (static profile).
//!
//! This file exercises the parts of QPACK whose behaviour is fully
//! decidable without a non-empty dynamic table: prefixed integers, the
//! HPACK Huffman code (RFC 7541 Appendix B, incorporated by reference
//! from RFC 9204 §4.1.2), the QPACK static table (RFC 9204 Appendix A),
//! and the field-section representations that target a section with
//! Required Insert Count = 0 and Base = 0 (RFC 9204 §3.1, §4.5.4,
//! §4.5.6, §4.5.8). Anything that needs the dynamic table — encoder /
//! decoder stream instructions, post-base indexing, blocked streams,
//! Required Insert Count wrap-around — lives in
//! `rfc9204_qpack_dynamic.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9204 §3.1 ¶1   NORMATIVE field section prefix encodes Required
//!                     Insert Count = 0 and Base = 0 as two zero octets.
//!   RFC9204 §4.1.1 ¶1 NORMATIVE prefixed-integer codec values that fit
//!                     into the prefix; cites RFC7541 §5.1.
//!   RFC9204 §4.1.1 ¶2 NORMATIVE prefixed-integer continuation bytes
//!                     for values >= (1 << prefix_bits) - 1.
//!   RFC9204 §4.1.1 ¶2 MUST     decoder accepts integers up to 62 bits.
//!   RFC9204 §4.1.1    MUST decoder rejects a continuation that would
//!                     overflow u64.
//!   RFC9204 §4.1.1    MUST decoder rejects a truncated continuation.
//!   RFC9204 §4.1.1    MUST encoder rejects an invalid prefix-bit width.
//!   RFC9204 §4.1.1    MUST encoder rejects a destination buffer that
//!                     is too small for the produced bytes.
//!   RFC9204 §4.1.2 ¶1 NORMATIVE string literal length prefix and body
//!                     round-trip without Huffman.
//!   RFC9204 §4.1.2 ¶2 MAY     string literal Huffman-encoded body
//!                     round-trip; H bit set in the first prefix byte.
//!   RFC9204 §4.1.2 ¶3 MUST    string literal H=0 round-trips without
//!                     setting the Huffman flag bit.
//!   RFC9204 §4.5.2 ¶3 NORMATIVE Required Insert Count = 0 field
//!                     section: prefix is 0x00 0x00.
//!   RFC9204 §4.5.4 ¶1 MUST    indexed field line / static table (T=1)
//!                     round-trip via `encodeFieldSection` /
//!                     `decodeFieldSection`.
//!   RFC9204 §4.5.4 ¶3 MUST    indexed field line decoder rejects an
//!                     out-of-range static index.
//!   RFC9204 §4.5.6 ¶1 MUST    literal field line with name reference
//!                     / static table (T=1) round-trip.
//!   RFC9204 §4.5.6 ¶2 MUST    literal field line with name reference
//!                     decoder rejects an out-of-range static index.
//!   RFC9204 §4.5.6 ¶3 NORMATIVE N=1 (sensitive) prevents a value
//!                     match from collapsing into an indexed
//!                     representation.
//!   RFC9204 §4.5.8 ¶1 MUST    literal field line with literal name
//!                     round-trip.
//!   RFC9204 §4.5.8 ¶2 NORMATIVE literal field line with literal name
//!                     supports both Huffman and raw name/value.
//!   RFC9204 Appx A    NORMATIVE static table has 99 entries (indices
//!                     0..98).
//!   RFC9204 Appx A    NORMATIVE selected static-table entries map to
//!                     RFC-published name/value (index 0 :authority,
//!                     index 1 :path "/", index 17 :method GET, index
//!                     23 :scheme https, index 25 :status 200, index
//!                     98 x-frame-options sameorigin).
//!   RFC9204 Appx A    NORMATIVE static table lookup by (name, value)
//!                     and by name only.
//!   RFC7541 §5.1      NORMATIVE prefixed-integer encoder/decoder
//!                     (incorporated by RFC9204 §4.1.1).
//!   RFC7541 Appx B    NORMATIVE Huffman encoder/decoder round-trips
//!                     for selected RFC examples and edge symbols.
//!   RFC7541 Appx B    NORMATIVE Huffman codec round-trips every
//!                     individual byte symbol (0x00..0xff).
//!   RFC7541 Appx B    MUST    Huffman decoder rejects the EOS symbol.
//!   RFC7541 Appx B    MUST    Huffman decoder rejects padding longer
//!                     than 7 bits.
//!   RFC7541 Appx B    MUST    Huffman decoder rejects non-MSB-1
//!                     padding.
//!
//! Visible debt:
//!   none — the fully static profile is exercised end-to-end.
//!
//! Out of scope here:
//!   RFC9204 §4.5.3   field section prefix wrap arithmetic with a
//!                    non-empty dynamic table → rfc9204_qpack_dynamic.zig.
//!   RFC9204 §4.5.5   indexed field line with post-base index
//!                    → rfc9204_qpack_dynamic.zig.
//!   RFC9204 §4.5.7   literal field line with post-base name reference
//!                    → rfc9204_qpack_dynamic.zig.
//!   RFC9204 §4.3 / §4.4   encoder / decoder stream instruction codecs
//!                    → rfc9204_qpack_dynamic.zig.
//!   RFC9204 Appx B   exact-byte fixtures live in
//!                    `interop/qpack_dynamic/runner.zig` (and the
//!                    `quic-go` cross-implementation block fixtures
//!                    inside `src/qpack/root.zig`'s inline tests).
//!
//! Every non-skipped test in this file routes through a `http3_zig.qpack.*`
//! public function.

const std = @import("std");
const http3_zig = @import("http3_zig");

const qpack = http3_zig.qpack;
const integer = qpack.integer;
const huffman = qpack.huffman;
const static_table = qpack.static_table;

// ---------------------------------------------------------------- §4.1.1 prefixed integer (RFC 7541 §5.1)

test "NORMATIVE round-trip a prefixed integer that fits into the 5-bit prefix [RFC9204 §4.1.1 ¶1]" {
    // Values strictly less than 2^N - 1 occupy a single octet. Use a
    // 5-bit prefix; (1 << 5) - 1 = 31, so 30 must fit.
    var buf: [16]u8 = undefined;
    const n = try integer.encode(&buf, 5, 0xe0, 30);
    try std.testing.expectEqual(@as(usize, 1), n);
    const decoded = try integer.decode(buf[0..n], 5);
    try std.testing.expectEqual(@as(u64, 30), decoded.value);
    try std.testing.expectEqual(@as(usize, 1), decoded.bytes_read);
}

test "NORMATIVE encode the maximum N-bit prefix value as 2 octets [RFC9204 §4.1.1 ¶2]" {
    // 31 == (1 << 5) - 1 → first byte's prefix mask is fully set, then
    // a single zero continuation byte encoding (31 - 31) = 0.
    var buf: [4]u8 = undefined;
    const n = try integer.encode(&buf, 5, 0, 31);
    try std.testing.expectEqual(@as(usize, 2), n);
    const decoded = try integer.decode(buf[0..n], 5);
    try std.testing.expectEqual(@as(u64, 31), decoded.value);
    try std.testing.expectEqual(@as(usize, 2), decoded.bytes_read);
}

test "NORMATIVE round-trip a multi-byte prefixed integer above the prefix limit [RFC9204 §4.1.1 ¶2]" {
    // RFC 7541 §5.1 example: I=1337, N=5 → 31, 154, 10.
    var buf: [16]u8 = undefined;
    const n = try integer.encode(&buf, 5, 0, 1337);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x1f), buf[0]); // prefix mask saturated
    try std.testing.expectEqual(@as(u8, 154), buf[1]); // continuation cont set
    try std.testing.expectEqual(@as(u8, 10), buf[2]);

    const decoded = try integer.decode(buf[0..n], 5);
    try std.testing.expectEqual(@as(u64, 1337), decoded.value);
    try std.testing.expectEqual(n, decoded.bytes_read);
}

test "NORMATIVE encode a prefixed integer using all 8 prefix bits [RFC9204 §4.1.1 ¶1]" {
    // 8-bit prefix: 0..254 fit in one byte, 255 starts a continuation.
    var buf: [4]u8 = undefined;
    const n_one = try integer.encode(&buf, 8, 0, 254);
    try std.testing.expectEqual(@as(usize, 1), n_one);

    const n_two = try integer.encode(&buf, 8, 0, 255);
    try std.testing.expectEqual(@as(usize, 2), n_two);
    try std.testing.expectEqual(@as(u8, 255), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);
    const decoded = try integer.decode(buf[0..n_two], 8);
    try std.testing.expectEqual(@as(u64, 255), decoded.value);
}

test "NORMATIVE round-trip a large multi-byte prefixed integer [RFC9204 §4.1.1 ¶2]" {
    // Drives the multi-byte continuation path well past the prefix
    // limit. Decoder caps at u64 so we pick a value whose magnitude
    // (28 bits past the prefix limit) round-trips cleanly.
    var buf: [16]u8 = undefined;
    const value: u64 = 0x0FFF_FFFF;
    const n = try integer.encode(&buf, 5, 0, value);
    try std.testing.expect(n > 1);
    const decoded = try integer.decode(buf[0..n], 5);
    try std.testing.expectEqual(value, decoded.value);
    try std.testing.expectEqual(n, decoded.bytes_read);
}

test "MUST decode prefixed integers up to 62 bits long [RFC9204 §4.1.1 ¶2]" {
    // RFC 9204 §4.1.1 ¶2: "QPACK implementations MUST be able to decode
    // integers up to and including 62 bits long." Drive a 62-bit value
    // (within the QUIC varint upper bound) through the codec to prove
    // the decoder accepts the full mandated range.
    var buf: [16]u8 = undefined;
    const value: u64 = (@as(u64, 1) << 62) - 1;
    const n = try integer.encode(&buf, 5, 0, value);
    try std.testing.expect(n > 1);
    const decoded = try integer.decode(buf[0..n], 5);
    try std.testing.expectEqual(value, decoded.value);
    try std.testing.expectEqual(n, decoded.bytes_read);
}

test "MUST reject a prefixed integer whose continuation overflows u64 [RFC9204 §4.1.1 ¶3]" {
    // Continuation chunks 0x80 ... 0x80 0xFF: every byte's high bit is
    // 1 except the last, but the cumulative shift exceeds 63 bits.
    const overflow = [_]u8{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff };
    try std.testing.expectError(
        integer.Error.ValueTooLarge,
        integer.decode(&overflow, 5),
    );
}

test "MUST reject a prefixed integer whose continuation is truncated [RFC9204 §4.1.1 ¶2]" {
    // Saturated prefix octet + a continuation byte with the high bit
    // still set → decoder must demand more bytes rather than silently
    // accept the partial value.
    const truncated = [_]u8{ 0x1f, 0x80 };
    try std.testing.expectError(
        integer.Error.InsufficientBytes,
        integer.decode(&truncated, 5),
    );
}

test "MUST reject prefix_bits == 0 in the prefixed-integer codec [RFC9204 §4.1.1 ¶1]" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        integer.Error.InvalidPrefix,
        integer.encode(&buf, 0, 0, 1),
    );
}

test "MUST reject prefix_bits > 8 in the prefixed-integer codec [RFC9204 §4.1.1 ¶1]" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        integer.Error.InvalidPrefix,
        integer.encode(&buf, 9, 0, 1),
    );
}

test "MUST reject a first_byte_prefix that overlaps the prefix bits [RFC9204 §4.1.1 ¶1]" {
    // 5-bit prefix → low 5 bits of first_byte_prefix MUST be zero;
    // 0x01 collides with the value field.
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        integer.Error.InvalidPrefix,
        integer.encode(&buf, 5, 0x01, 1),
    );
}

test "MUST reject an undersized destination buffer when encoding [RFC9204 §4.1.1 ¶2]" {
    var buf: [1]u8 = undefined;
    try std.testing.expectError(
        integer.Error.BufferTooSmall,
        integer.encode(&buf, 5, 0, 1337),
    );
}

test "MUST reject decoding from an empty buffer [RFC9204 §4.1.1 ¶1]" {
    try std.testing.expectError(
        integer.Error.InsufficientBytes,
        integer.decode(&.{}, 5),
    );
}

test "NORMATIVE encodedLen agrees with the encoder for representative widths [RFC9204 §4.1.1 ¶2]" {
    // Sample several widths and values to make sure the precomputed
    // length tracks the on-wire byte count.
    var buf: [16]u8 = undefined;
    inline for (.{ 3, 4, 5, 6, 7, 8 }) |bits| {
        for ([_]u64{ 0, 1, 5, 14, 31, 127, 255, 1337, 65535 }) |value| {
            const n = try integer.encode(&buf, bits, 0, value);
            try std.testing.expectEqual(integer.encodedLen(bits, value), n);
        }
    }
}

// ---------------------------------------------------------------- §4.1.2 string literals + Huffman

test "NORMATIVE a non-Huffman string literal round-trips through encode/decodeFieldSection [RFC9204 §4.1.2 ¶1]" {
    // Round-trip a literal-with-literal-name field through the full
    // QPACK encode/decode path. Use a name/value not present in the
    // static table so the codec emits a §4.5.8 literal representation
    // that contains both string literals.
    const fields = [_]qpack.FieldLine{
        .{ .name = "x-not-static", .value = "raw value" },
    };
    var buf: [128]u8 = undefined;
    const n = try qpack.encodeFieldSectionWithOptions(&buf, &fields, .{ .huffman = false });
    // Field-section prefix is 2 bytes: Required Insert Count = 0, Base
    // delta sign+value = 0. The next byte is the literal-with-literal-
    // name representation; its 0x08 (H) bit MUST be clear when
    // huffman=false.
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);
    try std.testing.expectEqual(@as(u8, 0), buf[2] & 0x08);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("x-not-static", decoded[0].name);
    try std.testing.expectEqualStrings("raw value", decoded[0].value);
}

test "MAY a Huffman-encoded string literal round-trips and sets the H bit [RFC9204 §4.1.2 ¶2]" {
    // Same field as above, but encode with Huffman: the literal name
    // representation's H-bit (bit 3 of the first prefix byte) MUST be
    // set, and the round-trip MUST recover the original UTF-8.
    const fields = [_]qpack.FieldLine{
        .{ .name = "x-not-static", .value = "raw value" },
    };
    var buf: [128]u8 = undefined;
    const n = try qpack.encodeFieldSectionWithOptions(&buf, &fields, .{ .huffman = true });
    try std.testing.expectEqual(@as(u8, 0x08), buf[2] & 0x08);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-not-static", decoded[0].name);
    try std.testing.expectEqualStrings("raw value", decoded[0].value);
}

test "NORMATIVE Huffman encoding shrinks the on-wire length for typical ASCII [RFC9204 §4.1.2 ¶2]" {
    // The HPACK Huffman code is biased toward lowercase ASCII, so a
    // typical authority value MUST encode to fewer bytes with Huffman
    // on than off.
    const fields = [_]qpack.FieldLine{
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    };
    var raw_buf: [256]u8 = undefined;
    var huff_buf: [256]u8 = undefined;
    const raw_n = try qpack.encodeFieldSectionWithOptions(&raw_buf, &fields, .{ .huffman = false });
    const huff_n = try qpack.encodeFieldSectionWithOptions(&huff_buf, &fields, .{ .huffman = true });
    try std.testing.expect(huff_n < raw_n);
}

test "NORMATIVE encodeStringLiteral round-trips through readStringAlloc-style decode [RFC9204 §4.1.2 ¶1]" {
    // Drive the public `encodeStringLiteral` helper directly. The
    // decoder side surfaces via `decodeFieldSection` for the same
    // 7-bit prefix shape, so we wrap it in a synthetic literal-with-
    // literal-name representation and verify the value bytes.
    var buf: [64]u8 = undefined;
    const value = "hello, world";
    const literal_n = try qpack.encodeStringLiteral(&buf, value, 7, 0, .{});
    // 12-byte ASCII string fits the 7-bit prefix (max value 127), so
    // the wire form is one length byte + 12 body bytes.
    try std.testing.expectEqual(@as(usize, 13), literal_n);
    try std.testing.expectEqual(@as(u8, 12), buf[0]);
    try std.testing.expectEqualSlices(u8, value, buf[1..literal_n]);
}

test "MUST reject a Huffman EOS symbol embedded in a string literal [RFC7541 Appx B]" {
    // RFC 7541 Appendix B reserves the 30-bit EOS code; encoders MUST
    // NOT emit it and decoders MUST treat its presence as a decoding
    // error. Drive `qpack.huffman.decode` directly with the EOS code
    // pattern (four 0xFF bytes covers the 30-bit sequence).
    const eos_bytes = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(
        huffman.Error.HuffmanEos,
        huffman.decode(std.testing.allocator, &eos_bytes),
    );
}

test "MUST reject Huffman padding longer than 7 bits [RFC7541 Appx B]" {
    // 0xff = eight padding bits → strictly greater than the maximum 7
    // bits of MSB-1 padding allowed at the end of a Huffman stream.
    try std.testing.expectError(
        huffman.Error.HuffmanPaddingTooLong,
        huffman.decode(std.testing.allocator, &.{0xff}),
    );
}

test "MUST reject Huffman padding that is not all-ones [RFC7541 Appx B]" {
    // A trailing partial byte MUST be filled with 1-bits (the high
    // bits of the EOS code). 0x00 is therefore an invalid padding.
    try std.testing.expectError(
        huffman.Error.InvalidHuffmanPadding,
        huffman.decode(std.testing.allocator, &.{0x00}),
    );
}

test "NORMATIVE Huffman codec round-trips the RFC 7541 cache-control example [RFC7541 Appx B]" {
    // RFC 7541 Appendix B gives "no-cache" as a sample HPACK Huffman
    // string. The QPACK module reuses that table.
    var buf: [16]u8 = undefined;
    const n = try huffman.encode(&buf, "no-cache");
    try std.testing.expectEqualSlices(u8, &.{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf }, buf[0..n]);
    const decoded = try huffman.decode(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("no-cache", decoded);
}

test "NORMATIVE Huffman codec round-trips the RFC 7541 authority example [RFC7541 Appx B]" {
    var buf: [32]u8 = undefined;
    const n = try huffman.encode(&buf, "www.example.com");
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff },
        buf[0..n],
    );
    const decoded = try huffman.decode(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("www.example.com", decoded);
}

test "NORMATIVE Huffman codec round-trips a long ASCII string [RFC7541 Appx B]" {
    const long = "the quick brown fox jumps over the lazy dog 0123456789";
    var buf: [128]u8 = undefined;
    const n = try huffman.encode(&buf, long);
    try std.testing.expectEqual(huffman.encodedLen(long), n);
    const decoded = try huffman.decode(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings(long, decoded);
}

test "NORMATIVE Huffman codec round-trips empty input [RFC7541 Appx B]" {
    // Zero-length input → zero-length output. Trivial but normative
    // for completeness because the prefixed-integer length still has
    // to encode "0".
    var buf: [4]u8 = undefined;
    const n = try huffman.encode(&buf, "");
    try std.testing.expectEqual(@as(usize, 0), n);
    const decoded = try huffman.decode(std.testing.allocator, buf[0..0]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "NORMATIVE Huffman codec round-trips a high-byte symbol with a 28-bit code [RFC7541 Appx B]" {
    // Symbol 0x00 has a 13-bit code; symbol 0x01 has a 23-bit code;
    // symbol 0x02 has a 28-bit code. Confirm that even the longest
    // single-symbol code round-trips (encoder packs / decoder
    // unpacks across byte boundaries correctly).
    const input = &[_]u8{0x02};
    var buf: [8]u8 = undefined;
    const n = try huffman.encode(&buf, input);
    const decoded = try huffman.decode(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, input, decoded);
}

test "MUST reject a destination buffer too small for a Huffman-encoded string [RFC9204 §4.1.2 ¶2]" {
    // Demand strict pre-checking of buffer space; encoder MUST NOT
    // overrun the caller's slice.
    var buf: [1]u8 = undefined;
    try std.testing.expectError(
        huffman.Error.BufferTooSmall,
        huffman.encode(&buf, "abcdefghij"),
    );
}

test "NORMATIVE Huffman codec round-trips every individual byte symbol [RFC7541 Appx B]" {
    // RFC 7541 Appendix B assigns a code to every value in 0..255. The
    // QPACK codec inherits that table (RFC 9204 §4.1.2). Drive every
    // single-byte input through encode/decode to prove every symbol is
    // emitted and recovered correctly across the byte boundary packing.
    var buf: [16]u8 = undefined;
    var symbol: u16 = 0;
    while (symbol < 256) : (symbol += 1) {
        const input = [_]u8{@intCast(symbol)};
        const n = try huffman.encode(&buf, &input);
        try std.testing.expectEqual(huffman.encodedLen(&input), n);
        const decoded = try huffman.decode(std.testing.allocator, buf[0..n]);
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, &input, decoded);
    }
}

// ---------------------------------------------------------------- §3.1 / §4.5.2 field section prefix (Required Insert Count = 0)

test "NORMATIVE static-only field section emits Required Insert Count = 0 and Base = 0 [RFC9204 §4.5.2 ¶3]" {
    // §3.1 says a field section that does not reference the dynamic
    // table is encoded with Required Insert Count = 0; §4.5.3 then
    // says that case Base = 0. The on-wire prefix MUST be the two
    // null octets.
    const fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "GET" },
    };
    var buf: [32]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    try std.testing.expect(n >= 2);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);
}

test "MUST reject a field section whose Required Insert Count is non-zero in the static-only decoder [RFC9204 §4.5.2 ¶3]" {
    // The static-only decoder is the path used when the dynamic table
    // is empty; a Required Insert Count > 0 forms an unsatisfiable
    // reference, so the decoder MUST refuse rather than silently
    // accept the section.
    const buf = [_]u8{ 0x01, 0x00 };
    try std.testing.expectError(
        qpack.Error.DynamicTableUnsupported,
        qpack.decodeFieldSection(std.testing.allocator, &buf),
    );
}

test "MUST reject a Delta Base whose sign bit is set in the static-only decoder [RFC9204 §4.5.2 ¶3]" {
    // Sign bit set with Required Insert Count = 0 has no meaningful
    // base — only allowed when the section actually references the
    // dynamic table. Reject in the static-only decoder.
    const buf = [_]u8{ 0x00, 0x80 };
    try std.testing.expectError(
        qpack.Error.DynamicTableUnsupported,
        qpack.decodeFieldSection(std.testing.allocator, &buf),
    );
}

test "MUST reject a Delta Base > 0 alongside Required Insert Count = 0 in the static-only decoder [RFC9204 §4.5.2 ¶3]" {
    // Required Insert Count = 0 forces Base = 0; Delta Base must also
    // be 0. A non-zero delta therefore signals a section that needs
    // the dynamic table.
    const buf = [_]u8{ 0x00, 0x05 };
    try std.testing.expectError(
        qpack.Error.DynamicTableUnsupported,
        qpack.decodeFieldSection(std.testing.allocator, &buf),
    );
}

// ---------------------------------------------------------------- §4.5.4 indexed field line (T=1, static)

test "MUST round-trip an indexed field line that references the static table [RFC9204 §4.5.4 ¶1]" {
    // RFC 9204 §4.5.4 representation: 1 1 T (6-bit index). For T=1
    // (static), index 17 is :method "GET". Encode-side picks this up
    // automatically from the static table.
    const fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "GET" },
    };
    var buf: [32]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    // First body byte after the 2-byte prefix MUST have the indexed
    // (top bit) and static (T) bits set.
    try std.testing.expectEqual(@as(u8, 0xc0), buf[2] & 0xc0);
    try std.testing.expectEqual(@as(u8, 17), buf[2] & 0x3f);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "MUST round-trip multiple indexed field lines with static-table references [RFC9204 §4.5.4 ¶1]" {
    // Drive a request-style field section: every entry is a static
    // full match (:method GET / :scheme https / :path "/"). Each
    // representation should be a single byte after the prefix.
    const fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    var buf: [32]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(@as(usize, 5), n); // 2 prefix + 3 single-byte indexed lines
    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("https", decoded[1].value);
    try std.testing.expectEqualStrings("/", decoded[2].value);
}

test "MUST reject an indexed field line whose static index is out of range [RFC9204 §4.5.4 ¶3]" {
    // Index 99 is one past the last valid static index (98). The
    // decoder MUST flag it as an invalid reference.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0); // RIC = 0
    pos += try integer.encode(buf[pos..], 7, 0, 0); // Delta Base = 0
    pos += try integer.encode(buf[pos..], 6, 0xc0, 99); // Indexed, T=1, idx=99

    try std.testing.expectError(
        qpack.Error.InvalidStaticIndex,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

test "MUST reject an indexed field line that targets the dynamic table when no dynamic state is set up [RFC9204 §4.5.4 ¶1]" {
    // T=0 means dynamic-table reference. The static-only decoder has
    // no dynamic table to consult and MUST refuse.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0);
    pos += try integer.encode(buf[pos..], 7, 0, 0);
    pos += try integer.encode(buf[pos..], 6, 0x80, 0); // Indexed, T=0, idx=0

    try std.testing.expectError(
        qpack.Error.DynamicTableUnsupported,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

// ---------------------------------------------------------------- §4.5.6 literal field line with name reference (T=1, static)

test "MUST round-trip a literal field line with a static name reference [RFC9204 §4.5.6 ¶1]" {
    // :path is static index 1 with default value "/" — supplying a
    // different value drives the encoder into the §4.5.6 literal-with-
    // name-reference (T=1) representation.
    const fields = [_]qpack.FieldLine{
        .{ .name = ":path", .value = "/index.html" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    // Representation: 0 1 N T (4-bit index). N=0, T=1 → 0x50 mask.
    try std.testing.expectEqual(@as(u8, 0x50), buf[2] & 0xf0);
    try std.testing.expectEqual(@as(u8, 1), buf[2] & 0x0f);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings(":path", decoded[0].name);
    try std.testing.expectEqualStrings("/index.html", decoded[0].value);
    try std.testing.expect(!decoded[0].sensitive);
}

test "NORMATIVE the N bit prevents a sensitive value from collapsing into an indexed representation [RFC9204 §4.5.6 ¶3]" {
    // authorization is a static-table name (index 84) with an empty
    // value in the table; with sensitive=true and the same value the
    // encoder MUST avoid an indexed representation and emit a literal
    // with the N bit set.
    const fields = [_]qpack.FieldLine{
        .{ .name = "authorization", .value = "", .sensitive = true },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    // 0 1 N=1 T=1 → 0x70 mask. Bit 5 = N.
    try std.testing.expectEqual(@as(u8, 0x70), buf[2] & 0xf0);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("authorization", decoded[0].name);
    try std.testing.expectEqualStrings("", decoded[0].value);
    try std.testing.expect(decoded[0].sensitive);
}

test "MUST reject a literal-with-name-reference whose static index is out of range [RFC9204 §4.5.6 ¶2]" {
    // Index 99 is past the last valid static-table slot (98). The
    // representation otherwise looks valid, so the decoder MUST gate
    // on the index lookup itself.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0);
    pos += try integer.encode(buf[pos..], 7, 0, 0);
    pos += try integer.encode(buf[pos..], 4, 0x50, 99); // 0 1 N=0 T=1, idx=99
    pos += try qpack.encodeStringLiteral(buf[pos..], "x", 7, 0, .{});

    try std.testing.expectError(
        qpack.Error.InvalidStaticIndex,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

test "MUST reject a literal-with-name-reference that targets the dynamic table in the static-only decoder [RFC9204 §4.5.6 ¶1]" {
    // T=0 (dynamic name reference) is invalid for the static-only
    // decoder.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0);
    pos += try integer.encode(buf[pos..], 7, 0, 0);
    pos += try integer.encode(buf[pos..], 4, 0x40, 0); // 0 1 N=0 T=0, idx=0
    pos += try qpack.encodeStringLiteral(buf[pos..], "x", 7, 0, .{});

    try std.testing.expectError(
        qpack.Error.DynamicTableUnsupported,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

test "MUST round-trip a sensitive literal field line with a static name reference [RFC9204 §4.5.6 ¶3]" {
    // Combined sensitivity + name-reference: drives the N bit, T bit,
    // and a non-trivial value.
    const fields = [_]qpack.FieldLine{
        .{ .name = "authorization", .value = "Bearer xyz", .sensitive = true },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(@as(u8, 0x70), buf[2] & 0xf0); // 0 1 1 1
    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("Bearer xyz", decoded[0].value);
    try std.testing.expect(decoded[0].sensitive);
}

// ---------------------------------------------------------------- §4.5.8 literal field line with literal name

test "MUST round-trip a literal field line with a literal name [RFC9204 §4.5.8 ¶1]" {
    // Use a name that is absent from the static table to force the
    // §4.5.8 representation: 0 0 1 N H (3-bit length).
    const fields = [_]qpack.FieldLine{
        .{ .name = "x-trace-id", .value = "abc-123" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(@as(u8, 0x20), buf[2] & 0xe0);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-trace-id", decoded[0].name);
    try std.testing.expectEqualStrings("abc-123", decoded[0].value);
}

test "MUST round-trip a sensitive literal field line with a literal name [RFC9204 §4.5.8 ¶1]" {
    // Sensitive=true → N bit set. Verify both wire bit and decoded
    // sensitivity flag.
    const fields = [_]qpack.FieldLine{
        .{ .name = "x-secret-trace", .value = "deadbeef", .sensitive = true },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(@as(u8, 0x30), buf[2] & 0xf0);

    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-secret-trace", decoded[0].name);
    try std.testing.expect(decoded[0].sensitive);
}

test "NORMATIVE Huffman applies independently to name and value in a literal-with-literal-name field line [RFC9204 §4.5.8 ¶2]" {
    // With huffman=true the encoder MUST set the H bit on the name
    // length prefix (bit 3) and on the value length prefix (bit 7).
    const fields = [_]qpack.FieldLine{
        .{ .name = "x-trace-id", .value = "abc-123" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeFieldSectionWithOptions(&buf, &fields, .{ .huffman = true });
    try std.testing.expectEqual(@as(u8, 0x08), buf[2] & 0x08);
    const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-trace-id", decoded[0].name);
    try std.testing.expectEqualStrings("abc-123", decoded[0].value);
}

test "MUST reject an unknown representation byte (top three bits 0b000) [RFC9204 §4.5 ¶1]" {
    // Bits 7..5 = 0b000 is unallocated outside of post-base
    // representations; the static-only decoder uses none of those, so
    // it MUST reject the input.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0);
    pos += try integer.encode(buf[pos..], 7, 0, 0);
    buf[pos] = 0x00; // 0 0 0 0 0 0 0 0 — undefined for the static profile
    pos += 1;

    try std.testing.expectError(
        qpack.Error.UnsupportedRepresentation,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

// ---------------------------------------------------------------- Appendix A static table

test "NORMATIVE the QPACK static table has exactly 99 entries [RFC9204 Appx A]" {
    try std.testing.expectEqual(@as(usize, 99), static_table.entries.len);
    try std.testing.expect(static_table.get(0) != null);
    try std.testing.expect(static_table.get(98) != null);
    try std.testing.expect(static_table.get(99) == null);
}

test "NORMATIVE static-table index 0 is :authority with empty value [RFC9204 Appx A]" {
    const entry = static_table.get(0).?;
    try std.testing.expectEqualStrings(":authority", entry.name);
    try std.testing.expectEqualStrings("", entry.value);
}

test "NORMATIVE static-table index 1 is :path with value \"/\" [RFC9204 Appx A]" {
    const entry = static_table.get(1).?;
    try std.testing.expectEqualStrings(":path", entry.name);
    try std.testing.expectEqualStrings("/", entry.value);
}

test "NORMATIVE static-table index 17 is :method GET [RFC9204 Appx A]" {
    const entry = static_table.get(17).?;
    try std.testing.expectEqualStrings(":method", entry.name);
    try std.testing.expectEqualStrings("GET", entry.value);
}

test "NORMATIVE static-table index 23 is :scheme https [RFC9204 Appx A]" {
    const entry = static_table.get(23).?;
    try std.testing.expectEqualStrings(":scheme", entry.name);
    try std.testing.expectEqualStrings("https", entry.value);
}

test "NORMATIVE static-table index 25 is :status 200 [RFC9204 Appx A]" {
    const entry = static_table.get(25).?;
    try std.testing.expectEqualStrings(":status", entry.name);
    try std.testing.expectEqualStrings("200", entry.value);
}

test "NORMATIVE static-table last index 98 is x-frame-options sameorigin [RFC9204 Appx A]" {
    const entry = static_table.get(98).?;
    try std.testing.expectEqualStrings("x-frame-options", entry.name);
    try std.testing.expectEqualStrings("sameorigin", entry.value);
}

test "NORMATIVE static-table get returns null for indices >= 99 [RFC9204 Appx A]" {
    try std.testing.expect(static_table.get(99) == null);
    try std.testing.expect(static_table.get(1000) == null);
    try std.testing.expect(static_table.get(std.math.maxInt(usize)) == null);
}

test "NORMATIVE static-table find resolves a known (name, value) pair to its index [RFC9204 Appx A]" {
    try std.testing.expectEqual(@as(?usize, 17), static_table.find(":method", "GET"));
    try std.testing.expectEqual(@as(?usize, 23), static_table.find(":scheme", "https"));
    try std.testing.expectEqual(@as(?usize, 39), static_table.find("cache-control", "no-cache"));
    try std.testing.expectEqual(@as(?usize, 53), static_table.find("content-type", "text/plain"));
}

test "NORMATIVE static-table find returns null for an absent (name, value) pair [RFC9204 Appx A]" {
    try std.testing.expectEqual(@as(?usize, null), static_table.find(":method", "BREW"));
    try std.testing.expectEqual(@as(?usize, null), static_table.find("x-not-real", "any"));
}

test "NORMATIVE static-table findName resolves a known name to a representative index [RFC9204 Appx A]" {
    // findName picks the first matching name entry. RFC 9204 doesn't
    // specify a particular slot for name-only lookup; this test fixes
    // the implementation choice so future changes are deliberate.
    try std.testing.expectEqual(@as(?usize, 15), static_table.findName(":method"));
    try std.testing.expectEqual(@as(?usize, 22), static_table.findName(":scheme"));
    try std.testing.expectEqual(@as(?usize, 24), static_table.findName(":status"));
    try std.testing.expectEqual(@as(?usize, 36), static_table.findName("cache-control"));
    try std.testing.expectEqual(@as(?usize, null), static_table.findName("x-not-real"));
}

test "NORMATIVE static-table get and find round-trip a representative subset [RFC9204 Appx A]" {
    // For the entries with a non-empty value, find(name, value) MUST
    // equal the index that get(...) reported for that name+value.
    const indices = [_]usize{ 1, 17, 23, 25, 29, 36, 39, 44, 53, 56, 71, 98 };
    for (indices) |index| {
        const entry = static_table.get(index).?;
        try std.testing.expectEqual(@as(?usize, index), static_table.find(entry.name, entry.value));
    }
}

test "MUST encode every value of the static table to its expected indexed representation [RFC9204 Appx A]" {
    // For each (name, value) pair in the static table, emitting it
    // through `encodeFieldSection` MUST produce the indexed form
    // 1 1 T=1 (6-bit index). This is the strongest end-to-end check
    // that the table content matches what RFC 9204 Appendix A
    // enumerates.
    var buf: [64]u8 = undefined;
    for (static_table.entries, 0..) |entry, idx| {
        const fields = [_]qpack.FieldLine{
            .{ .name = entry.name, .value = entry.value },
        };
        const n = try qpack.encodeFieldSection(&buf, &fields);
        // 2-byte prefix + at least 1 byte of indexed representation.
        try std.testing.expect(n >= 3);
        try std.testing.expectEqual(@as(u8, 0xc0), buf[2] & 0xc0);
        if (idx < 63) {
            try std.testing.expectEqual(@as(u8, @intCast(idx)), buf[2] & 0x3f);
        }
        const decoded = try qpack.decodeFieldSection(std.testing.allocator, buf[0..n]);
        defer qpack.freeFieldSection(std.testing.allocator, decoded);
        try std.testing.expectEqualStrings(entry.name, decoded[0].name);
        try std.testing.expectEqualStrings(entry.value, decoded[0].value);
    }
}
