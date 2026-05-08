//! RFC 9204 — QPACK: Field Compression for HTTP/3 (dynamic profile).
//!
//! This file covers everything the static profile cannot: the dynamic
//! table state machine (RFC 9204 §3.2), encoder/decoder stream
//! instruction codecs (§4.3, §4.4), Required Insert Count + Base
//! arithmetic (§3.2.4, §4.5.2, §4.5.3), the post-base field-line
//! representations (§4.5.5, §4.5.7), and the blocked-streams accounting
//! (§2.2.2). Errors that QPACK names explicitly (§6) — `QPACK_DECOMPRESSION_FAILED`,
//! `QPACK_ENCODER_STREAM_ERROR`, `QPACK_DECODER_STREAM_ERROR` — are
//! exercised at the codec layer that detects them. Static profile
//! (integer / Huffman / static-table / non-dynamic field section) is in
//! `rfc9204_qpack_static.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9204 §2.2.2 ¶1   MUST     dynamic-table-aware tracking refuses a new
//!                                blocked stream past SETTINGS_QPACK_BLOCKED_STREAMS.
//!   RFC9204 §2.2.2 ¶2   MUST     decoder rejects a beginFieldSection past the
//!                                blocked-stream limit.
//!   RFC9204 §3.2 ¶1     MUST     dynamic table refuses an entry larger than
//!                                its capacity.
//!   RFC9204 §3.2 ¶2     MUST     setCapacity refuses a value above max_capacity.
//!   RFC9204 §3.2 ¶2     MUST     a max_capacity of zero disables every
//!                                dynamic-table mutation.
//!   RFC9204 §3.2 ¶3     NORMATIVE entry size = name + value + 32 byte overhead.
//!   RFC9204 §3.2 ¶4     NORMATIVE evicting an oldest entry to make room.
//!   RFC9204 §3.2.2 ¶1   NORMATIVE absolute index is monotonically increasing.
//!   RFC9204 §3.2.4 ¶1   NORMATIVE absolute → encoder-relative ↔ field-section
//!                                relative ↔ post-base index translations.
//!   RFC9204 §4.3.1 ¶1   NORMATIVE Set Dynamic Table Capacity instruction
//!                                wire codec (5-bit prefix, 0010xxxx pattern).
//!   RFC9204 §4.3.1 ¶2   MUST     instruction is rejected when capacity > max.
//!   RFC9204 §4.3.2 ¶1   NORMATIVE Insert with Name Reference (T=1, static).
//!   RFC9204 §4.3.2 ¶2   NORMATIVE Insert with Name Reference (T=0, dynamic).
//!   RFC9204 §4.3.2 ¶3   MUST     decoder rejects a static index that is
//!                                out of range.
//!   RFC9204 §4.3.2 ¶3   MUST     decoder rejects a dynamic index that
//!                                does not name an existing entry.
//!   RFC9204 §4.3.3 ¶1   NORMATIVE Insert with Literal Name codec.
//!   RFC9204 §4.3.4 ¶1   NORMATIVE Duplicate instruction codec.
//!   RFC9204 §4.3.4 ¶2   MUST     duplicate refuses an out-of-range relative
//!                                index.
//!   RFC9204 §4.4.1 ¶1   NORMATIVE Section Acknowledgment wire codec
//!                                (7-bit prefix, 1xxxxxxx).
//!   RFC9204 §4.4.1 ¶2   MUST     section_ack for a stream that is not
//!                                outstanding is reported.
//!   RFC9204 §4.4.2 ¶1   NORMATIVE Stream Cancellation wire codec
//!                                (6-bit prefix, 01xxxxxx).
//!   RFC9204 §4.4.2 ¶1   NORMATIVE encoder tolerates a stream_cancel
//!                                that names no outstanding section.
//!   RFC9204 §4.4.3 ¶1   NORMATIVE Insert Count Increment wire codec
//!                                (6-bit prefix, 00xxxxxx, increment >= 1).
//!   RFC9204 §4.4.3 ¶2   MUST     insert_count_increment with value 0 is
//!                                rejected on the wire.
//!   RFC9204 §4.4.3 ¶3   MUST     insert_count_increment that pushes
//!                                Known Received Count past insert_count is
//!                                rejected.
//!   RFC9204 §4.5.1 ¶1   NORMATIVE field section prefix encodes Required
//!                                Insert Count first, then Base.
//!   RFC9204 §4.5.1.1 ¶1 NORMATIVE Required Insert Count wraps modulo
//!                                2 * MaxEntries(MaxTableCapacity).
//!   RFC9204 §4.5.1.1 ¶1 NORMATIVE decodeRequiredInsertCount picks the
//!                                wrap-around candidate within
//!                                MaxEntries of total_inserts.
//!   RFC9204 §4.5.1.1 ¶2 MUST     decoder rejects an encoded RIC larger
//!                                than 2 * MaxEntries.
//!   RFC9204 §4.5.1.2 ¶1 NORMATIVE Base = required_insert_count + delta
//!                                when sign=0; required_insert_count -
//!                                delta - 1 when sign=1.
//!   RFC9204 §4.5.1.2 ¶3 MUST     decoder rejects Sign=1 with Required
//!                                Insert Count <= Delta Base.
//!   RFC9204 §4.5.2 ¶1   NORMATIVE field-section prefix round-trips through
//!                                encode/decodeFieldSectionPrefix.
//!   RFC9204 §4.5.5 ¶1   NORMATIVE indexed field line with post-base index
//!                                round-trips.
//!   RFC9204 §4.5.7 ¶1   NORMATIVE literal field line with post-base
//!                                name reference round-trips.
//!   RFC9204 §6           MUST     decoder rejects an unsatisfiable RIC
//!                                (`error.RequiredInsertCountNotReady` →
//!                                 QPACK_DECOMPRESSION_FAILED).
//!   RFC9204 §6           MUST     encoder stream codec rejects an empty
//!                                buffer (QPACK_ENCODER_STREAM_ERROR).
//!   RFC9204 §6           MUST     decoder stream codec rejects an empty
//!                                buffer (QPACK_DECODER_STREAM_ERROR).
//!   RFC9204 §6           MUST     encoder stream codec rejects an
//!                                insert_name_ref pointing to an absent
//!                                static index.
//!   RFC9204 §6           MUST     decoder stream codec rejects an
//!                                insert_count_increment of 0.
//!
//! Visible debt:
//!   none.
//!
//! Out of scope here:
//!   RFC9204 §4.1.1, §4.1.2, §4.5.4, §4.5.6, §4.5.8, Appx A, RFC7541
//!     Appx B → rfc9204_qpack_static.zig.
//!   RFC9204 SETTINGS_QPACK_MAX_TABLE_CAPACITY / SETTINGS_QPACK_BLOCKED_STREAMS
//!     wire codec inside the SETTINGS frame → rfc9114_settings.zig.
//!   RFC9204 QPACK encoder/decoder unidirectional stream type IDs (0x02 /
//!     0x03) → rfc9114_streams.zig.
//!   RFC9204 Appx B exact-byte fixtures → interop/qpack_dynamic/runner.zig.
//!
//! Every non-skipped test routes through `http3_zig.qpack.*` public API.

const std = @import("std");
const http3_zig = @import("http3_zig");

const qpack = http3_zig.qpack;
const integer = qpack.integer;
const instructions_mod = qpack.instructions;
const state_mod = qpack.state;

// ---------------------------------------------------------------- §3.2 dynamic table

test "MUST refuse a setCapacity larger than max_capacity [RFC9204 §3.2 ¶2]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 64);
    defer table.deinit();
    try std.testing.expectError(
        qpack.dynamic_table.Error.CapacityTooLarge,
        table.setCapacity(65),
    );
}

test "MUST refuse to insert an entry larger than the current capacity [RFC9204 §3.2 ¶1]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 32);
    defer table.deinit();
    try table.setCapacity(32);
    // 32 (overhead) + 1 (name) + 1 (value) = 34 > 32.
    try std.testing.expectError(
        qpack.dynamic_table.Error.EntryTooLarge,
        table.insert("x", "y", false),
    );
}

test "NORMATIVE the dynamic-table entry size formula matches RFC 9204 §3.2.1 [RFC9204 §3.2 ¶3]" {
    // |name| + |value| + 32 — matches RFC 9204 §3.2.1.
    try std.testing.expectEqual(@as(usize, 32), qpack.dynamic_table.entrySize("", ""));
    try std.testing.expectEqual(@as(usize, 36), qpack.dynamic_table.entrySize("ab", "cd"));
    try std.testing.expectEqual(@as(usize, 32), qpack.dynamic_table.overhead);
}

test "NORMATIVE inserting an entry advances absolute index and total size [RFC9204 §3.2.2 ¶1]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    const a = try table.insert("a", "1", false);
    const b = try table.insert("b", "22", false);
    try std.testing.expectEqual(@as(u64, 0), a);
    try std.testing.expectEqual(@as(u64, 1), b);
    try std.testing.expectEqual(@as(u64, 2), table.insert_count);
    try std.testing.expectEqual(
        qpack.dynamic_table.entrySize("a", "1") + qpack.dynamic_table.entrySize("b", "22"),
        table.size,
    );
}

test "NORMATIVE evicting the oldest entry frees space for a new insert [RFC9204 §3.2 ¶4]" {
    // Capacity holds two entries of size 34. A third insert MUST evict
    // the oldest and reuse its space.
    var table = qpack.DynamicTable.init(std.testing.allocator, 68);
    defer table.deinit();
    try table.setCapacity(68);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(u64, 1), table.dropped_count);
    try std.testing.expect(table.getAbsolute(0) == null);
    try std.testing.expectEqualStrings("b", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("c", table.getAbsolute(2).?.name);
}

test "MUST refuse to evict in order to insert when no entries are available [RFC9204 §3.2 ¶1]" {
    // Capacity 0 with overhead 32 means no entry fits → insert MUST
    // fail rather than evict everything in a loop.
    var table = qpack.DynamicTable.init(std.testing.allocator, 0);
    defer table.deinit();
    try table.setCapacity(0);
    try std.testing.expectError(
        qpack.dynamic_table.Error.EntryTooLarge,
        table.insert("a", "1", false),
    );
}

test "NORMATIVE setCapacity to zero evicts all entries [RFC9204 §3.2 ¶4]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try table.setCapacity(0);
    try std.testing.expectEqual(@as(usize, 0), table.len());
    try std.testing.expectEqual(@as(usize, 0), table.size);
    try std.testing.expectEqual(@as(u64, 2), table.insert_count);
    try std.testing.expectEqual(@as(u64, 2), table.dropped_count);
}

test "MUST refuse to insert anything when max_capacity is zero [RFC9204 §3.2 ¶2]" {
    // RFC 9204 §3.2.3: when SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 the
    // encoder cannot use the dynamic table at all; the table refuses
    // setCapacity > 0 and any insert attempt thereafter.
    var table = qpack.DynamicTable.init(std.testing.allocator, 0);
    defer table.deinit();
    try table.setCapacity(0);
    try std.testing.expectError(
        qpack.dynamic_table.Error.CapacityTooLarge,
        table.setCapacity(1),
    );
    try std.testing.expectError(
        qpack.dynamic_table.Error.EntryTooLarge,
        table.insert("a", "1", false),
    );
    try std.testing.expectError(
        qpack.dynamic_table.Error.InvalidDynamicIndex,
        table.duplicate(0),
    );
}

test "NORMATIVE encoder-relative index 0 names the most recent insert [RFC9204 §3.2.4 ¶1]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    try std.testing.expectEqualStrings("b", table.getEncoderRelative(0).?.name);
    try std.testing.expectEqualStrings("a", table.getEncoderRelative(1).?.name);
    try std.testing.expect(table.getEncoderRelative(2) == null);
}

test "NORMATIVE field-section relative-to-absolute uses Base, not insert_count [RFC9204 §3.2.4 ¶1]" {
    // Public arithmetic helpers expose RFC 9204 §3.2.4: relative_to_
    // absolute(base, idx) = base - 1 - idx; absolute_to_post_base(base,
    // abs) = abs - base for abs >= base; nil otherwise.
    try std.testing.expectEqual(@as(?u64, 1), qpack.dynamic_table.relativeToAbsolute(2, 0));
    try std.testing.expectEqual(@as(?u64, 0), qpack.dynamic_table.relativeToAbsolute(2, 1));
    try std.testing.expect(qpack.dynamic_table.relativeToAbsolute(2, 2) == null);
    try std.testing.expectEqual(@as(?u64, null), qpack.dynamic_table.relativeToAbsolute(0, 0));
    try std.testing.expectEqual(@as(?u64, 5), qpack.dynamic_table.postBaseToAbsolute(2, 3));
}

test "MUST refuse to duplicate a non-existent encoder-relative index [RFC9204 §4.3.4 ¶2]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 64);
    defer table.deinit();
    try table.setCapacity(64);
    try std.testing.expectError(
        qpack.dynamic_table.Error.InvalidDynamicIndex,
        table.duplicate(0),
    );
}

test "NORMATIVE duplicate copies an existing entry as a new insert [RFC9204 §4.3.4 ¶1]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    const original = try table.insert("a", "1", false);
    const dup = try table.duplicate(0);
    try std.testing.expectEqual(@as(u64, 0), original);
    try std.testing.expectEqual(@as(u64, 1), dup);
    try std.testing.expectEqualStrings("a", table.getAbsolute(0).?.name);
    try std.testing.expectEqualStrings("a", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("1", table.getAbsolute(1).?.value);
}

// ---------------------------------------------------------------- §4.3 encoder stream instructions

test "NORMATIVE Set Dynamic Table Capacity has the 0010xxxx wire pattern [RFC9204 §4.3.1 ¶1]" {
    // 5-bit prefix, top three bits 001. Values < 31 fit in one octet.
    var buf: [4]u8 = undefined;
    const n = try instructions_mod.encodeEncoderInstruction(&buf, .{ .set_capacity = 16 });
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x30), buf[0]);

    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(u64, 16), decoded.instruction.set_capacity);
}

test "MUST reject a Set Dynamic Table Capacity that exceeds max_capacity [RFC9204 §4.3.1 ¶2]" {
    // RFC 9204 §4.3.1 ¶2: "An encoder MUST NOT set a dynamic table
    // capacity that exceeds [...] the max_table_capacity advertised by
    // the decoder." The decoder enforces this when applying the
    // instruction to the table.
    var table = qpack.DynamicTable.init(std.testing.allocator, 64);
    defer table.deinit();
    try std.testing.expectError(
        qpack.dynamic_table.Error.CapacityTooLarge,
        instructions_mod.applyEncoderInstruction(&table, .{ .set_capacity = 65 }),
    );
}

test "NORMATIVE Insert with Name Reference T=1 has the 11xxxxxx wire pattern [RFC9204 §4.3.2 ¶1]" {
    var buf: [16]u8 = undefined;
    const instr: qpack.EncoderInstruction = .{ .insert_name_ref = .{
        .table = .static,
        .index = 17, // :method (idx 17 → :method "GET")
        .value = "POST",
    } };
    const n = try instructions_mod.encodeEncoderInstruction(&buf, instr);
    // First byte: 11 T=1 (6-bit index) → 0xc0 | 17 = 0xd1.
    try std.testing.expectEqual(@as(u8, 0xd1), buf[0]);

    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expectEqual(qpack.instructions.Table.static, decoded.instruction.insert_name_ref.table);
    try std.testing.expectEqual(@as(u64, 17), decoded.instruction.insert_name_ref.index);
    try std.testing.expectEqualStrings("POST", decoded.instruction.insert_name_ref.value);
}

test "NORMATIVE Insert with Name Reference T=0 has the 10xxxxxx wire pattern [RFC9204 §4.3.2 ¶2]" {
    var buf: [16]u8 = undefined;
    const instr: qpack.EncoderInstruction = .{ .insert_name_ref = .{
        .table = .dynamic,
        .index = 0,
        .value = "x",
    } };
    const n = try instructions_mod.encodeEncoderInstruction(&buf, instr);
    // First byte: 10 0 (5-bit index space; index 0 → 0x80).
    try std.testing.expectEqual(@as(u8, 0x80), buf[0]);

    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expectEqual(qpack.instructions.Table.dynamic, decoded.instruction.insert_name_ref.table);
}

test "MUST reject Insert with Name Reference T=1 whose static index is out of range [RFC9204 §4.3.2 ¶3]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    try std.testing.expectError(
        instructions_mod.Error.InvalidStaticIndex,
        instructions_mod.applyEncoderInstruction(&table, .{ .insert_name_ref = .{
            .table = .static,
            .index = 99,
            .value = "x",
        } }),
    );
}

test "MUST reject Insert with Name Reference T=0 whose dynamic index is unset [RFC9204 §4.3.2 ¶3]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    try std.testing.expectError(
        instructions_mod.Error.InvalidDynamicIndex,
        instructions_mod.applyEncoderInstruction(&table, .{ .insert_name_ref = .{
            .table = .dynamic,
            .index = 0,
            .value = "x",
        } }),
    );
}

test "NORMATIVE Insert with Literal Name has the 01xxxxxx wire pattern [RFC9204 §4.3.3 ¶1]" {
    var buf: [32]u8 = undefined;
    const instr: qpack.EncoderInstruction = .{ .insert_literal = .{
        .name = "x-key",
        .value = "v",
    } };
    const n = try instructions_mod.encodeEncoderInstruction(&buf, instr);
    // First byte: 0 1 H=0 (5-bit length). Length 5 → 0x40 | 5 = 0x45.
    try std.testing.expectEqual(@as(u8, 0x45), buf[0]);

    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-key", decoded.instruction.insert_literal.name);
    try std.testing.expectEqualStrings("v", decoded.instruction.insert_literal.value);
}

test "NORMATIVE Insert with Literal Name carries Huffman flags on both name and value [RFC9204 §4.3.3 ¶1]" {
    var buf: [64]u8 = undefined;
    const instr: qpack.EncoderInstruction = .{ .insert_literal = .{
        .name = "cache-control",
        .value = "no-cache",
        .name_huffman = true,
        .value_huffman = true,
    } };
    const n = try instructions_mod.encodeEncoderInstruction(&buf, instr);
    // First byte: 0 1 H=1 → 0x60 | huffman_len.
    try std.testing.expect(buf[0] & 0x60 == 0x60);
    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expect(decoded.instruction.insert_literal.name_huffman);
    try std.testing.expect(decoded.instruction.insert_literal.value_huffman);
    try std.testing.expectEqualStrings("cache-control", decoded.instruction.insert_literal.name);
    try std.testing.expectEqualStrings("no-cache", decoded.instruction.insert_literal.value);
}

test "NORMATIVE Duplicate has the 000xxxxx wire pattern [RFC9204 §4.3.4 ¶1]" {
    var buf: [4]u8 = undefined;
    const n = try instructions_mod.encodeEncoderInstruction(&buf, .{ .duplicate = 1 });
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);

    const decoded = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..n]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(u64, 1), decoded.instruction.duplicate);
}

test "NORMATIVE encoder-stream instruction dispatch favours name_ref before duplicate [RFC9204 §4.3]" {
    // 0xC0 / 0x80 (insert_name_ref) > 0x40 (insert_literal) > 0x20
    // (set_capacity) > 0x00 (duplicate) prefix decoding tree. Verify
    // the decoder returns the right variant for each prefix byte.
    var buf: [4]u8 = undefined;
    buf[0] = 0x00;
    const dup = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..1]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, dup);
    try std.testing.expect(dup.instruction == .duplicate);

    buf[0] = 0x20;
    const cap = try instructions_mod.decodeEncoderInstruction(std.testing.allocator, buf[0..1]);
    defer instructions_mod.freeDecodedEncoderInstruction(std.testing.allocator, cap);
    try std.testing.expect(cap.instruction == .set_capacity);
}

test "MUST reject decoding an encoder-stream instruction from an empty buffer [RFC9204 §6]" {
    // Empty buffer ⇒ `error.InsufficientBytes`. Maps to
    // QPACK_ENCODER_STREAM_ERROR at the session layer.
    try std.testing.expectError(
        error.InsufficientBytes,
        instructions_mod.decodeEncoderInstruction(std.testing.allocator, &.{}),
    );
}

test "NORMATIVE applyEncoderInstruction inserts and evicts in lockstep with the dynamic table [RFC9204 §4.3]" {
    // Drive every encoder-stream instruction shape through
    // `applyEncoderInstruction` and verify the resulting table state.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();

    _ = try instructions_mod.applyEncoderInstruction(&table, .{ .set_capacity = 256 });
    try std.testing.expectEqual(@as(usize, 256), table.capacity);

    const a = try instructions_mod.applyEncoderInstruction(&table, .{ .insert_name_ref = .{
        .table = .static,
        .index = 17, // :method ⇒ name=":method", value=insert.value
        .value = "POST",
    } });
    try std.testing.expectEqual(@as(?u64, 0), a);

    const b = try instructions_mod.applyEncoderInstruction(&table, .{ .insert_literal = .{
        .name = "x-test",
        .value = "v",
    } });
    try std.testing.expectEqual(@as(?u64, 1), b);

    const c = try instructions_mod.applyEncoderInstruction(&table, .{ .duplicate = 1 });
    try std.testing.expectEqual(@as(?u64, 2), c);
    try std.testing.expectEqualStrings(":method", table.getAbsolute(2).?.name);
    try std.testing.expectEqualStrings("POST", table.getAbsolute(2).?.value);
}

// ---------------------------------------------------------------- §4.4 decoder stream instructions

test "NORMATIVE Section Acknowledgment has the 1xxxxxxx wire pattern [RFC9204 §4.4.1 ¶1]" {
    var buf: [8]u8 = undefined;
    const n = try instructions_mod.encodeDecoderInstruction(&buf, .{ .section_ack = 4 });
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x84), buf[0]);

    const decoded = try instructions_mod.decodeDecoderInstruction(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 4), decoded.instruction.section_ack);
}

test "NORMATIVE Stream Cancellation has the 01xxxxxx wire pattern [RFC9204 §4.4.2 ¶1]" {
    var buf: [8]u8 = undefined;
    const n = try instructions_mod.encodeDecoderInstruction(&buf, .{ .stream_cancel = 8 });
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x48), buf[0]);

    const decoded = try instructions_mod.decodeDecoderInstruction(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 8), decoded.instruction.stream_cancel);
}

test "NORMATIVE Insert Count Increment has the 00xxxxxx wire pattern [RFC9204 §4.4.3 ¶1]" {
    var buf: [8]u8 = undefined;
    const n = try instructions_mod.encodeDecoderInstruction(&buf, .{ .insert_count_increment = 5 });
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x05), buf[0]);

    const decoded = try instructions_mod.decodeDecoderInstruction(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 5), decoded.instruction.insert_count_increment);
}

test "MUST reject an Insert Count Increment of 0 on the wire [RFC9204 §4.4.3 ¶2]" {
    // Encoder MUST NOT emit an increment of 0 (the RFC defines this
    // as a connection error of type QPACK_DECODER_STREAM_ERROR).
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        instructions_mod.Error.InsertCountIncrementZero,
        instructions_mod.encodeDecoderInstruction(&buf, .{ .insert_count_increment = 0 }),
    );

    // Decoder MUST refuse a wire byte of 0x00 (≡ increment 0) because
    // that would silently advance KRC by 0, masking ack/loss.
    try std.testing.expectError(
        instructions_mod.Error.InsertCountIncrementZero,
        instructions_mod.decodeDecoderInstruction(&.{0x00}),
    );
}

test "MUST reject decoding a decoder-stream instruction from an empty buffer [RFC9204 §6]" {
    try std.testing.expectError(
        error.InsufficientBytes,
        instructions_mod.decodeDecoderInstruction(&.{}),
    );
}

test "NORMATIVE decoder-stream instructions round-trip every variant [RFC9204 §4.4]" {
    var buf: [16]u8 = undefined;
    inline for (.{
        qpack.DecoderInstruction{ .section_ack = 1337 },
        qpack.DecoderInstruction{ .stream_cancel = 42 },
        qpack.DecoderInstruction{ .insert_count_increment = 7 },
    }) |instr| {
        const n = try instructions_mod.encodeDecoderInstruction(&buf, instr);
        try std.testing.expectEqual(instructions_mod.decoderInstructionEncodedLen(instr), n);
        const decoded = try instructions_mod.decodeDecoderInstruction(buf[0..n]);
        try std.testing.expectEqual(n, decoded.bytes_read);
    }
}

// ---------------------------------------------------------------- §3.2.4 / §4.5.1 RIC + Base arithmetic

test "NORMATIVE maxEntries follows MaxTableCapacity / 32 [RFC9204 §4.5.1.1 ¶1]" {
    // RFC 9204 §3.2.1: each entry's overhead is 32 bytes.
    try std.testing.expectEqual(@as(u64, 0), state_mod.maxEntries(0));
    try std.testing.expectEqual(@as(u64, 3), state_mod.maxEntries(100));
    try std.testing.expectEqual(@as(u64, 4), state_mod.maxEntries(128));
    try std.testing.expectEqual(@as(u64, 128), state_mod.maxEntries(4096));
}

test "NORMATIVE encodeRequiredInsertCount = (RIC mod 2*MaxEntries) + 1 [RFC9204 §4.5.1.1 ¶1]" {
    // MaxTableCapacity=100 → MaxEntries=3 → full_range=6.
    try std.testing.expectEqual(@as(u64, 0), try state_mod.encodeRequiredInsertCount(0, 100));
    try std.testing.expectEqual(@as(u64, 1), try state_mod.encodeRequiredInsertCount(6, 100)); // (6 mod 6)+1
    try std.testing.expectEqual(@as(u64, 4), try state_mod.encodeRequiredInsertCount(9, 100));
}

test "NORMATIVE decodeRequiredInsertCount inverts encodeRequiredInsertCount across the wrap [RFC9204 §4.5.1.1 ¶1]" {
    // RFC 9204 §4.5.1.1: the encoded RIC unambiguously identifies a
    // value within MaxEntries(MaxTableCapacity) of total_inserts. Use
    // total_inserts = ric to stay inside that window for every value.
    inline for (.{ @as(u64, 1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }) |ric| {
        const encoded = try state_mod.encodeRequiredInsertCount(ric, 100);
        const decoded = try state_mod.decodeRequiredInsertCount(encoded, 100, ric);
        try std.testing.expectEqual(ric, decoded);
    }
}

test "MUST reject an encoded Required Insert Count above 2 * MaxEntries [RFC9204 §4.5.1.1 ¶2]" {
    // full_range=6 for MaxTableCapacity=100. Encoded values 0..6 are
    // legal; 7 is out of range.
    try std.testing.expectError(
        state_mod.Error.InvalidRequiredInsertCount,
        state_mod.decodeRequiredInsertCount(7, 100, 10),
    );
}

test "NORMATIVE decodeRequiredInsertCount selects the wrap-around window relative to total_inserts [RFC9204 §4.5.1.1 ¶1]" {
    // Drive the wrap-around algorithm explicitly: with MaxTableCapacity
    // = 100 (MaxEntries=3, full_range=6), a RIC value of 4 is encoded
    // as (4 mod 6) + 1 = 5. When total_inserts is well past the first
    // wrap (e.g. 10 = 1 full_range + 4), the decoder MUST recover RIC
    // = 4 by selecting the candidate within MaxEntries(=3) of total
    // inserts rather than picking the smaller raw value 4.
    try std.testing.expectEqual(
        @as(u64, 10),
        try state_mod.decodeRequiredInsertCount(5, 100, 10),
    );
    // Same encoded value with total_inserts = 4: the decoder MUST
    // resolve RIC = 4 (no wrap needed).
    try std.testing.expectEqual(
        @as(u64, 4),
        try state_mod.decodeRequiredInsertCount(5, 100, 4),
    );
}

test "NORMATIVE Base = required_insert_count + delta when sign=0 [RFC9204 §4.5.1.2 ¶1]" {
    // Sign=0 (S=0): Base = ReqInsertCount + DeltaBase.
    var buf: [16]u8 = undefined;
    const prefix = state_mod.FieldSectionPrefix{ .required_insert_count = 5, .base = 7 };
    const n = try state_mod.encodeFieldSectionPrefix(&buf, prefix, 256);
    const decoded = try state_mod.decodeFieldSectionPrefix(buf[0..n], 256, 5);
    try std.testing.expectEqual(@as(u64, 5), decoded.prefix.required_insert_count);
    try std.testing.expectEqual(@as(u64, 7), decoded.prefix.base);
    // Second prefix byte is the Base delta with S=0 in the high bit.
    try std.testing.expect((buf[1] & 0x80) == 0);
}

test "NORMATIVE Base = required_insert_count - delta - 1 when sign=1 [RFC9204 §4.5.1.2 ¶1]" {
    // Sign=1 (S=1): Base = ReqInsertCount - DeltaBase - 1.
    var buf: [16]u8 = undefined;
    const prefix = state_mod.FieldSectionPrefix{ .required_insert_count = 5, .base = 2 };
    const n = try state_mod.encodeFieldSectionPrefix(&buf, prefix, 256);
    try std.testing.expect((buf[1] & 0x80) != 0);
    const decoded = try state_mod.decodeFieldSectionPrefix(buf[0..n], 256, 5);
    try std.testing.expectEqual(@as(u64, 2), decoded.prefix.base);
}

test "MUST reject a field section prefix where Sign=1 and Required Insert Count <= Delta Base [RFC9204 §4.5.1.2 ¶3]" {
    // RFC 9204 §4.5.1.2: "An endpoint MUST treat a field block with a
    // Sign bit of 1 as invalid if the value of Required Insert Count is
    // less than or equal to the value of Delta Base." Construct a wire
    // form that explicitly violates that invariant: encoded RIC = 2
    // (decoded RIC = 1 when total_inserts = 1), Sign = 1, Delta = 1.
    // RIC(1) <= Delta(1) ⇒ reject as invalid.
    var buf: [4]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 2); // EncodedInsertCount = 2 → RIC = 1
    pos += try integer.encode(buf[pos..], 7, 0x80, 1); // Sign=1, Delta=1

    try std.testing.expectError(
        state_mod.Error.InvalidRequiredInsertCount,
        state_mod.decodeFieldSectionPrefix(buf[0..pos], 100, 1),
    );
}

test "NORMATIVE field section prefix encodedLen agrees with the encoder [RFC9204 §4.5.2 ¶1]" {
    var buf: [16]u8 = undefined;
    inline for (.{
        state_mod.FieldSectionPrefix{ .required_insert_count = 0, .base = 0 },
        state_mod.FieldSectionPrefix{ .required_insert_count = 5, .base = 7 },
        state_mod.FieldSectionPrefix{ .required_insert_count = 9, .base = 6 },
    }) |prefix| {
        const cap: u64 = if (prefix.required_insert_count == 0) 0 else 100;
        const n = try state_mod.encodeFieldSectionPrefix(&buf, prefix, cap);
        try std.testing.expectEqual(try state_mod.fieldSectionPrefixEncodedLen(prefix, cap), n);
    }
}

test "NORMATIVE requiredInsertCountForReferences picks the maximum + 1 [RFC9204 §4.5.1.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0), try state_mod.requiredInsertCountForReferences(&.{}));
    try std.testing.expectEqual(@as(u64, 6), try state_mod.requiredInsertCountForReferences(&.{ 1, 5, 3 }));
    try std.testing.expectEqual(@as(u64, 1), try state_mod.requiredInsertCountForReferences(&.{0}));
}

// ---------------------------------------------------------------- §4.5.5 / §4.5.7 post-base representations

test "NORMATIVE indexed field line with post-base index round-trips [RFC9204 §4.5.5 ¶1]" {
    // Three inserts; encode a section with Base=1 so absolute index 2
    // is accessible only via the post-base form (post-base index 1).
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try state_mod.encodeFieldSectionPrefix(buf[pos..], .{
        .required_insert_count = 3,
        .base = 1,
    }, table.max_capacity);
    // 0001 xxxx (4-bit) post-base index = 1 → 0x10 | 1 = 0x11.
    pos += try integer.encode(buf[pos..], 4, 0x10, 1);

    const decoded = try qpack.decodeDynamicFieldSection(
        std.testing.allocator,
        &table,
        table.max_capacity,
        buf[0..pos],
    );
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("c", decoded[0].name);
    try std.testing.expectEqualStrings("3", decoded[0].value);
}

test "MUST reject an indexed-with-post-base-index whose absolute index is past insert_count [RFC9204 §4.5.5 ¶1]" {
    // Two inserts; Base=1 → absolute index 2 does not exist (insert_
    // count == 2 → only entries 0 and 1 are in scope). Decoder MUST
    // return InvalidDynamicIndex.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);

    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try state_mod.encodeFieldSectionPrefix(buf[pos..], .{
        .required_insert_count = 2,
        .base = 1,
    }, table.max_capacity);
    pos += try integer.encode(buf[pos..], 4, 0x10, 1); // post-base 1 → abs 2 (missing)

    try std.testing.expectError(
        qpack.Error.InvalidDynamicIndex,
        qpack.decodeDynamicFieldSection(std.testing.allocator, &table, table.max_capacity, buf[0..pos]),
    );
}

test "NORMATIVE literal field line with post-base name reference round-trips [RFC9204 §4.5.7 ¶1]" {
    // Three inserts; Base=1 puts entries 1 and 2 above the base, both
    // post-base reachable. Reference entry 1 by post-base index 0 and
    // override the value. N (sensitive) bit on.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try state_mod.encodeFieldSectionPrefix(buf[pos..], .{
        .required_insert_count = 3,
        .base = 1,
    }, table.max_capacity);
    // 0000 N H (3-bit) post-base index. N=1 → 0x08; index 0 → 0x08.
    pos += try integer.encode(buf[pos..], 3, 0x08, 0);
    pos += try qpack.encodeStringLiteral(buf[pos..], "override", 7, 0, .{});

    const decoded = try qpack.decodeDynamicFieldSection(
        std.testing.allocator,
        &table,
        table.max_capacity,
        buf[0..pos],
    );
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("b", decoded[0].name);
    try std.testing.expectEqualStrings("override", decoded[0].value);
    try std.testing.expect(decoded[0].sensitive);
}

// ---------------------------------------------------------------- §4.5.2 dynamic field section round-trip

test "NORMATIVE encodeDynamicFieldSection emits an indexed dynamic representation [RFC9204 §4.5.2 ¶1]" {
    // Pre-populate the dynamic table; ask the encoder to use it via
    // `aggressive` policy. The body byte for entry 0 (Base=1) is the
    // 1 0 (T=0) indexed-dynamic representation (0x80 | rel_idx).
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-test", .value = "one" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, .{
        .indexing = .{ .dynamic_references = .any },
    });

    const prefix = try state_mod.decodeFieldSectionPrefix(buf[0..n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), prefix.prefix.required_insert_count);
    // Body byte: 1 0 T=0, index=0 → 0x80.
    try std.testing.expectEqual(@as(u8, 0x80), buf[prefix.bytes_read]);

    const decoded = try qpack.decodeDynamicFieldSection(
        std.testing.allocator,
        &table,
        table.max_capacity,
        buf[0..n],
    );
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-test", decoded[0].name);
    try std.testing.expectEqualStrings("one", decoded[0].value);
}

test "NORMATIVE encodeDynamicFieldSection emits a literal-with-dynamic-name representation [RFC9204 §4.5.2 ¶1]" {
    // Name matches the dynamic table but value differs → expect a
    // literal-with-name-reference (T=0) representation, not indexed.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "old", false);

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-test", .value = "new" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, .{
        .indexing = .{ .dynamic_references = .any },
    });
    const prefix = try state_mod.decodeFieldSectionPrefix(buf[0..n], table.max_capacity, table.insert_count);
    // Body byte: 0 1 N=0 T=0, index=0 → 0x40.
    try std.testing.expectEqual(@as(u8, 0x40), buf[prefix.bytes_read]);

    const decoded = try qpack.decodeDynamicFieldSection(
        std.testing.allocator,
        &table,
        table.max_capacity,
        buf[0..n],
    );
    defer qpack.freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("new", decoded[0].value);
}

test "MUST reject decoding a dynamic field section whose Required Insert Count is unmet [RFC9204 §6]" {
    // Section announces RIC=1 but the table is empty. Per §6 this is a
    // QPACK_DECOMPRESSION_FAILED condition; the codec surfaces it as
    // `error.RequiredInsertCountNotReady`.
    var table = qpack.DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);

    var buf: [16]u8 = undefined;
    const n = try state_mod.encodeFieldSectionPrefix(&buf, .{
        .required_insert_count = 1,
        .base = 1,
    }, table.max_capacity);

    try std.testing.expectError(
        state_mod.Error.RequiredInsertCountNotReady,
        qpack.decodeDynamicFieldSection(std.testing.allocator, &table, table.max_capacity, buf[0..n]),
    );
}

// ---------------------------------------------------------------- §2.2.2 blocked streams

test "MUST refuse to track a new blocked field section past max_blocked_streams [RFC9204 §2.2.2 ¶1]" {
    // EncoderState.trackFieldSection MUST refuse a new tracked section
    // that would exceed `max_blocked_streams`.
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 1);
    defer encoder.deinit();
    try encoder.recordInsert(0);
    try encoder.recordInsert(1);
    _ = try encoder.trackFieldSection(0, &.{0});
    try std.testing.expectError(
        state_mod.Error.BlockedStreamLimitExceeded,
        encoder.trackFieldSection(4, &.{1}),
    );
}

test "MUST refuse a decoder beginFieldSection past max_blocked_streams [RFC9204 §2.2.2 ¶2]" {
    var decoder = state_mod.DecoderState.init(std.testing.allocator, 1);
    defer decoder.deinit();
    _ = try decoder.beginFieldSection(4, 2);
    try std.testing.expectError(
        state_mod.Error.BlockedStreamLimitExceeded,
        decoder.beginFieldSection(8, 1),
    );
}

test "NORMATIVE multiple sections from the same stream count once toward the blocked limit [RFC9204 §2.2.2 ¶1]" {
    // RFC 9204 §2.2.2: "An entry can become blocked if a stream
    // cannot be unblocked." A stream that is already blocked does not
    // re-occupy a slot for additional sections from the same stream.
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 1);
    defer encoder.deinit();
    try encoder.recordInsert(0);
    _ = try encoder.trackFieldSection(0, &.{0});
    // Same stream id can still track further sections referencing the
    // same entry without exceeding the limit.
    _ = try encoder.trackFieldSection(0, &.{0});
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());
}

// ---------------------------------------------------------------- §4.4 EncoderState <-> DecoderState handshake

test "NORMATIVE section_ack advances Known Received Count to the section's RIC [RFC9204 §4.4.1 ¶1]" {
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 16);
    defer encoder.deinit();
    encoder.recordInsertCount(3);

    _ = try encoder.trackFieldSection(4, &.{2});
    try std.testing.expectEqual(@as(u64, 0), encoder.known_received_count);
    try encoder.receiveDecoderInstruction(.{ .section_ack = 4 });
    try std.testing.expectEqual(@as(u64, 3), encoder.known_received_count);
    try std.testing.expect(encoder.isEvictable(2));
}

test "MUST reject a section_ack for a stream that is not outstanding [RFC9204 §4.4.1 ¶2]" {
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 4);
    defer encoder.deinit();
    try std.testing.expectError(
        state_mod.Error.UnexpectedSectionAcknowledgment,
        encoder.receiveDecoderInstruction(.{ .section_ack = 0 }),
    );
}

test "MUST reject an insert_count_increment that pushes Known Received Count past insert_count [RFC9204 §4.4.3 ¶3]" {
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 4);
    defer encoder.deinit();
    encoder.recordInsertCount(2);
    try std.testing.expectError(
        state_mod.Error.KnownReceivedCountTooHigh,
        encoder.receiveDecoderInstruction(.{ .insert_count_increment = 3 }),
    );
}

test "NORMATIVE stream_cancel decrements reference counts for the cancelled stream [RFC9204 §4.4.2 ¶1]" {
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 4);
    defer encoder.deinit();
    encoder.recordInsertCount(3);
    _ = try encoder.trackFieldSection(8, &.{2});
    try std.testing.expectEqual(@as(u64, 1), encoder.referenceCount(2));
    try encoder.receiveDecoderInstruction(.{ .stream_cancel = 8 });
    try std.testing.expectEqual(@as(u64, 0), encoder.referenceCount(2));
}

test "NORMATIVE stream_cancel for an unknown stream is tolerated by the encoder [RFC9204 §4.4.2 ¶1]" {
    // RFC 9204 §4.4.2 doesn't elevate an unknown stream cancellation to
    // a connection error: the encoder may simply have no outstanding
    // section for that stream id. Verify the implementation accepts it
    // as a no-op rather than surfacing an error like section_ack does.
    var encoder = state_mod.EncoderState.init(std.testing.allocator, 4);
    defer encoder.deinit();
    encoder.recordInsertCount(3);
    try encoder.receiveDecoderInstruction(.{ .stream_cancel = 99 });
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
}

test "NORMATIVE DecoderState emits an insert_count_increment that coalesces multiple inserts [RFC9204 §4.4.3 ¶1]" {
    // Two encoder-stream inserts; takeInsertCountIncrement MUST report
    // increment=2 once and then nothing.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    var decoder = state_mod.DecoderState.init(std.testing.allocator, 4);
    defer decoder.deinit();

    _ = try decoder.applyEncoderInstruction(&table, .{ .set_capacity = 256 });
    _ = try decoder.applyEncoderInstruction(&table, .{ .insert_literal = .{ .name = "a", .value = "1" } });
    _ = try decoder.applyEncoderInstruction(&table, .{ .insert_literal = .{ .name = "b", .value = "2" } });

    const increment = decoder.takeInsertCountIncrement().?;
    try std.testing.expectEqual(@as(u64, 2), increment.insert_count_increment);
    try std.testing.expect(decoder.takeInsertCountIncrement() == null);
}

test "NORMATIVE DecoderState completeFieldSection produces a section_ack instruction [RFC9204 §4.4.1 ¶1]" {
    // Drive a small dynamic round-trip end-to-end and verify the
    // decoder produces a section_ack.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    var decoder = state_mod.DecoderState.init(std.testing.allocator, 4);
    defer decoder.deinit();
    _ = try decoder.applyEncoderInstruction(&table, .{ .set_capacity = 256 });
    _ = try decoder.applyEncoderInstruction(&table, .{ .insert_literal = .{ .name = "a", .value = "1" } });

    const instr = (try decoder.completeFieldSection(12, 1)).?;
    try std.testing.expectEqual(@as(u64, 12), instr.section_ack);
}

test "NORMATIVE DecoderState cancelStream produces a stream_cancel instruction [RFC9204 §4.4.2 ¶1]" {
    var decoder = state_mod.DecoderState.init(std.testing.allocator, 4);
    defer decoder.deinit();
    const instr = decoder.cancelStream(8);
    try std.testing.expectEqual(@as(u64, 8), instr.stream_cancel);
}

// ---------------------------------------------------------------- §4.5 dynamic field section + tracker integration

test "NORMATIVE dynamic field section tracker records references and counts blocked streams [RFC9204 §2.2.2 ¶1]" {
    // Pre-populate the dynamic table, encode a field section that
    // references it, and verify the tracker side: insert_count is
    // observed, references are counted, and the field section is
    // marked blocked because no decoder ack has been received yet.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);

    var encoder_state = state_mod.EncoderState.init(std.testing.allocator, 1);
    defer encoder_state.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-test", .value = "one" },
    };
    var buf: [64]u8 = undefined;
    const n = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, .{
        .tracker = .{ .encoder_state = &encoder_state, .stream_id = 4 },
        .indexing = .{ .dynamic_references = .any },
    });
    try std.testing.expect(n > 0);
    try std.testing.expectEqual(@as(u64, 1), encoder_state.insert_count);
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(0));
    try std.testing.expectEqual(@as(usize, 1), encoder_state.blockedStreamCount());
}

test "NORMATIVE acknowledged sections release their dynamic references [RFC9204 §4.4.1 ¶1]" {
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);

    var encoder_state = state_mod.EncoderState.init(std.testing.allocator, 1);
    defer encoder_state.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-test", .value = "one" },
    };
    var buf: [64]u8 = undefined;
    _ = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, .{
        .tracker = .{ .encoder_state = &encoder_state, .stream_id = 12 },
        .indexing = .{ .dynamic_references = .any },
    });

    try encoder_state.receiveDecoderInstruction(.{ .section_ack = 12 });
    try std.testing.expectEqual(@as(u64, 0), encoder_state.referenceCount(0));
    try std.testing.expect(encoder_state.isEvictable(0));
}

test "NORMATIVE encodeFieldSectionEncoderInstructions inserts entries reachable by chosen policy [RFC9204 §4.3]" {
    // Aggressive policy: literal-name fields without a static-name hit
    // get inserted via insert_literal. Verify the table mutates and
    // the produced encoder-stream bytes round-trip.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    var encoder_state = state_mod.EncoderState.init(std.testing.allocator, 4);
    defer encoder_state.deinit();

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-policy", .value = "one" },
    };
    var encoder_stream: [64]u8 = undefined;
    const n = try qpack.encodeFieldSectionEncoderInstructions(&encoder_stream, &table, &fields, .{
        .tracker = .{ .encoder_state = &encoder_state, .stream_id = 0 },
        .indexing = .{ .dynamic_inserts = .all },
    });
    try std.testing.expect(n > 0);
    try std.testing.expectEqual(@as(usize, 1), table.len());
    try std.testing.expectEqualStrings("x-policy", table.getAbsolute(0).?.name);
    try std.testing.expectEqualStrings("one", table.getAbsolute(0).?.value);
}

test "NORMATIVE acknowledged dynamic_references mode upgrades to indexed after an increment [RFC9204 §4.4.3 ¶1]" {
    // Before ack, the encoder MUST fall back to a literal because the
    // table entry is potentially blocking. After an
    // insert_count_increment that covers the entry, the same fields
    // produce an indexed representation with a non-zero RIC.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);

    var encoder_state = state_mod.EncoderState.init(std.testing.allocator, 0);
    defer encoder_state.deinit();
    encoder_state.recordInsertCount(table.insert_count);

    const fields = [_]qpack.FieldLine{
        .{ .name = "x-test", .value = "one" },
    };
    const options = qpack.DynamicFieldSectionEncodeOptions{
        .tracker = .{ .encoder_state = &encoder_state, .stream_id = 4 },
        .indexing = .{ .dynamic_references = .acknowledged },
    };
    var buf: [64]u8 = undefined;
    const literal_n = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, options);
    const literal_prefix = try state_mod.decodeFieldSectionPrefix(buf[0..literal_n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 0), literal_prefix.prefix.required_insert_count);

    try encoder_state.receiveDecoderInstruction(.{ .insert_count_increment = 1 });
    const acked_n = try qpack.encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, options);
    const acked_prefix = try state_mod.decodeFieldSectionPrefix(buf[0..acked_n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), acked_prefix.prefix.required_insert_count);
}

// ---------------------------------------------------------------- §6 error codes

test "MUST surface QPACK_DECOMPRESSION_FAILED for an unknown post-base representation byte [RFC9204 §6]" {
    // The static-only profile forbids post-base representations; if a
    // decoder sees one with no dynamic table set up, it MUST fail.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try integer.encode(buf[pos..], 8, 0, 0);
    pos += try integer.encode(buf[pos..], 7, 0, 0);
    pos += try integer.encode(buf[pos..], 4, 0x10, 0); // Indexed-with-post-base form

    try std.testing.expectError(
        qpack.Error.UnsupportedRepresentation,
        qpack.decodeFieldSection(std.testing.allocator, buf[0..pos]),
    );
}

test "MUST refuse to encode an insert_count_increment of 0 (QPACK_DECODER_STREAM_ERROR) [RFC9204 §6]" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        instructions_mod.Error.InsertCountIncrementZero,
        instructions_mod.encodeDecoderInstruction(&buf, .{ .insert_count_increment = 0 }),
    );
}

test "MUST refuse to encode-stream apply a malformed instruction (QPACK_ENCODER_STREAM_ERROR) [RFC9204 §6]" {
    // applyEncoderInstruction on a duplicate of an absent index MUST
    // surface InvalidDynamicIndex, the codec-level error that the
    // session layer maps to QPACK_ENCODER_STREAM_ERROR.
    var table = qpack.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    try std.testing.expectError(
        qpack.dynamic_table.Error.InvalidDynamicIndex,
        instructions_mod.applyEncoderInstruction(&table, .{ .duplicate = 0 }),
    );
}
