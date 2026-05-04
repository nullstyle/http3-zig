//! QPACK encoder and decoder stream instruction codecs.
//!
//! These codecs are transport-free: callers feed bytes from the HTTP/3 QPACK
//! encoder/decoder streams and receive one decoded instruction plus its length.

const std = @import("std");

const dynamic_table = @import("dynamic_table.zig");
const huffman = @import("huffman.zig");
const integer = @import("integer.zig");
const static_table = @import("static_table.zig");

pub const Error = integer.Error || huffman.Error || dynamic_table.Error || std.mem.Allocator.Error || error{
    InvalidStaticIndex,
    MalformedEncoderInstruction,
    MalformedDecoderInstruction,
    InsertCountIncrementZero,
};

pub const Table = enum {
    static,
    dynamic,
};

pub const InsertNameReference = struct {
    table: Table,
    index: u64,
    value: []const u8,
    value_huffman: bool = false,
};

pub const InsertLiteralName = struct {
    name: []const u8,
    value: []const u8,
    name_huffman: bool = false,
    value_huffman: bool = false,
};

pub const EncoderInstruction = union(enum) {
    set_capacity: u64,
    insert_name_ref: InsertNameReference,
    insert_literal: InsertLiteralName,
    duplicate: u64,
};

pub const DecodedEncoderInstruction = struct {
    instruction: EncoderInstruction,
    bytes_read: usize,
};

pub const DecoderInstruction = union(enum) {
    section_ack: u64,
    stream_cancel: u64,
    insert_count_increment: u64,
};

pub const DecodedDecoderInstruction = struct {
    instruction: DecoderInstruction,
    bytes_read: usize,
};

const DecodedString = struct {
    value: []u8,
    huffman: bool,
};

pub fn encoderInstructionEncodedLen(instruction: EncoderInstruction) usize {
    return switch (instruction) {
        .set_capacity => |capacity| integer.encodedLen(5, capacity),
        .insert_name_ref => |insert| integer.encodedLen(6, insert.index) +
            stringLiteralEncodedLen(7, insert.value, insert.value_huffman),
        .insert_literal => |insert| stringLiteralEncodedLen(5, insert.name, insert.name_huffman) +
            stringLiteralEncodedLen(7, insert.value, insert.value_huffman),
        .duplicate => |index| integer.encodedLen(5, index),
    };
}

pub fn encodeEncoderInstruction(dst: []u8, instruction: EncoderInstruction) Error!usize {
    var pos: usize = 0;
    switch (instruction) {
        .set_capacity => |capacity| {
            pos += try integer.encode(dst[pos..], 5, 0x20, capacity);
        },
        .insert_name_ref => |insert| {
            const prefix: u8 = if (insert.table == .static) 0xc0 else 0x80;
            pos += try integer.encode(dst[pos..], 6, prefix, insert.index);
            pos += try encodeStringLiteral(dst[pos..], insert.value, 7, 0, insert.value_huffman);
        },
        .insert_literal => |insert| {
            pos += try encodeStringLiteral(dst[pos..], insert.name, 5, 0x40, insert.name_huffman);
            pos += try encodeStringLiteral(dst[pos..], insert.value, 7, 0, insert.value_huffman);
        },
        .duplicate => |index| {
            pos += try integer.encode(dst[pos..], 5, 0, index);
        },
    }
    return pos;
}

pub fn decodeEncoderInstruction(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error!DecodedEncoderInstruction {
    if (src.len == 0) return error.InsufficientBytes;

    var pos: usize = 0;
    const first = src[0];
    if ((first & 0x80) != 0) {
        const index = try decodeEncoderInteger(src[pos..], 6);
        pos += index.bytes_read;
        const value = try readEncoderStringAlloc(allocator, src, &pos, 7);
        return .{
            .instruction = .{ .insert_name_ref = .{
                .table = if ((first & 0x40) != 0) .static else .dynamic,
                .index = index.value,
                .value = value.value,
                .value_huffman = value.huffman,
            } },
            .bytes_read = pos,
        };
    }

    if ((first & 0x40) != 0) {
        const name = try readEncoderStringAlloc(allocator, src, &pos, 5);
        errdefer allocator.free(name.value);
        const value = try readEncoderStringAlloc(allocator, src, &pos, 7);
        return .{
            .instruction = .{ .insert_literal = .{
                .name = name.value,
                .value = value.value,
                .name_huffman = name.huffman,
                .value_huffman = value.huffman,
            } },
            .bytes_read = pos,
        };
    }

    if ((first & 0xe0) == 0x20) {
        const capacity = try decodeEncoderInteger(src[pos..], 5);
        return .{
            .instruction = .{ .set_capacity = capacity.value },
            .bytes_read = capacity.bytes_read,
        };
    }

    const index = try decodeEncoderInteger(src[pos..], 5);
    return .{
        .instruction = .{ .duplicate = index.value },
        .bytes_read = index.bytes_read,
    };
}

pub fn freeDecodedEncoderInstruction(
    allocator: std.mem.Allocator,
    decoded: DecodedEncoderInstruction,
) void {
    switch (decoded.instruction) {
        .insert_name_ref => |insert| allocator.free(@constCast(insert.value)),
        .insert_literal => |insert| {
            allocator.free(@constCast(insert.name));
            allocator.free(@constCast(insert.value));
        },
        .set_capacity, .duplicate => {},
    }
}

pub fn applyEncoderInstruction(
    table: *dynamic_table.DynamicTable,
    instruction: EncoderInstruction,
) Error!?u64 {
    return switch (instruction) {
        .set_capacity => |capacity| blk: {
            const capacity_usize = std.math.cast(usize, capacity) orelse return error.CapacityTooLarge;
            try table.setCapacity(capacity_usize);
            break :blk null;
        },
        .insert_name_ref => |insert| blk: {
            const name = switch (insert.table) {
                .static => static: {
                    const index = std.math.cast(usize, insert.index) orelse return error.InvalidStaticIndex;
                    break :static (static_table.get(index) orelse return error.InvalidStaticIndex).name;
                },
                .dynamic => (table.getEncoderRelative(insert.index) orelse return error.InvalidDynamicIndex).name,
            };
            break :blk try table.insert(name, insert.value, false);
        },
        .insert_literal => |insert| try table.insert(insert.name, insert.value, false),
        .duplicate => |index| try table.duplicate(index),
    };
}

pub fn decoderInstructionEncodedLen(instruction: DecoderInstruction) usize {
    return switch (instruction) {
        .section_ack => |stream_id| integer.encodedLen(7, stream_id),
        .stream_cancel => |stream_id| integer.encodedLen(6, stream_id),
        .insert_count_increment => |increment| integer.encodedLen(6, increment),
    };
}

pub fn encodeDecoderInstruction(dst: []u8, instruction: DecoderInstruction) Error!usize {
    return switch (instruction) {
        .section_ack => |stream_id| try integer.encode(dst, 7, 0x80, stream_id),
        .stream_cancel => |stream_id| try integer.encode(dst, 6, 0x40, stream_id),
        .insert_count_increment => |increment| blk: {
            if (increment == 0) return error.InsertCountIncrementZero;
            break :blk try integer.encode(dst, 6, 0, increment);
        },
    };
}

pub fn decodeDecoderInstruction(src: []const u8) Error!DecodedDecoderInstruction {
    if (src.len == 0) return error.InsufficientBytes;

    const first = src[0];
    if ((first & 0x80) != 0) {
        const stream_id = try decodeDecoderInteger(src, 7);
        return .{
            .instruction = .{ .section_ack = stream_id.value },
            .bytes_read = stream_id.bytes_read,
        };
    }

    if ((first & 0x40) != 0) {
        const stream_id = try decodeDecoderInteger(src, 6);
        return .{
            .instruction = .{ .stream_cancel = stream_id.value },
            .bytes_read = stream_id.bytes_read,
        };
    }

    const increment = try decodeDecoderInteger(src, 6);
    if (increment.value == 0) return error.InsertCountIncrementZero;
    return .{
        .instruction = .{ .insert_count_increment = increment.value },
        .bytes_read = increment.bytes_read,
    };
}

pub fn stringLiteralEncodedLen(prefix_bits: u8, value: []const u8, huffman_enabled: bool) usize {
    const body_len = if (huffman_enabled) huffman.encodedLen(value) else value.len;
    return integer.encodedLen(prefix_bits, body_len) + body_len;
}

fn encodeStringLiteral(
    dst: []u8,
    value: []const u8,
    prefix_bits: u8,
    first_byte_prefix: u8,
    huffman_enabled: bool,
) Error!usize {
    var pos: usize = 0;
    const encoded_len = if (huffman_enabled) huffman.encodedLen(value) else value.len;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const prefix = first_byte_prefix | if (huffman_enabled) huffman_mask else 0;
    pos += try integer.encode(dst[pos..], prefix_bits, prefix, @intCast(encoded_len));
    if (dst.len - pos < encoded_len) return error.BufferTooSmall;
    if (huffman_enabled) {
        pos += try huffman.encode(dst[pos..], value);
    } else {
        @memcpy(dst[pos .. pos + value.len], value);
        pos += value.len;
    }
    return pos;
}

fn readEncoderStringAlloc(
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: *usize,
    prefix_bits: u8,
) Error!DecodedString {
    if (pos.* >= src.len) return error.InsufficientBytes;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const huffman_encoded = (src[pos.*] & huffman_mask) != 0;
    const len = try decodeEncoderInteger(src[pos.*..], prefix_bits);
    pos.* += len.bytes_read;
    const len_usize: usize = @intCast(len.value);
    if (src.len - pos.* < len_usize) return error.InsufficientBytes;
    const encoded = src[pos.* .. pos.* + len_usize];
    pos.* += len_usize;
    const value = if (huffman_encoded) try huffman.decode(allocator, encoded) else try allocator.dupe(u8, encoded);
    return .{ .value = value, .huffman = huffman_encoded };
}

fn decodeEncoderInteger(src: []const u8, prefix_bits: u8) Error!integer.Decoded {
    return integer.decode(src, prefix_bits) catch |err| switch (err) {
        error.InsufficientBytes => error.InsufficientBytes,
        error.ValueTooLarge, error.InvalidPrefix => error.MalformedEncoderInstruction,
        error.BufferTooSmall => unreachable,
    };
}

fn decodeDecoderInteger(src: []const u8, prefix_bits: u8) Error!integer.Decoded {
    return integer.decode(src, prefix_bits) catch |err| switch (err) {
        error.InsufficientBytes => error.InsufficientBytes,
        error.ValueTooLarge, error.InvalidPrefix => error.MalformedDecoderInstruction,
        error.BufferTooSmall => unreachable,
    };
}

test "encoder stream instruction codec round-trips all instruction shapes" {
    var buf: [256]u8 = undefined;

    const capacity = EncoderInstruction{ .set_capacity = 4096 };
    const capacity_n = try encodeEncoderInstruction(&buf, capacity);
    try std.testing.expectEqual(encoderInstructionEncodedLen(capacity), capacity_n);
    const decoded_capacity = try decodeEncoderInstruction(std.testing.allocator, buf[0..capacity_n]);
    defer freeDecodedEncoderInstruction(std.testing.allocator, decoded_capacity);
    try std.testing.expectEqual(@as(u64, 4096), decoded_capacity.instruction.set_capacity);
    try std.testing.expectEqual(capacity_n, decoded_capacity.bytes_read);

    const name_ref = EncoderInstruction{ .insert_name_ref = .{
        .table = .static,
        .index = 17,
        .value = "GET",
    } };
    const name_ref_n = try encodeEncoderInstruction(&buf, name_ref);
    try std.testing.expectEqual(encoderInstructionEncodedLen(name_ref), name_ref_n);
    const decoded_name_ref = try decodeEncoderInstruction(std.testing.allocator, buf[0..name_ref_n]);
    defer freeDecodedEncoderInstruction(std.testing.allocator, decoded_name_ref);
    try std.testing.expectEqual(Table.static, decoded_name_ref.instruction.insert_name_ref.table);
    try std.testing.expectEqual(@as(u64, 17), decoded_name_ref.instruction.insert_name_ref.index);
    try std.testing.expectEqualStrings("GET", decoded_name_ref.instruction.insert_name_ref.value);

    const literal = EncoderInstruction{ .insert_literal = .{
        .name = "cache-control",
        .value = "no-cache",
        .name_huffman = true,
        .value_huffman = true,
    } };
    const literal_n = try encodeEncoderInstruction(&buf, literal);
    try std.testing.expectEqual(encoderInstructionEncodedLen(literal), literal_n);
    const decoded_literal = try decodeEncoderInstruction(std.testing.allocator, buf[0..literal_n]);
    defer freeDecodedEncoderInstruction(std.testing.allocator, decoded_literal);
    try std.testing.expect(decoded_literal.instruction.insert_literal.name_huffman);
    try std.testing.expect(decoded_literal.instruction.insert_literal.value_huffman);
    try std.testing.expectEqualStrings("cache-control", decoded_literal.instruction.insert_literal.name);
    try std.testing.expectEqualStrings("no-cache", decoded_literal.instruction.insert_literal.value);

    const duplicate = EncoderInstruction{ .duplicate = 42 };
    const duplicate_n = try encodeEncoderInstruction(&buf, duplicate);
    try std.testing.expectEqual(encoderInstructionEncodedLen(duplicate), duplicate_n);
    const decoded_duplicate = try decodeEncoderInstruction(std.testing.allocator, buf[0..duplicate_n]);
    defer freeDecodedEncoderInstruction(std.testing.allocator, decoded_duplicate);
    try std.testing.expectEqual(@as(u64, 42), decoded_duplicate.instruction.duplicate);
}

test "encoder stream instructions apply to the dynamic table" {
    var table = dynamic_table.DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();

    try std.testing.expectEqual(@as(?u64, null), try applyEncoderInstruction(
        &table,
        .{ .set_capacity = 256 },
    ));

    const static_insert = try applyEncoderInstruction(&table, .{ .insert_name_ref = .{
        .table = .static,
        .index = 17,
        .value = "POST",
    } });
    try std.testing.expectEqual(@as(?u64, 0), static_insert);
    try std.testing.expectEqualStrings(":method", table.getAbsolute(0).?.name);
    try std.testing.expectEqualStrings("POST", table.getAbsolute(0).?.value);

    const literal_insert = try applyEncoderInstruction(&table, .{ .insert_literal = .{
        .name = "x-test",
        .value = "one",
    } });
    try std.testing.expectEqual(@as(?u64, 1), literal_insert);

    const dynamic_insert = try applyEncoderInstruction(&table, .{ .insert_name_ref = .{
        .table = .dynamic,
        .index = 0,
        .value = "two",
    } });
    try std.testing.expectEqual(@as(?u64, 2), dynamic_insert);
    try std.testing.expectEqualStrings("x-test", table.getAbsolute(2).?.name);
    try std.testing.expectEqualStrings("two", table.getAbsolute(2).?.value);

    const duplicate = try applyEncoderInstruction(&table, .{ .duplicate = 1 });
    try std.testing.expectEqual(@as(?u64, 3), duplicate);
    try std.testing.expectEqualStrings("x-test", table.getAbsolute(3).?.name);
    try std.testing.expectEqualStrings("one", table.getAbsolute(3).?.value);
}

test "decoder stream instruction codec round-trips all instruction shapes" {
    var buf: [32]u8 = undefined;

    const ack = DecoderInstruction{ .section_ack = 1337 };
    const ack_n = try encodeDecoderInstruction(&buf, ack);
    try std.testing.expectEqual(decoderInstructionEncodedLen(ack), ack_n);
    const decoded_ack = try decodeDecoderInstruction(buf[0..ack_n]);
    try std.testing.expectEqual(@as(u64, 1337), decoded_ack.instruction.section_ack);
    try std.testing.expectEqual(ack_n, decoded_ack.bytes_read);

    const cancel = DecoderInstruction{ .stream_cancel = 4 };
    const cancel_n = try encodeDecoderInstruction(&buf, cancel);
    try std.testing.expectEqual(decoderInstructionEncodedLen(cancel), cancel_n);
    const decoded_cancel = try decodeDecoderInstruction(buf[0..cancel_n]);
    try std.testing.expectEqual(@as(u64, 4), decoded_cancel.instruction.stream_cancel);

    const increment = DecoderInstruction{ .insert_count_increment = 9 };
    const increment_n = try encodeDecoderInstruction(&buf, increment);
    try std.testing.expectEqual(decoderInstructionEncodedLen(increment), increment_n);
    const decoded_increment = try decodeDecoderInstruction(buf[0..increment_n]);
    try std.testing.expectEqual(@as(u64, 9), decoded_increment.instruction.insert_count_increment);
}

test "instruction decoders report malformed or invalid instructions" {
    try std.testing.expectError(error.InsufficientBytes, decodeEncoderInstruction(std.testing.allocator, &.{}));
    try std.testing.expectError(error.InsufficientBytes, decodeDecoderInstruction(&.{}));

    const zero_increment = [_]u8{0};
    try std.testing.expectError(error.InsertCountIncrementZero, decodeDecoderInstruction(&zero_increment));
    var zero_increment_buf = [_]u8{0};
    try std.testing.expectError(
        error.InsertCountIncrementZero,
        encodeDecoderInstruction(&zero_increment_buf, .{ .insert_count_increment = 0 }),
    );
}
