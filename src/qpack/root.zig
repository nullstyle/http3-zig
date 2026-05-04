//! QPACK primitives and a non-blocking field-section codec.

const std = @import("std");

pub const integer = @import("integer.zig");
pub const static_table = @import("static_table.zig");

pub const Error = integer.Error || error{
    BufferTooSmall,
    OutOfMemory,
    HuffmanUnsupported,
    DynamicTableUnsupported,
    UnsupportedRepresentation,
    MalformedFieldSection,
    InvalidStaticIndex,
};

pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    /// Maps to QPACK's N bit. Sensitive fields are never indexed.
    sensitive: bool = false,
};

pub fn literalFieldSectionEncodedLen(fields: []const FieldLine) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        n += integer.encodedLen(3, field.name.len) + field.name.len;
        n += integer.encodedLen(7, field.value.len) + field.value.len;
    }
    return n;
}

/// Length for `encodeFieldSection`: static full matches become indexed
/// representations; static name matches become literal-with-name-reference;
/// everything else uses a literal-name representation.
pub fn fieldSectionEncodedLen(fields: []const FieldLine) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        if (!field.sensitive and static_table.find(field.name, field.value) != null) {
            const index = static_table.find(field.name, field.value).?;
            n += integer.encodedLen(6, index);
        } else if (static_table.findName(field.name)) |index| {
            n += integer.encodedLen(4, index);
            n += integer.encodedLen(7, field.value.len) + field.value.len;
        } else {
            n += integer.encodedLen(3, field.name.len) + field.name.len;
            n += integer.encodedLen(7, field.value.len) + field.value.len;
        }
    }
    return n;
}

/// Encode a non-blocking QPACK field section using literal-name
/// representations only. This is valid QPACK and is the safe baseline
/// until the dynamic table lands.
pub fn encodeLiteralFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], 8, 0, 0); // Required Insert Count.
    pos += try integer.encode(dst[pos..], 7, 0, 0); // Sign bit 0, Delta Base 0.

    for (fields) |field| {
        const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
        pos += try integer.encode(dst[pos..], 3, prefix, @intCast(field.name.len));
        if (dst.len - pos < field.name.len) return Error.BufferTooSmall;
        @memcpy(dst[pos .. pos + field.name.len], field.name);
        pos += field.name.len;

        pos += try integer.encode(dst[pos..], 7, 0, @intCast(field.value.len));
        if (dst.len - pos < field.value.len) return Error.BufferTooSmall;
        @memcpy(dst[pos .. pos + field.value.len], field.value);
        pos += field.value.len;
    }
    return pos;
}

/// Encode a non-blocking QPACK field section using the static table when
/// possible. It never references the dynamic table, so it cannot block on
/// QPACK encoder-stream delivery.
pub fn encodeFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], 8, 0, 0); // Required Insert Count.
    pos += try integer.encode(dst[pos..], 7, 0, 0); // Sign bit 0, Delta Base 0.

    for (fields) |field| {
        if (!field.sensitive) {
            if (static_table.find(field.name, field.value)) |index| {
                pos += try integer.encode(dst[pos..], 6, 0xc0, @intCast(index));
                continue;
            }
        }

        if (static_table.findName(field.name)) |index| {
            const prefix: u8 = 0x50 | if (field.sensitive) @as(u8, 0x20) else 0;
            pos += try integer.encode(dst[pos..], 4, prefix, @intCast(index));
            pos += try writePlainString(dst[pos..], field.value, 7, 0);
        } else {
            const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
            pos += try writePlainString(dst[pos..], field.name, 3, prefix);
            pos += try writePlainString(dst[pos..], field.value, 7, 0);
        }
    }
    return pos;
}

/// Decode a field section that avoids the dynamic table. Static indexed
/// fields, static name references, and literal-name representations are
/// supported; Huffman and dynamic references are left for the full QPACK
/// phase.
pub fn decodeFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

/// Decode the static/literal profile produced by `encodeFieldSection`.
/// The returned field list borrows name/value slices from `src`; callers own
/// only the returned slice of `FieldLine`.
pub fn decodeLiteralFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

fn writePlainString(
    dst: []u8,
    value: []const u8,
    prefix_bits: u8,
    first_byte_prefix: u8,
) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], prefix_bits, first_byte_prefix, @intCast(value.len));
    if (dst.len - pos < value.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + value.len], value);
    return pos + value.len;
}

fn readPlainString(src: []const u8, pos: *usize, prefix_bits: u8) Error![]const u8 {
    if (pos.* >= src.len) return Error.MalformedFieldSection;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    if ((src[pos.*] & huffman_mask) != 0) return Error.HuffmanUnsupported;
    const len = try integer.decode(src[pos.*..], prefix_bits);
    pos.* += len.bytes_read;
    const len_usize: usize = @intCast(len.value);
    if (src.len - pos.* < len_usize) return Error.MalformedFieldSection;
    const out = src[pos.* .. pos.* + len_usize];
    pos.* += len_usize;
    return out;
}

fn decodeStaticOnlyFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    var pos: usize = 0;
    const ric = try integer.decode(src[pos..], 8);
    pos += ric.bytes_read;
    if (ric.value != 0) return Error.DynamicTableUnsupported;

    if (pos >= src.len) return Error.MalformedFieldSection;
    const delta_first = src[pos];
    const delta = try integer.decode(src[pos..], 7);
    pos += delta.bytes_read;
    if ((delta_first & 0x80) != 0 or delta.value != 0) return Error.DynamicTableUnsupported;

    var fields: std.ArrayList(FieldLine) = .empty;
    errdefer fields.deinit(allocator);

    while (pos < src.len) {
        const first = src[pos];
        if ((first & 0x80) != 0) {
            if ((first & 0x40) == 0) return Error.DynamicTableUnsupported;
            const index = try integer.decode(src[pos..], 6);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            try fields.append(allocator, .{ .name = entry.name, .value = entry.value });
        } else if ((first & 0xc0) == 0x40) {
            if ((first & 0x10) == 0) return Error.DynamicTableUnsupported;
            const sensitive = (first & 0x20) != 0;
            const index = try integer.decode(src[pos..], 4);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            const value = try readPlainString(src, &pos, 7);
            try fields.append(allocator, .{
                .name = entry.name,
                .value = value,
                .sensitive = sensitive,
            });
        } else if ((first & 0xe0) == 0x20) {
            const sensitive = (first & 0x10) != 0;
            const name = try readPlainString(src, &pos, 3);
            const value = try readPlainString(src, &pos, 7);
            try fields.append(allocator, .{
                .name = name,
                .value = value,
                .sensitive = sensitive,
            });
        } else {
            return Error.UnsupportedRepresentation;
        }
    }

    return try fields.toOwnedSlice(allocator);
}

test "static table indexed fields and name references round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "authorization", .value = "bearer nope", .sensitive = true },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(fieldSectionEncodedLen(&fields), n);
    try std.testing.expect(buf[2] & 0xc0 == 0xc0);

    const decoded = try decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("/index.html", decoded[2].value);
    try std.testing.expect(decoded[3].sensitive);
}

test "literal field section round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeLiteralFieldSection(&buf, &fields);
    try std.testing.expectEqual(literalFieldSectionEncodedLen(&fields), n);

    const decoded = try decodeLiteralFieldSection(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}
