//! QPACK primitives and a non-blocking field-section codec.

const std = @import("std");

pub const integer = @import("integer.zig");
pub const huffman = @import("huffman.zig");
pub const dynamic_table = @import("dynamic_table.zig");
pub const instructions = @import("instructions.zig");
pub const state = @import("state.zig");
pub const static_table = @import("static_table.zig");

pub const DynamicTable = dynamic_table.DynamicTable;
pub const DynamicEntry = dynamic_table.Entry;
pub const EncoderInstruction = instructions.EncoderInstruction;
pub const DecoderInstruction = instructions.DecoderInstruction;
pub const QpackEncoderState = state.EncoderState;
pub const QpackDecoderState = state.DecoderState;
pub const FieldSectionPrefix = state.FieldSectionPrefix;

pub const Error = integer.Error || huffman.Error || dynamic_table.Error || instructions.Error || state.Error || error{
    BufferTooSmall,
    OutOfMemory,
    HuffmanUnsupported,
    DynamicTableUnsupported,
    UnsupportedRepresentation,
    MalformedFieldSection,
    InvalidStaticIndex,
};

pub const StringOptions = struct {
    huffman: bool = false,
};

pub const FieldSectionEncodeOptions = struct {
    huffman: bool = false,
};

pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    /// Maps to QPACK's N bit. Sensitive fields are never indexed.
    sensitive: bool = false,
};

pub fn literalFieldSectionEncodedLen(fields: []const FieldLine) usize {
    return literalFieldSectionEncodedLenWithOptions(fields, .{});
}

pub fn literalFieldSectionEncodedLenWithOptions(
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        const string_options: StringOptions = .{ .huffman = options.huffman };
        n += stringLiteralEncodedLen(3, field.name, string_options);
        n += stringLiteralEncodedLen(7, field.value, string_options);
    }
    return n;
}

/// Length for `encodeFieldSection`: static full matches become indexed
/// representations; static name matches become literal-with-name-reference;
/// everything else uses a literal-name representation.
pub fn fieldSectionEncodedLen(fields: []const FieldLine) usize {
    return fieldSectionEncodedLenWithOptions(fields, .{});
}

pub fn fieldSectionEncodedLenWithOptions(
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        if (!field.sensitive and static_table.find(field.name, field.value) != null) {
            const index = static_table.find(field.name, field.value).?;
            n += integer.encodedLen(6, index);
        } else if (static_table.findName(field.name)) |index| {
            n += integer.encodedLen(4, index);
            n += stringLiteralEncodedLen(7, field.value, .{ .huffman = options.huffman });
        } else {
            const string_options: StringOptions = .{ .huffman = options.huffman };
            n += stringLiteralEncodedLen(3, field.name, string_options);
            n += stringLiteralEncodedLen(7, field.value, string_options);
        }
    }
    return n;
}

/// Encode a non-blocking QPACK field section using literal-name
/// representations only. This is valid QPACK and is the safe baseline
/// until the dynamic table lands.
pub fn encodeLiteralFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    return encodeLiteralFieldSectionWithOptions(dst, fields, .{});
}

pub fn encodeLiteralFieldSectionWithOptions(
    dst: []u8,
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], 8, 0, 0); // Required Insert Count.
    pos += try integer.encode(dst[pos..], 7, 0, 0); // Sign bit 0, Delta Base 0.

    for (fields) |field| {
        const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
        const string_options: StringOptions = .{ .huffman = options.huffman };
        pos += try encodeStringLiteral(dst[pos..], field.name, 3, prefix, string_options);
        pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, string_options);
    }
    return pos;
}

/// Encode a non-blocking QPACK field section using the static table when
/// possible. It never references the dynamic table, so it cannot block on
/// QPACK encoder-stream delivery.
pub fn encodeFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    return encodeFieldSectionWithOptions(dst, fields, .{});
}

pub fn encodeFieldSectionWithOptions(
    dst: []u8,
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) Error!usize {
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
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, .{
                .huffman = options.huffman,
            });
        } else {
            const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
            const string_options: StringOptions = .{ .huffman = options.huffman };
            pos += try encodeStringLiteral(dst[pos..], field.name, 3, prefix, string_options);
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, string_options);
        }
    }
    return pos;
}

/// Decode a field section that avoids the dynamic table. The returned field
/// list owns its name/value strings and must be released with
/// `freeFieldSection`.
pub fn decodeFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

/// Decode the static/literal profile produced by `encodeFieldSection`.
/// The returned field list owns its name/value strings and must be released
/// with `freeFieldSection`.
pub fn decodeLiteralFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

pub fn freeFieldSection(allocator: std.mem.Allocator, fields: []FieldLine) void {
    for (fields) |field| {
        allocator.free(@constCast(field.name));
        allocator.free(@constCast(field.value));
    }
    allocator.free(fields);
}

pub fn stringLiteralEncodedLen(prefix_bits: u8, value: []const u8, options: StringOptions) usize {
    const body_len = if (options.huffman) huffman.encodedLen(value) else value.len;
    return integer.encodedLen(prefix_bits, body_len) + body_len;
}

pub fn encodeStringLiteral(
    dst: []u8,
    value: []const u8,
    prefix_bits: u8,
    first_byte_prefix: u8,
    options: StringOptions,
) Error!usize {
    var pos: usize = 0;
    const encoded_len = if (options.huffman) huffman.encodedLen(value) else value.len;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const prefix = first_byte_prefix | if (options.huffman) huffman_mask else 0;
    pos += try integer.encode(dst[pos..], prefix_bits, prefix, @intCast(encoded_len));
    if (dst.len - pos < encoded_len) return Error.BufferTooSmall;
    if (options.huffman) {
        pos += try huffman.encode(dst[pos..], value);
    } else {
        @memcpy(dst[pos .. pos + value.len], value);
        pos += value.len;
    }
    return pos;
}

fn readStringAlloc(
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: *usize,
    prefix_bits: u8,
) Error![]u8 {
    if (pos.* >= src.len) return Error.MalformedFieldSection;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const huffman_encoded = (src[pos.*] & huffman_mask) != 0;
    const len = try integer.decode(src[pos.*..], prefix_bits);
    pos.* += len.bytes_read;
    const len_usize: usize = @intCast(len.value);
    if (src.len - pos.* < len_usize) return Error.MalformedFieldSection;
    const encoded = src[pos.* .. pos.* + len_usize];
    pos.* += len_usize;
    if (huffman_encoded) return try huffman.decode(allocator, encoded);
    return try allocator.dupe(u8, encoded);
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
    errdefer {
        for (fields.items) |field| {
            allocator.free(@constCast(field.name));
            allocator.free(@constCast(field.value));
        }
        fields.deinit(allocator);
    }

    while (pos < src.len) {
        const first = src[pos];
        if ((first & 0x80) != 0) {
            if ((first & 0x40) == 0) return Error.DynamicTableUnsupported;
            const index = try integer.decode(src[pos..], 6);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            try appendCopiedField(&fields, allocator, entry.name, entry.value, false);
        } else if ((first & 0xc0) == 0x40) {
            if ((first & 0x10) == 0) return Error.DynamicTableUnsupported;
            const sensitive = (first & 0x20) != 0;
            const index = try integer.decode(src[pos..], 4);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            try appendCopiedNameField(
                &fields,
                allocator,
                entry.name,
                try readStringAlloc(allocator, src, &pos, 7),
                sensitive,
            );
        } else if ((first & 0xe0) == 0x20) {
            const sensitive = (first & 0x10) != 0;
            try appendLiteralField(&fields, allocator, src, &pos, sensitive);
        } else {
            return Error.UnsupportedRepresentation;
        }
    }

    return try fields.toOwnedSlice(allocator);
}

fn appendCopiedField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name_src: []const u8,
    value_src: []const u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    const name = try allocator.dupe(u8, name_src);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, value_src);
    errdefer allocator.free(value);
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendCopiedNameField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name_src: []const u8,
    value: []u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    errdefer allocator.free(value);
    const name = try allocator.dupe(u8, name_src);
    errdefer allocator.free(name);
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendOwnedField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name: []u8,
    value: []u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    errdefer {
        allocator.free(name);
        allocator.free(value);
    }
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendLiteralField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: *usize,
    sensitive: bool,
) Error!void {
    const name = try readStringAlloc(allocator, src, pos, 3);
    const value = readStringAlloc(allocator, src, pos, 7) catch |err| {
        allocator.free(name);
        return err;
    };
    try appendOwnedField(fields, allocator, name, value, sensitive);
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
    defer freeFieldSection(std.testing.allocator, decoded);
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
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "Huffman string literal field section round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    };
    var huffman_buf: [256]u8 = undefined;
    var plain_buf: [256]u8 = undefined;
    const huffman_n = try encodeFieldSectionWithOptions(&huffman_buf, &fields, .{ .huffman = true });
    const plain_n = try encodeFieldSection(&plain_buf, &fields);
    try std.testing.expect(huffman_n < plain_n);

    const decoded = try decodeFieldSection(std.testing.allocator, huffman_buf[0..huffman_n]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("www.example.com", decoded[0].value);
    try std.testing.expectEqualStrings("no-cache", decoded[1].value);
}
