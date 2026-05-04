//! HPACK/QPACK static Huffman codec.
//!
//! QPACK reuses the HPACK Huffman code for string literals. Codes are stored
//! LSB-aligned as listed in RFC 7541 Appendix B and emitted MSB-first.

const std = @import("std");

pub const Error = error{
    BufferTooSmall,
    OutOfMemory,
    InvalidHuffmanCode,
    InvalidHuffmanPadding,
    HuffmanPaddingTooLong,
    HuffmanEos,
};

const Code = struct {
    bits: u32,
    len: u8,
};

const eos: Code = .{ .bits = 0x3fffffff, .len = 30 };

pub const table = [_]Code{
    .{ .bits = 0x1ff8, .len = 13 },
    .{ .bits = 0x7fffd8, .len = 23 },
    .{ .bits = 0xfffffe2, .len = 28 },
    .{ .bits = 0xfffffe3, .len = 28 },
    .{ .bits = 0xfffffe4, .len = 28 },
    .{ .bits = 0xfffffe5, .len = 28 },
    .{ .bits = 0xfffffe6, .len = 28 },
    .{ .bits = 0xfffffe7, .len = 28 },
    .{ .bits = 0xfffffe8, .len = 28 },
    .{ .bits = 0xffffea, .len = 24 },
    .{ .bits = 0x3ffffffc, .len = 30 },
    .{ .bits = 0xfffffe9, .len = 28 },
    .{ .bits = 0xfffffea, .len = 28 },
    .{ .bits = 0x3ffffffd, .len = 30 },
    .{ .bits = 0xfffffeb, .len = 28 },
    .{ .bits = 0xfffffec, .len = 28 },
    .{ .bits = 0xfffffed, .len = 28 },
    .{ .bits = 0xfffffee, .len = 28 },
    .{ .bits = 0xfffffef, .len = 28 },
    .{ .bits = 0xffffff0, .len = 28 },
    .{ .bits = 0xffffff1, .len = 28 },
    .{ .bits = 0xffffff2, .len = 28 },
    .{ .bits = 0x3ffffffe, .len = 30 },
    .{ .bits = 0xffffff3, .len = 28 },
    .{ .bits = 0xffffff4, .len = 28 },
    .{ .bits = 0xffffff5, .len = 28 },
    .{ .bits = 0xffffff6, .len = 28 },
    .{ .bits = 0xffffff7, .len = 28 },
    .{ .bits = 0xffffff8, .len = 28 },
    .{ .bits = 0xffffff9, .len = 28 },
    .{ .bits = 0xffffffa, .len = 28 },
    .{ .bits = 0xffffffb, .len = 28 },
    .{ .bits = 0x14, .len = 6 },
    .{ .bits = 0x3f8, .len = 10 },
    .{ .bits = 0x3f9, .len = 10 },
    .{ .bits = 0xffa, .len = 12 },
    .{ .bits = 0x1ff9, .len = 13 },
    .{ .bits = 0x15, .len = 6 },
    .{ .bits = 0xf8, .len = 8 },
    .{ .bits = 0x7fa, .len = 11 },
    .{ .bits = 0x3fa, .len = 10 },
    .{ .bits = 0x3fb, .len = 10 },
    .{ .bits = 0xf9, .len = 8 },
    .{ .bits = 0x7fb, .len = 11 },
    .{ .bits = 0xfa, .len = 8 },
    .{ .bits = 0x16, .len = 6 },
    .{ .bits = 0x17, .len = 6 },
    .{ .bits = 0x18, .len = 6 },
    .{ .bits = 0x0, .len = 5 },
    .{ .bits = 0x1, .len = 5 },
    .{ .bits = 0x2, .len = 5 },
    .{ .bits = 0x19, .len = 6 },
    .{ .bits = 0x1a, .len = 6 },
    .{ .bits = 0x1b, .len = 6 },
    .{ .bits = 0x1c, .len = 6 },
    .{ .bits = 0x1d, .len = 6 },
    .{ .bits = 0x1e, .len = 6 },
    .{ .bits = 0x1f, .len = 6 },
    .{ .bits = 0x5c, .len = 7 },
    .{ .bits = 0xfb, .len = 8 },
    .{ .bits = 0x7ffc, .len = 15 },
    .{ .bits = 0x20, .len = 6 },
    .{ .bits = 0xffb, .len = 12 },
    .{ .bits = 0x3fc, .len = 10 },
    .{ .bits = 0x1ffa, .len = 13 },
    .{ .bits = 0x21, .len = 6 },
    .{ .bits = 0x5d, .len = 7 },
    .{ .bits = 0x5e, .len = 7 },
    .{ .bits = 0x5f, .len = 7 },
    .{ .bits = 0x60, .len = 7 },
    .{ .bits = 0x61, .len = 7 },
    .{ .bits = 0x62, .len = 7 },
    .{ .bits = 0x63, .len = 7 },
    .{ .bits = 0x64, .len = 7 },
    .{ .bits = 0x65, .len = 7 },
    .{ .bits = 0x66, .len = 7 },
    .{ .bits = 0x67, .len = 7 },
    .{ .bits = 0x68, .len = 7 },
    .{ .bits = 0x69, .len = 7 },
    .{ .bits = 0x6a, .len = 7 },
    .{ .bits = 0x6b, .len = 7 },
    .{ .bits = 0x6c, .len = 7 },
    .{ .bits = 0x6d, .len = 7 },
    .{ .bits = 0x6e, .len = 7 },
    .{ .bits = 0x6f, .len = 7 },
    .{ .bits = 0x70, .len = 7 },
    .{ .bits = 0x71, .len = 7 },
    .{ .bits = 0x72, .len = 7 },
    .{ .bits = 0xfc, .len = 8 },
    .{ .bits = 0x73, .len = 7 },
    .{ .bits = 0xfd, .len = 8 },
    .{ .bits = 0x1ffb, .len = 13 },
    .{ .bits = 0x7fff0, .len = 19 },
    .{ .bits = 0x1ffc, .len = 13 },
    .{ .bits = 0x3ffc, .len = 14 },
    .{ .bits = 0x22, .len = 6 },
    .{ .bits = 0x7ffd, .len = 15 },
    .{ .bits = 0x3, .len = 5 },
    .{ .bits = 0x23, .len = 6 },
    .{ .bits = 0x4, .len = 5 },
    .{ .bits = 0x24, .len = 6 },
    .{ .bits = 0x5, .len = 5 },
    .{ .bits = 0x25, .len = 6 },
    .{ .bits = 0x26, .len = 6 },
    .{ .bits = 0x27, .len = 6 },
    .{ .bits = 0x6, .len = 5 },
    .{ .bits = 0x74, .len = 7 },
    .{ .bits = 0x75, .len = 7 },
    .{ .bits = 0x28, .len = 6 },
    .{ .bits = 0x29, .len = 6 },
    .{ .bits = 0x2a, .len = 6 },
    .{ .bits = 0x7, .len = 5 },
    .{ .bits = 0x2b, .len = 6 },
    .{ .bits = 0x76, .len = 7 },
    .{ .bits = 0x2c, .len = 6 },
    .{ .bits = 0x8, .len = 5 },
    .{ .bits = 0x9, .len = 5 },
    .{ .bits = 0x2d, .len = 6 },
    .{ .bits = 0x77, .len = 7 },
    .{ .bits = 0x78, .len = 7 },
    .{ .bits = 0x79, .len = 7 },
    .{ .bits = 0x7a, .len = 7 },
    .{ .bits = 0x7b, .len = 7 },
    .{ .bits = 0x7ffe, .len = 15 },
    .{ .bits = 0x7fc, .len = 11 },
    .{ .bits = 0x3ffd, .len = 14 },
    .{ .bits = 0x1ffd, .len = 13 },
    .{ .bits = 0xffffffc, .len = 28 },
    .{ .bits = 0xfffe6, .len = 20 },
    .{ .bits = 0x3fffd2, .len = 22 },
    .{ .bits = 0xfffe7, .len = 20 },
    .{ .bits = 0xfffe8, .len = 20 },
    .{ .bits = 0x3fffd3, .len = 22 },
    .{ .bits = 0x3fffd4, .len = 22 },
    .{ .bits = 0x3fffd5, .len = 22 },
    .{ .bits = 0x7fffd9, .len = 23 },
    .{ .bits = 0x3fffd6, .len = 22 },
    .{ .bits = 0x7fffda, .len = 23 },
    .{ .bits = 0x7fffdb, .len = 23 },
    .{ .bits = 0x7fffdc, .len = 23 },
    .{ .bits = 0x7fffdd, .len = 23 },
    .{ .bits = 0x7fffde, .len = 23 },
    .{ .bits = 0xffffeb, .len = 24 },
    .{ .bits = 0x7fffdf, .len = 23 },
    .{ .bits = 0xffffec, .len = 24 },
    .{ .bits = 0xffffed, .len = 24 },
    .{ .bits = 0x3fffd7, .len = 22 },
    .{ .bits = 0x7fffe0, .len = 23 },
    .{ .bits = 0xffffee, .len = 24 },
    .{ .bits = 0x7fffe1, .len = 23 },
    .{ .bits = 0x7fffe2, .len = 23 },
    .{ .bits = 0x7fffe3, .len = 23 },
    .{ .bits = 0x7fffe4, .len = 23 },
    .{ .bits = 0x1fffdc, .len = 21 },
    .{ .bits = 0x3fffd8, .len = 22 },
    .{ .bits = 0x7fffe5, .len = 23 },
    .{ .bits = 0x3fffd9, .len = 22 },
    .{ .bits = 0x7fffe6, .len = 23 },
    .{ .bits = 0x7fffe7, .len = 23 },
    .{ .bits = 0xffffef, .len = 24 },
    .{ .bits = 0x3fffda, .len = 22 },
    .{ .bits = 0x1fffdd, .len = 21 },
    .{ .bits = 0xfffe9, .len = 20 },
    .{ .bits = 0x3fffdb, .len = 22 },
    .{ .bits = 0x3fffdc, .len = 22 },
    .{ .bits = 0x7fffe8, .len = 23 },
    .{ .bits = 0x7fffe9, .len = 23 },
    .{ .bits = 0x1fffde, .len = 21 },
    .{ .bits = 0x7fffea, .len = 23 },
    .{ .bits = 0x3fffdd, .len = 22 },
    .{ .bits = 0x3fffde, .len = 22 },
    .{ .bits = 0xfffff0, .len = 24 },
    .{ .bits = 0x1fffdf, .len = 21 },
    .{ .bits = 0x3fffdf, .len = 22 },
    .{ .bits = 0x7fffeb, .len = 23 },
    .{ .bits = 0x7fffec, .len = 23 },
    .{ .bits = 0x1fffe0, .len = 21 },
    .{ .bits = 0x1fffe1, .len = 21 },
    .{ .bits = 0x3fffe0, .len = 22 },
    .{ .bits = 0x1fffe2, .len = 21 },
    .{ .bits = 0x7fffed, .len = 23 },
    .{ .bits = 0x3fffe1, .len = 22 },
    .{ .bits = 0x7fffee, .len = 23 },
    .{ .bits = 0x7fffef, .len = 23 },
    .{ .bits = 0xfffea, .len = 20 },
    .{ .bits = 0x3fffe2, .len = 22 },
    .{ .bits = 0x3fffe3, .len = 22 },
    .{ .bits = 0x3fffe4, .len = 22 },
    .{ .bits = 0x7ffff0, .len = 23 },
    .{ .bits = 0x3fffe5, .len = 22 },
    .{ .bits = 0x3fffe6, .len = 22 },
    .{ .bits = 0x7ffff1, .len = 23 },
    .{ .bits = 0x3ffffe0, .len = 26 },
    .{ .bits = 0x3ffffe1, .len = 26 },
    .{ .bits = 0xfffeb, .len = 20 },
    .{ .bits = 0x7fff1, .len = 19 },
    .{ .bits = 0x3fffe7, .len = 22 },
    .{ .bits = 0x7ffff2, .len = 23 },
    .{ .bits = 0x3fffe8, .len = 22 },
    .{ .bits = 0x1ffffec, .len = 25 },
    .{ .bits = 0x3ffffe2, .len = 26 },
    .{ .bits = 0x3ffffe3, .len = 26 },
    .{ .bits = 0x3ffffe4, .len = 26 },
    .{ .bits = 0x7ffffde, .len = 27 },
    .{ .bits = 0x7ffffdf, .len = 27 },
    .{ .bits = 0x3ffffe5, .len = 26 },
    .{ .bits = 0xfffff1, .len = 24 },
    .{ .bits = 0x1ffffed, .len = 25 },
    .{ .bits = 0x7fff2, .len = 19 },
    .{ .bits = 0x1fffe3, .len = 21 },
    .{ .bits = 0x3ffffe6, .len = 26 },
    .{ .bits = 0x7ffffe0, .len = 27 },
    .{ .bits = 0x7ffffe1, .len = 27 },
    .{ .bits = 0x3ffffe7, .len = 26 },
    .{ .bits = 0x7ffffe2, .len = 27 },
    .{ .bits = 0xfffff2, .len = 24 },
    .{ .bits = 0x1fffe4, .len = 21 },
    .{ .bits = 0x1fffe5, .len = 21 },
    .{ .bits = 0x3ffffe8, .len = 26 },
    .{ .bits = 0x3ffffe9, .len = 26 },
    .{ .bits = 0xffffffd, .len = 28 },
    .{ .bits = 0x7ffffe3, .len = 27 },
    .{ .bits = 0x7ffffe4, .len = 27 },
    .{ .bits = 0x7ffffe5, .len = 27 },
    .{ .bits = 0xfffec, .len = 20 },
    .{ .bits = 0xfffff3, .len = 24 },
    .{ .bits = 0xfffed, .len = 20 },
    .{ .bits = 0x1fffe6, .len = 21 },
    .{ .bits = 0x3fffe9, .len = 22 },
    .{ .bits = 0x1fffe7, .len = 21 },
    .{ .bits = 0x1fffe8, .len = 21 },
    .{ .bits = 0x7ffff3, .len = 23 },
    .{ .bits = 0x3fffea, .len = 22 },
    .{ .bits = 0x3fffeb, .len = 22 },
    .{ .bits = 0x1ffffee, .len = 25 },
    .{ .bits = 0x1ffffef, .len = 25 },
    .{ .bits = 0xfffff4, .len = 24 },
    .{ .bits = 0xfffff5, .len = 24 },
    .{ .bits = 0x3ffffea, .len = 26 },
    .{ .bits = 0x7ffff4, .len = 23 },
    .{ .bits = 0x3ffffeb, .len = 26 },
    .{ .bits = 0x7ffffe6, .len = 27 },
    .{ .bits = 0x3ffffec, .len = 26 },
    .{ .bits = 0x3ffffed, .len = 26 },
    .{ .bits = 0x7ffffe7, .len = 27 },
    .{ .bits = 0x7ffffe8, .len = 27 },
    .{ .bits = 0x7ffffe9, .len = 27 },
    .{ .bits = 0x7ffffea, .len = 27 },
    .{ .bits = 0x7ffffeb, .len = 27 },
    .{ .bits = 0xffffffe, .len = 28 },
    .{ .bits = 0x7ffffec, .len = 27 },
    .{ .bits = 0x7ffffed, .len = 27 },
    .{ .bits = 0x7ffffee, .len = 27 },
    .{ .bits = 0x7ffffef, .len = 27 },
    .{ .bits = 0x7fffff0, .len = 27 },
    .{ .bits = 0x3ffffee, .len = 26 },
};

pub fn encodedLen(src: []const u8) usize {
    var bits: usize = 0;
    for (src) |b| bits += table[b].len;
    return (bits + 7) / 8;
}

pub fn encode(dst: []u8, src: []const u8) Error!usize {
    const needed = encodedLen(src);
    if (dst.len < needed) return Error.BufferTooSmall;

    var acc: u64 = 0;
    var acc_bits: u8 = 0;
    var pos: usize = 0;

    for (src) |b| {
        const code = table[b];
        acc = (acc << @intCast(code.len)) | code.bits;
        acc_bits += code.len;

        while (acc_bits >= 8) {
            const shift: u6 = @intCast(acc_bits - 8);
            dst[pos] = @truncate(acc >> shift);
            pos += 1;
            acc_bits -= 8;
            acc &= lowMask(acc_bits);
        }
    }

    if (acc_bits > 0) {
        const pad: u3 = @intCast(8 - acc_bits);
        dst[pos] = @truncate((acc << pad) | lowMask(pad));
        pos += 1;
    }

    return pos;
}

pub fn decode(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var acc: u32 = 0;
    var acc_bits: u8 = 0;

    for (src) |byte| {
        var bit_index: u8 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const shift: u3 = @intCast(7 - bit_index);
            const bit: u32 = (byte >> shift) & 1;
            acc = (acc << 1) | bit;
            acc_bits += 1;

            if (acc_bits == eos.len and acc == eos.bits) return Error.HuffmanEos;
            if (findSymbol(acc, acc_bits)) |symbol| {
                try out.append(allocator, symbol);
                acc = 0;
                acc_bits = 0;
            } else if (acc_bits >= eos.len) {
                return Error.InvalidHuffmanCode;
            }
        }
    }

    if (acc_bits > 7) return Error.HuffmanPaddingTooLong;
    if (acc_bits > 0 and acc != lowMask(acc_bits)) return Error.InvalidHuffmanPadding;

    return try out.toOwnedSlice(allocator);
}

fn findSymbol(bits: u32, len: u8) ?u8 {
    for (table, 0..) |code, symbol| {
        if (code.len == len and code.bits == bits) return @intCast(symbol);
    }
    return null;
}

fn lowMask(bits: u8) u64 {
    if (bits == 0) return 0;
    return (@as(u64, 1) << @intCast(bits)) - 1;
}

test "RFC examples encode and decode" {
    const allocator = std.testing.allocator;

    const authority = "www.example.com";
    const encoded_authority = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var buf: [64]u8 = undefined;
    const authority_len = try encode(&buf, authority);
    try std.testing.expectEqualSlices(u8, &encoded_authority, buf[0..authority_len]);
    const decoded_authority = try decode(allocator, &encoded_authority);
    defer allocator.free(decoded_authority);
    try std.testing.expectEqualStrings(authority, decoded_authority);

    const cache_control = "no-cache";
    const encoded_cache_control = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    const cache_control_len = try encode(&buf, cache_control);
    try std.testing.expectEqualSlices(u8, &encoded_cache_control, buf[0..cache_control_len]);
    const decoded_cache_control = try decode(allocator, &encoded_cache_control);
    defer allocator.free(decoded_cache_control);
    try std.testing.expectEqualStrings(cache_control, decoded_cache_control);
}

test "decoder rejects invalid padding and EOS" {
    try std.testing.expectError(Error.InvalidHuffmanPadding, decode(std.testing.allocator, &.{0x00}));
    try std.testing.expectError(Error.HuffmanPaddingTooLong, decode(std.testing.allocator, &.{0xff}));

    const eos_bytes = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(Error.HuffmanEos, decode(std.testing.allocator, &eos_bytes));
}
