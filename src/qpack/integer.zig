//! QPACK prefixed integer codec (RFC 9204 §4.1.1).

pub const Error = error{
    InvalidPrefix,
    BufferTooSmall,
    InsufficientBytes,
    ValueTooLarge,
};

pub const Decoded = struct {
    value: u64,
    bytes_read: usize,
};

pub fn encodedLen(prefix_bits: u8, value: u64) usize {
    const max = prefixLimit(prefix_bits) catch return 0;
    if (value < max) return 1;
    var rest = value - max;
    var n: usize = 1;
    while (rest >= 128) : (rest >>= 7) n += 1;
    return n + 1;
}

pub fn encode(dst: []u8, prefix_bits: u8, first_byte_prefix: u8, value: u64) Error!usize {
    const max = try prefixLimit(prefix_bits);
    const mask: u8 = @intCast(max);
    if ((first_byte_prefix & mask) != 0) return Error.InvalidPrefix;
    if (dst.len == 0) return Error.BufferTooSmall;

    if (value < max) {
        dst[0] = first_byte_prefix | @as(u8, @intCast(value));
        return 1;
    }

    dst[0] = first_byte_prefix | mask;
    var rest = value - max;
    var pos: usize = 1;
    while (rest >= 128) {
        if (pos >= dst.len) return Error.BufferTooSmall;
        dst[pos] = @as(u8, @intCast(rest & 0x7f)) | 0x80;
        rest >>= 7;
        pos += 1;
    }
    if (pos >= dst.len) return Error.BufferTooSmall;
    dst[pos] = @intCast(rest);
    return pos + 1;
}

pub fn decode(src: []const u8, prefix_bits: u8) Error!Decoded {
    const max = try prefixLimit(prefix_bits);
    const mask: u8 = @intCast(max);
    if (src.len == 0) return Error.InsufficientBytes;

    var value: u64 = src[0] & mask;
    if (value < max) return .{ .value = value, .bytes_read = 1 };

    var shift: u6 = 0;
    var pos: usize = 1;
    while (true) {
        if (pos >= src.len) return Error.InsufficientBytes;
        const b = src[pos];
        const chunk = @as(u64, b & 0x7f);
        if (shift >= 63 and chunk != 0) return Error.ValueTooLarge;
        value += chunk << shift;
        pos += 1;
        if ((b & 0x80) == 0) return .{ .value = value, .bytes_read = pos };
        if (shift > 56) return Error.ValueTooLarge;
        shift += 7;
    }
}

fn prefixLimit(prefix_bits: u8) Error!u64 {
    if (prefix_bits == 0 or prefix_bits > 8) return Error.InvalidPrefix;
    const shift: u6 = @intCast(prefix_bits);
    return (@as(u64, 1) << shift) - 1;
}

test "QPACK integer round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 5, 0b1110_0000, 1337);
    const d = try decode(buf[0..n], 5);
    try std.testing.expectEqual(@as(u64, 1337), d.value);
    try std.testing.expectEqual(n, d.bytes_read);
}
