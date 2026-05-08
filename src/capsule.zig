//! Capsule Protocol codec (RFC 9297).

const std = @import("std");
const quic_zig = @import("quic_zig");

const varint = quic_zig.wire.varint;

pub const Error = varint.Error || error{
    BufferTooSmall,
};

pub const Type = struct {
    pub const datagram: u64 = 0x00;
};

pub const Capsule = struct {
    capsule_type: u64,
    value: []const u8,

    pub fn isDatagram(self: Capsule) bool {
        return self.capsule_type == Type.datagram;
    }
};

pub const Decoded = struct {
    capsule: Capsule,
    bytes_read: usize,
};

pub fn encodedLen(capsule_type: u64, value_len: usize) usize {
    return varint.encodedLen(capsule_type) + varint.encodedLen(value_len) + value_len;
}

pub fn datagramEncodedLen(payload_len: usize) usize {
    return encodedLen(Type.datagram, payload_len);
}

pub fn encode(dst: []u8, capsule_type: u64, value: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], capsule_type);
    pos += try varint.encode(dst[pos..], value.len);
    if (dst.len - pos < value.len) return error.BufferTooSmall;
    @memcpy(dst[pos .. pos + value.len], value);
    return pos + value.len;
}

pub fn encodeDatagram(dst: []u8, payload: []const u8) Error!usize {
    return encode(dst, Type.datagram, payload);
}

pub fn decode(src: []const u8) Error!Decoded {
    var pos: usize = 0;
    const type_dec = try varint.decode(src[pos..]);
    pos += type_dec.bytes_read;
    const len_dec = try varint.decode(src[pos..]);
    pos += len_dec.bytes_read;

    const value_len: usize = @intCast(len_dec.value);
    if (src.len - pos < value_len) return error.InsufficientBytes;
    return .{
        .capsule = .{
            .capsule_type = type_dec.value,
            .value = src[pos .. pos + value_len],
        },
        .bytes_read = pos + value_len,
    };
}

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) Error!?Decoded {
        if (self.pos >= self.bytes.len) return null;
        const decoded = try decode(self.bytes[self.pos..]);
        self.pos += decoded.bytes_read;
        return decoded;
    }
};

pub fn iter(bytes: []const u8) Iterator {
    return .{ .bytes = bytes };
}

test "DATAGRAM capsule round-trip" {
    var buf: [64]u8 = undefined;
    const n = try encodeDatagram(&buf, "payload");
    const decoded = try decode(buf[0..n]);
    try std.testing.expectEqual(Type.datagram, decoded.capsule.capsule_type);
    try std.testing.expect(decoded.capsule.isDatagram());
    try std.testing.expectEqualStrings("payload", decoded.capsule.value);
    try std.testing.expectEqual(n, decoded.bytes_read);
}

test "capsule iterator skips unknown types as opaque values" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try encode(buf[pos..], 0x29 * 3 + 0x17, "grease");
    pos += try encodeDatagram(buf[pos..], "dgram");

    var it = iter(buf[0..pos]);
    const unknown = (try it.next()).?;
    try std.testing.expect(!unknown.capsule.isDatagram());
    try std.testing.expectEqualStrings("grease", unknown.capsule.value);
    const datagram = (try it.next()).?;
    try std.testing.expect(datagram.capsule.isDatagram());
    try std.testing.expectEqualStrings("dgram", datagram.capsule.value);
    try std.testing.expect((try it.next()) == null);
}
