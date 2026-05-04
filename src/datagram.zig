//! HTTP/3 DATAGRAM payload codec (RFC 9297).

const std = @import("std");
const nullq = @import("nullq");

const varint = nullq.wire.varint;

pub const Error = varint.Error || error{
    InvalidDatagramStream,
    BufferTooSmall,
};

pub const Decoded = struct {
    stream_id: u64,
    payload: []const u8,
};

pub fn encodedLen(stream_id: u64, payload_len: usize) Error!usize {
    return varint.encodedLen(try quarterStreamId(stream_id)) + payload_len;
}

pub fn encode(dst: []u8, stream_id: u64, payload: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], try quarterStreamId(stream_id));
    if (dst.len - pos < payload.len) return error.BufferTooSmall;
    @memcpy(dst[pos .. pos + payload.len], payload);
    pos += payload.len;
    return pos;
}

pub fn decode(src: []const u8) Error!Decoded {
    const quarter = try varint.decode(src);
    const stream_id = quarter.value * 4;
    return .{
        .stream_id = stream_id,
        .payload = src[quarter.bytes_read..],
    };
}

pub fn validateStreamId(stream_id: u64) Error!void {
    _ = try quarterStreamId(stream_id);
}

fn quarterStreamId(stream_id: u64) Error!u64 {
    if ((stream_id & 0b11) != 0) return error.InvalidDatagramStream;
    return stream_id / 4;
}

test "HTTP/3 DATAGRAM payload round-trip" {
    const testing = std.testing;

    var buf: [64]u8 = undefined;
    const n = try encode(&buf, 8, "capsule-free");
    const decoded = try decode(buf[0..n]);
    try testing.expectEqual(@as(u64, 8), decoded.stream_id);
    try testing.expectEqualStrings("capsule-free", decoded.payload);
}

test "HTTP/3 DATAGRAM only uses client-initiated bidi stream ids" {
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(1));
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(2));
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(3));
    try validateStreamId(4);
}
