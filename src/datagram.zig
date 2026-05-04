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

    pub fn context(self: Decoded) Error!ContextPayload {
        return decodeContextPayload(self.payload);
    }
};

pub const ContextPayload = struct {
    context_id: u64,
    payload: []const u8,
};

pub fn encodedLen(stream_id: u64, payload_len: usize) Error!usize {
    return varint.encodedLen(try quarterStreamId(stream_id)) + payload_len;
}

pub fn encodedLenWithContext(stream_id: u64, context_id: u64, payload_len: usize) Error!usize {
    return try encodedLen(stream_id, contextPayloadEncodedLen(context_id, payload_len));
}

pub fn encode(dst: []u8, stream_id: u64, payload: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], try quarterStreamId(stream_id));
    if (dst.len - pos < payload.len) return error.BufferTooSmall;
    @memcpy(dst[pos .. pos + payload.len], payload);
    pos += payload.len;
    return pos;
}

pub fn encodeWithContext(
    dst: []u8,
    stream_id: u64,
    context_id: u64,
    payload: []const u8,
) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], try quarterStreamId(stream_id));
    pos += try encodeContextPayload(dst[pos..], context_id, payload);
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

pub fn contextPayloadEncodedLen(context_id: u64, payload_len: usize) usize {
    return varint.encodedLen(context_id) + payload_len;
}

pub fn encodeContextPayload(dst: []u8, context_id: u64, payload: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], context_id);
    if (dst.len - pos < payload.len) return error.BufferTooSmall;
    @memcpy(dst[pos .. pos + payload.len], payload);
    return pos + payload.len;
}

pub fn decodeContextPayload(src: []const u8) Error!ContextPayload {
    const context = try varint.decode(src);
    return .{
        .context_id = context.value,
        .payload = src[context.bytes_read..],
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

test "HTTP/3 DATAGRAM context payload round-trip" {
    const testing = std.testing;

    var buf: [64]u8 = undefined;
    const n = try encodeWithContext(&buf, 4, 7, "contextual");
    const decoded = try decode(buf[0..n]);
    try testing.expectEqual(@as(u64, 4), decoded.stream_id);
    const context = try decoded.context();
    try testing.expectEqual(@as(u64, 7), context.context_id);
    try testing.expectEqualStrings("contextual", context.payload);

    var payload_buf: [64]u8 = undefined;
    const payload_n = try encodeContextPayload(&payload_buf, 0, "default");
    const payload = try decodeContextPayload(payload_buf[0..payload_n]);
    try testing.expectEqual(@as(u64, 0), payload.context_id);
    try testing.expectEqualStrings("default", payload.payload);
}

test "HTTP/3 DATAGRAM only uses client-initiated bidi stream ids" {
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(1));
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(2));
    try std.testing.expectError(error.InvalidDatagramStream, validateStreamId(3));
    try validateStreamId(4);
}
