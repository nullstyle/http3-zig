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

pub const ReassembleError = Error || std.mem.Allocator.Error || error{
    /// A capsule declared a value length exceeding
    /// `Reassembler.max_capsule_value_len`. Rejected on the declared length,
    /// before the whole value is buffered, so a hostile peer can't force
    /// unbounded reassembly of one oversized capsule.
    CapsuleTooLong,
};

/// Reassembles complete capsules (RFC 9297) from the CONNECT-stream DATA a
/// caller receives in arbitrary chunks. A single capsule may legally span
/// multiple HTTP/3 DATA frames / QUIC STREAM frames, so decoding each DATA
/// event independently corrupts a split capsule; feed every DATA event's
/// bytes through `push` and drain complete capsules with `next`.
pub const Reassembler = struct {
    buf: std.ArrayList(u8) = .empty,
    consumed: usize = 0,
    /// Optional cap on a single capsule's declared value length, enforced on
    /// the declared length before the value is fully buffered. Null =
    /// unbounded (bounded only by however much the caller pushes).
    max_capsule_value_len: ?u64 = null,

    pub fn deinit(self: *Reassembler, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    /// Append one DATA event's worth of CONNECT-stream bytes.
    pub fn push(self: *Reassembler, allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
        self.dropConsumed();
        try self.buf.appendSlice(allocator, bytes);
    }

    /// Pop the next COMPLETE capsule, or null if only a partial capsule is
    /// buffered (push more bytes and retry). The returned capsule's `value`
    /// aliases the internal buffer and is valid only until the next `push` /
    /// `next` — copy it if you need to retain it.
    pub fn next(self: *Reassembler) ReassembleError!?Capsule {
        self.dropConsumed();
        if (self.buf.items.len == 0) return null;
        if (self.max_capsule_value_len) |max| {
            if (peekValueLen(self.buf.items)) |len| {
                if (len > max) return error.CapsuleTooLong;
            }
        }
        const decoded = decode(self.buf.items) catch |err| {
            if (err == error.InsufficientBytes) return null; // partial; wait for more
            return err;
        };
        self.consumed = decoded.bytes_read;
        return decoded.capsule;
    }

    /// Bytes buffered but not yet consumed as a complete capsule.
    pub fn buffered(self: *const Reassembler) usize {
        return self.buf.items.len - self.consumed;
    }

    fn dropConsumed(self: *Reassembler) void {
        if (self.consumed == 0) return;
        const remaining = self.buf.items.len - self.consumed;
        std.mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[self.consumed..]);
        self.buf.shrinkRetainingCapacity(remaining);
        self.consumed = 0;
    }
};

/// Peek a capsule's declared value length from its two leading varints, or
/// null if fewer than both are buffered yet.
fn peekValueLen(bytes: []const u8) ?u64 {
    const type_dec = varint.decode(bytes) catch return null;
    const len_dec = varint.decode(bytes[type_dec.bytes_read..]) catch return null;
    return len_dec.value;
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

test "Reassembler joins a capsule split across DATA-event boundaries" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    const n = try encodeDatagram(&buf, "hello-masque-payload");
    const full = buf[0..n];

    var r: Reassembler = .{};
    defer r.deinit(allocator);

    // First DATA event carries only part of the capsule value.
    const split = n - 5;
    try r.push(allocator, full[0..split]);
    try std.testing.expect((try r.next()) == null); // partial → wait for more
    try std.testing.expect(r.buffered() == split);

    // Second DATA event completes it.
    try r.push(allocator, full[split..]);
    const cap = (try r.next()).?;
    try std.testing.expect(cap.isDatagram());
    try std.testing.expectEqualStrings("hello-masque-payload", cap.value);
    try std.testing.expect((try r.next()) == null); // drained
    try std.testing.expectEqual(@as(usize, 0), r.buffered());
}

test "Reassembler yields multiple capsules and caps declared value length" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try encodeDatagram(buf[pos..], "one");
    pos += try encodeDatagram(buf[pos..], "two");

    var r: Reassembler = .{};
    defer r.deinit(allocator);
    try r.push(allocator, buf[0..pos]);
    try std.testing.expectEqualStrings("one", (try r.next()).?.value);
    try std.testing.expectEqualStrings("two", (try r.next()).?.value);
    try std.testing.expect((try r.next()) == null);

    // A capsule declaring more than the cap is rejected on its declared
    // length, before its (never-arriving) value is buffered.
    var big: [8]u8 = undefined;
    var bp: usize = 0;
    bp += try varint.encode(big[bp..], Type.datagram);
    bp += try varint.encode(big[bp..], 1_000_000);
    var capped: Reassembler = .{ .max_capsule_value_len = 4096 };
    defer capped.deinit(allocator);
    try capped.push(allocator, big[0..bp]);
    try std.testing.expectError(error.CapsuleTooLong, capped.next());
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
