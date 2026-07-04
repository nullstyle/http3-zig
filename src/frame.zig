//! HTTP/3 frame codec.

const quic_zig = @import("quic_zig");
const protocol = @import("protocol.zig");
const settings_mod = @import("settings.zig");

const varint = quic_zig.wire.varint;

pub const Error = varint.Error || settings_mod.Error || error{
    InvalidFramePayload,
};

pub const PushPromise = struct {
    push_id: u64,
    field_section: []const u8,
};

pub const PriorityUpdate = struct {
    prioritized_element_id: u64,
    priority_field_value: []const u8,
};

pub const Unknown = struct {
    frame_type: u64,
    payload: []const u8,
};

pub const Frame = union(enum) {
    data: []const u8,
    headers: []const u8,
    cancel_push: u64,
    settings: settings_mod.Settings,
    push_promise: PushPromise,
    goaway: u64,
    max_push_id: u64,
    priority_update_request: PriorityUpdate,
    priority_update_push: PriorityUpdate,
    unknown: Unknown,
};

pub const Decoded = struct {
    frame: Frame,
    bytes_read: usize,
};

/// A frame's type and declared payload length, decodable from just the two
/// leading varints — before the payload itself is present.
pub const Header = struct {
    frame_type: u64,
    /// Declared payload length (does not include the type/length varints).
    length: u64,
    /// Bytes occupied by the type + length varints.
    header_len: usize,
};

/// Peek a frame's type and declared length without requiring its payload to
/// be buffered. Returns null when fewer than the two leading varints are
/// present yet (caller waits for more bytes). Lets a consumer reject an
/// over-cap frame on its declared length before reassembling the payload —
/// `decode` below requires the whole payload up front, so a size check that
/// runs only after `decode` succeeds has already paid the buffering cost.
pub fn peekHeader(src: []const u8) ?Header {
    const typ_dec = varint.decode(src) catch return null;
    const len_dec = varint.decode(src[typ_dec.bytes_read..]) catch return null;
    return .{
        .frame_type = typ_dec.value,
        .length = len_dec.value,
        .header_len = typ_dec.bytes_read + len_dec.bytes_read,
    };
}

test "peekHeader reads type+length without the payload; null when incomplete" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    var n: usize = 0;
    n += try varint.encode(buf[n..], protocol.FrameType.headers);
    n += try varint.encode(buf[n..], 200_000); // declared length, no payload present
    const hdr = peekHeader(buf[0..n]).?;
    try std.testing.expectEqual(protocol.FrameType.headers, hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 200_000), hdr.length);
    try std.testing.expectEqual(n, hdr.header_len);
    // One byte short of the length varint, and empty input: not enough to
    // peek the header yet -> null (caller waits for more bytes).
    try std.testing.expect(peekHeader(buf[0 .. n - 1]) == null);
    try std.testing.expect(peekHeader("") == null);
}

pub const Iterator = struct {
    src: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) Error!?Decoded {
        if (self.pos >= self.src.len) return null;
        const d = try decode(self.src[self.pos..]);
        self.pos += d.bytes_read;
        return d;
    }
};

pub fn iter(src: []const u8) Iterator {
    return .{ .src = src };
}

pub fn frameType(frame: Frame) u64 {
    return switch (frame) {
        .data => protocol.FrameType.data,
        .headers => protocol.FrameType.headers,
        .cancel_push => protocol.FrameType.cancel_push,
        .settings => protocol.FrameType.settings,
        .push_promise => protocol.FrameType.push_promise,
        .goaway => protocol.FrameType.goaway,
        .max_push_id => protocol.FrameType.max_push_id,
        .priority_update_request => protocol.FrameType.priority_update_request,
        .priority_update_push => protocol.FrameType.priority_update_push,
        .unknown => |u| u.frame_type,
    };
}

pub fn payloadLen(frame: Frame) usize {
    return switch (frame) {
        .data => |bytes| bytes.len,
        .headers => |bytes| bytes.len,
        .cancel_push => |id| varint.encodedLen(id),
        .settings => |s| s.encodedLen(),
        .push_promise => |p| varint.encodedLen(p.push_id) + p.field_section.len,
        .goaway => |id| varint.encodedLen(id),
        .max_push_id => |id| varint.encodedLen(id),
        .priority_update_request, .priority_update_push => |p| varint.encodedLen(p.prioritized_element_id) + p.priority_field_value.len,
        .unknown => |u| u.payload.len,
    };
}

pub fn encodedLen(frame: Frame) usize {
    const typ = frameType(frame);
    const len = payloadLen(frame);
    return varint.encodedLen(typ) + varint.encodedLen(len) + len;
}

pub fn encode(dst: []u8, frame: Frame) Error!usize {
    var pos: usize = 0;
    const typ = frameType(frame);
    const len = payloadLen(frame);
    pos += try varint.encode(dst[pos..], typ);
    pos += try varint.encode(dst[pos..], len);
    switch (frame) {
        .data, .headers => |bytes| {
            if (dst.len - pos < bytes.len) return Error.BufferTooSmall;
            @memcpy(dst[pos .. pos + bytes.len], bytes);
            pos += bytes.len;
        },
        .cancel_push, .goaway, .max_push_id => |id| {
            pos += try varint.encode(dst[pos..], id);
        },
        .settings => |s| {
            pos += try s.encode(dst[pos..]);
        },
        .push_promise => |p| {
            pos += try varint.encode(dst[pos..], p.push_id);
            if (dst.len - pos < p.field_section.len) return Error.BufferTooSmall;
            @memcpy(dst[pos .. pos + p.field_section.len], p.field_section);
            pos += p.field_section.len;
        },
        .priority_update_request, .priority_update_push => |p| {
            pos += try varint.encode(dst[pos..], p.prioritized_element_id);
            if (dst.len - pos < p.priority_field_value.len) return Error.BufferTooSmall;
            @memcpy(dst[pos .. pos + p.priority_field_value.len], p.priority_field_value);
            pos += p.priority_field_value.len;
        },
        .unknown => |u| {
            if (dst.len - pos < u.payload.len) return Error.BufferTooSmall;
            @memcpy(dst[pos .. pos + u.payload.len], u.payload);
            pos += u.payload.len;
        },
    }
    return pos;
}

pub fn decode(src: []const u8) Error!Decoded {
    var pos: usize = 0;
    const typ_dec = try varint.decode(src[pos..]);
    pos += typ_dec.bytes_read;
    const len_dec = try varint.decode(src[pos..]);
    pos += len_dec.bytes_read;
    const len: usize = @intCast(len_dec.value);
    if (src.len - pos < len) return Error.InsufficientBytes;
    const payload = src[pos .. pos + len];
    pos += len;

    const frame: Frame = switch (typ_dec.value) {
        protocol.FrameType.data => .{ .data = payload },
        protocol.FrameType.headers => .{ .headers = payload },
        protocol.FrameType.cancel_push => .{ .cancel_push = try decodeSingleVarintPayload(payload) },
        protocol.FrameType.settings => .{ .settings = try settings_mod.Settings.decode(payload) },
        protocol.FrameType.push_promise => blk: {
            const first = try varint.decode(payload);
            const used: usize = first.bytes_read;
            break :blk .{ .push_promise = .{
                .push_id = first.value,
                .field_section = payload[used..],
            } };
        },
        protocol.FrameType.goaway => .{ .goaway = try decodeSingleVarintPayload(payload) },
        protocol.FrameType.max_push_id => .{ .max_push_id = try decodeSingleVarintPayload(payload) },
        protocol.FrameType.priority_update_request => blk: {
            const first = try varint.decode(payload);
            const used: usize = first.bytes_read;
            break :blk .{ .priority_update_request = .{
                .prioritized_element_id = first.value,
                .priority_field_value = payload[used..],
            } };
        },
        protocol.FrameType.priority_update_push => blk: {
            const first = try varint.decode(payload);
            const used: usize = first.bytes_read;
            break :blk .{ .priority_update_push = .{
                .prioritized_element_id = first.value,
                .priority_field_value = payload[used..],
            } };
        },
        else => .{ .unknown = .{ .frame_type = typ_dec.value, .payload = payload } },
    };
    return .{ .frame = frame, .bytes_read = pos };
}

fn decodeSingleVarintPayload(payload: []const u8) Error!u64 {
    const d = try varint.decode(payload);
    if (d.bytes_read != payload.len) return Error.InvalidFramePayload;
    return d.value;
}

test "DATA frame round-trip" {
    const std = @import("std");
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, .{ .data = "hello" });
    const d = try decode(buf[0..n]);
    try std.testing.expectEqual(n, d.bytes_read);
    switch (d.frame) {
        .data => |bytes| try std.testing.expectEqualStrings("hello", bytes),
        else => return error.TestExpectedEqual,
    }
}

test "frame iterator walks concatenated frames" {
    const std = @import("std");
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try encode(buf[pos..], .{ .headers = "abc" });
    pos += try encode(buf[pos..], .{ .data = "def" });

    var it = iter(buf[0..pos]);
    const first = (try it.next()).?;
    switch (first.frame) {
        .headers => |bytes| try std.testing.expectEqualStrings("abc", bytes),
        else => return error.TestExpectedEqual,
    }
    const second = (try it.next()).?;
    switch (second.frame) {
        .data => |bytes| try std.testing.expectEqualStrings("def", bytes),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expect((try it.next()) == null);
}
