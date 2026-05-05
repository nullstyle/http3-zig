//! RFC 6455 WebSocket frame codec.
//!
//! The codec is transport-free. Decoding returns owned payload bytes so masked
//! client frames can be unmasked in place before applications inspect them.

const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn isData(self: Opcode) bool {
        return self == .text or self == .binary;
    }
};

pub const MaskPolicy = enum {
    any,
    required,
    forbidden,
};

pub const Error = std.mem.Allocator.Error || error{
    BufferTooSmall,
    InsufficientBytes,
    InvalidRsv,
    InvalidOpcode,
    PayloadTooLarge,
    NonMinimalLength,
    MaskRequired,
    MaskForbidden,
    FragmentedControlFrame,
    ControlPayloadTooLarge,
    InvalidClosePayload,
    InvalidCloseCode,
    UnexpectedContinuation,
    FragmentedMessageInProgress,
};

pub const EncodeOptions = struct {
    mask: bool = false,
    masking_key: [4]u8 = .{ 0, 0, 0, 0 },
};

pub const DecodeOptions = struct {
    mask_policy: MaskPolicy = .any,
    max_payload_len: ?usize = null,
};

pub const Frame = struct {
    fin: bool = true,
    opcode: Opcode,
    payload: []const u8 = &.{},
};

pub const OwnedFrame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []u8,

    pub fn deinit(self: OwnedFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    pub fn borrowed(self: *const OwnedFrame) Frame {
        return .{
            .fin = self.fin,
            .opcode = self.opcode,
            .payload = self.payload,
        };
    }
};

pub const Decoded = struct {
    frame: OwnedFrame,
    bytes_read: usize,

    pub fn deinit(self: Decoded, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
    }
};

pub fn encodedLen(frame: Frame, options: EncodeOptions) Error!usize {
    try validateFrameShape(frame);
    return headerLen(frame.payload.len, options.mask) + frame.payload.len;
}

pub fn encode(dst: []u8, frame: Frame, options: EncodeOptions) Error!usize {
    try validateFrameShape(frame);
    const needed = headerLen(frame.payload.len, options.mask) + frame.payload.len;
    if (dst.len < needed) return Error.BufferTooSmall;

    var pos: usize = 0;
    dst[pos] = if (frame.fin) 0x80 else 0;
    dst[pos] |= @intFromEnum(frame.opcode);
    pos += 1;

    const mask_bit: u8 = if (options.mask) 0x80 else 0;
    if (frame.payload.len <= 125) {
        dst[pos] = mask_bit | @as(u8, @intCast(frame.payload.len));
        pos += 1;
    } else if (frame.payload.len <= std.math.maxInt(u16)) {
        dst[pos] = mask_bit | 126;
        pos += 1;
        std.mem.writeInt(u16, dst[pos..][0..2], @intCast(frame.payload.len), .big);
        pos += 2;
    } else {
        dst[pos] = mask_bit | 127;
        pos += 1;
        std.mem.writeInt(u64, dst[pos..][0..8], @intCast(frame.payload.len), .big);
        pos += 8;
    }

    if (options.mask) {
        @memcpy(dst[pos .. pos + 4], &options.masking_key);
        pos += 4;
        @memcpy(dst[pos .. pos + frame.payload.len], frame.payload);
        applyMask(dst[pos .. pos + frame.payload.len], options.masking_key);
        pos += frame.payload.len;
    } else {
        @memcpy(dst[pos .. pos + frame.payload.len], frame.payload);
        pos += frame.payload.len;
    }

    return pos;
}

pub fn decode(
    allocator: std.mem.Allocator,
    src: []const u8,
    options: DecodeOptions,
) Error!Decoded {
    if (src.len < 2) return Error.InsufficientBytes;

    const first = src[0];
    if ((first & 0x70) != 0) return Error.InvalidRsv;
    const fin = (first & 0x80) != 0;
    const opcode = try opcodeFromValue(first & 0x0f);

    const second = src[1];
    const masked = (second & 0x80) != 0;
    switch (options.mask_policy) {
        .any => {},
        .required => if (!masked) return Error.MaskRequired,
        .forbidden => if (masked) return Error.MaskForbidden,
    }

    var pos: usize = 2;
    var payload_len: u64 = second & 0x7f;
    if (payload_len == 126) {
        if (src.len - pos < 2) return Error.InsufficientBytes;
        payload_len = std.mem.readInt(u16, src[pos..][0..2], .big);
        if (payload_len < 126) return Error.NonMinimalLength;
        pos += 2;
    } else if (payload_len == 127) {
        if (src.len - pos < 8) return Error.InsufficientBytes;
        payload_len = std.mem.readInt(u64, src[pos..][0..8], .big);
        if ((payload_len & (@as(u64, 1) << 63)) != 0) return Error.PayloadTooLarge;
        if (payload_len <= std.math.maxInt(u16)) return Error.NonMinimalLength;
        pos += 8;
    }

    const payload_len_usize = std.math.cast(usize, payload_len) orelse return Error.PayloadTooLarge;
    if (options.max_payload_len) |max| {
        if (payload_len_usize > max) return Error.PayloadTooLarge;
    }
    try validateDecodedFrameShape(fin, opcode, payload_len_usize);

    var masking_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (src.len - pos < 4) return Error.InsufficientBytes;
        @memcpy(&masking_key, src[pos .. pos + 4]);
        pos += 4;
    }

    if (src.len - pos < payload_len_usize) return Error.InsufficientBytes;
    const payload_src = src[pos .. pos + payload_len_usize];
    pos += payload_len_usize;

    const payload = try allocator.dupe(u8, payload_src);
    errdefer allocator.free(payload);
    if (masked) applyMask(payload, masking_key);
    if (opcode == .close) try validateClosePayload(payload);

    return .{
        .frame = .{
            .fin = fin,
            .opcode = opcode,
            .payload = payload,
        },
        .bytes_read = pos,
    };
}

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    options: DecodeOptions = .{},
    buffer: std.ArrayList(u8) = .empty,
    fragmented_opcode: ?Opcode = null,

    pub fn init(allocator: std.mem.Allocator, options: DecodeOptions) Decoder {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn push(self: *Decoder, bytes: []const u8) Error!void {
        try self.buffer.appendSlice(self.allocator, bytes);
    }

    pub fn next(self: *Decoder) Error!?OwnedFrame {
        const decoded = decode(self.allocator, self.buffer.items, self.options) catch |err| switch (err) {
            error.InsufficientBytes => return null,
            else => return err,
        };
        errdefer decoded.frame.deinit(self.allocator);

        try self.validateFragmentState(decoded.frame);
        compactBuffer(&self.buffer, decoded.bytes_read);
        return decoded.frame;
    }

    pub fn receive(self: *Decoder, bytes: []const u8) Error!?OwnedFrame {
        try self.push(bytes);
        return try self.next();
    }

    fn validateFragmentState(self: *Decoder, frame: OwnedFrame) Error!void {
        if (frame.opcode.isControl()) return;

        if (frame.opcode == .continuation) {
            if (self.fragmented_opcode == null) return Error.UnexpectedContinuation;
            if (frame.fin) self.fragmented_opcode = null;
            return;
        }

        if (!frame.opcode.isData()) return Error.InvalidOpcode;
        if (self.fragmented_opcode != null) return Error.FragmentedMessageInProgress;
        if (!frame.fin) self.fragmented_opcode = frame.opcode;
    }
};

pub fn encodeText(dst: []u8, payload: []const u8, options: EncodeOptions) Error!usize {
    return encode(dst, .{ .opcode = .text, .payload = payload }, options);
}

pub fn encodeBinary(dst: []u8, payload: []const u8, options: EncodeOptions) Error!usize {
    return encode(dst, .{ .opcode = .binary, .payload = payload }, options);
}

pub fn encodePing(dst: []u8, payload: []const u8, options: EncodeOptions) Error!usize {
    return encode(dst, .{ .opcode = .ping, .payload = payload }, options);
}

pub fn encodePong(dst: []u8, payload: []const u8, options: EncodeOptions) Error!usize {
    return encode(dst, .{ .opcode = .pong, .payload = payload }, options);
}

pub fn encodeClose(
    dst: []u8,
    code: ?u16,
    reason: []const u8,
    options: EncodeOptions,
) Error!usize {
    var payload_buf: [125]u8 = undefined;
    const payload = try closePayload(&payload_buf, code, reason);
    return encode(dst, .{ .opcode = .close, .payload = payload }, options);
}

fn closePayload(dst: []u8, code: ?u16, reason: []const u8) Error![]const u8 {
    if (code == null and reason.len > 0) return Error.InvalidClosePayload;
    const code_len: usize = if (code == null) 0 else 2;
    if (code_len + reason.len > 125) return Error.ControlPayloadTooLarge;
    if (code) |value| {
        try validateCloseCode(value);
        std.mem.writeInt(u16, dst[0..2], value, .big);
    }
    @memcpy(dst[code_len .. code_len + reason.len], reason);
    return dst[0 .. code_len + reason.len];
}

fn headerLen(payload_len: usize, masked: bool) usize {
    const length_bytes: usize = if (payload_len <= 125)
        0
    else if (payload_len <= std.math.maxInt(u16))
        2
    else
        8;
    return 2 + length_bytes + if (masked) @as(usize, 4) else 0;
}

fn opcodeFromValue(value: u8) Error!Opcode {
    return switch (value) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xa => .pong,
        else => Error.InvalidOpcode,
    };
}

fn validateFrameShape(frame: Frame) Error!void {
    try validateDecodedFrameShape(frame.fin, frame.opcode, frame.payload.len);
    if (frame.opcode == .close) try validateClosePayload(frame.payload);
}

fn validateDecodedFrameShape(fin: bool, opcode: Opcode, payload_len: usize) Error!void {
    if (opcode.isControl()) {
        if (!fin) return Error.FragmentedControlFrame;
        if (payload_len > 125) return Error.ControlPayloadTooLarge;
    }
}

fn validateClosePayload(payload: []const u8) Error!void {
    if (payload.len == 1) return Error.InvalidClosePayload;
    if (payload.len >= 2) try validateCloseCode(std.mem.readInt(u16, payload[0..2], .big));
}

fn validateCloseCode(code: u16) Error!void {
    if (code >= 1000 and code <= 1014) {
        switch (code) {
            1004, 1005, 1006 => return Error.InvalidCloseCode,
            else => return,
        }
    }
    if (code >= 3000 and code <= 4999) return;
    return Error.InvalidCloseCode;
}

fn applyMask(payload: []u8, key: [4]u8) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= key[i & 3];
    }
}

fn compactBuffer(buffer: *std.ArrayList(u8), consumed: usize) void {
    if (consumed == 0) return;
    const remaining = buffer.items.len - consumed;
    std.mem.copyForwards(u8, buffer.items[0..remaining], buffer.items[consumed..]);
    buffer.shrinkRetainingCapacity(remaining);
}

test "WebSocket frame codec encodes and decodes masked text" {
    var buf: [64]u8 = undefined;
    const n = try encodeText(&buf, "Hi", .{
        .mask = true,
        .masking_key = .{ 0x37, 0xfa, 0x21, 0x3d },
    });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93 }, buf[0..n]);

    const decoded = try decode(std.testing.allocator, buf[0..n], .{ .mask_policy = .required });
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, n), decoded.bytes_read);
    try std.testing.expect(decoded.frame.fin);
    try std.testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try std.testing.expectEqualStrings("Hi", decoded.frame.payload);
}

test "WebSocket frame codec handles extended payload lengths" {
    var payload: [126]u8 = undefined;
    @memset(&payload, 'a');
    var buf: [256]u8 = undefined;
    const n = try encodeBinary(&buf, &payload, .{});
    try std.testing.expectEqual(@as(u8, 0x82), buf[0]);
    try std.testing.expectEqual(@as(u8, 126), buf[1]);
    try std.testing.expectEqual(@as(u16, 126), std.mem.readInt(u16, buf[2..4], .big));

    const decoded = try decode(std.testing.allocator, buf[0..n], .{ .mask_policy = .forbidden });
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqual(Opcode.binary, decoded.frame.opcode);
    try std.testing.expectEqualSlices(u8, &payload, decoded.frame.payload);
}

test "WebSocket incremental decoder preserves fragmentation state" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "hel" }, .{});
    pos += try encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "lo" }, .{});

    var decoder = Decoder.init(std.testing.allocator, .{ .mask_policy = .forbidden });
    defer decoder.deinit();
    try decoder.push(buf[0..2]);
    try std.testing.expect((try decoder.next()) == null);
    try decoder.push(buf[2..pos]);

    const first = (try decoder.next()).?;
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(Opcode.text, first.opcode);
    try std.testing.expect(!first.fin);

    const second = (try decoder.next()).?;
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(Opcode.continuation, second.opcode);
    try std.testing.expect(second.fin);
    try std.testing.expect((try decoder.next()) == null);
}

test "WebSocket frame codec rejects protocol violations" {
    try std.testing.expectError(Error.InvalidRsv, decode(std.testing.allocator, &[_]u8{ 0xc1, 0x00 }, .{}));
    try std.testing.expectError(Error.InvalidOpcode, decode(std.testing.allocator, &[_]u8{ 0x83, 0x00 }, .{}));
    try std.testing.expectError(Error.MaskRequired, decode(std.testing.allocator, &[_]u8{ 0x81, 0x00 }, .{ .mask_policy = .required }));
    try std.testing.expectError(Error.MaskForbidden, decode(std.testing.allocator, &[_]u8{ 0x81, 0x80, 0, 0, 0, 0 }, .{ .mask_policy = .forbidden }));
    try std.testing.expectError(Error.FragmentedControlFrame, decode(std.testing.allocator, &[_]u8{ 0x09, 0x00 }, .{}));
    try std.testing.expectError(Error.InvalidClosePayload, decode(std.testing.allocator, &[_]u8{ 0x88, 0x01, 0x00 }, .{}));
    try std.testing.expectError(Error.InvalidCloseCode, decode(std.testing.allocator, &[_]u8{ 0x88, 0x02, 0x03, 0xed }, .{}));
    var close_buf: [16]u8 = undefined;
    try std.testing.expectError(Error.InvalidCloseCode, encodeClose(&close_buf, 1005, "", .{}));

    var too_big_ping: [128]u8 = undefined;
    too_big_ping[0] = 0x89;
    too_big_ping[1] = 126;
    std.mem.writeInt(u16, too_big_ping[2..4], 126, .big);
    try std.testing.expectError(Error.ControlPayloadTooLarge, decode(std.testing.allocator, too_big_ping[0..4], .{}));

    var decoder = Decoder.init(std.testing.allocator, .{});
    defer decoder.deinit();
    try decoder.push(&[_]u8{ 0x80, 0x00 });
    try std.testing.expectError(Error.UnexpectedContinuation, decoder.next());
}
