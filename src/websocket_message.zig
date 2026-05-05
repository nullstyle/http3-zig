//! RFC 6455 WebSocket message assembly.
//!
//! This layer consumes owned frames from `websocket_frame.zig` and emits owned
//! application-level events. Fragmented text/binary frames are assembled into a
//! single message while control frames remain observable between fragments.

const std = @import("std");

const frame_mod = @import("websocket_frame.zig");

pub const Kind = enum {
    text,
    binary,
};

pub const Close = struct {
    code: ?u16 = null,
    reason: []u8 = &.{},

    pub fn deinit(self: Close, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

pub const Event = union(enum) {
    text: []u8,
    binary: []u8,
    ping: []u8,
    pong: []u8,
    close: Close,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .text => |payload| allocator.free(payload),
            .binary => |payload| allocator.free(payload),
            .ping => |payload| allocator.free(payload),
            .pong => |payload| allocator.free(payload),
            .close => |close| close.deinit(allocator),
        }
    }
};

pub const Error = frame_mod.Error || error{
    MessageTooLarge,
    InvalidUtf8,
};

pub const DecodeOptions = struct {
    frame: frame_mod.DecodeOptions = .{},
    max_message_len: ?usize = null,
    validate_utf8: bool = true,
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    options: DecodeOptions,
    frame_decoder: frame_mod.Decoder,
    fragmented_kind: ?Kind = null,
    message: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, options: DecodeOptions) Decoder {
        return .{
            .allocator = allocator,
            .options = options,
            .frame_decoder = frame_mod.Decoder.init(allocator, options.frame),
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.frame_decoder.deinit();
        self.message.deinit(self.allocator);
    }

    pub fn push(self: *Decoder, bytes: []const u8) Error!void {
        try self.frame_decoder.push(bytes);
    }

    pub fn next(self: *Decoder) Error!?Event {
        while (true) {
            var owned_frame = (try self.frame_decoder.next()) orelse return null;
            switch (owned_frame.opcode) {
                .text, .binary => {
                    defer owned_frame.deinit(self.allocator);
                    const kind = kindFromOpcode(owned_frame.opcode) orelse return Error.InvalidOpcode;
                    try self.appendPayload(owned_frame.payload);
                    if (!owned_frame.fin) {
                        self.fragmented_kind = kind;
                        continue;
                    }
                    return try self.takeDataEvent(kind);
                },
                .continuation => {
                    defer owned_frame.deinit(self.allocator);
                    const kind = self.fragmented_kind orelse return Error.UnexpectedContinuation;
                    try self.appendPayload(owned_frame.payload);
                    if (!owned_frame.fin) continue;
                    self.fragmented_kind = null;
                    return try self.takeDataEvent(kind);
                },
                .ping => return .{ .ping = owned_frame.payload },
                .pong => return .{ .pong = owned_frame.payload },
                .close => {
                    defer owned_frame.deinit(self.allocator);
                    return .{ .close = try parseClose(self.allocator, owned_frame.payload, self.options.validate_utf8) };
                },
            }
        }
    }

    pub fn receive(self: *Decoder, bytes: []const u8) Error!?Event {
        try self.push(bytes);
        return try self.next();
    }

    fn appendPayload(self: *Decoder, payload: []const u8) Error!void {
        if (self.options.max_message_len) |max| {
            if (self.message.items.len > max or payload.len > max - self.message.items.len) {
                self.message.clearRetainingCapacity();
                self.fragmented_kind = null;
                return Error.MessageTooLarge;
            }
        }
        try self.message.appendSlice(self.allocator, payload);
    }

    fn takeDataEvent(self: *Decoder, kind: Kind) Error!Event {
        const payload = try self.message.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(payload);
        if (kind == .text and self.options.validate_utf8 and !std.unicode.utf8ValidateSlice(payload)) {
            return Error.InvalidUtf8;
        }
        return switch (kind) {
            .text => .{ .text = payload },
            .binary => .{ .binary = payload },
        };
    }
};

pub fn opcodeForKind(kind: Kind) frame_mod.Opcode {
    return switch (kind) {
        .text => .text,
        .binary => .binary,
    };
}

fn kindFromOpcode(opcode: frame_mod.Opcode) ?Kind {
    return switch (opcode) {
        .text => .text,
        .binary => .binary,
        else => null,
    };
}

fn parseClose(allocator: std.mem.Allocator, payload: []const u8, validate_utf8: bool) Error!Close {
    if (payload.len == 0) {
        return .{ .reason = try allocator.dupe(u8, &.{}) };
    }
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const reason = try allocator.dupe(u8, payload[2..]);
    errdefer allocator.free(reason);
    if (validate_utf8 and !std.unicode.utf8ValidateSlice(reason)) return Error.InvalidUtf8;
    return .{
        .code = code,
        .reason = reason,
    };
}

test "WebSocket message decoder assembles fragmented text around control frames" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "hel" }, .{});
    pos += try frame_mod.encodePing(buf[pos..], "?", .{});
    pos += try frame_mod.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "lo" }, .{});

    var decoder = Decoder.init(std.testing.allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const ping = (try decoder.next()).?;
    defer ping.deinit(std.testing.allocator);
    switch (ping) {
        .ping => |payload| try std.testing.expectEqualStrings("?", payload),
        else => return error.UnexpectedWebSocketEvent,
    }

    const text = (try decoder.next()).?;
    defer text.deinit(std.testing.allocator);
    switch (text) {
        .text => |payload| try std.testing.expectEqualStrings("hello", payload),
        else => return error.UnexpectedWebSocketEvent,
    }
    try std.testing.expect((try decoder.next()) == null);
}

test "WebSocket message decoder emits binary and close events" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try frame_mod.encodeBinary(buf[pos..], "\x00\x01\x02", .{});
    pos += try frame_mod.encodeClose(buf[pos..], 1000, "done", .{});

    var decoder = Decoder.init(std.testing.allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const binary = (try decoder.next()).?;
    defer binary.deinit(std.testing.allocator);
    switch (binary) {
        .binary => |payload| try std.testing.expectEqualSlices(u8, "\x00\x01\x02", payload),
        else => return error.UnexpectedWebSocketEvent,
    }

    const close = (try decoder.next()).?;
    defer close.deinit(std.testing.allocator);
    switch (close) {
        .close => |payload| {
            try std.testing.expectEqual(@as(?u16, 1000), payload.code);
            try std.testing.expectEqualStrings("done", payload.reason);
        },
        else => return error.UnexpectedWebSocketEvent,
    }
    try std.testing.expect((try decoder.next()) == null);
}

test "WebSocket message decoder enforces aggregate message limits" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "abc" }, .{});
    pos += try frame_mod.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "def" }, .{});

    var decoder = Decoder.init(std.testing.allocator, .{
        .frame = .{ .mask_policy = .forbidden },
        .max_message_len = 5,
    });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);
    try std.testing.expectError(Error.MessageTooLarge, decoder.next());
}

test "WebSocket message decoder validates UTF-8 text and close reasons" {
    var text_buf: [16]u8 = undefined;
    const text_n = try frame_mod.encodeText(text_buf[0..], "\xff", .{});

    var decoder = Decoder.init(std.testing.allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(text_buf[0..text_n]);
    try std.testing.expectError(Error.InvalidUtf8, decoder.next());

    var close_payload = [_]u8{ 0x03, 0xe8, 0xff };
    var close_buf: [16]u8 = undefined;
    const close_n = try frame_mod.encode(close_buf[0..], .{ .opcode = .close, .payload = &close_payload }, .{});

    var close_decoder = Decoder.init(std.testing.allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer close_decoder.deinit();
    try close_decoder.push(close_buf[0..close_n]);
    try std.testing.expectError(Error.InvalidUtf8, close_decoder.next());
}
