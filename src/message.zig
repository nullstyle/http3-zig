//! HTTP/3 request/response message helpers.
//!
//! These utilities are intentionally transport-free. They turn field lines
//! and body bytes into HTTP/3 stream bytes, and validate decoded frame
//! sequences for request, response, and push streams.

const std = @import("std");
const nullq = @import("nullq");

const frame_mod = @import("frame.zig");
const headers_mod = @import("headers.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const stream_mod = @import("stream.zig");

const varint = nullq.wire.varint;

pub const Error = frame_mod.Error || qpack.Error || headers_mod.Error || stream_mod.FrameValidationError || varint.Error || error{
    OutOfMemory,
    BufferTooSmall,
    HeaderSectionTooLarge,
    DataBeforeHeaders,
    DuplicateHeaders,
    DataAfterTrailers,
    UnexpectedPushPromise,
    MissingHeaders,
};

pub const Kind = enum {
    request,
    response,
    push,
};

pub const EncodeOptions = struct {
    max_field_section_size: ?usize = null,
};

pub const DecodeOptions = struct {
    max_field_section_size: ?usize = null,
};

pub const Event = union(enum) {
    headers: []qpack.FieldLine,
    data: []const u8,
    trailers: []qpack.FieldLine,
    push_promise: frame_mod.PushPromise,
    ignored_unknown: u64,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .headers, .trailers => |fields| qpack.freeFieldSection(allocator, fields),
            else => {},
        }
    }
};

pub const Encoder = struct {
    kind: Kind,
    options: EncodeOptions = .{},
    sent_headers: bool = false,
    sent_trailers: bool = false,

    pub fn init(kind: Kind, options: EncodeOptions) Encoder {
        return .{ .kind = kind, .options = options };
    }

    pub fn encodeHeaders(self: *Encoder, dst: []u8, fields: []const qpack.FieldLine) Error!usize {
        if (self.sent_headers) return Error.DuplicateHeaders;
        try validateFields(self.kind, fields);
        const n = try encodeHeadersFrame(dst, fields, self.options);
        self.sent_headers = true;
        return n;
    }

    pub fn encodeData(self: *Encoder, dst: []u8, data: []const u8) Error!usize {
        if (!self.sent_headers) return Error.DataBeforeHeaders;
        if (self.sent_trailers) return Error.DataAfterTrailers;
        return try encodeDataFrame(dst, data);
    }

    pub fn encodeTrailers(self: *Encoder, dst: []u8, fields: []const qpack.FieldLine) Error!usize {
        if (!self.sent_headers) return Error.MissingHeaders;
        if (self.sent_trailers) return Error.DuplicateHeaders;
        try headers_mod.validateTrailers(fields);
        const n = try encodeHeadersFrame(dst, fields, self.options);
        self.sent_trailers = true;
        return n;
    }
};

pub const Decoder = struct {
    kind: Kind,
    options: DecodeOptions = .{},
    validator: stream_mod.FrameValidator,
    seen_headers: bool = false,
    seen_trailers: bool = false,

    pub fn init(kind: Kind, options: DecodeOptions) Decoder {
        return .{
            .kind = kind,
            .options = options,
            .validator = stream_mod.FrameValidator.init(frameContext(kind)),
        };
    }

    pub fn observe(self: *Decoder, allocator: std.mem.Allocator, f: frame_mod.Frame) Error!?Event {
        try self.validator.observe(frame_mod.frameType(f));
        switch (f) {
            .headers => |block| {
                if (self.seen_trailers) return Error.DuplicateHeaders;
                if (self.options.max_field_section_size) |max| {
                    if (block.len > max) return Error.HeaderSectionTooLarge;
                }
                const fields = try qpack.decodeFieldSection(allocator, block);
                errdefer allocator.free(fields);
                if (!self.seen_headers) {
                    try validateFields(self.kind, fields);
                    self.seen_headers = true;
                    return .{ .headers = fields };
                }
                try headers_mod.validateTrailers(fields);
                self.seen_trailers = true;
                return .{ .trailers = fields };
            },
            .data => |bytes| {
                if (!self.seen_headers) return Error.DataBeforeHeaders;
                if (self.seen_trailers) return Error.DataAfterTrailers;
                return .{ .data = bytes };
            },
            .push_promise => |promise| {
                if (self.kind != .request) return Error.UnexpectedPushPromise;
                return .{ .push_promise = promise };
            },
            .unknown => |u| return .{ .ignored_unknown = u.frame_type },
            else => return null,
        }
    }

    pub fn observeBytes(
        self: *Decoder,
        allocator: std.mem.Allocator,
        bytes: []const u8,
        events: *std.ArrayList(Event),
    ) Error!void {
        var it = frame_mod.iter(bytes);
        while (try it.next()) |decoded| {
            if (try self.observe(allocator, decoded.frame)) |event| {
                events.append(allocator, event) catch |err| {
                    event.deinit(allocator);
                    return err;
                };
            }
        }
    }

    pub fn finish(self: *const Decoder) Error!void {
        if (!self.seen_headers) return Error.MissingHeaders;
    }
};

pub fn encodeHeadersFrame(
    dst: []u8,
    fields: []const qpack.FieldLine,
    options: EncodeOptions,
) Error!usize {
    const field_section_len = qpack.fieldSectionEncodedLen(fields);
    if (options.max_field_section_size) |max| {
        if (field_section_len > max) return Error.HeaderSectionTooLarge;
    }

    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], protocol.FrameType.headers);
    pos += try varint.encode(dst[pos..], field_section_len);
    pos += try qpack.encodeFieldSection(dst[pos..], fields);
    return pos;
}

pub fn encodeDataFrame(dst: []u8, data: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], protocol.FrameType.data);
    pos += try varint.encode(dst[pos..], data.len);
    if (dst.len - pos < data.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + data.len], data);
    return pos + data.len;
}

fn validateFields(kind: Kind, fields: []const qpack.FieldLine) headers_mod.Error!void {
    switch (kind) {
        .request => try headers_mod.validateRequest(fields),
        .response, .push => try headers_mod.validateResponse(fields),
    }
}

fn frameContext(kind: Kind) stream_mod.FrameContext {
    return switch (kind) {
        .request, .response => .request,
        .push => .push,
    };
}

test "request encoder and decoder round-trip headers data trailers" {
    const fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/upload" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]qpack.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = Encoder.init(.request, .{});
    pos += try enc.encodeHeaders(buf[pos..], &fields);
    pos += try enc.encodeData(buf[pos..], "hello");
    pos += try enc.encodeTrailers(buf[pos..], &trailers);

    var dec = Decoder.init(.request, .{});
    var events: std.ArrayList(Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }
    try dec.observeBytes(std.testing.allocator, buf[0..pos], &events);
    try dec.finish();

    try std.testing.expectEqual(@as(usize, 3), events.items.len);
    switch (events.items[0]) {
        .headers => |h| try std.testing.expectEqualStrings("/upload", h[2].value),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[1]) {
        .data => |bytes| try std.testing.expectEqualStrings("hello", bytes),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[2]) {
        .trailers => |t| try std.testing.expectEqualStrings("ok", t[0].value),
        else => return error.TestExpectedEqual,
    }
}
