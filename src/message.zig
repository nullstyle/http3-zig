//! HTTP/3 request/response message helpers.
//!
//! These utilities are intentionally transport-free. They turn field lines
//! and body bytes into HTTP/3 stream bytes, and validate decoded frame
//! sequences for request, response, and push streams.

const std = @import("std");
const quic_zig = @import("quic_zig");

const frame_mod = @import("frame.zig");
const headers_mod = @import("headers.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const stream_mod = @import("stream.zig");

const varint = quic_zig.wire.varint;

pub const Error = frame_mod.Error || qpack.Error || headers_mod.Error || stream_mod.FrameValidationError || varint.Error || error{
    OutOfMemory,
    BufferTooSmall,
    HeaderSectionTooLarge,
    /// An incoming frame's DECLARED length exceeds the configured
    /// `max_incoming_frame_length` (non-DATA frames). Rejected on the
    /// declared length before the payload is reassembled — a receive-buffer
    /// DoS bound. Maps to H3_EXCESSIVE_LOAD.
    FrameTooLong,
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
    enable_connect_protocol: bool = false,
};

pub const DecodeOptions = struct {
    max_field_section_size: ?usize = null,
    enable_connect_protocol: bool = false,
};

pub const Event = union(enum) {
    headers: []qpack.FieldLine,
    /// 1xx informational response (RFC 9110 §15.2). Surfaces a
    /// non-final response HEADERS section. The application should
    /// expect more HEADERS sections — possibly more `interim_headers`
    /// events, then exactly one final `headers` event with `:status`
    /// outside the 1xx range. Only emitted on response streams (the
    /// decoder treats interim headers as illegal on requests / pushes).
    interim_headers: []qpack.FieldLine,
    data: []const u8,
    trailers: []qpack.FieldLine,
    push_promise: frame_mod.PushPromise,
    ignored_unknown: u64,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .headers, .interim_headers, .trailers => |fields| qpack.freeFieldSection(allocator, fields),
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
        // RFC 9110 §15.2: response streams MAY emit one or more 1xx
        // interim responses before the final response. Detect that
        // case via `:status` and don't flip `sent_headers` so a
        // subsequent HEADERS call can land. Request and push streams
        // get the strict no-duplicate behavior.
        const interim = self.kind == .response and isInterim(fields);
        if (self.sent_headers and !interim) return Error.DuplicateHeaders;
        try validateFields(self.kind, fields, .{
            .max_field_section_size = self.options.max_field_section_size,
            .enable_connect_protocol = self.options.enable_connect_protocol,
        });
        const n = try encodeHeadersFrame(dst, fields, self.options);
        if (!interim) self.sent_headers = true;
        return n;
    }

    pub fn encodeHeadersBlock(
        self: *Encoder,
        dst: []u8,
        fields: []const qpack.FieldLine,
        field_section: []const u8,
    ) Error!usize {
        const interim = self.kind == .response and isInterim(fields);
        if (self.sent_headers and !interim) return Error.DuplicateHeaders;
        try validateFields(self.kind, fields, .{
            .max_field_section_size = self.options.max_field_section_size,
            .enable_connect_protocol = self.options.enable_connect_protocol,
        });
        const n = try encodeHeadersFrameFromBlock(dst, field_section, self.options);
        if (!interim) self.sent_headers = true;
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

    pub fn encodeTrailersBlock(
        self: *Encoder,
        dst: []u8,
        fields: []const qpack.FieldLine,
        field_section: []const u8,
    ) Error!usize {
        if (!self.sent_headers) return Error.MissingHeaders;
        if (self.sent_trailers) return Error.DuplicateHeaders;
        try headers_mod.validateTrailers(fields);
        const n = try encodeHeadersFrameFromBlock(dst, field_section, self.options);
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
    /// Parsed `content-length` from the initial HEADERS field section, if
    /// present. RFC 9114 §4.1.2 / RFC 9110 §8.6 require the receiver to
    /// treat any mismatch with the actual message-content length as a
    /// malformed message.
    expected_body_len: ?u64 = null,
    /// Running tally of DATA frame payload bytes observed since the
    /// initial HEADERS section. Compared to `expected_body_len` at trailer
    /// arrival and at `finish()`.
    body_bytes: u64 = 0,

    pub fn init(kind: Kind, options: DecodeOptions) Decoder {
        return .{
            .kind = kind,
            .options = options,
            .validator = stream_mod.FrameValidator.init(frameContext(kind)),
        };
    }

    pub fn observe(self: *Decoder, allocator: std.mem.Allocator, f: frame_mod.Frame) Error!?Event {
        switch (f) {
            .headers => |block| {
                if (self.options.max_field_section_size) |max| {
                    if (block.len > max) return Error.HeaderSectionTooLarge;
                }
                const fields = try qpack.decodeFieldSection(allocator, block);
                return try self.observeOwnedFieldLines(allocator, fields);
            },
            .data => |bytes| {
                try self.validator.observe(frame_mod.frameType(f));
                if (!self.seen_headers) return Error.DataBeforeHeaders;
                if (self.seen_trailers) return Error.DataAfterTrailers;
                self.body_bytes = std.math.add(u64, self.body_bytes, bytes.len) catch
                    return Error.ContentLengthMismatch;
                if (self.expected_body_len) |expected| {
                    if (self.body_bytes > expected) return Error.ContentLengthMismatch;
                }
                return .{ .data = bytes };
            },
            .push_promise => |promise| {
                try self.validator.observe(frame_mod.frameType(f));
                if (self.kind != .response) return Error.UnexpectedPushPromise;
                return .{ .push_promise = promise };
            },
            .unknown => |u| {
                try self.validator.observe(frame_mod.frameType(f));
                return .{ .ignored_unknown = u.frame_type };
            },
            else => {
                try self.validator.observe(frame_mod.frameType(f));
                return null;
            },
        }
    }

    pub fn validateFrame(self: *const Decoder, f: frame_mod.Frame) Error!void {
        try stream_mod.validateFrameType(
            frameContext(self.kind),
            frame_mod.frameType(f),
            !self.validator.seen_any,
            self.validator.settings_seen,
        );

        switch (f) {
            .data => {
                if (!self.seen_headers) return Error.DataBeforeHeaders;
                if (self.seen_trailers) return Error.DataAfterTrailers;
            },
            .push_promise => {
                if (self.kind != .response) return Error.UnexpectedPushPromise;
            },
            else => {},
        }
    }

    pub fn validateOwnedFieldLines(
        self: *const Decoder,
        fields: []const qpack.FieldLine,
    ) Error!void {
        try stream_mod.validateFrameType(
            frameContext(self.kind),
            protocol.FrameType.headers,
            !self.validator.seen_any,
            self.validator.settings_seen,
        );
        if (self.seen_trailers) return Error.DuplicateHeaders;
        if (!self.seen_headers) {
            try validateFields(self.kind, fields, self.options);
        } else {
            try headers_mod.validateTrailers(fields);
        }
    }

    pub fn observeOwnedFieldLines(
        self: *Decoder,
        allocator: std.mem.Allocator,
        fields: []qpack.FieldLine,
    ) Error!Event {
        errdefer qpack.freeFieldSection(allocator, fields);

        try self.validator.observe(protocol.FrameType.headers);
        if (self.seen_trailers) return Error.DuplicateHeaders;
        if (!self.seen_headers) {
            try validateFields(self.kind, fields, self.options);

            // RFC 9110 §15.2: a 1xx (informational) response is
            // followed by at least one further response, including the
            // final response. On the response side, look at `:status`:
            // if it's 1xx, this is an interim — surface as a separate
            // event, do NOT mark `seen_headers`, and keep the decoder
            // ready to receive more HEADERS frames. On request /
            // push streams, 1xx isn't meaningful, so we fall through
            // to the regular path (validateFields would have rejected
            // it if it were structurally malformed anyway).
            if (self.kind == .response and isInterim(fields)) {
                return .{ .interim_headers = fields };
            }

            self.expected_body_len = try headers_mod.parseContentLength(fields);
            self.seen_headers = true;
            return .{ .headers = fields };
        }
        try headers_mod.validateTrailers(fields);
        // RFC 9114 §4.1.2: at trailer arrival, the body is complete. If a
        // content-length was advertised, the accumulated body length must
        // match exactly.
        if (self.expected_body_len) |expected| {
            if (self.body_bytes != expected) return Error.ContentLengthMismatch;
        }
        self.seen_trailers = true;
        return .{ .trailers = fields };
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
        // RFC 9114 §4.1.2: an under-length body (DATA bytes < advertised
        // content-length) is just as malformed as an over-length body. The
        // over-length case is already caught at observe-time.
        if (self.expected_body_len) |expected| {
            if (self.body_bytes != expected) return Error.ContentLengthMismatch;
        }
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

pub fn encodeHeadersFrameFromBlock(
    dst: []u8,
    field_section: []const u8,
    options: EncodeOptions,
) Error!usize {
    if (options.max_field_section_size) |max| {
        if (field_section.len > max) return Error.HeaderSectionTooLarge;
    }

    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], protocol.FrameType.headers);
    pos += try varint.encode(dst[pos..], field_section.len);
    if (dst.len - pos < field_section.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + field_section.len], field_section);
    return pos + field_section.len;
}

pub fn encodeDataFrame(dst: []u8, data: []const u8) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], protocol.FrameType.data);
    pos += try varint.encode(dst[pos..], data.len);
    if (dst.len - pos < data.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + data.len], data);
    return pos + data.len;
}

fn validateFields(kind: Kind, fields: []const qpack.FieldLine, options: DecodeOptions) headers_mod.Error!void {
    switch (kind) {
        .request => try headers_mod.validateRequestWithOptions(fields, .{
            .enable_connect_protocol = options.enable_connect_protocol,
        }),
        .response, .push => try headers_mod.validateResponse(fields),
    }
}

fn frameContext(kind: Kind) stream_mod.FrameContext {
    return switch (kind) {
        .request, .response => .request,
        .push => .push,
    };
}

/// True when a response field section's `:status` is in the 1xx range
/// (RFC 9110 §15.2 informational responses). The HTTP/3 mapping of
/// pseudo-headers per RFC 9114 §4.3.2 puts `:status` at the front of
/// the section; we accept it anywhere among the pseudo-headers but
/// require its first character to be ASCII '1'.
fn isInterim(fields: []const qpack.FieldLine) bool {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            return field.value.len > 0 and field.value[0] == '1';
        }
    }
    return false;
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
