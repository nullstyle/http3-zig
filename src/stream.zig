//! HTTP/3 stream-type helpers.

const std = @import("std");
const nullq = @import("nullq");
const protocol = @import("protocol.zig");

const varint = nullq.wire.varint;

pub const Kind = union(enum) {
    control,
    push,
    qpack_encoder,
    qpack_decoder,
    unknown: u64,
};

pub const FrameContext = enum {
    control,
    request,
    push,
};

pub const FrameValidationError = error{
    MissingSettings,
    DuplicateSettings,
    FrameUnexpected,
};

pub const FrameValidator = struct {
    context: FrameContext,
    seen_any: bool = false,
    settings_seen: bool = false,

    pub fn init(context: FrameContext) FrameValidator {
        return .{ .context = context };
    }

    pub fn observe(self: *FrameValidator, frame_type: u64) FrameValidationError!void {
        try validateFrameType(self.context, frame_type, !self.seen_any, self.settings_seen);
        self.seen_any = true;
        if (frame_type == protocol.FrameType.settings) self.settings_seen = true;
    }
};

pub const DecodedType = struct {
    kind: Kind,
    bytes_read: usize,
};

pub fn kindFromType(stream_type: u64) Kind {
    return switch (stream_type) {
        protocol.StreamType.control => .control,
        protocol.StreamType.push => .push,
        protocol.StreamType.qpack_encoder => .qpack_encoder,
        protocol.StreamType.qpack_decoder => .qpack_decoder,
        else => .{ .unknown = stream_type },
    };
}

pub fn decodeType(src: []const u8) varint.Error!DecodedType {
    const d = try varint.decode(src);
    return .{ .kind = kindFromType(d.value), .bytes_read = d.bytes_read };
}

pub fn encodeType(dst: []u8, stream_type: u64) varint.Error!usize {
    return varint.encode(dst, stream_type);
}

pub fn isClientInitiated(stream_id: u64) bool {
    return (stream_id & 0x01) == 0;
}

pub fn isUnidirectional(stream_id: u64) bool {
    return (stream_id & 0x02) != 0;
}

pub fn validateFrameType(
    context: FrameContext,
    frame_type: u64,
    is_first: bool,
    settings_seen: bool,
) FrameValidationError!void {
    if (protocol.isReservedHttp2FrameType(frame_type)) return FrameValidationError.FrameUnexpected;
    if (!protocol.isKnownFrameType(frame_type)) return;

    switch (context) {
        .control => {
            if (is_first and frame_type != protocol.FrameType.settings) {
                return FrameValidationError.MissingSettings;
            }
            if (frame_type == protocol.FrameType.settings and settings_seen) {
                return FrameValidationError.DuplicateSettings;
            }
            switch (frame_type) {
                protocol.FrameType.settings,
                protocol.FrameType.cancel_push,
                protocol.FrameType.goaway,
                protocol.FrameType.max_push_id,
                protocol.FrameType.priority_update_request,
                protocol.FrameType.priority_update_push,
                => return,
                else => return FrameValidationError.FrameUnexpected,
            }
        },
        .request => {
            switch (frame_type) {
                protocol.FrameType.data,
                protocol.FrameType.headers,
                protocol.FrameType.push_promise,
                => return,
                else => return FrameValidationError.FrameUnexpected,
            }
        },
        .push => {
            switch (frame_type) {
                protocol.FrameType.data,
                protocol.FrameType.headers,
                => return,
                else => return FrameValidationError.FrameUnexpected,
            }
        },
    }
}

test "control stream requires first SETTINGS and rejects DATA" {
    var v = FrameValidator.init(.control);
    try std.testing.expectError(FrameValidationError.MissingSettings, v.observe(protocol.FrameType.goaway));
    try v.observe(protocol.FrameType.settings);
    try std.testing.expectError(FrameValidationError.FrameUnexpected, v.observe(protocol.FrameType.data));
    try std.testing.expectError(FrameValidationError.DuplicateSettings, v.observe(protocol.FrameType.settings));
}

test "request streams allow request frames and ignore extensions" {
    var v = FrameValidator.init(.request);
    try v.observe(protocol.FrameType.headers);
    try v.observe(protocol.FrameType.data);
    try v.observe(0xface);
    try std.testing.expectError(FrameValidationError.FrameUnexpected, v.observe(protocol.FrameType.goaway));
}
