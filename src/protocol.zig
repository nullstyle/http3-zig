//! HTTP/3 protocol constants and small classification helpers.

const std = @import("std");

pub const alpn_h3 = "h3";
pub const alpn_protocols = [_][]const u8{alpn_h3};

pub const Role = enum { client, server };

/// HTTP/3 frame type IDs (RFC 9114 §7.2, RFC 9218 §7.2).
pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const http2_priority: u64 = 0x02;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const http2_ping: u64 = 0x06;
    pub const goaway: u64 = 0x07;
    pub const http2_window_update: u64 = 0x08;
    pub const http2_continuation: u64 = 0x09;
    pub const max_push_id: u64 = 0x0d;
    pub const priority_update_request: u64 = 0x0f0700;
    pub const priority_update_push: u64 = 0x0f0701;
};

/// HTTP/3 unidirectional stream type IDs (RFC 9114 §6.2, RFC 9204 §4.2).
pub const StreamType = struct {
    pub const control: u64 = 0x00;
    pub const push: u64 = 0x01;
    pub const qpack_encoder: u64 = 0x02;
    pub const qpack_decoder: u64 = 0x03;
};

/// HTTP/3 SETTINGS IDs (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3, RFC 9297 §2.1).
pub const SettingId = struct {
    pub const qpack_max_table_capacity: u64 = 0x01;
    pub const max_field_section_size: u64 = 0x06;
    pub const qpack_blocked_streams: u64 = 0x07;
    pub const enable_connect_protocol: u64 = 0x08;
    pub const h3_datagram: u64 = 0x33;
};

/// HTTP/3 and QPACK error codes (RFC 9114 §8.1, RFC 9204 §6).
pub const ErrorCode = struct {
    pub const no_error: u64 = 0x0100;
    pub const general_protocol_error: u64 = 0x0101;
    pub const internal_error: u64 = 0x0102;
    pub const stream_creation_error: u64 = 0x0103;
    pub const closed_critical_stream: u64 = 0x0104;
    pub const frame_unexpected: u64 = 0x0105;
    pub const frame_error: u64 = 0x0106;
    pub const excess_load: u64 = 0x0107;
    pub const id_error: u64 = 0x0108;
    pub const settings_error: u64 = 0x0109;
    pub const missing_settings: u64 = 0x010a;
    pub const request_rejected: u64 = 0x010b;
    pub const request_cancelled: u64 = 0x010c;
    pub const request_incomplete: u64 = 0x010d;
    pub const message_error: u64 = 0x010e;
    pub const connect_error: u64 = 0x010f;
    pub const version_fallback: u64 = 0x0110;
    pub const qpack_decompression_failed: u64 = 0x0200;
    pub const qpack_encoder_stream_error: u64 = 0x0201;
    pub const qpack_decoder_stream_error: u64 = 0x0202;
};

/// QUIC registries reserve all values of the form 0x1f * N + 0x21 for GREASE.
pub fn isGreaseValue(value: u64) bool {
    return value >= 0x21 and (value - 0x21) % 0x1f == 0;
}

pub fn isReservedHttp2Setting(setting_id: u64) bool {
    return setting_id == 0x00 or (setting_id >= 0x02 and setting_id <= 0x05);
}

pub fn isKnownFrameType(frame_type: u64) bool {
    return switch (frame_type) {
        FrameType.data,
        FrameType.headers,
        FrameType.cancel_push,
        FrameType.settings,
        FrameType.push_promise,
        FrameType.goaway,
        FrameType.max_push_id,
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        => true,
        else => false,
    };
}

pub fn isReservedHttp2FrameType(frame_type: u64) bool {
    return switch (frame_type) {
        FrameType.http2_priority,
        FrameType.http2_ping,
        FrameType.http2_window_update,
        FrameType.http2_continuation,
        => true,
        else => false,
    };
}

test "GREASE value classification" {
    try std.testing.expect(isGreaseValue(0x21));
    try std.testing.expect(isGreaseValue(0x40));
    try std.testing.expect(!isGreaseValue(FrameType.settings));
}
