//! WebSocket-over-HTTP/3 helpers.
//!
//! This module covers the RFC 9220 Extended CONNECT handshake shape. The
//! tunneled byte stream remains application-owned; RFC 6455 frame and message
//! codecs can layer above these helpers.

const std = @import("std");

const qpack = @import("qpack/root.zig");

pub const frame = @import("websocket_frame.zig");
pub const message = @import("websocket_message.zig");

pub const protocol_token = "websocket";

/// RFC 6455 §4.1 / §11.6: 13 is the only currently-defined
/// `Sec-WebSocket-Version`, and RFC 9220 §4.2 inherits the requirement.
pub const version_token = "13";

/// Field name (lowercased per RFC 9114 §4.2) for `Sec-WebSocket-Version`.
pub const version_header_name = "sec-websocket-version";

pub const Error = error{
    NotWebSocket,
    InvalidAcceptStatus,
    UnsupportedWebSocketVersion,
};

pub const ConnectOptions = struct {
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    headers: []const qpack.FieldLine = &.{},
};

pub const AcceptOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
};

pub fn isProtocolToken(value: []const u8) bool {
    return std.mem.eql(u8, value, protocol_token);
}

pub fn requestProtocol(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, ":protocol");
}

pub fn isRequest(fields: []const qpack.FieldLine) bool {
    const method = fieldValue(fields, ":method") orelse return false;
    const token = requestProtocol(fields) orelse return false;
    return std.mem.eql(u8, method, "CONNECT") and isProtocolToken(token);
}

pub fn isAcceptedStatus(status: []const u8) bool {
    if (status.len != 3 or status[0] != '2') return false;
    return std.ascii.isDigit(status[1]) and std.ascii.isDigit(status[2]);
}

pub fn responseAccepted(fields: []const qpack.FieldLine) bool {
    const status = fieldValue(fields, ":status") orelse return false;
    return isAcceptedStatus(status);
}

/// Returns the value of the `sec-websocket-version` request header (case-
/// folded by RFC 9114 §4.2 to lowercase) if present, else null.
pub fn requestVersion(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, version_header_name);
}

/// Validates RFC 9220 §4.2 / RFC 6455 §4.1: an inbound WebSocket bootstrap
/// request MUST carry `Sec-WebSocket-Version: 13`. The header is required —
/// a missing header is a protocol error. The value comparison is exact after
/// trimming optional surrounding whitespace per RFC 6455 §4.1; comma-
/// separated lists (technically permitted by HTTP field syntax) are not
/// accepted because RFC 6455 §11.6 reserves `13` as the sole defined value.
pub fn validateClientRequestVersion(fields: []const qpack.FieldLine) Error!void {
    const raw = requestVersion(fields) orelse return error.UnsupportedWebSocketVersion;
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (!std.mem.eql(u8, trimmed, version_token)) return error.UnsupportedWebSocketVersion;
}

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

test "WebSocket helper classifies Extended CONNECT handshakes" {
    const request = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":protocol", .value = protocol_token },
    };
    try std.testing.expect(isRequest(&request));
    try std.testing.expectEqualStrings(protocol_token, requestProtocol(&request).?);

    const accepted = [_]qpack.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expect(responseAccepted(&accepted));
    try std.testing.expect(isAcceptedStatus("204"));
    try std.testing.expect(!isAcceptedStatus("101"));
    try std.testing.expect(!isAcceptedStatus("300"));
}
