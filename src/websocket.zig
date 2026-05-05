//! WebSocket-over-HTTP/3 helpers.
//!
//! This module covers the RFC 9220 Extended CONNECT handshake shape. The
//! tunneled byte stream remains application-owned; a full RFC 6455 WebSocket
//! frame codec can layer above these helpers.

const std = @import("std");

const qpack = @import("qpack/root.zig");

pub const frame = @import("websocket_frame.zig");

pub const protocol_token = "websocket";

pub const Error = error{
    NotWebSocket,
    InvalidAcceptStatus,
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
