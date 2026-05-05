//! MASQUE-style protocol helpers over Extended CONNECT and HTTP Datagrams.
//!
//! The first concrete protocol covered here is CONNECT-UDP. The helpers stay
//! transport-free: client/server facades open the CONNECT stream, while this
//! module owns request classification, target path construction, and the
//! Context ID 0 UDP payload shape used by CONNECT-UDP datagrams and capsules.

const std = @import("std");

const datagram_mod = @import("datagram.zig");
const qpack = @import("qpack/root.zig");

pub const connect_udp_protocol = "connect-udp";
pub const default_connect_udp_path_prefix = "/.well-known/masque/udp";
pub const capsule_protocol_header = "capsule-protocol";
pub const capsule_protocol_value = "?1";
pub const udp_context_id: u64 = 0;

pub const Error = datagram_mod.Error || std.mem.Allocator.Error || error{
    BufferTooSmall,
    InvalidConnectUdpPath,
    InvalidConnectUdpTarget,
    InvalidAcceptStatus,
    NotConnectUdp,
    UnexpectedContext,
};

pub const ConnectUdpTarget = struct {
    host: []const u8,
    port: u16,
};

pub const OwnedConnectUdpTarget = struct {
    host: []u8,
    port: u16,

    pub fn deinit(self: OwnedConnectUdpTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn borrowed(self: *const OwnedConnectUdpTarget) ConnectUdpTarget {
        return .{
            .host = self.host,
            .port = self.port,
        };
    }
};

pub const ConnectUdpOptions = struct {
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    target_host: []const u8,
    target_port: u16,
    path_prefix: []const u8 = default_connect_udp_path_prefix,
    headers: []const qpack.FieldLine = &.{},
    capsule_protocol: bool = true,
};

pub const AcceptOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    capsule_protocol: bool = true,
};

pub fn isProtocolToken(value: []const u8) bool {
    return std.mem.eql(u8, value, connect_udp_protocol);
}

pub fn requestProtocol(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, ":protocol");
}

pub fn isConnectUdpRequest(fields: []const qpack.FieldLine) bool {
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

pub fn capsuleProtocolEnabled(fields: []const qpack.FieldLine) bool {
    const value = fieldValue(fields, capsule_protocol_header) orelse return false;
    return std.mem.eql(u8, value, capsule_protocol_value);
}

pub fn allocCapsuleProtocolHeaders(
    allocator: std.mem.Allocator,
    headers: []const qpack.FieldLine,
    enabled: bool,
) std.mem.Allocator.Error![]qpack.FieldLine {
    const add_header = enabled and !hasField(headers, capsule_protocol_header);
    const out = try allocator.alloc(qpack.FieldLine, headers.len + if (add_header) @as(usize, 1) else 0);
    @memcpy(out[0..headers.len], headers);
    if (add_header) {
        out[headers.len] = .{
            .name = capsule_protocol_header,
            .value = capsule_protocol_value,
        };
    }
    return out;
}

pub fn allocConnectUdpPath(allocator: std.mem.Allocator, options: ConnectUdpOptions) Error![]u8 {
    const target: ConnectUdpTarget = .{
        .host = options.target_host,
        .port = options.target_port,
    };
    const len = try connectUdpPathEncodedLen(options.path_prefix, target);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    const n = try encodeConnectUdpPath(out, options.path_prefix, target);
    std.debug.assert(n == out.len);
    return out;
}

pub fn connectUdpPathEncodedLen(prefix: []const u8, target: ConnectUdpTarget) Error!usize {
    try validatePathPrefix(prefix);
    try validateTarget(target);
    const separator_len: usize = if (std.mem.endsWith(u8, prefix, "/")) 0 else 1;
    return prefix.len +
        separator_len +
        percentEncodedLen(target.host) +
        1 +
        std.fmt.count("{d}", .{target.port}) +
        1;
}

pub fn encodeConnectUdpPath(
    dst: []u8,
    prefix: []const u8,
    target: ConnectUdpTarget,
) Error!usize {
    const needed = try connectUdpPathEncodedLen(prefix, target);
    if (dst.len < needed) return Error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(dst[pos .. pos + prefix.len], prefix);
    pos += prefix.len;
    if (!std.mem.endsWith(u8, prefix, "/")) {
        dst[pos] = '/';
        pos += 1;
    }
    pos += percentEncodeSegment(dst[pos..], target.host);
    dst[pos] = '/';
    pos += 1;
    const port = std.fmt.bufPrint(dst[pos..], "{d}", .{target.port}) catch return Error.BufferTooSmall;
    pos += port.len;
    dst[pos] = '/';
    pos += 1;
    return pos;
}

pub fn parseConnectUdpTarget(
    allocator: std.mem.Allocator,
    path: []const u8,
    prefix: []const u8,
) Error!OwnedConnectUdpTarget {
    try validatePathPrefix(prefix);

    if (!std.mem.startsWith(u8, path, prefix)) return Error.InvalidConnectUdpPath;
    var rest = path[prefix.len..];
    if (!std.mem.endsWith(u8, prefix, "/")) {
        if (rest.len == 0 or rest[0] != '/') return Error.InvalidConnectUdpPath;
        rest = rest[1..];
    }
    if (rest.len == 0) return Error.InvalidConnectUdpPath;

    const host_end = std.mem.indexOfScalar(u8, rest, '/') orelse return Error.InvalidConnectUdpPath;
    const encoded_host = rest[0..host_end];
    rest = rest[host_end + 1 ..];
    if (encoded_host.len == 0 or rest.len == 0) return Error.InvalidConnectUdpPath;

    const port_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const port_text = rest[0..port_end];
    if (port_text.len == 0) return Error.InvalidConnectUdpPath;
    if (port_end < rest.len and rest[port_end + 1 ..].len != 0) return Error.InvalidConnectUdpPath;

    const port = std.fmt.parseUnsigned(u16, port_text, 10) catch return Error.InvalidConnectUdpPath;
    if (port == 0) return Error.InvalidConnectUdpTarget;

    const host = try percentDecodeSegment(allocator, encoded_host);
    errdefer allocator.free(host);
    if (host.len == 0) return Error.InvalidConnectUdpTarget;
    return .{
        .host = host,
        .port = port,
    };
}

pub fn udpPayloadEncodedLen(payload_len: usize) usize {
    return datagram_mod.contextPayloadEncodedLen(udp_context_id, payload_len);
}

pub fn encodeUdpPayload(dst: []u8, payload: []const u8) Error!usize {
    return datagram_mod.encodeContextPayload(dst, udp_context_id, payload);
}

pub fn decodeUdpPayload(src: []const u8) Error![]const u8 {
    const context = try datagram_mod.decodeContextPayload(src);
    if (context.context_id != udp_context_id) return Error.UnexpectedContext;
    return context.payload;
}

fn validatePathPrefix(prefix: []const u8) Error!void {
    if (prefix.len == 0 or prefix[0] != '/') return Error.InvalidConnectUdpPath;
}

fn validateTarget(target: ConnectUdpTarget) Error!void {
    if (target.host.len == 0 or target.port == 0) return Error.InvalidConnectUdpTarget;
}

fn percentEncodedLen(input: []const u8) usize {
    var len: usize = 0;
    for (input) |byte| {
        len += if (isUnreserved(byte)) @as(usize, 1) else 3;
    }
    return len;
}

fn percentEncodeSegment(dst: []u8, input: []const u8) usize {
    const hex = "0123456789ABCDEF";
    var pos: usize = 0;
    for (input) |byte| {
        if (isUnreserved(byte)) {
            dst[pos] = byte;
            pos += 1;
        } else {
            dst[pos] = '%';
            dst[pos + 1] = hex[byte >> 4];
            dst[pos + 2] = hex[byte & 0x0f];
            pos += 3;
        }
    }
    return pos;
}

fn percentDecodeSegment(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    var out = try allocator.alloc(u8, input.len);
    errdefer allocator.free(out);
    var read: usize = 0;
    var write: usize = 0;
    while (read < input.len) {
        if (input[read] != '%') {
            out[write] = input[read];
            read += 1;
            write += 1;
            continue;
        }
        if (input.len - read < 3) return Error.InvalidConnectUdpPath;
        const high = hexValue(input[read + 1]) orelse return Error.InvalidConnectUdpPath;
        const low = hexValue(input[read + 2]) orelse return Error.InvalidConnectUdpPath;
        out[write] = (high << 4) | low;
        read += 3;
        write += 1;
    }
    return try allocator.realloc(out, write);
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn hasField(fields: []const qpack.FieldLine, name: []const u8) bool {
    return fieldValue(fields, name) != null;
}

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

test "CONNECT-UDP path helpers percent-encode and parse targets" {
    const allocator = std.testing.allocator;
    const options: ConnectUdpOptions = .{
        .authority = "proxy.example",
        .target_host = "2001:db8::1",
        .target_port = 443,
    };
    const path = try allocConnectUdpPath(allocator, options);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", path);

    const target = try parseConnectUdpTarget(allocator, path, default_connect_udp_path_prefix);
    defer target.deinit(allocator);
    try std.testing.expectEqualStrings("2001:db8::1", target.host);
    try std.testing.expectEqual(@as(u16, 443), target.port);

    try std.testing.expectError(
        Error.InvalidConnectUdpPath,
        parseConnectUdpTarget(allocator, "/.well-known/masque/udpx/example.com/443/", default_connect_udp_path_prefix),
    );
}

test "CONNECT-UDP request and capsule protocol helpers classify headers" {
    const allocator = std.testing.allocator;
    const headers = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/.well-known/masque/udp/example.com/443/" },
        .{ .name = ":protocol", .value = connect_udp_protocol },
    };
    try std.testing.expect(isConnectUdpRequest(&headers));
    try std.testing.expect(!capsuleProtocolEnabled(&headers));

    const with_capsules = try allocCapsuleProtocolHeaders(allocator, &headers, true);
    defer allocator.free(with_capsules);
    try std.testing.expect(capsuleProtocolEnabled(with_capsules));
}

test "CONNECT-UDP UDP payload helpers use context zero" {
    var buf: [64]u8 = undefined;
    const n = try encodeUdpPayload(&buf, "packet");
    try std.testing.expectEqualStrings("packet", try decodeUdpPayload(buf[0..n]));

    const bad_n = try datagram_mod.encodeContextPayload(&buf, 7, "packet");
    try std.testing.expectError(Error.UnexpectedContext, decodeUdpPayload(buf[0..bad_n]));
}
