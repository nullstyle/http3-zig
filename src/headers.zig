//! HTTP field and pseudo-header validation helpers.

const std = @import("std");
const qpack = @import("qpack/root.zig");

pub const FieldLine = qpack.FieldLine;

pub const Error = error{
    EmptyFieldName,
    UppercaseFieldName,
    PseudoHeaderAfterRegular,
    DuplicatePseudoHeader,
    MissingPseudoHeader,
    InvalidPseudoHeader,
    ExtendedConnectNotEnabled,
    ConnectionSpecificField,
};

pub const RequestValidationOptions = struct {
    enable_connect_protocol: bool = false,
};

pub fn validateTrailers(fields: []const FieldLine) Error!void {
    for (fields) |field| {
        try validateName(field.name);
        if (field.name[0] == ':') return Error.InvalidPseudoHeader;
        if (isConnectionSpecific(field.name)) return Error.ConnectionSpecificField;
    }
}

pub fn validateRequest(fields: []const FieldLine) Error!void {
    try validateRequestWithOptions(fields, .{});
}

pub fn validateRequestWithOptions(fields: []const FieldLine, options: RequestValidationOptions) Error!void {
    var seen_regular = false;
    var method_value: ?[]const u8 = null;
    var scheme = false;
    var path = false;
    var authority = false;
    var protocol_value: ?[]const u8 = null;

    for (fields) |field| {
        try validateName(field.name);
        const pseudo = field.name[0] == ':';
        if (pseudo and seen_regular) return Error.PseudoHeaderAfterRegular;
        if (!pseudo) {
            seen_regular = true;
            if (isConnectionSpecific(field.name)) return Error.ConnectionSpecificField;
            continue;
        }

        if (std.mem.eql(u8, field.name, ":method")) {
            if (method_value != null) return Error.DuplicatePseudoHeader;
            method_value = field.value;
        } else if (std.mem.eql(u8, field.name, ":scheme")) {
            if (scheme) return Error.DuplicatePseudoHeader;
            scheme = true;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            if (path) return Error.DuplicatePseudoHeader;
            path = true;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            if (authority) return Error.DuplicatePseudoHeader;
            authority = true;
        } else if (std.mem.eql(u8, field.name, ":protocol")) {
            if (protocol_value != null) return Error.DuplicatePseudoHeader;
            protocol_value = field.value;
        } else {
            return Error.InvalidPseudoHeader;
        }
    }

    const method = method_value orelse return Error.MissingPseudoHeader;
    if (!scheme or !path) return Error.MissingPseudoHeader;

    if (protocol_value) |value| {
        if (!options.enable_connect_protocol) return Error.ExtendedConnectNotEnabled;
        if (!std.mem.eql(u8, method, "CONNECT")) return Error.InvalidPseudoHeader;
        if (value.len == 0) return Error.InvalidPseudoHeader;
    }
}

pub fn requestProtocol(fields: []const FieldLine) ?[]const u8 {
    return fieldValue(fields, ":protocol");
}

pub fn isExtendedConnect(fields: []const FieldLine) bool {
    return requestProtocol(fields) != null;
}

pub fn validateResponse(fields: []const FieldLine) Error!void {
    var seen_regular = false;
    var status = false;

    for (fields) |field| {
        try validateName(field.name);
        const pseudo = field.name[0] == ':';
        if (pseudo and seen_regular) return Error.PseudoHeaderAfterRegular;
        if (!pseudo) {
            seen_regular = true;
            if (isConnectionSpecific(field.name)) return Error.ConnectionSpecificField;
            continue;
        }
        if (!std.mem.eql(u8, field.name, ":status")) return Error.InvalidPseudoHeader;
        if (status) return Error.DuplicatePseudoHeader;
        status = true;
    }

    if (!status) return Error.MissingPseudoHeader;
}

fn validateName(name: []const u8) Error!void {
    if (name.len == 0) return Error.EmptyFieldName;
    for (name) |c| {
        if (std.ascii.isUpper(c)) return Error.UppercaseFieldName;
    }
}

fn isConnectionSpecific(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

fn fieldValue(fields: []const FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

test "valid request pseudo-header block" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "accept", .value = "*/*" },
    };
    try validateRequest(&fields);
}

test "extended CONNECT request requires SETTINGS opt-in and CONNECT method" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };

    try std.testing.expectError(Error.ExtendedConnectNotEnabled, validateRequest(&fields));
    try validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
    try std.testing.expectEqualStrings("websocket", requestProtocol(&fields).?);
    try std.testing.expect(isExtendedConnect(&fields));

    const bad_method = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        Error.InvalidPseudoHeader,
        validateRequestWithOptions(&bad_method, .{ .enable_connect_protocol = true }),
    );
}
