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
    ConnectionSpecificField,
};

pub fn validateTrailers(fields: []const FieldLine) Error!void {
    for (fields) |field| {
        try validateName(field.name);
        if (field.name[0] == ':') return Error.InvalidPseudoHeader;
        if (isConnectionSpecific(field.name)) return Error.ConnectionSpecificField;
    }
}

pub fn validateRequest(fields: []const FieldLine) Error!void {
    var seen_regular = false;
    var method = false;
    var scheme = false;
    var path = false;
    var authority = false;
    var protocol_pseudo = false;

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
            if (method) return Error.DuplicatePseudoHeader;
            method = true;
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
            if (protocol_pseudo) return Error.DuplicatePseudoHeader;
            protocol_pseudo = true;
        } else {
            return Error.InvalidPseudoHeader;
        }
    }

    if (!method or !scheme or !path) return Error.MissingPseudoHeader;
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
