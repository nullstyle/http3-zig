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
    var scheme_value: ?[]const u8 = null;
    var path_value: ?[]const u8 = null;
    var authority_value: ?[]const u8 = null;
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
            if (scheme_value != null) return Error.DuplicatePseudoHeader;
            scheme_value = field.value;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            if (path_value != null) return Error.DuplicatePseudoHeader;
            path_value = field.value;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            if (authority_value != null) return Error.DuplicatePseudoHeader;
            authority_value = field.value;
        } else if (std.mem.eql(u8, field.name, ":protocol")) {
            if (protocol_value != null) return Error.DuplicatePseudoHeader;
            protocol_value = field.value;
        } else {
            return Error.InvalidPseudoHeader;
        }
    }

    const method = method_value orelse return Error.MissingPseudoHeader;
    const scheme = scheme_value orelse return Error.MissingPseudoHeader;
    const path = path_value orelse return Error.MissingPseudoHeader;

    // RFC 9114 §4.3.1: ":authority" is the URI authority component, which
    // per RFC 3986 §3.2 contains only host and optional ":port" — no
    // userinfo ("user:pass@…") and no fragment ("…#frag"). Empty values
    // are accepted (the field MAY be absent), but a non-empty value must
    // parse cleanly.
    if (authority_value) |authority| {
        if (authority.len != 0) try validateAuthority(authority);
    }

    // RFC 9114 §4.3.1 ¶? : "If the :scheme pseudo-header field identifies
    // a scheme that has a mandatory authority component (including 'http'
    // and 'https'), the request MUST contain ... ':path' that is not
    // empty." CONNECT (§4.4) is exempt — it carries an authority instead
    // of a path — but is gated separately because §4.3.2 ":path" semantics
    // for CONNECT come from the method, not the scheme.
    if (requiresNonEmptyPath(scheme, method) and path.len == 0) {
        return Error.InvalidPseudoHeader;
    }

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
    var status_value: ?[]const u8 = null;

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
        if (status_value != null) return Error.DuplicatePseudoHeader;
        status_value = field.value;
    }

    const status = status_value orelse return Error.MissingPseudoHeader;
    // RFC 9114 §4.4: ":status" carries the HTTP response status code. The
    // status code is "a three-digit integer code" (RFC 9110 §15) — three
    // ASCII digits, no whitespace, no sign. Anything else is malformed
    // (§4.6 → H3_MESSAGE_ERROR).
    if (!isValidStatus(status)) return Error.InvalidPseudoHeader;
}

fn validateName(name: []const u8) Error!void {
    if (name.len == 0) return Error.EmptyFieldName;
    for (name) |c| {
        if (std.ascii.isUpper(c)) return Error.UppercaseFieldName;
    }
}

// RFC 9114 §4.3.1 / RFC 3986 §3.2 — the URI authority component. We
// reject anything that signals a userinfo segment ("@") or a fragment
// ("#"); RFC 9110 §7.2 also forbids whitespace in the authority. The
// host/port shape itself is left to the recipient (host parsing varies
// with IDNA / IPv6-zone normalisation, which RFC 9114 explicitly
// declines to mandate).
fn validateAuthority(value: []const u8) Error!void {
    for (value) |c| {
        switch (c) {
            '@', '#', ' ', '\t', '\r', '\n' => return Error.InvalidPseudoHeader,
            else => {},
        }
    }
}

fn requiresNonEmptyPath(scheme: []const u8, method: []const u8) bool {
    // §4.3.2: CONNECT (Classic CONNECT, RFC 9110 §9.3.6) omits ":path"
    // entirely; Extended CONNECT (RFC 8441 / §4.3.2) keeps the regular
    // ":path" rule and is reached through the same code path with method
    // != "CONNECT" being false. The non-empty-path rule applies to the
    // schemes whose URI grammar requires the path-absolute form: "http"
    // and "https" (RFC 9110 §4.2). Other schemes (e.g. "wss" used in
    // Extended CONNECT or future protocols) inherit the rule too because
    // the wire-level HTTP/3 representation is the same.
    if (std.mem.eql(u8, method, "CONNECT")) return false;
    return std.mem.eql(u8, scheme, "http") or
        std.mem.eql(u8, scheme, "https");
}

fn isValidStatus(value: []const u8) bool {
    if (value.len != 3) return false;
    for (value) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
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
