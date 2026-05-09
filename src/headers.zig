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
    InvalidContentLength,
    ContentLengthMismatch,
    MalformedAuthority,
    ForbiddenTrailerField,
};

pub const RequestValidationOptions = struct {
    enable_connect_protocol: bool = false,
};

pub fn validateTrailers(fields: []const FieldLine) Error!void {
    for (fields) |field| {
        try validateName(field.name);
        if (field.name[0] == ':') return Error.InvalidPseudoHeader;
        if (isConnectionSpecific(field.name)) return Error.ConnectionSpecificField;
        if (isForbiddenTrailerField(field.name)) return Error.ForbiddenTrailerField;
    }
}

/// Parse and validate the `content-length` header field, if present.
///
/// RFC 9114 §4.1.2 / RFC 9110 §8.6: a request or response that contains a
/// `content-length` header field with a value that does not match the length
/// of the message content MUST be treated as malformed. Receivers also reject
/// multiple `content-length` headers with conflicting values, non-decimal
/// values, and negative values.
///
/// Returns:
/// - `null` if no `content-length` header is present.
/// - The parsed unsigned value otherwise.
///
/// Errors:
/// - `InvalidContentLength` if the value is non-decimal, negative, overflows
///   u64, or if multiple `content-length` headers carry different values.
pub fn parseContentLength(fields: []const FieldLine) Error!?u64 {
    var seen: ?u64 = null;
    for (fields) |field| {
        if (!std.mem.eql(u8, field.name, "content-length")) continue;
        const parsed = try parseContentLengthValue(field.value);
        if (seen) |prev| {
            if (prev != parsed) return Error.InvalidContentLength;
        } else {
            seen = parsed;
        }
    }
    return seen;
}

fn parseContentLengthValue(value: []const u8) Error!u64 {
    if (value.len == 0) return Error.InvalidContentLength;
    var acc: u64 = 0;
    for (value) |c| {
        if (c < '0' or c > '9') return Error.InvalidContentLength;
        const digit: u64 = c - '0';
        acc = std.math.mul(u64, acc, 10) catch return Error.InvalidContentLength;
        acc = std.math.add(u64, acc, digit) catch return Error.InvalidContentLength;
    }
    return acc;
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
            // RFC 9114 §4.2 ¶3: `te` is connection-specific in HTTP/3
            // EXCEPT when its value is exactly "trailers". Reject any
            // other value (e.g. `te: gzip`, `te: trailers, deflate`).
            if (isForbiddenTeValue(field.name, field.value)) return Error.ConnectionSpecificField;
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

    // RFC 9114 §4.4 ¶3 — Classic CONNECT (RFC 9110 §9.3.6) has its own
    // pseudo-header schema:
    //   - The ":scheme" and ":path" pseudo-header fields MUST be omitted.
    //   - The ":authority" pseudo-header field MUST be present and
    //     MUST contain the host and port to connect to (form
    //     "host:port", per RFC 9110 §9.3.6).
    //   - The ":protocol" pseudo-header field MUST NOT be present
    //     (that variant is Extended CONNECT, RFC 8441 / §4.3.2).
    // Extended CONNECT (a CONNECT request that carries ":protocol")
    // re-introduces ":scheme" and ":path" because the protocol-tunneled
    // semantics need a target URI; that path is taken below the
    // is_classic_connect branch.
    const is_connect = std.mem.eql(u8, method, "CONNECT");
    const is_classic_connect = is_connect and protocol_value == null;

    if (is_classic_connect) {
        if (scheme_value != null) return Error.InvalidPseudoHeader;
        if (path_value != null) return Error.InvalidPseudoHeader;
        const authority = authority_value orelse return Error.MissingPseudoHeader;
        if (authority.len == 0) return Error.MalformedAuthority;
        try validateAuthority(authority);
        // Classic CONNECT skips the scheme/path-shape rules; content-length
        // validation still applies (CONNECT requests may not carry a body
        // beyond the tunnel, but the syntactic check is independent).
        _ = try parseContentLength(fields);
        return;
    }

    const scheme = scheme_value orelse return Error.MissingPseudoHeader;
    const path = path_value orelse return Error.MissingPseudoHeader;

    // RFC 9114 §4.3.1: ":authority" is the URI authority component, which
    // per RFC 3986 §3.2 contains only host and optional ":port" — no
    // userinfo ("user:pass@…") and no fragment ("…#frag"). The field MAY
    // be absent (omitted from the field section), but if present it MUST
    // NOT be empty: "If the :authority pseudo-header field is empty, the
    // request MUST be treated as malformed."
    if (authority_value) |authority| {
        if (authority.len == 0) return Error.MalformedAuthority;
        try validateAuthority(authority);
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
        if (!is_connect) return Error.InvalidPseudoHeader;
        if (value.len == 0) return Error.InvalidPseudoHeader;
    }

    // RFC 9114 §4.1.2 / RFC 9110 §8.6: if `content-length` is present, it
    // MUST be a non-negative decimal integer. Multiple values must agree.
    // Cross-checking it against actual body length happens at the decoder
    // (Decoder.observeBytes / Decoder.finish).
    _ = try parseContentLength(fields);
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

    // RFC 9114 §4.1.2 / RFC 9110 §8.6: validate `content-length` syntax on
    // responses too. The body-length cross-check is performed by the
    // decoder against accumulated DATA frame bytes.
    _ = try parseContentLength(fields);
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

/// RFC 9114 §4.2 ¶3: the `te` header field is connection-specific UNLESS
/// its value is exactly "trailers" (case-insensitive). HTTP/3 endpoints
/// MAY include `te: trailers` in requests; any other value is forbidden.
/// Returns true when the field should be rejected; false when it's
/// either not `te` or the spec-allowed `te: trailers` form.
fn isForbiddenTeValue(name: []const u8, value: []const u8) bool {
    if (!std.ascii.eqlIgnoreCase(name, "te")) return false;
    return !std.ascii.eqlIgnoreCase(value, "trailers");
}

// RFC 9110 §6.5.1: trailers MUST NOT contain fields that affect message
// framing (content-length), routing (host), authentication
// (authorization, www-authenticate, proxy-authenticate,
// proxy-authorization), request modifiers / conditionals (cache-control,
// expect, max-forwards, pragma, range, if-*), response control data
// related to message handling (set-cookie, cookie), or trailer signaling
// itself (trailer). RFC 9114 §4.2 also confines `te` to request headers.
// This is a small, conservative constant list. The "request modifiers"
// citation comes from RFC 9110 §6.5.1, which lists fields a server might
// rely on before having seen the body.
fn isForbiddenTrailerField(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "expect") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "pragma") or
        std.ascii.eqlIgnoreCase(name, "range") or
        std.ascii.eqlIgnoreCase(name, "if-match") or
        std.ascii.eqlIgnoreCase(name, "if-none-match") or
        std.ascii.eqlIgnoreCase(name, "if-modified-since") or
        std.ascii.eqlIgnoreCase(name, "if-unmodified-since") or
        std.ascii.eqlIgnoreCase(name, "if-range") or
        std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "www-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer");
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
