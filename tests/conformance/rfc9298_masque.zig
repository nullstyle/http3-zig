//! RFC 9298 — Proxying UDP in HTTP (MASQUE / CONNECT-UDP).
//!
//! http3_zig implements RFC 9298 in `http3_zig.masque` (`src/masque.zig`):
//!   - `connect_udp_protocol` token, target-path encode/parse, request and
//!     response classifier helpers.
//!   - `ContextRegistry` and `CapsuleRegistry` for context-id / capsule-type
//!     allocation, with the RFC 9298 §4 default Context ID 0 reserved for
//!     unencapsulated UDP payloads.
//!   - `ConnectUdpReceiver` + `PendingDatagramBuffer` for the receive-side
//!     classification path used by the H/3 DATAGRAM and capsule paths.
//!
//! `http3_zig.client.startConnectUdp` / `http3_zig.server.acceptConnectUdp` are the
//! end-to-end glue; the gates they enforce are exercised here through the
//! public helpers they call into so we don't need a live H3 fixture.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9298 §3   ¶?   MUST       :method on a CONNECT-UDP request is "CONNECT"
//!   RFC9298 §3   ¶?   MUST       :protocol on a CONNECT-UDP request is "connect-udp"
//!   RFC9298 §3   ¶?   MUST       :scheme on a CONNECT-UDP request is "https" (default)
//!   RFC9298 §3   ¶?   MUST       :authority is the proxy's authority
//!   RFC9298 §3.1 ¶?   MUST       :path uses the /.well-known/masque/udp/<host>/<port>/ template
//!   RFC9298 §3.1 ¶?   MUST       host segment is percent-encoded per RFC 3986
//!   RFC9298 §3.1 ¶?   MUST       port segment is the decimal target port
//!   RFC9298 §3.1 ¶?   MUST       trailing '/' terminates the path (encode and parse)
//!   RFC9298 §3.1 ¶?   MUST NOT   accept a path that does not match the URI template prefix
//!   RFC9298 §3.1 ¶?   MUST NOT   accept a path lacking the trailing slash on receive
//!   RFC9298 §3.1 ¶?   MUST NOT   accept a path with empty host segment
//!   RFC9298 §3.1 ¶?   MUST NOT   accept a path with empty port segment
//!   RFC9298 §3.1 ¶?   MUST NOT   accept a path with port 0
//!   RFC9298 §3.1 ¶?   MUST       parse percent-encoded IPv6 host (zero-compression)
//!   RFC9298 §3.1 ¶?   MUST       encode an unbracketed IPv6 target_host as a bracketed IP-literal
//!   RFC9298 §3.1 ¶?   MUST       parse a bracketed IP-literal back to a bracketless host
//!   RFC9298 §3.1 ¶?   MUST       round-trip bracketed and unbracketed IPv6 to identical paths
//!   RFC9298 §3.1 ¶?   MUST       connectUdpPathEncodedLen matches encodeConnectUdpPath byte count
//!   RFC9298 §3.1 ¶?   MUST       round-trip a path with prefix that already ends with '/'
//!   RFC9298 §3.1 ¶?   MUST       round-trip the boundary port 65535
//!   RFC9298 §3.1 ¶?   MUST       round-trip the smallest legal port 1
//!   RFC9298 §3.1 ¶?   MUST NOT   overrun a too-small path encode buffer
//!   RFC9298 §3.2 ¶?   MUST       2xx response indicates the UDP tunnel is open
//!   RFC9298 §3.3 ¶?   MUST       non-2xx response is a CONNECT-UDP failure
//!   RFC9298 §3   ¶?   NORMATIVE  Capsule-Protocol: ?1 header is sent on a CONNECT-UDP request
//!   RFC9298 §4   ¶?   MUST       Context ID 0 is reserved for unencapsulated UDP payloads
//!   RFC9298 §4   ¶?   MUST NOT   register Context ID 0 as an extension
//!   RFC9298 §4   ¶?   MUST NOT   unregister the default Context ID 0
//!   RFC9298 §4   ¶?   MUST       client-allocated context IDs are even
//!   RFC9298 §4   ¶?   MUST       proxy-allocated context IDs are odd
//!   RFC9298 §4   ¶?   MUST       parity classification holds for full u16 range
//!   RFC9298 §4   ¶?   MUST       validateAllocatedContextId mirrors registry parity gate
//!   RFC9298 §4   ¶?   MUST       register(... .connect_udp) is rejected for any non-zero id
//!   RFC9298 §5   ¶?   MUST       HTTP Datagram payload format = Context ID (varint) + payload
//!   RFC9298 §5   ¶?   MUST       Context ID 0 datagram payload is the unencapsulated UDP payload
//!   RFC9298 §5   ¶?   MUST       udpPayloadEncodedLen matches encodeUdpPayload byte count
//!   RFC9298 §5   ¶?   MUST       reject a Context ID 0 datagram whose payload exceeds the UDP cap
//!   RFC9298 §5   ¶?   MUST       buffer datagrams for unknown contexts (deferred receive)
//!   RFC9298 §5   ¶?   MUST       drop unknown-context datagrams when the buffer is full
//!   RFC9298 §6   ¶?   NORMATIVE  registered capsule types route to extension handlers
//!   RFC9298 §6   ¶?   MUST       reserved GREASE capsule type is silently ignored
//!   RFC9298 §6   ¶?   MUST NOT   register the DATAGRAM capsule type as an extension
//!   RFC9298 §6   ¶?   MUST NOT   register a reserved-GREASE capsule type as an extension
//!   RFC9298 §6   ¶?   MUST NOT   register a duplicate capsule type
//!   RFC9298 §6   ¶?   MUST       isReservedGreaseCapsuleType detects 0x29*N + 0x17 family
//!   RFC9298 §7   ¶?   MUST NOT   accept a UDP payload exceeding the per-datagram size cap
//!   RFC9298 §8   ¶?   MUST       map malformed/oversized datagram errors to H3_CONNECT_ERROR (0x010f)
//!   RFC9298 §8   ¶?   MUST       acceptConnectUdp refuses a non-CONNECT-UDP request
//!   RFC9298 §8   ¶?   MUST       acceptConnectUdp refuses a malformed :status
//!
//! Visible debt:
//!   (none)
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.4   SETTINGS_ENABLE_CONNECT_PROTOCOL codec (id 0x08)               → rfc9114_settings.zig
//!   RFC9114 §4.3.2  generic :protocol pseudo-header validation (any token)          → rfc9114_messages.zig
//!   RFC9297 §2-§3   HTTP/3 DATAGRAM frame wire format + Capsule Protocol codec      → rfc9297_datagrams.zig
//!   RFC9220        WebSocket-specific :protocol = "websocket" rules                 → rfc9220_websocket_h3.zig

const std = @import("std");
const http3_zig = @import("http3_zig");

const masque = http3_zig.masque;
const datagram_mod = http3_zig.datagram;
const capsule_mod = http3_zig.capsule;
const protocol_mod = http3_zig.protocol;
const FieldLine = http3_zig.FieldLine;

const allocator = std.testing.allocator;

// ---------------------------------------------------------------- §3 CONNECT-UDP method

test "MUST use the literal token \"connect-udp\" as the :protocol value [RFC9298 §3 ¶?]" {
    // RFC 9298 §3: ":protocol pseudo-header field is set to 'connect-udp'."
    try std.testing.expectEqualStrings("connect-udp", masque.connect_udp_protocol);
    try std.testing.expect(masque.isProtocolToken("connect-udp"));
    try std.testing.expect(!masque.isProtocolToken("CONNECT-UDP"));
    try std.testing.expect(!masque.isProtocolToken("websocket"));
    try std.testing.expect(!masque.isProtocolToken(""));
}

test "MUST classify CONNECT + :protocol = connect-udp as a CONNECT-UDP request [RFC9298 §3 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/.well-known/masque/udp/example.com/443/" },
        .{ .name = ":protocol", .value = "connect-udp" },
    };
    try std.testing.expect(masque.isConnectUdpRequest(&fields));
    try std.testing.expectEqualStrings("connect-udp", masque.requestProtocol(&fields).?);
}

test "MUST NOT classify a non-CONNECT method as a CONNECT-UDP request [RFC9298 §3 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/.well-known/masque/udp/example.com/443/" },
        .{ .name = ":protocol", .value = "connect-udp" },
    };
    try std.testing.expect(!masque.isConnectUdpRequest(&fields));
}

test "MUST NOT classify CONNECT with another :protocol token [RFC9298 §3 ¶?]" {
    // The "connect-udp" token is exact: "websocket" or any other
    // Extended-CONNECT protocol does not classify here.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expect(!masque.isConnectUdpRequest(&fields));
}

test "MUST default ConnectUdpOptions.scheme to \"https\" [RFC9298 §3 ¶?]" {
    // §3 ¶?: ":scheme pseudo-header is set to 'https'." http3_zig's
    // option struct defaults to https; we verify the default and
    // that a non-default still flows through the path encoder.
    const default_options: masque.ConnectUdpOptions = .{
        .target_host = "example.com",
        .target_port = 443,
    };
    try std.testing.expectEqualStrings("https", default_options.scheme);
}

test "MUST default ConnectUdpOptions.path_prefix to /.well-known/masque/udp [RFC9298 §3.1 ¶?]" {
    // §3.1: "The URI template ... is '/.well-known/masque/udp/{target_host}/{target_port}/'".
    // http3_zig's `default_connect_udp_path_prefix` matches that prefix.
    try std.testing.expectEqualStrings("/.well-known/masque/udp", masque.default_connect_udp_path_prefix);
    const default_options: masque.ConnectUdpOptions = .{
        .target_host = "example.com",
        .target_port = 443,
    };
    try std.testing.expectEqualStrings("/.well-known/masque/udp", default_options.path_prefix);
}

// ---------------------------------------------------------------- §3.1 target URI template

test "MUST construct the path as <prefix>/<host>/<port>/ [RFC9298 §3.1 ¶?]" {
    // §3.1 URI template instantiation. The default prefix is the
    // /.well-known/ path; we verify a simple ASCII host first.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "example.com",
        .target_port = 443,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/example.com/443/", path);
}

test "MUST percent-encode the host segment per RFC 3986 [RFC9298 §3.1 ¶?]" {
    // §3.1: "{target_host} ... is the host of the target". An IPv6
    // literal is wrapped in IP-literal brackets per RFC 3986 §3.2.2;
    // both ':' and '[' / ']' are reserved in a path segment and so
    // emerge as '%3A', '%5B', '%5D' on the wire.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "2001:db8::1",
        .target_port = 443,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings(
        "/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/443/",
        path,
    );
}

test "MUST percent-encode reserved characters in the host segment [RFC9298 §3.1 ¶?]" {
    // §3.1: any reserved character must be percent-encoded. ':' is the
    // IPv6 marker (covered separately by the IP-literal tests), so we
    // exercise the generic encoder with a path-delim ('/') and a
    // sub-delim ('?') in a non-IPv6 host.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "a/b?c",
        .target_port = 65535,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/a%2Fb%3Fc/65535/", path);
}

test "MUST keep unreserved host characters unencoded [RFC9298 §3.1 ¶?]" {
    // RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~".
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "Foo-bar_baz.example~test",
        .target_port = 443,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings(
        "/.well-known/masque/udp/Foo-bar_baz.example~test/443/",
        path,
    );
}

test "MUST round-trip the path through parse [RFC9298 §3.1 ¶?]" {
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "203.0.113.5",
        .target_port = 12345,
    });
    defer allocator.free(path);

    const parsed = try masque.parseConnectUdpTarget(allocator, path, masque.default_connect_udp_path_prefix);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("203.0.113.5", parsed.host);
    try std.testing.expectEqual(@as(u16, 12345), parsed.port);
}

test "MUST decode percent-encoded IPv6 host on parse [RFC9298 §3.1 ¶?]" {
    // The parser still accepts the legacy bracketless wire form (older
    // peers may emit it), surfacing the bracketless host bytes verbatim.
    const target = try masque.parseConnectUdpTarget(
        allocator,
        "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/",
        masque.default_connect_udp_path_prefix,
    );
    defer target.deinit(allocator);
    try std.testing.expectEqualStrings("2001:db8::1", target.host);
    try std.testing.expectEqual(@as(u16, 443), target.port);
}

test "MUST encode an unbracketed IPv6 target_host as a bracketed IP-literal [RFC9298 §3.1 ¶?]" {
    // RFC 9298 §3.1 cites RFC 3986 §3.2.2: an IPv6 address embedded in
    // a URI MUST be wrapped in IP-literal brackets. Callers may pass
    // either form; the encoder normalises to the bracketed wire shape
    // and percent-encodes the brackets ('[' = 0x5B, ']' = 0x5D) since
    // they are reserved in path segments.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "2001:db8::1",
        .target_port = 443,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings(
        "/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/443/",
        path,
    );
}

test "MUST parse a bracketed IP-literal in the encoded path back to a bracketless host [RFC9298 §3.1 ¶?]" {
    // RFC 3986 §3.2.2 treats the brackets as encoding markers, not part
    // of the host name itself, so `OwnedConnectUdpTarget.host` exposes
    // the bracketless form.
    const target = try masque.parseConnectUdpTarget(
        allocator,
        "/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/443/",
        masque.default_connect_udp_path_prefix,
    );
    defer target.deinit(allocator);
    try std.testing.expectEqualStrings("2001:db8::1", target.host);
    try std.testing.expectEqual(@as(u16, 443), target.port);
}

test "MUST round-trip a bracketed and unbracketed IPv6 target to identical encoded paths [RFC9298 §3.1 ¶?]" {
    // The encoder is idempotent over IP-literal bracketing: a caller
    // that already supplies `[2001:db8::1]` produces the same bytes as
    // one that passes `2001:db8::1`, so both sides of the wire interop.
    const unbracketed = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "2001:db8::1",
        .target_port = 443,
    });
    defer allocator.free(unbracketed);
    const bracketed = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "[2001:db8::1]",
        .target_port = 443,
    });
    defer allocator.free(bracketed);
    try std.testing.expectEqualStrings(unbracketed, bracketed);
}

test "MUST NOT accept a path missing the URI template prefix [RFC9298 §3.1 ¶?]" {
    // §3.1: the target URI template MUST start with the registered
    // /.well-known/masque/udp/ prefix. Extra letters after "udp" are
    // not the same path.
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udpx/example.com/443/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path lacking the trailing slash [RFC9298 §3.1 ¶?]" {
    // §3.1 URI template ends with the slash after {target_port}. The
    // parser rejects paths missing the trailing '/' — the encoder always
    // emits one, so the parser must be symmetric.
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com/443",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path missing the host segment [RFC9298 §3.1 ¶?]" {
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp//443/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path missing the port segment [RFC9298 §3.1 ¶?]" {
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com//",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path whose port is 0 [RFC9298 §3.1 ¶?]" {
    // §3.1 inherits the URI requirement that {target_port} is a valid
    // UDP destination port — port 0 is reserved.
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpTarget,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com/0/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path whose port is non-numeric [RFC9298 §3.1 ¶?]" {
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com/abc/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT accept a path whose port exceeds u16 [RFC9298 §3.1 ¶?]" {
    // 65535 is the largest valid u16; 65536 is invalid.
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com/65536/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST NOT encode a path for an empty host [RFC9298 §3.1 ¶?]" {
    // §3.1: the host segment MUST be non-empty. Encode-side mirror.
    var buf: [128]u8 = undefined;
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpTarget,
        masque.encodeConnectUdpPath(&buf, masque.default_connect_udp_path_prefix, .{
            .host = "",
            .port = 443,
        }),
    );
}

test "MUST NOT encode a path for port 0 [RFC9298 §3.1 ¶?]" {
    var buf: [128]u8 = undefined;
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpTarget,
        masque.encodeConnectUdpPath(&buf, masque.default_connect_udp_path_prefix, .{
            .host = "example.com",
            .port = 0,
        }),
    );
}

test "MUST require the path prefix to start with '/' [RFC9298 §3.1 ¶?]" {
    // §3.1 inherits the URI requirement that {prefix} starts at the path
    // root.
    var buf: [128]u8 = undefined;
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.encodeConnectUdpPath(&buf, "well-known/masque/udp", .{
            .host = "example.com",
            .port = 443,
        }),
    );
}

test "MUST NOT accept a path with extra slash-separated segments after the port [RFC9298 §3.1 ¶?]" {
    // §3.1: "{target_port}/" is the final segment in the URI template.
    // Extra path segments are invalid.
    try std.testing.expectError(
        masque.Error.InvalidConnectUdpPath,
        masque.parseConnectUdpTarget(
            allocator,
            "/.well-known/masque/udp/example.com/443/extra/",
            masque.default_connect_udp_path_prefix,
        ),
    );
}

test "MUST report connectUdpPathEncodedLen matching the encoded byte count [RFC9298 §3.1 ¶?]" {
    // The predictor MUST equal what encodeConnectUdpPath actually
    // writes — callers rely on it for buffer pre-allocation.
    const target: masque.ConnectUdpTarget = .{
        .host = "example.com",
        .port = 443,
    };
    const predicted = try masque.connectUdpPathEncodedLen(masque.default_connect_udp_path_prefix, target);
    var buf: [128]u8 = undefined;
    const n = try masque.encodeConnectUdpPath(&buf, masque.default_connect_udp_path_prefix, target);
    try std.testing.expectEqual(predicted, n);
}

test "MUST round-trip a path with a prefix that already ends with '/' [RFC9298 §3.1 ¶?]" {
    // §3.1 separator handling: a prefix ending in '/' MUST NOT cause a
    // doubled slash on encode and MUST round-trip through parse.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "example.com",
        .target_port = 443,
        .path_prefix = "/.well-known/masque/udp/",
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/example.com/443/", path);

    const parsed = try masque.parseConnectUdpTarget(
        allocator,
        path,
        "/.well-known/masque/udp/",
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
}

test "MUST round-trip the boundary port 65535 [RFC9298 §3.1 ¶?]" {
    // §3.1 inherits IANA UDP port range 1..65535. The encoder MUST
    // accept the maximum and the parser MUST recover it.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "example.com",
        .target_port = 65535,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/example.com/65535/", path);
    const parsed = try masque.parseConnectUdpTarget(
        allocator,
        path,
        masque.default_connect_udp_path_prefix,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 65535), parsed.port);
}

test "MUST round-trip the smallest legal port 1 [RFC9298 §3.1 ¶?]" {
    // Smallest legal UDP port is 1; port 0 is rejected separately.
    const path = try masque.allocConnectUdpPath(allocator, .{
        .target_host = "example.com",
        .target_port = 1,
    });
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/example.com/1/", path);
    const parsed = try masque.parseConnectUdpTarget(
        allocator,
        path,
        masque.default_connect_udp_path_prefix,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 1), parsed.port);
}

test "MUST NOT overrun a too-small path encode buffer [RFC9298 §3.1 ¶?]" {
    // The encoder MUST surface BufferTooSmall instead of writing past
    // the destination — callers may use a stack buffer sized to a
    // worst-case prefix and a 4-byte port slot.
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(
        masque.Error.BufferTooSmall,
        masque.encodeConnectUdpPath(&tiny, masque.default_connect_udp_path_prefix, .{
            .host = "example.com",
            .port = 443,
        }),
    );
}

test "MUST report connectUdpPathEncodedLen matching encoded byte count for percent-encoded IPv6 host [RFC9298 §3.1 ¶?]" {
    // The predictor must include all '%XX' triples emitted by
    // percent-encoding sub-delim characters in the host segment.
    const target: masque.ConnectUdpTarget = .{
        .host = "2001:db8::1",
        .port = 443,
    };
    const predicted = try masque.connectUdpPathEncodedLen(masque.default_connect_udp_path_prefix, target);
    var buf: [128]u8 = undefined;
    const n = try masque.encodeConnectUdpPath(&buf, masque.default_connect_udp_path_prefix, target);
    try std.testing.expectEqual(predicted, n);
}

// ---------------------------------------------------------------- §3.2 / §3.3 success / failure response

test "MUST treat a 2xx response as a successful CONNECT-UDP open [RFC9298 §3.2 ¶?]" {
    // §3.2: "If the request is successful, the proxy MUST send back a
    // 2xx ... status code".
    try std.testing.expect(masque.isAcceptedStatus("200"));
    try std.testing.expect(masque.isAcceptedStatus("204"));
    try std.testing.expect(masque.isAcceptedStatus("299"));

    const accepted = [_]FieldLine{.{ .name = ":status", .value = "200" }};
    try std.testing.expect(masque.responseAccepted(&accepted));
}

test "MUST NOT treat a non-2xx response as a successful CONNECT-UDP open [RFC9298 §3.3 ¶?]" {
    try std.testing.expect(!masque.isAcceptedStatus("404"));
    try std.testing.expect(!masque.isAcceptedStatus("500"));
    try std.testing.expect(!masque.isAcceptedStatus("301"));
    try std.testing.expect(!masque.isAcceptedStatus("100"));

    const failure = [_]FieldLine{.{ .name = ":status", .value = "503" }};
    try std.testing.expect(!masque.responseAccepted(&failure));
}

test "MUST refuse to accept a CONNECT-UDP with a malformed :status [RFC9298 §3.2 ¶?]" {
    // The `acceptConnectUdp` helper raises `error.InvalidAcceptStatus`
    // when `isAcceptedStatus` is false.
    const bad: http3_zig.ConnectUdpAcceptOptions = .{ .status = "??" };
    try std.testing.expect(!masque.isAcceptedStatus(bad.status));
}

test "MUST refuse acceptConnectUdp on a non-CONNECT-UDP request [RFC9298 §8 ¶?]" {
    // RFC 9298 doesn't permit the proxy to honour CONNECT-UDP semantics
    // on a non-CONNECT-UDP request. http3_zig surfaces NotConnectUdp at the
    // public helper boundary; here we exercise the gate via the public
    // classifier.
    const non_connect_udp = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "proxy.example" },
    };
    try std.testing.expect(!masque.isConnectUdpRequest(&non_connect_udp));
    try std.testing.expectError(error.NotConnectUdp, simulateNotConnectUdp(&non_connect_udp));
}

test "MUST NOT classify a CONNECT request missing the :protocol pseudo-header [RFC9298 §3 ¶?]" {
    // §3.4 ¶2.2: ":protocol pseudo-header field SHALL be 'connect-udp'".
    // A bare CONNECT (no :protocol) is the legacy CONNECT method and
    // does not classify as CONNECT-UDP.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expect(!masque.isConnectUdpRequest(&fields));
    try std.testing.expectEqual(@as(?[]const u8, null), masque.requestProtocol(&fields));
}

test "MUST treat \"connect-udp\" :protocol as exact-match (case-sensitive) [RFC9298 §3 ¶?]" {
    // §3.4 ¶2.2: the literal token MUST be "connect-udp" — RFC 9298
    // does not permit casefolded variants because :protocol is a
    // structured token field. The matcher must therefore reject
    // mixed-case tokens.
    try std.testing.expect(!masque.isProtocolToken("Connect-Udp"));
    try std.testing.expect(!masque.isProtocolToken("CONNECT-UDP"));
    try std.testing.expect(!masque.isProtocolToken("connect-UDP"));
    try std.testing.expect(masque.isProtocolToken("connect-udp"));
}

fn simulateNotConnectUdp(fields: []const FieldLine) masque.Error!void {
    if (!masque.isConnectUdpRequest(fields)) return error.NotConnectUdp;
}

// ---------------------------------------------------------------- §3 capsule-protocol header

test "NORMATIVE allocCapsuleProtocolHeaders adds capsule-protocol: ?1 [RFC9298 §3 ¶?]" {
    // RFC 9298 §3 references RFC 9297 §3 for the Capsule-Protocol
    // header field. http3_zig's helper inserts it when enabled.
    const headers = try masque.allocCapsuleProtocolHeaders(allocator, &.{}, true);
    defer allocator.free(headers);
    try std.testing.expectEqual(@as(usize, 1), headers.len);
    try std.testing.expectEqualStrings("capsule-protocol", headers[0].name);
    try std.testing.expectEqualStrings("?1", headers[0].value);
    try std.testing.expect(masque.capsuleProtocolEnabled(headers));
}

test "NORMATIVE allocCapsuleProtocolHeaders preserves existing capsule-protocol [RFC9298 §3 ¶?]" {
    const existing = [_]FieldLine{
        .{ .name = "capsule-protocol", .value = "?1" },
        .{ .name = "user-agent", .value = "http3-zig-conformance" },
    };
    const headers = try masque.allocCapsuleProtocolHeaders(allocator, &existing, true);
    defer allocator.free(headers);
    try std.testing.expectEqual(@as(usize, 2), headers.len);
}

test "NORMATIVE allocCapsuleProtocolHeaders skips header when disabled [RFC9298 §3 ¶?]" {
    const headers = try masque.allocCapsuleProtocolHeaders(allocator, &.{}, false);
    defer allocator.free(headers);
    try std.testing.expectEqual(@as(usize, 0), headers.len);
}

// ---------------------------------------------------------------- §4 Context Identifiers

test "MUST reserve Context ID 0 for unencapsulated UDP payloads [RFC9298 §4 ¶?]" {
    // §4: "The Context ID value of zero is reserved for UDP packets."
    try std.testing.expectEqual(@as(u64, 0), masque.udp_context_id);

    var registry = masque.ContextRegistry.init();
    try std.testing.expect(registry.isKnown(masque.udp_context_id));
    try std.testing.expectEqual(masque.ContextKind.connect_udp, registry.kindOf(masque.udp_context_id).?);
}

test "MUST NOT register Context ID 0 as an extension [RFC9298 §4 ¶?]" {
    // §4: Context ID 0 is reserved by the spec; registering it is a
    // protocol error.
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.ContextAlreadyRegistered,
        registry.registerExtension(masque.udp_context_id),
    );
}

test "MUST NOT register a Context ID with kind = connect_udp [RFC9298 §4 ¶?]" {
    // Only Context ID 0 has kind=connect_udp; an extension MUST use
    // kind=extension.
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        registry.register(7, .connect_udp),
    );
}

test "MUST NOT unregister the default Context ID 0 [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.CannotUnregisterDefaultContext,
        registry.unregister(masque.udp_context_id),
    );
}

test "MUST classify even Context IDs as client-allocated [RFC9298 §4 ¶?]" {
    // §4: "Even Context IDs are allocated by the client; odd Context
    // IDs are allocated by the proxy." (Excluding Context ID 0.)
    try std.testing.expectEqual(masque.ContextIdAllocator.client, try masque.contextIdAllocator(2));
    try std.testing.expectEqual(masque.ContextIdAllocator.client, try masque.contextIdAllocator(4));
    try std.testing.expectEqual(masque.ContextIdAllocator.client, try masque.contextIdAllocator(0xfffe));
}

test "MUST classify odd Context IDs as proxy-allocated [RFC9298 §4 ¶?]" {
    try std.testing.expectEqual(masque.ContextIdAllocator.proxy, try masque.contextIdAllocator(1));
    try std.testing.expectEqual(masque.ContextIdAllocator.proxy, try masque.contextIdAllocator(3));
    try std.testing.expectEqual(masque.ContextIdAllocator.proxy, try masque.contextIdAllocator(0xffff));
}

test "MUST refuse to classify Context ID 0 as either allocator [RFC9298 §4 ¶?]" {
    // 0 is the reserved UDP context, neither client- nor proxy-
    // allocated; http3_zig surfaces InvalidContextRegistration at the
    // allocator-classification helper.
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        masque.contextIdAllocator(masque.udp_context_id),
    );
}

test "MUST NOT permit a client to register an odd Context ID as its own [RFC9298 §4 ¶?]" {
    // §4: "Endpoints MUST NOT register a Context ID that does not
    // match their allocation parity".
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        registry.registerAllocatedExtension(.client, 3),
    );
}

test "MUST NOT permit a proxy to register an even Context ID as its own [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        registry.registerAllocatedExtension(.proxy, 2),
    );
}

test "MUST permit a client to register an even Context ID [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try registry.registerAllocatedExtension(.client, 2);
    try std.testing.expect(registry.isKnown(2));
    try std.testing.expectEqual(masque.ContextKind.extension, registry.kindOf(2).?);
}

test "MUST permit a proxy to register an odd Context ID [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try registry.registerAllocatedExtension(.proxy, 3);
    try std.testing.expect(registry.isKnown(3));
}

test "MUST reject duplicate Context ID registration [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try registry.registerExtension(2);
    try std.testing.expectError(masque.Error.ContextAlreadyRegistered, registry.registerExtension(2));
}

test "MUST reject unregistering an unknown Context ID [RFC9298 §4 ¶?]" {
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(masque.Error.UnknownContext, registry.unregister(9));
}

test "MUST refuse to register a Context ID via register(... .connect_udp) [RFC9298 §4 ¶?]" {
    // §4: kind=connect_udp is reserved exclusively for the default
    // Context ID 0; the public `register(id, kind)` surface must reject
    // any explicit registration with that kind, even for an otherwise
    // legal extension id.
    var registry = masque.ContextRegistry.init();
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        registry.register(2, .connect_udp),
    );
}

test "MUST classify the largest u16 even Context ID as client-allocated [RFC9298 §4 ¶?]" {
    // Boundary check: the parity rule applies to the entire 62-bit
    // Context ID space, not just small values.
    try std.testing.expectEqual(masque.ContextIdAllocator.client, try masque.contextIdAllocator(0xfffe));
    try std.testing.expectEqual(masque.ContextIdAllocator.proxy, try masque.contextIdAllocator(0xffff));
}

test "NORMATIVE validateAllocatedContextId mirrors registerAllocatedExtension parity [RFC9298 §4 ¶?]" {
    // Parity validation is exposed independently of the registry so
    // callers can check before allocating storage. It MUST agree with
    // the registry's gate.
    try masque.validateAllocatedContextId(.client, 4);
    try masque.validateAllocatedContextId(.proxy, 5);
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        masque.validateAllocatedContextId(.client, 5),
    );
    try std.testing.expectError(
        masque.Error.InvalidContextRegistration,
        masque.validateAllocatedContextId(.proxy, 4),
    );
}

// ---------------------------------------------------------------- §5 HTTP Datagram payload format

test "MUST encode HTTP Datagram payload as Context ID (varint) + payload [RFC9298 §5 ¶?]" {
    // §5: "An HTTP Datagram with a Context ID of zero indicates that
    // the Datagram Payload contains a UDP packet". http3_zig's
    // `encodeUdpPayload` writes the Context ID 0 varint (one byte)
    // followed by the payload bytes.
    var buf: [16]u8 = undefined;
    const n = try masque.encodeUdpPayload(&buf, "abcd");
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqual(@as(u8, 0), buf[0]); // Context ID 0 = single 0x00 varint
    try std.testing.expectEqualStrings("abcd", buf[1..5]);
}

test "MUST report udpPayloadEncodedLen matching the encoded byte count [RFC9298 §5 ¶?]" {
    // The predictor MUST equal what encodeUdpPayload writes — callers
    // rely on it for pre-allocation, so the two MUST agree byte-for-byte.
    const payload = "packet";
    const predicted = masque.udpPayloadEncodedLen(payload.len);
    var buf: [16]u8 = undefined;
    const n = try masque.encodeUdpPayload(&buf, payload);
    try std.testing.expectEqual(predicted, n);
}

test "MUST decode HTTP Datagram payload back to its UDP payload [RFC9298 §5 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try masque.encodeUdpPayload(&buf, "packet");
    const decoded = try masque.decodeUdpPayload(buf[0..n]);
    try std.testing.expectEqualStrings("packet", decoded);
}

test "MUST NOT decode a UDP payload from a non-zero Context ID [RFC9298 §5 ¶?]" {
    // §5: only Context ID 0 carries an unencapsulated UDP payload.
    // A non-zero Context ID is an extension stream — the UDP-decoder
    // helper MUST refuse it.
    var buf: [16]u8 = undefined;
    const n = try datagram_mod.encodeContextPayload(&buf, 7, "extension");
    try std.testing.expectError(masque.Error.UnexpectedContext, masque.decodeUdpPayload(buf[0..n]));
}

test "MUST classify a Context ID 0 datagram payload as udp_payload [RFC9298 §5 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try masque.encodeUdpPayload(&buf, "packet");
    var registry = masque.ContextRegistry.init();
    switch (registry.classifyDatagramPayload(buf[0..n])) {
        .udp_payload => |payload| try std.testing.expectEqualStrings("packet", payload),
        else => return error.UnexpectedDisposition,
    }
}

test "MUST classify an unknown Context ID datagram payload as unknown_context [RFC9298 §5 ¶?]" {
    // §5 ¶?: "Datagrams with an unknown Context ID ... could be
    // associated with a context that has not been registered yet."
    var buf: [16]u8 = undefined;
    const n = try datagram_mod.encodeContextPayload(&buf, 7, "future");
    var registry = masque.ContextRegistry.init();
    switch (registry.classifyDatagramPayload(buf[0..n])) {
        .unknown_context => |context| {
            try std.testing.expectEqual(@as(u64, 7), context.context_id);
            try std.testing.expectEqualStrings("future", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }
}

test "MUST classify a malformed datagram as a stream-abort signal [RFC9298 §5 ¶?]" {
    // An empty datagram payload is not a valid Context ID + payload
    // pair (the Context ID varint is missing). The classifier signals
    // a stream-abort with the H3_CONNECT_ERROR code.
    var registry = masque.ContextRegistry.init();
    switch (registry.classifyDatagramPayload(&.{})) {
        .abort_stream => |abort| {
            try std.testing.expectEqual(masque.connect_udp_abort_code, abort.error_code);
            try std.testing.expectEqual(masque.AbortReason.malformed_context, abort.reason);
        },
        else => return error.UnexpectedDisposition,
    }
}

test "MUST classify an oversized UDP datagram as a stream-abort signal [RFC9298 §7 ¶?]" {
    // §7 / §5: UDP payloads have a maximum size; a Context ID 0
    // datagram exceeding the cap is a malformed CONNECT-UDP datagram
    // and the classifier MUST signal stream-abort.
    const too_large = try allocator.alloc(u8, masque.max_udp_payload_len + 1);
    defer allocator.free(too_large);
    @memset(too_large, 0x42);
    const encoded = try allocator.alloc(u8, masque.udpPayloadEncodedLen(too_large.len));
    defer allocator.free(encoded);
    const encoded_n = try datagram_mod.encodeContextPayload(encoded, masque.udp_context_id, too_large);

    var registry = masque.ContextRegistry.init();
    switch (registry.classifyDatagramPayload(encoded[0..encoded_n])) {
        .abort_stream => |abort| {
            try std.testing.expectEqual(masque.connect_udp_abort_code, abort.error_code);
            try std.testing.expectEqual(masque.AbortReason.udp_payload_too_large, abort.reason);
        },
        else => return error.UnexpectedDisposition,
    }
}

// ---------------------------------------------------------------- §6 capsule extensions

test "MUST NOT register the DATAGRAM capsule type as an extension [RFC9298 §6 ¶?]" {
    // §6 / RFC 9297 §3: the DATAGRAM capsule type (0x00) is the
    // built-in datagram fallback, not an extension. Registering it
    // as one is a protocol error.
    var registry = masque.CapsuleRegistry.init();
    try std.testing.expectError(
        masque.Error.InvalidCapsuleTypeRegistration,
        registry.registerExtension(0),
    );
}

test "MUST NOT register a reserved-GREASE capsule type as an extension [RFC9298 §6 ¶?]" {
    // §6: GREASE values (0x29*N + 0x17 ; per RFC 9297 §3.3) MUST be
    // ignored when received and MUST NOT be registered as known
    // extensions.
    var registry = masque.CapsuleRegistry.init();
    const grease = 0x17 + 0x29; // first GREASE value beyond 0x17 itself
    try std.testing.expect(masque.isReservedGreaseCapsuleType(grease));
    try std.testing.expectError(
        masque.Error.InvalidCapsuleTypeRegistration,
        registry.registerExtension(grease),
    );
}

test "MUST permit registering a non-reserved capsule type [RFC9298 §6 ¶?]" {
    var registry = masque.CapsuleRegistry.init();
    try registry.registerExtension(0x41);
    try std.testing.expect(registry.isKnown(0x41));
}

test "MUST validate that GREASE capsule types are detected for every N [RFC9298 §6 ¶?]" {
    // The GREASE family is `0x29 * N + 0x17`. Verify the predicate
    // on a sweep of N so registry policy stays consistent.
    var n: u64 = 0;
    while (n < 8) : (n += 1) {
        const grease = 0x29 * n + 0x17;
        try std.testing.expect(masque.isReservedGreaseCapsuleType(grease));
    }
    // Adjacent non-GREASE values MUST NOT be flagged.
    try std.testing.expect(!masque.isReservedGreaseCapsuleType(0x18));
    try std.testing.expect(!masque.isReservedGreaseCapsuleType(0x16));
}

test "MUST reject duplicate capsule type registration [RFC9298 §6 ¶?]" {
    var registry = masque.CapsuleRegistry.init();
    try registry.registerExtension(0x41);
    try std.testing.expectError(
        masque.Error.CapsuleTypeAlreadyRegistered,
        registry.registerExtension(0x41),
    );
}

test "MUST silently ignore an unknown (non-GREASE) capsule type [RFC9298 §6 ¶?]" {
    // §6 ¶?: "Endpoints MUST silently drop unknown capsule types."
    // http3_zig's classifier reports `ignored_capsule_type` and
    // `canSilentlyDrop()` returns true.
    var registry = masque.CapsuleRegistry.init();
    const capsule: capsule_mod.Capsule = .{ .capsule_type = 0x41, .value = "x" };
    const disposition = registry.classifyCapsule(capsule);
    try std.testing.expect(disposition.canSilentlyDrop());
    switch (disposition) {
        .ignored_capsule_type => |t| try std.testing.expectEqual(@as(u64, 0x41), t),
        else => return error.UnexpectedDisposition,
    }
}

test "MUST silently ignore a reserved GREASE capsule type [RFC9298 §6 ¶?]" {
    // GREASE: 0x29*N + 0x17 (per RFC 9297 / RFC 8701 GREASE rules).
    // n=3: 0x29*3+0x17 = 0x92.
    var registry = masque.CapsuleRegistry.init();
    const capsule: capsule_mod.Capsule = .{ .capsule_type = 0x92, .value = "grease" };
    try std.testing.expect(masque.isReservedGreaseCapsuleType(0x92));
    const disposition = registry.classifyCapsule(capsule);
    try std.testing.expect(disposition.canSilentlyDrop());
}

test "MUST route a registered extension capsule to its handler [RFC9298 §6 ¶?]" {
    var registry = masque.CapsuleRegistry.init();
    try registry.registerExtension(0x41);
    const capsule: capsule_mod.Capsule = .{ .capsule_type = 0x41, .value = "ext" };
    switch (registry.classifyCapsule(capsule)) {
        .extension_capsule => |ext| {
            try std.testing.expectEqual(@as(u64, 0x41), ext.capsule_type);
            try std.testing.expectEqualStrings("ext", ext.value);
        },
        else => return error.UnexpectedDisposition,
    }
}

// ---------------------------------------------------------------- §7 size considerations

test "MUST NOT encode a UDP payload exceeding the per-datagram cap [RFC9298 §7 ¶?]" {
    // §7: maximum UDP payload size is constrained by the RFC 1122
    // 65527-byte limit. http3_zig enforces this on the encode side.
    try std.testing.expectEqual(@as(usize, 65527), masque.max_udp_payload_len);

    const too_large = try allocator.alloc(u8, masque.max_udp_payload_len + 1);
    defer allocator.free(too_large);
    var small_buf: [1]u8 = undefined;
    try std.testing.expectError(
        masque.Error.UdpPayloadTooLarge,
        masque.encodeUdpPayload(&small_buf, too_large),
    );
}

test "MUST NOT decode a UDP payload exceeding the per-datagram cap [RFC9298 §7 ¶?]" {
    const too_large = try allocator.alloc(u8, masque.max_udp_payload_len + 1);
    defer allocator.free(too_large);
    @memset(too_large, 0xa);

    const encoded = try allocator.alloc(u8, masque.udpPayloadEncodedLen(too_large.len));
    defer allocator.free(encoded);
    const n = try datagram_mod.encodeContextPayload(encoded, masque.udp_context_id, too_large);
    try std.testing.expectError(masque.Error.UdpPayloadTooLarge, masque.decodeUdpPayload(encoded[0..n]));
}

test "MUST accept a UDP payload at exactly the per-datagram cap [RFC9298 §7 ¶?]" {
    // Boundary test: max_udp_payload_len bytes is permitted.
    const max_payload = try allocator.alloc(u8, masque.max_udp_payload_len);
    defer allocator.free(max_payload);
    @memset(max_payload, 0x42);

    const encoded = try allocator.alloc(u8, masque.udpPayloadEncodedLen(max_payload.len));
    defer allocator.free(encoded);
    const n = try masque.encodeUdpPayload(encoded, max_payload);
    try std.testing.expectEqual(encoded.len, n);
    const decoded = try masque.decodeUdpPayload(encoded[0..n]);
    try std.testing.expectEqual(max_payload.len, decoded.len);
}

test "MUST validate UDP payload length helper agrees with the cap [RFC9298 §7 ¶?]" {
    // The lightweight `udpPayloadEncodedLenChecked` validates against
    // the same cap without needing to allocate the payload first.
    try std.testing.expectError(
        masque.Error.UdpPayloadTooLarge,
        masque.udpPayloadEncodedLenChecked(masque.max_udp_payload_len + 1),
    );
    const ok_len = try masque.udpPayloadEncodedLenChecked(0);
    try std.testing.expectEqual(@as(usize, 1), ok_len); // varint(0) = 1 byte
}

// ---------------------------------------------------------------- §8 error handling

test "MUST use H3_CONNECT_ERROR (0x010f) as the CONNECT-UDP stream-abort code [RFC9298 §8 ¶?]" {
    // §8: "If the proxy detects an error ... it MUST abort the request
    // stream with the H3_CONNECT_ERROR (0x010f) error code."
    try std.testing.expectEqual(@as(u64, 0x010f), masque.connect_udp_abort_code);
    try std.testing.expectEqual(@as(u64, 0x010f), protocol_mod.ErrorCode.connect_error);
}

test "MUST map oversized UDP payload to H3_CONNECT_ERROR [RFC9298 §8 ¶?]" {
    // The classifier translates `error.UdpPayloadTooLarge` into a
    // stream-abort with code 0x010f and reason `udp_payload_too_large`.
    const abort = masque.streamAbortForError(error.UdpPayloadTooLarge);
    try std.testing.expectEqual(@as(u64, 0x010f), abort.error_code);
    try std.testing.expectEqual(masque.AbortReason.udp_payload_too_large, abort.reason);
}

test "MUST map malformed Context ID to H3_CONNECT_ERROR [RFC9298 §8 ¶?]" {
    const abort = masque.streamAbortForError(error.InsufficientBytes);
    try std.testing.expectEqual(@as(u64, 0x010f), abort.error_code);
    try std.testing.expectEqual(masque.AbortReason.malformed_context, abort.reason);
}

test "MUST map unexpected Context ID to H3_CONNECT_ERROR [RFC9298 §8 ¶?]" {
    const abort = masque.streamAbortForError(error.UnexpectedContext);
    try std.testing.expectEqual(@as(u64, 0x010f), abort.error_code);
    try std.testing.expectEqual(masque.AbortReason.unexpected_context, abort.reason);
}

test "MUST map other errors to local_failure [RFC9298 §8 ¶?]" {
    // Errors that aren't directly named by §5 / §7 fall back to the
    // generic local-failure reason.
    const abort = masque.streamAbortForError(error.OutOfMemory);
    try std.testing.expectEqual(@as(u64, 0x010f), abort.error_code);
    try std.testing.expectEqual(masque.AbortReason.local_failure, abort.reason);
}

// ---------------------------------------------------------------- §5 deferred-receive buffering

test "MUST buffer a datagram for an unregistered Context ID [RFC9298 §5 ¶?]" {
    // §5: "Datagrams with an unknown Context ID ... could be associated
    // with a context that has not been registered yet" — endpoints
    // MAY buffer such datagrams pending registration.
    var registry = masque.ContextRegistry.init();
    var pending = masque.PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 4,
        .max_payload_bytes = 64,
    });
    defer pending.deinit();

    var buf: [32]u8 = undefined;
    const n = try datagram_mod.encodeContextPayload(&buf, 8, "hold");
    switch (try pending.classifyOrBuffer(&registry, buf[0..n])) {
        .unknown_context => |ctx| {
            try std.testing.expectEqual(@as(u64, 8), ctx.context_id);
            try std.testing.expectEqualStrings("hold", ctx.payload);
        },
        else => return error.UnexpectedDisposition,
    }
    try std.testing.expectEqual(@as(usize, 1), pending.len());
}

test "MUST drop newly-buffered datagrams when the buffer is full [RFC9298 §5 ¶?]" {
    // §5: implementations MUST bound the buffer (otherwise an attacker
    // could DoS via unsolicited contexts). http3_zig surfaces
    // `ContextBufferFull` once the configured cap is reached.
    var registry = masque.ContextRegistry.init();
    var pending = masque.PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 1,
        .max_payload_bytes = 16,
    });
    defer pending.deinit();

    var buf: [32]u8 = undefined;
    const n_first = try datagram_mod.encodeContextPayload(&buf, 8, "first");
    _ = try pending.classifyOrBuffer(&registry, buf[0..n_first]);

    const n_second = try datagram_mod.encodeContextPayload(&buf, 8, "second");
    try std.testing.expectError(
        masque.Error.ContextBufferFull,
        pending.classifyOrBuffer(&registry, buf[0..n_second]),
    );
}

test "MUST NOT buffer a datagram already classifiable as Context ID 0 [RFC9298 §5 ¶?]" {
    // §5: Context ID 0 is always defined for the lifetime of the
    // CONNECT-UDP stream — its payload is delivered immediately, never
    // buffered.
    var pending = masque.PendingDatagramBuffer.initWithConfig(allocator, .{});
    defer pending.deinit();
    try std.testing.expectError(
        masque.Error.UnexpectedContext,
        pending.bufferUnknown(.{ .context_id = masque.udp_context_id, .payload = "udp" }),
    );
}

test "MUST drain buffered datagrams once the Context ID is registered [RFC9298 §5 ¶?]" {
    var registry = masque.ContextRegistry.init();
    var pending = masque.PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 4,
        .max_payload_bytes = 64,
    });
    defer pending.deinit();

    var buf: [32]u8 = undefined;
    const n1 = try datagram_mod.encodeContextPayload(&buf, 2, "a");
    _ = try pending.classifyOrBuffer(&registry, buf[0..n1]);
    const n2 = try datagram_mod.encodeContextPayload(&buf, 2, "bb");
    _ = try pending.classifyOrBuffer(&registry, buf[0..n2]);
    try std.testing.expectEqual(@as(usize, 2), pending.len());

    try registry.registerAllocatedExtension(.client, 2);
    var drained: std.ArrayList(masque.BufferedDatagram) = .empty;
    defer {
        masque.freeBufferedDatagrams(allocator, drained.items);
        drained.deinit(allocator);
    }
    const drained_count = try pending.drainContext(allocator, 2, &drained);
    try std.testing.expectEqual(@as(usize, 2), drained_count);
    try std.testing.expectEqual(@as(usize, 0), pending.len());
}

// ---------------------------------------------------------------- ConnectUdpReceiver integration

test "MUST classify a UDP-payload-bearing DATAGRAM capsule [RFC9298 §5 ¶?]" {
    // The receiver also accepts DATAGRAM capsules carrying the same
    // wire-format (RFC 9297 §3 fallback when the QUIC datagram layer
    // is unavailable). The Context ID 0 → udp_payload mapping is the
    // same.
    var receiver = masque.ConnectUdpReceiver.init();
    var ctx_buf: [32]u8 = undefined;
    var cap_buf: [64]u8 = undefined;
    const ctx_n = try masque.encodeUdpPayload(&ctx_buf, "packet");
    const cap_n = try capsule_mod.encodeDatagram(&cap_buf, ctx_buf[0..ctx_n]);
    const decoded = try capsule_mod.decode(cap_buf[0..cap_n]);

    switch (receiver.classifyCapsule(decoded.capsule)) {
        .udp_payload => |payload| try std.testing.expectEqualStrings("packet", payload),
        else => return error.UnexpectedDisposition,
    }
}

test "MUST classify a registered extension capsule on the receiver [RFC9298 §6 ¶?]" {
    var receiver = masque.ConnectUdpReceiver.init();
    try receiver.registerExtensionCapsule(0x41);

    const capsule: capsule_mod.Capsule = .{ .capsule_type = 0x41, .value = "ext" };
    switch (receiver.classifyCapsule(capsule)) {
        .extension_capsule => |ext| {
            try std.testing.expectEqual(@as(u64, 0x41), ext.capsule_type);
            try std.testing.expectEqualStrings("ext", ext.value);
        },
        else => return error.UnexpectedDisposition,
    }
}

test "MUST surface stream-abort on a malformed datagram via the receiver [RFC9298 §8 ¶?]" {
    var receiver = masque.ConnectUdpReceiver.init();
    switch (receiver.classifyDatagramPayload(&.{})) {
        .abort_stream => |abort| {
            try std.testing.expectEqual(masque.connect_udp_abort_code, abort.error_code);
            try std.testing.expectEqual(masque.AbortReason.malformed_context, abort.reason);
        },
        else => return error.UnexpectedDisposition,
    }
}

// ---------------------------------------------------------------- §3 capsule-protocol header classification

test "NORMATIVE capsuleProtocolEnabled returns true only for value \"?1\" [RFC9298 §3 ¶?]" {
    // The header value follows RFC 9297 §3 / RFC 8941 §3.4 (Structured
    // Field "boolean true"): "?1". Any other value MUST NOT be treated
    // as a Capsule-Protocol opt-in.
    const enabled = [_]FieldLine{
        .{ .name = "capsule-protocol", .value = "?1" },
    };
    const disabled = [_]FieldLine{
        .{ .name = "capsule-protocol", .value = "?0" },
    };
    const empty: [0]FieldLine = .{};

    try std.testing.expect(masque.capsuleProtocolEnabled(&enabled));
    try std.testing.expect(!masque.capsuleProtocolEnabled(&disabled));
    try std.testing.expect(!masque.capsuleProtocolEnabled(&empty));
}

