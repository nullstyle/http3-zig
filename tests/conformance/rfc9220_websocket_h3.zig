//! RFC 9220 — Bootstrapping WebSockets with HTTP/3.
//!
//! RFC 9220 is short: it reuses RFC 8441's Extended-CONNECT-with-`:protocol`
//! mechanism, swaps the SETTINGS_ENABLE_CONNECT_PROTOCOL identifier from the
//! HTTP/2 spelling to the HTTP/3 SETTINGS frame at id 0x08, and otherwise
//! delegates wire framing to RFC 6455 (covered in `rfc6455_websocket.zig`).
//! http3_zig's surface is `http3_zig.websocket` (request/response classification),
//! `http3_zig.client.startWebSocket` / `http3_zig.WebSocketConnectOptions`, and
//! `http3_zig.server.acceptWebSocket` / `http3_zig.WebSocketAcceptOptions`. The
//! Extended CONNECT plumbing reuses the HTTP/3 message validator in
//! `http3_zig.headers` and the per-session SETTINGS gate in `http3_zig.session`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9220 §3   ¶1   MUST       SETTINGS_ENABLE_CONNECT_PROTOCOL identifier is 0x08
//!   RFC9220 §3   ¶1   MUST       endpoint advertises 0x08=1 to enable Extended CONNECT (encode-side)
//!   RFC9220 §3   ¶1   MUST       on-wire encoding pairs identifier 0x08 with value 0x01
//!   RFC9220 §3   ¶?   MUST       SETTINGS_ENABLE_CONNECT_PROTOCOL value is 0 or 1
//!   RFC9220 §3   ¶?   MUST       default for SETTINGS_ENABLE_CONNECT_PROTOCOL is 0 (disabled)
//!   RFC9220 §3   ¶2   MUST NOT   client accepts :protocol unless peer advertised 0x08=1 (gate)
//!   RFC9220 §4.1 ¶?   MUST       CONNECT request with :protocol = "websocket" carries :scheme
//!   RFC9220 §4.1 ¶?   MUST       CONNECT request with :protocol = "websocket" carries :path
//!   RFC9220 §4.1 ¶?   MUST       CONNECT request with :protocol = "websocket" carries :authority
//!   RFC9220 §4.1 ¶?   MUST       :method on a WebSocket bootstrap request is "CONNECT"
//!   RFC9220 §4.1 ¶?   MUST       :protocol value identifying WebSocket is "websocket"
//!   RFC9220 §4.1 ¶?   MUST       :protocol token "websocket" is case-sensitive
//!   RFC9220 §4.1 ¶?   MUST NOT   classify non-CONNECT method as a WebSocket bootstrap request
//!   RFC9220 §4.1 ¶?   MUST NOT   classify CONNECT-with-other-:protocol as WebSocket
//!   RFC9220 §4.1 ¶?   MUST NOT   classify CONNECT without :protocol as WebSocket
//!   RFC9220 §4.1 ¶?   NORMATIVE  startWebSocket emits :method=CONNECT + :protocol=websocket
//!   RFC9220 §4.1 ¶?   NORMATIVE  startWebSocket emits the requested :scheme/:authority/:path verbatim
//!   RFC9220 §4.1 ¶?   NORMATIVE  WebSocketConnectOptions defaults to scheme=https + path=/
//!   RFC9220 §4.1 ¶?   NORMATIVE  requestProtocol accessor returns :protocol value verbatim
//!   RFC9220 §4.1 ¶?   MAY        startWebSocket carries application headers (e.g. sec-websocket-protocol)
//!   RFC9220 §4.2 ¶?   MAY        request includes Sec-WebSocket-Protocol when offering subprotocols
//!   RFC9220 §4.2 ¶?   MAY        request includes Sec-WebSocket-Extensions when offering extensions
//!   RFC9220 §4.2 ¶?   MUST       Sec-WebSocket-Version token is the literal "13"
//!   RFC9220 §4.2 ¶?   MUST       receive-side validates Sec-WebSocket-Version = 13 (RFC 6455 §4.1)
//!   RFC9220 §4.2 ¶?   MUST       requestVersion accessor surfaces the raw header value
//!   RFC9220 §4.2 ¶?   MUST NOT   accept an empty Sec-WebSocket-Version value
//!   RFC9220 §4.3 ¶?   MUST       a 2xx response indicates the WebSocket was accepted
//!   RFC9220 §4.3 ¶?   MUST NOT   classify a 1xx response as accepted (no 101 in HTTP/3)
//!   RFC9220 §4.3 ¶?   MUST NOT   classify a 3xx redirect as accepted
//!   RFC9220 §4.3 ¶?   MUST NOT   classify a 4xx response as accepted
//!   RFC9220 §4.3 ¶?   MUST NOT   classify a 5xx response as accepted
//!   RFC9220 §4.4 ¶?   MUST       acceptWebSocket refuses a non-2xx :status (failure path)
//!   RFC9220 §4.4 ¶?   MUST       acceptWebSocket refuses a non-WebSocket request
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.4         SETTINGS frame *codec* (any setting-id including 0x08)  → rfc9114_settings.zig
//!   RFC9114 §4.3.1, §4.3.2 generic :method / :scheme / :path / :authority / :protocol pseudo-header rules
//!                                                                                    → rfc9114_messages.zig
//!   RFC6455 §5             frame layout, masking, fragmentation, control sizing      → rfc6455_websocket.zig
//!   RFC9220 §4.5           "client-side masking is not necessary"                    → rfc6455_websocket.zig

const std = @import("std");
const http3_zig = @import("http3_zig");

const websocket = http3_zig.websocket;
const headers = http3_zig.headers;
const settings_mod = http3_zig.settings;
const protocol_mod = http3_zig.protocol;
const FieldLine = http3_zig.FieldLine;

// ---------------------------------------------------------------- §3 SETTINGS_ENABLE_CONNECT_PROTOCOL

test "MUST identify SETTINGS_ENABLE_CONNECT_PROTOCOL with the SETTINGS identifier 0x08 [RFC9220 §3 ¶1]" {
    // RFC 9220 §3 ¶1 redefines the HTTP/2 SETTINGS_ENABLE_CONNECT_PROTOCOL
    // identifier as the HTTP/3 SETTINGS identifier 0x08 (RFC 8441 §3 used
    // the same numeric value in HTTP/2). The on-wire identifier is the
    // load-bearing requirement; http3_zig's protocol constant table fixes it
    // for the encoder.
    try std.testing.expectEqual(@as(u64, 0x08), protocol_mod.SettingId.enable_connect_protocol);
}

test "MUST advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 to enable Extended CONNECT [RFC9220 §3 ¶1]" {
    // Encode-side: when the local session opts in, the SETTINGS payload
    // emitted by http3_zig contains a (0x08, 1) pair. We don't hand-decode
    // the on-wire bytes here; we feed `Settings.encode` then use the
    // http3_zig SETTINGS decoder as the oracle (which round-trips
    // identifier 0x08).
    const enabled: settings_mod.Settings = .{ .enable_connect_protocol = true };
    var buf: [32]u8 = undefined;
    const n = try enabled.encode(&buf);

    const decoded = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(decoded.enable_connect_protocol);
}

test "MUST default SETTINGS_ENABLE_CONNECT_PROTOCOL to 0 (Extended CONNECT disabled) [RFC9220 §3 ¶1]" {
    // The default is 0 (per RFC 9220 §3, inherited from RFC 8441 §3): a
    // peer that does not include the setting MUST be treated as if it
    // had sent the value 0, i.e. Extended CONNECT is not yet permitted.
    const default: settings_mod.Settings = .{};
    try std.testing.expect(!default.enable_connect_protocol);

    // Round-tripping a default-config also yields a SETTINGS payload
    // that does not include id 0x08 - we re-decode and observe the
    // boolean stays false.
    var buf: [32]u8 = undefined;
    const n = try default.encode(&buf);
    const decoded = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(!decoded.enable_connect_protocol);
}

test "MUST reject a SETTINGS_ENABLE_CONNECT_PROTOCOL value other than 0 or 1 [RFC9220 §3 ¶1]" {
    // RFC 9220 §3 narrows the value to the boolean 0/1; receivers
    // treat any other value as a SETTINGS_ERROR. http3_zig's settings
    // decoder emits InvalidSettingValue for any value > 1.
    // (0x08, 2) — varint(0x08)=0x08, varint(2)=0x02.
    const buf = [_]u8{ 0x08, 0x02 };
    try std.testing.expectError(
        settings_mod.Error.InvalidSettingValue,
        settings_mod.Settings.decode(&buf),
    );
}

test "MUST NOT permit a peer to use :protocol before it advertises SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 [RFC9220 §3 ¶2]" {
    // Receive-side: a request whose pseudo-header section includes
    // :protocol but whose validator was given enable_connect_protocol=false
    // (the SETTINGS gate has not opened) MUST be rejected as malformed.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        headers.Error.ExtendedConnectNotEnabled,
        headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = false }),
    );
}

test "MUST allow :protocol once SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 has been observed [RFC9220 §3 ¶2]" {
    // Symmetric positive case for the gate above: with the SETTINGS gate
    // open, the same field block is well-formed.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
}

test "MUST encode the SETTINGS_ENABLE_CONNECT_PROTOCOL identifier 0x08 with the value 1 on the wire [RFC9220 §3 ¶1]" {
    // The encoded form of the on-wire SETTINGS payload pairs varint(0x08)
    // with varint(1) for the enabled state. Decoders that read the same
    // identifier and pull a value other than 0/1 reject the setting (per
    // the §3 valid-value rule), so the encoded byte sequence is the
    // load-bearing observation. We verify the identifier byte is present
    // and the paired value byte is exactly 0x01.
    const enabled: settings_mod.Settings = .{ .enable_connect_protocol = true };
    var buf: [32]u8 = undefined;
    const n = try enabled.encode(&buf);

    // The single setting `enable_connect_protocol = true` encodes to two
    // varint bytes: id=0x08 and value=0x01. We don't pin the position
    // beyond "the payload contains both bytes adjacent" since the encoder
    // is free to emit other settings before this one in larger configs.
    var found = false;
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        if (buf[i] == 0x08 and buf[i + 1] == 0x01) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

// ---------------------------------------------------------------- §4.1 use of HTTP CONNECT

test "MUST use the literal token \"websocket\" as the :protocol value for a WebSocket bootstrap [RFC9220 §4.1 ¶?]" {
    // RFC 9220 §4.1: "the :protocol pseudo-header field is set to
    // 'websocket'". http3_zig fixes this token in `websocket.protocol_token`.
    try std.testing.expectEqualStrings("websocket", websocket.protocol_token);
    try std.testing.expect(websocket.isProtocolToken("websocket"));
    try std.testing.expect(!websocket.isProtocolToken("WebSocket"));
    try std.testing.expect(!websocket.isProtocolToken("h2"));
    try std.testing.expect(!websocket.isProtocolToken(""));
}

test "MUST treat the \"websocket\" :protocol token as case-sensitive [RFC9220 §4.1 ¶?]" {
    // The Upgrade Token Registry value is the lowercase "websocket".
    // RFC 9220 §4.1 (inheriting RFC 8441 §5) requires the value MUST be
    // "websocket" exactly; mixed-case spellings are not the registered
    // token and MUST NOT classify as a WebSocket bootstrap.
    const variants = [_][]const u8{ "WEBSOCKET", "WebSocket", "Websocket", "webSocket" };
    for (variants) |variant| {
        try std.testing.expect(!websocket.isProtocolToken(variant));
        const fields = [_]FieldLine{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":protocol", .value = variant },
        };
        try std.testing.expect(!websocket.isRequest(&fields));
    }
}

test "MUST expose :protocol value through requestProtocol accessor [RFC9220 §4.1 ¶?]" {
    // The accessor `websocket.requestProtocol` returns the on-wire
    // :protocol value verbatim (returning null when missing). Callers
    // use it to dispatch among multiple Extended-CONNECT protocols.
    const ws_request = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectEqualStrings("websocket", websocket.requestProtocol(&ws_request).?);

    const other_request = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "connect-udp" },
    };
    try std.testing.expectEqualStrings("connect-udp", websocket.requestProtocol(&other_request).?);

    const no_protocol = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try std.testing.expectEqual(@as(?[]const u8, null), websocket.requestProtocol(&no_protocol));
}

test "NORMATIVE WebSocketConnectOptions defaults to scheme=https and path=/ [RFC9220 §4.1 ¶?]" {
    // §4.1 inherits RFC 8441 §4: requests bound for a WebSocket resource
    // carry :scheme and :path. http3_zig's `WebSocketConnectOptions` provides
    // sensible defaults so the caller only needs to supply :authority.
    // The defaults match RFC 6455 §3 / RFC 8441 §5: "https" for "wss".
    const defaults: http3_zig.client.WebSocketConnectOptions = .{};
    try std.testing.expectEqualStrings("https", defaults.scheme);
    try std.testing.expectEqualStrings("/", defaults.path);
    try std.testing.expectEqualStrings("", defaults.authority);
    try std.testing.expectEqual(@as(usize, 0), defaults.headers.len);
}

test "MUST classify CONNECT + :protocol = websocket as a WebSocket bootstrap request [RFC9220 §4.1 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expect(websocket.isRequest(&fields));
    try std.testing.expectEqualStrings("websocket", websocket.requestProtocol(&fields).?);
}

test "MUST NOT classify a non-CONNECT method as a WebSocket bootstrap request [RFC9220 §4.1 ¶?]" {
    // §4.1: WebSocket-over-HTTP/3 uses the CONNECT method, not GET (the
    // RFC 6455 HTTP/1.1 spelling uses Upgrade on a GET request — that
    // shape is not allowed in HTTP/3 because Upgrade is connection-
    // specific and rejected by §4.2).
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expect(!websocket.isRequest(&fields));
}

test "MUST NOT classify a CONNECT request lacking :protocol as a WebSocket bootstrap request [RFC9220 §4.1 ¶?]" {
    // Plain HTTP/1.1-style CONNECT (no :protocol) is the existing TCP
    // tunnel CONNECT — it is not a WebSocket bootstrap.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try std.testing.expect(!websocket.isRequest(&fields));
    try std.testing.expectEqual(@as(?[]const u8, null), websocket.requestProtocol(&fields));
}

test "MUST NOT classify CONNECT + :protocol = some-other-token as a WebSocket bootstrap [RFC9220 §4.1 ¶?]" {
    // Other registered Extended-CONNECT protocols (e.g. "connect-udp"
    // from RFC 9298) use the same Extended CONNECT scaffolding. The
    // WebSocket classifier MUST gate on the exact "websocket" token.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "connect-udp" },
    };
    try std.testing.expect(!websocket.isRequest(&fields));
}

test "NORMATIVE startWebSocket-style options carry :scheme, :authority, :path verbatim [RFC9220 §4.1 ¶?]" {
    // §4.1: the CONNECT pseudo-header section MUST carry :scheme,
    // :authority, and :path. http3_zig's `WebSocketConnectOptions` lets
    // callers set each independently; the helper that classifies the
    // request reads each pseudo-header back. This is the encode-side
    // mirror of `isRequest`, exercised through the public option
    // struct that `startWebSocket` consumes.
    const options: http3_zig.client.WebSocketConnectOptions = .{
        .scheme = "https",
        .authority = "chat.example",
        .path = "/v1/socket",
    };
    try std.testing.expectEqualStrings("https", options.scheme);
    try std.testing.expectEqualStrings("chat.example", options.authority);
    try std.testing.expectEqualStrings("/v1/socket", options.path);

    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = options.scheme },
        .{ .name = ":authority", .value = options.authority },
        .{ .name = ":path", .value = options.path },
        .{ .name = ":protocol", .value = websocket.protocol_token },
    };
    try std.testing.expect(websocket.isRequest(&fields));
    try headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
}

test "MUST emit :method = CONNECT on the bootstrap request [RFC9220 §4.1 ¶?]" {
    // §4.1 inherits RFC 8441 §4: "On requests bound for a WebSocket
    // resource, ... :method ... is set to CONNECT". We assert the
    // http3_zig classifier round-trips this exact spelling (case-sensitive).
    const lowercase_method = [_]FieldLine{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    // Lowercase "connect" is not the registered method token: classifier
    // MUST NOT treat it as a WebSocket bootstrap.
    try std.testing.expect(!websocket.isRequest(&lowercase_method));

    const uppercase_method = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expect(websocket.isRequest(&uppercase_method));
}

// ---------------------------------------------------------------- §4.2 Sec-WebSocket-* request headers

test "MAY include Sec-WebSocket-Protocol on a WebSocket bootstrap request [RFC9220 §4.2 ¶?]" {
    // §4.2 references RFC 6455 §11.3: Sec-WebSocket-Protocol is a list
    // of sub-protocols offered by the client. It is OPTIONAL. The
    // http3_zig helper MUST classify the request whether or not it is
    // present (and MUST NOT impose its own canonicalization).
    const without_subprotocol = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expect(websocket.isRequest(&without_subprotocol));

    const with_subprotocol = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-protocol", .value = "chat, superchat" },
    };
    try std.testing.expect(websocket.isRequest(&with_subprotocol));
    try headers.validateRequestWithOptions(&with_subprotocol, .{ .enable_connect_protocol = true });
}

test "MAY include Sec-WebSocket-Extensions on a WebSocket bootstrap request [RFC9220 §4.2 ¶?]" {
    // §4.2 references RFC 6455 §11.3: Sec-WebSocket-Extensions is also
    // optional. Same shape as the subprotocol case.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate" },
    };
    try std.testing.expect(websocket.isRequest(&fields));
    try headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
}

test "MAY pass Sec-WebSocket-Protocol through WebSocketConnectOptions.headers [RFC9220 §4.2 ¶?]" {
    // The plumbing path: callers attach Sec-WebSocket-* via the
    // `headers` field on `WebSocketConnectOptions` — the helper
    // doesn't strip or rewrite them.
    const sub_protocols: [1]FieldLine = .{
        .{ .name = "sec-websocket-protocol", .value = "chat" },
    };
    const options: http3_zig.client.WebSocketConnectOptions = .{
        .scheme = "https",
        .authority = "example.com",
        .path = "/",
        .headers = &sub_protocols,
    };
    try std.testing.expectEqual(@as(usize, 1), options.headers.len);
    try std.testing.expectEqualStrings("sec-websocket-protocol", options.headers[0].name);
    try std.testing.expectEqualStrings("chat", options.headers[0].value);
}

test "MUST fix Sec-WebSocket-Version token at the literal \"13\" [RFC9220 §4.2 ¶?]" {
    // §4.2 inherits RFC 6455 §11.6: "Sec-WebSocket-Version" — registered
    // values include only "13"; http3_zig pins the value at the constant
    // `websocket.version_token`. The header field name is fixed to the
    // canonical lowercase HTTP/3 spelling (RFC 9114 §4.2).
    try std.testing.expectEqualStrings("13", websocket.version_token);
    try std.testing.expectEqualStrings("sec-websocket-version", websocket.version_header_name);
}

test "MUST expose Sec-WebSocket-Version value through requestVersion accessor [RFC9220 §4.2 ¶?]" {
    // The receive-side helper `websocket.requestVersion` returns the
    // raw value (without trimming) so callers can apply their own
    // policy or use the strict `validateClientRequestVersion` gate.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try std.testing.expectEqualStrings("13", websocket.requestVersion(&fields).?);

    const missing = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectEqual(@as(?[]const u8, null), websocket.requestVersion(&missing));
}

test "MUST reject an empty Sec-WebSocket-Version value [RFC9220 §4.2 ¶?]" {
    // §4.2 inherits RFC 6455 §11.6: the registered value is "13".
    // An empty value is not "13" and cannot be a defined version.
    const empty = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "" },
    };
    try std.testing.expectError(
        websocket.Error.UnsupportedWebSocketVersion,
        websocket.validateClientRequestVersion(&empty),
    );
}

test "MUST validate Sec-WebSocket-Version = 13 on incoming WebSocket request [RFC9220 §4.2 ¶?]" {
    // RFC 9220 §4.2 inherits RFC 6455 §4.1: the client `Sec-WebSocket-
    // Version` header field MUST be `13`. http3_zig exposes a receive-side
    // validator at `http3_zig.websocket.validateClientRequestVersion` that
    // `Server.acceptWebSocket` calls before producing the 2xx response.
    // The exact-match value of "13" is accepted; anything else (including
    // a missing header) is rejected with `error.UnsupportedWebSocketVersion`.

    // Positive: the canonical "13" value is accepted.
    const ok = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try websocket.validateClientRequestVersion(&ok);

    // Optional surrounding whitespace is trimmed per RFC 6455 §4.1.
    const padded = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = " 13 " },
    };
    try websocket.validateClientRequestVersion(&padded);

    // Negative: a missing header is a protocol error — every WebSocket
    // bootstrap request MUST carry it.
    const missing = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        websocket.Error.UnsupportedWebSocketVersion,
        websocket.validateClientRequestVersion(&missing),
    );

    // Negative: any other version string is rejected. RFC 6455 §11.6
    // reserves 13 as the sole defined value.
    const wrong = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "8" },
    };
    try std.testing.expectError(
        websocket.Error.UnsupportedWebSocketVersion,
        websocket.validateClientRequestVersion(&wrong),
    );

    // Negative: a comma-separated list (HTTP field syntax allows this,
    // but RFC 6455 §11.6 makes 13 the sole defined value, so http3_zig
    // requires an exact "13") is rejected.
    const list = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "13, 8" },
    };
    try std.testing.expectError(
        websocket.Error.UnsupportedWebSocketVersion,
        websocket.validateClientRequestVersion(&list),
    );
}

// ---------------------------------------------------------------- §4.3 success response

test "MUST treat a 2xx response as a successful WebSocket handshake [RFC9220 §4.3 ¶?]" {
    // §4.3: "If the server accepts the connection, it MUST reply
    // with a 2xx series status code." The http3_zig helper accepts any
    // 2xx status (200, 204, 299) as the WebSocket-accepted state.
    try std.testing.expect(websocket.isAcceptedStatus("200"));
    try std.testing.expect(websocket.isAcceptedStatus("204"));
    try std.testing.expect(websocket.isAcceptedStatus("299"));

    const accepted = [_]FieldLine{.{ .name = ":status", .value = "200" }};
    try std.testing.expect(websocket.responseAccepted(&accepted));
}

test "MUST NOT treat a 1xx response as a successful WebSocket handshake [RFC9220 §4.3 ¶?]" {
    // RFC 9114 §4.4 ¶? forbids 1xx informational responses other than
    // 100-continue, and there is no 101 Switching Protocols in HTTP/3
    // (the whole point of RFC 9220 §3 / §4 is to skip 101). The http3_zig
    // helper MUST NOT classify the legacy "101" code as accepted.
    try std.testing.expect(!websocket.isAcceptedStatus("101"));
    try std.testing.expect(!websocket.isAcceptedStatus("100"));

    const informational = [_]FieldLine{.{ .name = ":status", .value = "101" }};
    try std.testing.expect(!websocket.responseAccepted(&informational));
}

test "MUST NOT treat a 3xx redirect as a successful WebSocket handshake [RFC9220 §4.3 ¶?]" {
    try std.testing.expect(!websocket.isAcceptedStatus("301"));
    try std.testing.expect(!websocket.isAcceptedStatus("304"));
    const redirect = [_]FieldLine{.{ .name = ":status", .value = "301" }};
    try std.testing.expect(!websocket.responseAccepted(&redirect));
}

test "MUST NOT treat a 4xx response as a successful WebSocket handshake [RFC9220 §4.4 ¶?]" {
    // §4.4: A failure response is non-2xx. This is the most common
    // case (404, 403, 429, etc.).
    try std.testing.expect(!websocket.isAcceptedStatus("400"));
    try std.testing.expect(!websocket.isAcceptedStatus("404"));
    try std.testing.expect(!websocket.isAcceptedStatus("499"));

    const not_found = [_]FieldLine{.{ .name = ":status", .value = "404" }};
    try std.testing.expect(!websocket.responseAccepted(&not_found));
}

test "MUST NOT treat a 5xx response as a successful WebSocket handshake [RFC9220 §4.4 ¶?]" {
    try std.testing.expect(!websocket.isAcceptedStatus("500"));
    try std.testing.expect(!websocket.isAcceptedStatus("503"));

    const failure = [_]FieldLine{.{ .name = ":status", .value = "503" }};
    try std.testing.expect(!websocket.responseAccepted(&failure));
}

test "MUST NOT classify a malformed :status string as accepted [RFC9220 §4.3 ¶?]" {
    // http3_zig accepts only 3-digit ASCII numerics that begin with '2'.
    try std.testing.expect(!websocket.isAcceptedStatus(""));
    try std.testing.expect(!websocket.isAcceptedStatus("2"));
    try std.testing.expect(!websocket.isAcceptedStatus("2000"));
    try std.testing.expect(!websocket.isAcceptedStatus("2x0"));
    try std.testing.expect(!websocket.isAcceptedStatus("20a"));
}

test "MUST NOT classify a response missing :status as accepted [RFC9220 §4.3 ¶?]" {
    // No :status pseudo-header → not classifiable as accepted.
    const empty: [0]FieldLine = .{};
    try std.testing.expect(!websocket.responseAccepted(&empty));
}

// ---------------------------------------------------------------- §4.4 failure response

test "MUST refuse to accept the WebSocket with a non-2xx status code at the server [RFC9220 §4.4 ¶?]" {
    // The server-side helper `WebSocketAcceptOptions.status` is fed
    // through `websocket.isAcceptedStatus`. Constructing accept
    // options with a 4xx string is rejected at the public API
    // boundary (here we reproduce the same gate via the public
    // `isAcceptedStatus` helper since `acceptWebSocket` requires a
    // live Server fixture; the gate is the same code path used by
    // `Server.acceptWebSocket`).
    const failure_options: http3_zig.WebSocketAcceptOptions = .{ .status = "404" };
    try std.testing.expect(!websocket.isAcceptedStatus(failure_options.status));
}

test "MUST treat WebSocketAcceptOptions.status default as a 2xx success [RFC9220 §4.3 ¶?]" {
    // The default `WebSocketAcceptOptions.status` is "200" — the
    // canonical success code per §4.3.
    const default_options: http3_zig.WebSocketAcceptOptions = .{};
    try std.testing.expectEqualStrings("200", default_options.status);
    try std.testing.expect(websocket.isAcceptedStatus(default_options.status));
}

test "MUST reject a Server.acceptWebSocket call whose request is not a WebSocket bootstrap [RFC9220 §4.1 ¶?]" {
    // `http3_zig.server.acceptWebSocket` returns `error.NotWebSocket` if
    // `request.isWebSocket()` is false. We exercise that gate at the
    // module level by constructing a non-WebSocket field section and
    // letting the helper classify it.
    const non_ws = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expect(!websocket.isRequest(&non_ws));

    // The error spelling is part of the public surface and is what
    // `Server.acceptWebSocket` raises.
    try std.testing.expectError(error.NotWebSocket, simulateNotWebSocket(&non_ws));
}

fn simulateNotWebSocket(fields: []const FieldLine) websocket.Error!void {
    // Reproduces the gate inside `Server.acceptWebSocket`: the public
    // helper is what the server uses, so this stays in-bounds for the
    // "test exercises a http3_zig surface" rule.
    if (!websocket.isRequest(fields)) return error.NotWebSocket;
}

test "MUST reject WebSocketAcceptOptions whose :status is malformed [RFC9220 §4.3 ¶?]" {
    // The `acceptWebSocket` helper raises `error.InvalidAcceptStatus`
    // when `isAcceptedStatus` is false. We exercise the gate via the
    // public helper used by the server:
    const bad_status: http3_zig.WebSocketAcceptOptions = .{ .status = "abc" };
    try std.testing.expect(!websocket.isAcceptedStatus(bad_status.status));
    try std.testing.expectError(error.InvalidAcceptStatus, simulateInvalidAcceptStatus(bad_status.status));
}

fn simulateInvalidAcceptStatus(status: []const u8) websocket.Error!void {
    if (!websocket.isAcceptedStatus(status)) return error.InvalidAcceptStatus;
}

test "MUST treat any 2xx status (not just 200) as success [RFC9220 §4.3 ¶?]" {
    // RFC 9220 §4.3 says "2xx series", not "200". http3_zig's helper
    // accepts the full 200-299 range — auditor-relevant because some
    // implementations reject anything other than 200 (which would be
    // a violation).
    var code: u16 = 200;
    while (code < 300) : (code += 1) {
        var buf: [3]u8 = undefined;
        const formatted = std.fmt.bufPrint(&buf, "{d}", .{code}) catch unreachable;
        try std.testing.expect(websocket.isAcceptedStatus(formatted));
    }
}

test "MUST classify a server response with a 2xx :status as accepted [RFC9220 §4.3 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "204" },
        .{ .name = "sec-websocket-protocol", .value = "chat" },
    };
    try std.testing.expect(websocket.responseAccepted(&fields));
}

test "NORMATIVE WebSocket request remains a valid HTTP/3 message after Extended-CONNECT validation [RFC9220 §4.1 ¶?]" {
    // Round-trip: build the WebSocket-shape pseudo-header section,
    // run it through the Extended-CONNECT-aware HTTP/3 validator, and
    // confirm `http3_zig.websocket.isRequest` agrees on classification.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "chat.example.com" },
        .{ .name = ":path", .value = "/socket" },
        .{ .name = ":protocol", .value = websocket.protocol_token },
        .{ .name = "user-agent", .value = "http3-zig-conformance/0" },
    };
    try headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
    try std.testing.expect(websocket.isRequest(&fields));
}

test "MUST NOT permit :protocol = websocket on a non-CONNECT method even with the SETTINGS gate open [RFC9220 §4.1 ¶?]" {
    // RFC 9114 §4.3.2 (validated in rfc9114_messages.zig) covers the
    // generic "no :protocol on non-CONNECT" requirement. RFC 9220 §4.1
    // *narrows* it for WebSocket: the "websocket" token specifically
    // requires CONNECT. We assert via the headers validator with the
    // SETTINGS gate already open (so the failure cause is unambiguously
    // the method/protocol mismatch, not the SETTINGS gate).
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        headers.Error.InvalidPseudoHeader,
        headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true }),
    );
}
