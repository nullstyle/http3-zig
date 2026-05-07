//! RFC 9114 §4 — Expressing HTTP Semantics in HTTP/3.
//!
//! HTTP/3 carries the same HTTP request/response shape as the HTTP/1.1 line
//! format defined by RFC 9110, encoded as QPACK field sections (RFC 9204) on
//! request, response, and push streams. The implementation under test lives
//! in `src/headers.zig` (pseudo-header / connection-specific / trailer
//! validation) and `src/message.zig` (`MessageEncoder` / `MessageDecoder`
//! state machine, malformed-message detection across the encoded direction).
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §4.1   ¶1   NORMATIVE  request consists of HEADERS then optional DATA then optional trailers
//!   RFC9114 §4.1   ¶?   NORMATIVE  response carries one HEADERS field section followed by DATA / trailers
//!   RFC9114 §4.2   ¶?   MUST       field names contain only lowercase ASCII (no uppercase)
//!   RFC9114 §4.2   ¶?   MUST NOT   accept a field name containing an uppercase ASCII letter
//!   RFC9114 §4.2   ¶?   MUST NOT   accept an empty field name
//!   RFC9114 §4.2   ¶?   MUST NOT   include connection-specific fields (Connection, Keep-Alive, …)
//!   RFC9114 §4.2   ¶?   MUST NOT   include Transfer-Encoding (always connection-specific in HTTP/3)
//!   RFC9114 §4.2   ¶?   MUST NOT   include Proxy-Connection / Upgrade
//!   RFC9114 §4.2.1 ¶?   MUST NOT   reject pseudo-header before regular header (ordering)
//!   RFC9114 §4.2.2 ¶?   MUST       :status appears in responses
//!   RFC9114 §4.2.2 ¶?   MUST NOT   pseudo-header used outside of its defined role appears
//!   RFC9114 §4.2.2 ¶?   MUST NOT   :status appear in a request
//!   RFC9114 §4.2.2 ¶?   MUST NOT   :method appear in a response
//!   RFC9114 §4.2.2 ¶?   MUST NOT   :scheme appear in a response
//!   RFC9114 §4.2.2 ¶?   MUST NOT   :path appear in a response
//!   RFC9114 §4.2.2 ¶?   MUST NOT   :authority appear in a response
//!   RFC9114 §4.2.2 ¶?   MUST NOT   pseudo-headers follow a regular field on request
//!   RFC9114 §4.2.2 ¶?   MUST NOT   pseudo-headers follow a regular field on response
//!   RFC9114 §4.2.2 ¶?   MUST NOT   accept duplicate pseudo-headers
//!   RFC9114 §4.3   ¶?   MUST       accept a request with :method, :scheme, :path
//!   RFC9114 §4.3.1 ¶?   MUST       request includes :method
//!   RFC9114 §4.3.1 ¶?   MUST       request includes :scheme
//!   RFC9114 §4.3.1 ¶?   MUST       request includes :path
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept a request missing :method
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept a request missing :scheme
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept a request missing :path
//!   RFC9114 §4.3.1 ¶?   MUST       request MAY include :authority
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept duplicate :method
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept duplicate :scheme
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept duplicate :path
//!   RFC9114 §4.3.1 ¶?   MUST NOT   accept duplicate :authority
//!   RFC9114 §4.3.2 ¶?   NORMATIVE  Extended CONNECT carries :protocol; gated by enable_connect_protocol
//!   RFC9114 §4.3.2 ¶?   MUST NOT   accept :protocol when CONNECT is not negotiated
//!   RFC9114 §4.3.2 ¶?   MUST NOT   accept :protocol when :method != CONNECT
//!   RFC9114 §4.3.2 ¶?   MUST NOT   accept duplicate :protocol
//!   RFC9114 §4.3.2 ¶?   MUST NOT   accept :protocol with empty value
//!   RFC9114 §4.4   ¶?   MUST       response carries :status
//!   RFC9114 §4.4   ¶?   MUST NOT   accept a response without :status
//!   RFC9114 §4.4   ¶?   MUST NOT   accept duplicate :status
//!   RFC9114 §4.5   ¶?   NORMATIVE  trailer field section permitted after request body
//!   RFC9114 §4.5   ¶?   NORMATIVE  trailer field section permitted after response body
//!   RFC9114 §4.5   ¶?   MUST NOT   include any pseudo-header in trailers
//!   RFC9114 §4.5   ¶?   MUST NOT   include connection-specific fields in trailers
//!   RFC9114 §4.5   ¶?   MUST NOT   send DATA after trailers
//!   RFC9114 §4.5   ¶?   MUST NOT   send a second HEADERS section after trailers
//!   RFC9114 §4.5   ¶?   MUST NOT   send DATA before a HEADERS section
//!   RFC9114 §4.5   ¶?   MUST NOT   close request stream before a HEADERS section is observed
//!   RFC9114 §4.6   ¶?   MUST       reject malformed messages — encoder side refuses bad outbound
//!   RFC9114 §4.6   ¶?   MUST       reject malformed messages — decoder side refuses bad inbound
//!
//! Visible debt:
//!   RFC9114 §4.3.1 ¶?  MUST   :authority host syntactic validation (no userinfo, no fragment)
//!                      → headers.zig only checks presence/uniqueness; URI-syntax
//!                        validation is not yet implemented.
//!   RFC9114 §4.3.1 ¶?  MUST   :path non-empty for non-OPTIONS / non-CONNECT
//!                      → headers.zig accepts an empty :path; the RFC mandates non-empty
//!                        for "http"/"https" requests.
//!   RFC9114 §4.4   ¶?  MUST   :status three-ASCII-digit syntactic validation
//!                      → headers.zig only enforces presence; numeric format unchecked.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.2  HEADERS frame *wire* (length, type, varint)         → rfc9114_frames.zig
//!   RFC9114 §6.1    HEADERS-on-control-stream rejection (stream context) → rfc9114_streams.zig
//!   RFC9204         field-section *encoding* (static-table / Huffman)   → rfc9204_qpack_*.zig
//!   RFC9220         WebSocket-specific :protocol value validation       → rfc9220_websocket_h3.zig

const std = @import("std");
const null3 = @import("null3");

const headers = null3.headers;
const message = null3.message;
const FieldLine = null3.FieldLine;
const MessageEncoder = null3.MessageEncoder;
const MessageDecoder = null3.MessageDecoder;

// Convenience for the "minimal valid request" baseline — a GET that all of
// RFC 9114 §4.3.1's MUST requirements satisfy in one go. Construct copies of
// this for negative tests so the failure cause is unambiguously the field
// each test mutates.
const minimal_request = [_]FieldLine{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "example.com" },
};

const minimal_response = [_]FieldLine{
    .{ .name = ":status", .value = "200" },
};

// ---------------------------------------------------------------- §4.1 message exchanges

test "NORMATIVE encoder accepts HEADERS then DATA then trailers on a request stream [RFC9114 §4.1 ¶1]" {
    // §4.1: "An HTTP message ... consists of: ... the header section, ...
    // the message content, and optionally trailers."
    var buf: [256]u8 = undefined;
    const trailers = [_]FieldLine{.{ .name = "x-trailer", .value = "ok" }};

    var enc = MessageEncoder.init(.request, .{});
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &minimal_request);
    pos += try enc.encodeData(buf[pos..], "abc");
    pos += try enc.encodeTrailers(buf[pos..], &trailers);

    try std.testing.expect(enc.sent_headers);
    try std.testing.expect(enc.sent_trailers);
    try std.testing.expect(pos > 0);
}

test "NORMATIVE encoder accepts HEADERS then DATA then trailers on a response stream [RFC9114 §4.1 ¶2]" {
    var buf: [256]u8 = undefined;
    const trailers = [_]FieldLine{.{ .name = "x-checksum", .value = "0" }};

    var enc = MessageEncoder.init(.response, .{});
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &minimal_response);
    pos += try enc.encodeData(buf[pos..], "ok");
    pos += try enc.encodeTrailers(buf[pos..], &trailers);

    try std.testing.expect(enc.sent_trailers);
}

test "MUST NOT close a request stream before any HEADERS section was observed [RFC9114 §4.1 ¶3]" {
    // §4.1 last paragraph: "A server can send a complete response prior to
    // ... receiving the entire request ... ", but also defines that a
    // request without HEADERS is malformed (§4.6).
    var dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(message.Error.MissingHeaders, dec.finish());
}

// ---------------------------------------------------------------- §4.2 HTTP fields

test "MUST allow lowercase ASCII field names [RFC9114 §4.2 ¶?]" {
    // §4.2: "Characters in field names MUST be converted to lowercase prior
    // to their encoding."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "accept", .value = "*/*" },
    };
    try headers.validateRequest(&fields);
}

test "MUST NOT accept a field name containing an uppercase ASCII letter [RFC9114 §4.2 ¶?]" {
    // The mandate is "convert to lowercase prior to encoding"; receivers
    // MUST treat an uppercase character on the wire as malformed.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "Accept", .value = "*/*" },
    };
    try std.testing.expectError(headers.Error.UppercaseFieldName, headers.validateRequest(&fields));
}

test "MUST NOT accept an empty field name [RFC9114 §4.2 ¶?]" {
    // Field name "MUST NOT be empty" — also implied by §4.2 referring to
    // RFC 9110's HTTP field-name production (1*tchar).
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "", .value = "x" },
    };
    try std.testing.expectError(headers.Error.EmptyFieldName, headers.validateRequest(&fields));
}

test "MUST NOT accept a Connection field on a request [RFC9114 §4.2 ¶?]" {
    // §4.2: "An intermediary transforming an HTTP/1.x message to HTTP/3
    // MUST remove connection-specific header fields ... or their messages
    // will be treated by other HTTP/3 endpoints as malformed".
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "connection", .value = "close" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateRequest(&fields));
}

test "MUST NOT accept a Keep-Alive field on a request [RFC9114 §4.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "keep-alive", .value = "timeout=5" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateRequest(&fields));
}

test "MUST NOT accept a Proxy-Connection field on a request [RFC9114 §4.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "proxy-connection", .value = "keep-alive" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateRequest(&fields));
}

test "MUST NOT accept a Transfer-Encoding field on a request [RFC9114 §4.2 ¶?]" {
    // §4.2: "The only exception ... is the TE header field, which MAY be
    // present in an HTTP/3 request, but only if it ... contains the value
    // 'trailers'." Transfer-Encoding itself remains forbidden.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateRequest(&fields));
}

test "MUST NOT accept an Upgrade field on a request [RFC9114 §4.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "upgrade", .value = "websocket" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateRequest(&fields));
}

test "MUST NOT accept a connection-specific field on a response [RFC9114 §4.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "connection", .value = "close" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateResponse(&fields));
}

// ---------------------------------------------------------------- §4.2.2 pseudo-header rules

test "MUST NOT accept a pseudo-header following a regular header in a request [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: "Pseudo-header fields MUST appear in the header section before
    // regular header fields. Any request or response that contains a pseudo-
    // header field that appears in a header section after a regular header
    // field MUST be treated as malformed."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(headers.Error.PseudoHeaderAfterRegular, headers.validateRequest(&fields));
}

test "MUST NOT accept a pseudo-header following a regular header in a response [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = ":status", .value = "204" }, // any pseudo after a regular: malformed
    };
    try std.testing.expectError(headers.Error.PseudoHeaderAfterRegular, headers.validateResponse(&fields));
}

test "MUST NOT accept :status on a request [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: pseudo-headers used in a way other than their defined role.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept :method on a response [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: pseudo-headers used outside of their defined role are
    // malformed. The validator surfaces that as InvalidPseudoHeader for any
    // non-:status pseudo on a response.
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":method", .value = "GET" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateResponse(&fields));
}

test "MUST NOT accept :scheme on a response [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateResponse(&fields));
}

test "MUST NOT accept :path on a response [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateResponse(&fields));
}

test "MUST NOT accept :authority on a response [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateResponse(&fields));
}

test "MUST NOT accept an unknown pseudo-header on a request [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: "Endpoints MUST treat a request or response that contains
    // undefined or invalid pseudo-header fields as malformed."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":made-up", .value = "x" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept an unknown pseudo-header on a response [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try headers.validateResponse(&fields);

    const bad = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":also-bad", .value = "x" }, // unknown pseudo, but caught after :status as PseudoAfterRegular vs Invalid…
    };
    // The validator walks pseudos before regulars; an unknown pseudo fails
    // the InvalidPseudoHeader gate. Either error suffices for the
    // RFC-required malformed-message handling — assert one or the other.
    const r = headers.validateResponse(&bad);
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, r);
}

test "MUST NOT accept a duplicate :method [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: "Endpoints MUST treat a request or response that contains ...
    // multiple values for a pseudo-header field as malformed."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(headers.Error.DuplicatePseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a duplicate :scheme [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(headers.Error.DuplicatePseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a duplicate :path [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":path", .value = "/other" },
    };
    try std.testing.expectError(headers.Error.DuplicatePseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a duplicate :authority [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "a.example" },
        .{ .name = ":authority", .value = "b.example" },
    };
    try std.testing.expectError(headers.Error.DuplicatePseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a duplicate :status [RFC9114 §4.2.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "204" },
    };
    try std.testing.expectError(headers.Error.DuplicatePseudoHeader, headers.validateResponse(&fields));
}

// ---------------------------------------------------------------- §4.3 / §4.3.1 request pseudo-headers

test "MUST accept a request with :method, :scheme, :path, :authority [RFC9114 §4.3.1 ¶?]" {
    try headers.validateRequest(&minimal_request);
}

test "MUST accept a request without :authority [RFC9114 §4.3.1 ¶?]" {
    // §4.3.1: ":authority MAY be omitted (per RFC 9110)" — only :method,
    // :scheme, :path are universally required.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try headers.validateRequest(&fields);
}

test "MUST NOT accept a request without :method [RFC9114 §4.3.1 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(headers.Error.MissingPseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a request without :scheme [RFC9114 §4.3.1 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(headers.Error.MissingPseudoHeader, headers.validateRequest(&fields));
}

test "MUST NOT accept a request without :path [RFC9114 §4.3.1 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(headers.Error.MissingPseudoHeader, headers.validateRequest(&fields));
}

// ---------------------------------------------------------------- §4.3.2 Extended CONNECT (:protocol)

test "NORMATIVE Extended CONNECT request validates only when enable_connect_protocol is set [RFC9114 §4.3.2 ¶?]" {
    // §4.3.2 / RFC 8441 §4: ":protocol pseudo-header MUST be omitted by
    // clients ... unless they have received the SETTINGS_ENABLE_CONNECT_PROTOCOL
    // setting from the peer." We surface this as an explicit toggle on the
    // validation options.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true });
    try std.testing.expectEqualStrings("websocket", headers.requestProtocol(&fields).?);
    try std.testing.expect(headers.isExtendedConnect(&fields));
}

test "MUST NOT accept :protocol when CONNECT is not negotiated [RFC9114 §4.3.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(headers.Error.ExtendedConnectNotEnabled, headers.validateRequest(&fields));
}

test "MUST NOT accept :protocol when :method is not CONNECT [RFC9114 §4.3.2 ¶?]" {
    // §4.3.2: ":protocol pseudo-header is only valid on CONNECT requests."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(
        headers.Error.InvalidPseudoHeader,
        headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true }),
    );
}

test "MUST NOT accept duplicate :protocol [RFC9114 §4.3.2 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":protocol", .value = "h2" },
    };
    try std.testing.expectError(
        headers.Error.DuplicatePseudoHeader,
        headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true }),
    );
}

test "MUST NOT accept :protocol with an empty value [RFC9114 §4.3.2 ¶?]" {
    // RFC 8441 §4: the ":protocol" value must be non-empty.
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "" },
    };
    try std.testing.expectError(
        headers.Error.InvalidPseudoHeader,
        headers.validateRequestWithOptions(&fields, .{ .enable_connect_protocol = true }),
    );
}

// ---------------------------------------------------------------- §4.4 response pseudo-headers

test "MUST accept a minimal response with :status [RFC9114 §4.4 ¶?]" {
    try headers.validateResponse(&minimal_response);
}

test "MUST NOT accept a response without :status [RFC9114 §4.4 ¶?]" {
    // §4.4: "For responses, a single ':status' pseudo-header field is
    // defined ... All HTTP/3 responses MUST include exactly one valid value
    // for the ':status' pseudo-header field, unless the response is a
    // CONNECT response that omits the response status line."
    const fields = [_]FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    // The validator walks pseudo-headers first; with no pseudo it sees a
    // regular and then fails missing-pseudo at finish.
    try std.testing.expectError(headers.Error.MissingPseudoHeader, headers.validateResponse(&fields));
}

// ---------------------------------------------------------------- §4.5 trailers

test "NORMATIVE trailer field section may follow request DATA [RFC9114 §4.5 ¶?]" {
    // §4.5: "An HTTP message can include a final field section, known as
    // 'trailers', that follows the message content."
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &minimal_request);
    pos += try enc.encodeData(buf[pos..], "body");
    pos += try enc.encodeTrailers(buf[pos..], &[_]FieldLine{.{ .name = "x-trailer", .value = "v" }});
    try std.testing.expect(enc.sent_trailers);
}

test "MUST NOT include a pseudo-header in trailers [RFC9114 §4.5 ¶?]" {
    // §4.5: "Pseudo-header fields MUST NOT appear in trailers."
    const trailers = [_]FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expectError(headers.Error.InvalidPseudoHeader, headers.validateTrailers(&trailers));
}

test "MUST NOT include a connection-specific field in trailers [RFC9114 §4.5 ¶?]" {
    // §4.2's connection-specific prohibition applies to trailers as well.
    const trailers = [_]FieldLine{
        .{ .name = "connection", .value = "close" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateTrailers(&trailers));
}

test "MUST NOT include a Transfer-Encoding field in trailers [RFC9114 §4.5 ¶?]" {
    const trailers = [_]FieldLine{
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    try std.testing.expectError(headers.Error.ConnectionSpecificField, headers.validateTrailers(&trailers));
}

test "MUST NOT include an empty trailer field name [RFC9114 §4.5 ¶?]" {
    const trailers = [_]FieldLine{
        .{ .name = "", .value = "x" },
    };
    try std.testing.expectError(headers.Error.EmptyFieldName, headers.validateTrailers(&trailers));
}

test "MUST NOT include an uppercase trailer field name [RFC9114 §4.5 ¶?]" {
    const trailers = [_]FieldLine{
        .{ .name = "X-Foo", .value = "x" },
    };
    try std.testing.expectError(headers.Error.UppercaseFieldName, headers.validateTrailers(&trailers));
}

test "MUST NOT send DATA after a trailer field section [RFC9114 §4.5 ¶?]" {
    // §4.5: trailers, when present, end the message body. DATA after
    // trailers is malformed.
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    _ = try enc.encodeHeaders(buf[0..], &minimal_request);
    _ = try enc.encodeData(buf[0..], "x");
    _ = try enc.encodeTrailers(buf[0..], &[_]FieldLine{.{ .name = "x-end", .value = "1" }});
    try std.testing.expectError(message.Error.DataAfterTrailers, enc.encodeData(buf[0..], "after"));
}

test "MUST NOT send a second HEADERS section after a trailer section [RFC9114 §4.5 ¶?]" {
    // §4.5 / §4.1: the trailer field section closes the body; another
    // HEADERS would mean two trailer blocks or a fresh request body, both
    // malformed.
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    _ = try enc.encodeHeaders(buf[0..], &minimal_request);
    _ = try enc.encodeTrailers(buf[0..], &[_]FieldLine{.{ .name = "x-end", .value = "1" }});
    try std.testing.expectError(
        message.Error.DuplicateHeaders,
        enc.encodeTrailers(buf[0..], &[_]FieldLine{.{ .name = "x-end2", .value = "1" }}),
    );
}

test "MUST NOT send DATA before any HEADERS section [RFC9114 §4.5 ¶?]" {
    // The HEADERS-then-DATA-then-trailers ordering is normative; data
    // before headers is malformed.
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    try std.testing.expectError(message.Error.DataBeforeHeaders, enc.encodeData(buf[0..], "x"));
}

test "MUST NOT send trailers before any HEADERS section [RFC9114 §4.5 ¶?]" {
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    try std.testing.expectError(
        message.Error.MissingHeaders,
        enc.encodeTrailers(buf[0..], &[_]FieldLine{.{ .name = "x-end", .value = "1" }}),
    );
}

test "MUST NOT send a duplicate request HEADERS section [RFC9114 §4.5 ¶?]" {
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    _ = try enc.encodeHeaders(buf[0..], &minimal_request);
    try std.testing.expectError(message.Error.DuplicateHeaders, enc.encodeHeaders(buf[0..], &minimal_request));
}

// ---------------------------------------------------------------- §4.6 malformed messages — decode side

test "MUST reject a decoded request that is missing :path [RFC9114 §4.6 ¶?]" {
    // §4.6: "A malformed request or response is one that ... contains
    // an invalid sequence of HTTP fields. Receipt of a malformed request
    // ... MUST be treated as a stream error of type H3_MESSAGE_ERROR."
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(headers.Error.MissingPseudoHeader, dec.validateOwnedFieldLines(&fields));
}

test "MUST reject a decoded response that is missing :status [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    var dec = MessageDecoder.init(.response, .{});
    try std.testing.expectError(headers.Error.MissingPseudoHeader, dec.validateOwnedFieldLines(&fields));
}

test "MUST reject a decoded message whose pseudo-header follows a regular field [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "x-extra", .value = "y" },
        .{ .name = ":path", .value = "/" },
    };
    var dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(headers.Error.PseudoHeaderAfterRegular, dec.validateOwnedFieldLines(&fields));
}

test "MUST reject a decoded message containing a connection-specific field [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    var dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(headers.Error.ConnectionSpecificField, dec.validateOwnedFieldLines(&fields));
}

test "MUST reject a decoded message containing an uppercase field name [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "Accept", .value = "*/*" },
    };
    var dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(headers.Error.UppercaseFieldName, dec.validateOwnedFieldLines(&fields));
}

test "MUST reject decoded trailers containing a pseudo-header [RFC9114 §4.6 ¶?]" {
    // After observing a HEADERS, a subsequent HEADERS is treated as
    // trailers and validated as such.
    const allocator = std.testing.allocator;
    var dec = MessageDecoder.init(.request, .{});

    const initial = try allocator.alloc(FieldLine, minimal_request.len);
    for (minimal_request, 0..) |f, i| {
        initial[i] = .{
            .name = try allocator.dupe(u8, f.name),
            .value = try allocator.dupe(u8, f.value),
        };
    }
    const ev = try dec.observeOwnedFieldLines(allocator, initial);
    defer ev.deinit(allocator);

    const trailers = try allocator.alloc(FieldLine, 1);
    trailers[0] = .{
        .name = try allocator.dupe(u8, ":status"),
        .value = try allocator.dupe(u8, "200"),
    };
    try std.testing.expectError(
        headers.Error.InvalidPseudoHeader,
        dec.observeOwnedFieldLines(allocator, trailers),
    );
}

test "MUST reject DATA observed before HEADERS on a request stream [RFC9114 §4.6 ¶?]" {
    const allocator = std.testing.allocator;
    var dec = MessageDecoder.init(.request, .{});
    var events = std.ArrayList(message.Event).empty;
    defer {
        for (events.items) |e| e.deinit(allocator);
        events.deinit(allocator);
    }

    // Emit a DATA frame on the wire (type=0x00, length=1, payload=0xff)
    // before any HEADERS — observeBytes routes it through the decoder.
    var buf: [16]u8 = undefined;
    const n = try message.encodeDataFrame(buf[0..], "x");
    try std.testing.expectError(
        message.Error.DataBeforeHeaders,
        dec.observeBytes(allocator, buf[0..n], &events),
    );
}

test "MUST reject DATA observed after trailers on a request stream [RFC9114 §4.6 ¶?]" {
    const allocator = std.testing.allocator;
    const trailers_in = [_]FieldLine{.{ .name = "x-end", .value = "1" }};

    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    var pos: usize = 0;
    pos += try enc.encodeHeaders(buf[pos..], &minimal_request);
    pos += try enc.encodeTrailers(buf[pos..], &trailers_in);
    pos += try message.encodeDataFrame(buf[pos..], "after");

    var dec = MessageDecoder.init(.request, .{});
    var events = std.ArrayList(message.Event).empty;
    defer {
        for (events.items) |e| e.deinit(allocator);
        events.deinit(allocator);
    }
    try std.testing.expectError(
        message.Error.DataAfterTrailers,
        dec.observeBytes(allocator, buf[0..pos], &events),
    );
}

test "MUST reject a request stream that closes without HEADERS [RFC9114 §4.6 ¶?]" {
    const dec = MessageDecoder.init(.request, .{});
    try std.testing.expectError(message.Error.MissingHeaders, dec.finish());
}

// ---------------------------------------------------------------- §4.6 malformed messages — encode side

test "MUST reject encoding a request HEADERS missing :method [RFC9114 §4.6 ¶?]" {
    // The encoder runs the same pseudo-header gate before serializing. A
    // bad outbound request is refused, not transmitted as malformed.
    const fields = [_]FieldLine{
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    try std.testing.expectError(headers.Error.MissingPseudoHeader, enc.encodeHeaders(buf[0..], &fields));
}

test "MUST reject encoding a request HEADERS with an uppercase field name [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "Accept", .value = "*/*" },
    };
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    try std.testing.expectError(headers.Error.UppercaseFieldName, enc.encodeHeaders(buf[0..], &fields));
}

test "MUST reject encoding a response HEADERS missing :status [RFC9114 §4.6 ¶?]" {
    const fields = [_]FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.response, .{});
    try std.testing.expectError(headers.Error.MissingPseudoHeader, enc.encodeHeaders(buf[0..], &fields));
}

test "MUST reject encoding trailers containing a pseudo-header [RFC9114 §4.6 ¶?]" {
    var buf: [256]u8 = undefined;
    var enc = MessageEncoder.init(.request, .{});
    _ = try enc.encodeHeaders(buf[0..], &minimal_request);
    try std.testing.expectError(
        headers.Error.InvalidPseudoHeader,
        enc.encodeTrailers(buf[0..], &[_]FieldLine{.{ .name = ":status", .value = "200" }}),
    );
}

// ---------------------------------------------------------------- §4.3.1 deferred URI-syntax checks

test "skip_MUST validate :authority host syntax (no userinfo, no fragment) [RFC9114 §4.3.1 ¶?]" {
    // TODO: headers.zig only checks presence/uniqueness of :authority. The
    // RFC mandates the value parse as a URI authority component (no
    // userinfo, no fragment).
    return error.SkipZigTest;
}

test "skip_MUST validate :path is non-empty for http/https requests [RFC9114 §4.3.1 ¶?]" {
    // TODO: headers.zig accepts a zero-length :path. RFC 9114 §4.3.1 says
    // for "http" or "https" requests, :path MUST NOT be empty unless the
    // request is OPTIONS or CONNECT.
    return error.SkipZigTest;
}

test "skip_MUST validate :status is exactly three ASCII digits [RFC9114 §4.4 ¶?]" {
    // TODO: headers.zig only enforces presence/uniqueness of :status; it
    // does not check that the value is three ASCII digits in [100..999].
    return error.SkipZigTest;
}
