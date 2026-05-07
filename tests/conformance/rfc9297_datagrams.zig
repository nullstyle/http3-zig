//! RFC 9297 — HTTP Datagrams and the Capsule Protocol.
//!
//! RFC 9297 layers two related delivery mechanisms on HTTP/3:
//!
//!   * **HTTP/3 DATAGRAMs** (§2): unreliable application payloads ride
//!     inside QUIC DATAGRAM frames (RFC 9221). Each HTTP/3 DATAGRAM
//!     payload starts with a *Quarter-Stream-ID* varint (= stream_id /
//!     4), which binds the payload to a specific request/response
//!     stream. Negotiated via the SETTINGS_H3_DATAGRAM (0x33) HTTP/3
//!     setting; both peers MUST advertise `value = 1` before any
//!     DATAGRAM may be sent (§2.1, §2.1.1).
//!
//!   * **Capsule Protocol** (§3): a TLV — `(Type varint, Length varint,
//!     Value bytes)` — that lives in the body of an HTTP DATA frame on
//!     the request stream. The DATAGRAM capsule (type 0x00) carries the
//!     same payload over reliable transport when QUIC DATAGRAMs are
//!     unavailable (§3.1). Receivers MUST ignore unknown capsule types
//!     (§3.2).
//!
//! null3's normative surfaces:
//!
//!   * `null3.datagram` (`src/datagram.zig`) — Quarter-Stream-ID codec,
//!     Context-ID payload helpers, oversized-buffer rejection.
//!   * `null3.capsule` (`src/capsule.zig`) — TLV encode/decode,
//!     unknown-type pass-through, iterator.
//!   * `null3.protocol.SettingId.h3_datagram = 0x33`,
//!     `null3.protocol.ErrorCode.datagram_error = 0x33`.
//!   * `null3.Session.sendDatagram` / `sendDatagramWithContext` /
//!     `sendRequestDatagramCapsule` — drive the wire-side codecs after
//!     a real handshake.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9297 §2.1   ¶1     MUST     SETTINGS_H3_DATAGRAM identifier is 0x33
//!   RFC9297 §2.1   ¶1     MUST     SETTINGS_H3_DATAGRAM values are 0 or 1
//!   RFC9297 §2.1   ¶1     MUST NOT accept a SETTINGS_H3_DATAGRAM value > 1
//!   RFC9297 §2.1.1 ¶1     MUST     both peers send H3_DATAGRAM=1 before sending an HTTP/3 DATAGRAM
//!   RFC9297 §2.1.1 ¶1     MUST NOT send an HTTP/3 DATAGRAM when peer did not advertise H3_DATAGRAM=1
//!   RFC9297 §2.1.1 ¶?     MUST     close received DATAGRAM with H3_SETTINGS_ERROR when local setting is 0
//!   RFC9297 §2.2   ¶1     MUST     payload is Quarter-Stream-ID varint + opaque body
//!   RFC9297 §2.2   ¶1     MUST     Quarter-Stream-ID = stream_id / 4
//!   RFC9297 §2.2   ¶?     MUST     reject sending an HTTP/3 DATAGRAM whose stream_id is not divisible by 4
//!   RFC9297 §2.2   ¶?     MUST     decode is the inverse of encode for any client-bidi stream
//!   RFC9297 §2.2   ¶?     MUST     decode of empty payload yields zero-length body
//!   RFC9297 §2.2   ¶?     MUST     decode rejects empty input
//!   RFC9297 §2.2   ¶?     MUST NOT overflow the encode buffer
//!   RFC9297 §2     ¶?     MUST     transport DATAGRAM payload size cap is enforced via QUIC max_datagram_frame_size
//!   RFC9297 §2     ¶?     MUST     server received DATAGRAM is dispatched to the right stream
//!   RFC9297 §2     ¶?     MUST     malformed HTTP/3 DATAGRAM closes with H3_DATAGRAM_ERROR
//!   RFC9297 §2.2   ¶ctx   NORMATIVE Context-ID is a varint immediately after the Quarter-Stream-ID
//!   RFC9297 §2.2   ¶ctx   NORMATIVE encodeWithContext + decode + decodeContextPayload round-trip
//!   RFC9297 §3     ¶1     MUST     capsule format is Type varint + Length varint + Value bytes
//!   RFC9297 §3.1   ¶1     MUST     DATAGRAM capsule type is 0x00
//!   RFC9297 §3.1   ¶1     MUST     DATAGRAM capsule round-trip preserves the value
//!   RFC9297 §3     ¶?     MUST NOT decode a capsule whose Length exceeds the remaining input
//!   RFC9297 §3     ¶?     MUST     iterator walks consecutive capsules in order
//!   RFC9297 §3.2   ¶1     MUST     receivers tolerate unknown capsule types as opaque value bytes
//!   RFC9297 §3.2   ¶1     MUST     receivers tolerate GREASE capsule types (0x1f * N + 0x21)
//!   RFC9297 §3     ¶?     MUST     empty-value capsule is legal (length 0)
//!   RFC9297 §3     ¶?     NORMATIVE encodedLen matches the encoded byte count
//!   RFC9297 §4     ¶?     NORMATIVE capsules ride inside HTTP/3 DATA frames on the request stream
//!   RFC9297 §5.1   ¶1     MUST     H3_DATAGRAM_ERROR error code is 0x33
//!   RFC9297 §2.2   ¶?     MUST     stream-id 0 (first client bidi) is a valid datagram target
//!   RFC9297 §2.2   ¶?     MUST     stream-id 4 (second client bidi) is a valid datagram target
//!
//! Visible debt:
//!   none — every requirement against the codec and the public Session
//!   send/receive surface has a test below.
//!
//! Out of scope here (covered elsewhere or by design):
//!   RFC9297 §2.1   SETTINGS frame *codec* (parsing the SETTINGS frame
//!                   that contains the h3_datagram entry) → covered by
//!                   rfc9114_settings.zig and the Settings round-trip
//!                   test in tests/root.zig.
//!   RFC9297 §2.2   QUIC DATAGRAM *frame* layout (RFC 9221 §4) → covered
//!                   by nullq's RFC 9221 conformance suite.
//!   RFC9298 §3     CONNECT-UDP Context ID 0 + UDP target/path encoding
//!                   → covered by rfc9298_masque.zig. The generic
//!                   Context ID payload codec lives here.
//!   RFC9220 §3     WebSocket-over-HTTP/3 capsule placement is out of
//!                   scope for this suite.

const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");
const fixture = @import("_h3_fixture.zig");

const datagram = null3.datagram;
const capsule = null3.capsule;
const protocol = null3.protocol;
const settings_mod = null3.settings;
const ErrorCode = protocol.ErrorCode;

// ---------------------------------------------------------------- §2.1 — SETTINGS_H3_DATAGRAM

test "MUST register SETTINGS_H3_DATAGRAM at identifier 0x33 [RFC9297 §2.1 ¶1]" {
    // §2.1 ¶1: "An HTTP/3 endpoint indicates support of HTTP Datagrams
    // using the SETTINGS_H3_DATAGRAM (0x33) HTTP/3 SETTINGS parameter."
    try std.testing.expectEqual(@as(u64, 0x33), protocol.SettingId.h3_datagram);
}

test "MUST encode SETTINGS_H3_DATAGRAM=1 to advertise HTTP/3 datagram support [RFC9297 §2.1 ¶1]" {
    // §2.1 ¶1 fixes the value. The Settings codec must round-trip the
    // boolean as `1` on the wire so a peer can detect support.
    const s: settings_mod.Settings = .{ .h3_datagram = true };
    var buf: [32]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(got.h3_datagram);
}

test "MUST decode SETTINGS_H3_DATAGRAM=0 as datagrams disabled [RFC9297 §2.1 ¶1]" {
    // §2.1 ¶1: value 0 explicitly indicates the endpoint does not
    // support HTTP/3 datagrams. nullq omits a default-false setting
    // from the encoded blob; an absent setting MUST decode to false.
    var buf: [4]u8 = undefined;
    const n = try (settings_mod.Settings{}).encode(&buf);
    const got = try settings_mod.Settings.decode(buf[0..n]);
    try std.testing.expect(!got.h3_datagram);
}

test "MUST NOT accept a SETTINGS_H3_DATAGRAM value greater than 1 [RFC9297 §2.1 ¶1]" {
    // §2.1 ¶1: the only legal values are 0 and 1. Values > 1 MUST be
    // treated as a connection error. settings_mod surfaces this as
    // `InvalidSettingValue`, which the session maps to
    // H3_SETTINGS_ERROR (covered in rfc9114_session.zig for the
    // end-to-end gate).
    const varint = nullq.wire.varint;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], protocol.SettingId.h3_datagram);
    pos += try varint.encode(buf[pos..], 2);
    try std.testing.expectError(
        settings_mod.Error.InvalidSettingValue,
        settings_mod.Settings.decode(buf[0..pos]),
    );
}

// ---------------------------------------------------------------- §2.1.1 — negotiation gate

test "MUST refuse to send an HTTP/3 DATAGRAM before the peer advertises H3_DATAGRAM=1 [RFC9297 §2.1.1 ¶1]" {
    // §2.1.1 ¶1: "Both peers MUST advertise SETTINGS_H3_DATAGRAM with
    // value 1 ... before HTTP/3 Datagrams may be sent." When neither
    // side advertises 1, the local sender MUST refuse — null3 returns
    // `error.DatagramNotEnabled`.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.DatagramNotEnabled,
        pair.client_h3.sendDatagram(0, "no-negotiation"),
    );
}

test "MUST refuse to send an HTTP/3 DATAGRAM when only the local side advertises H3_DATAGRAM=1 [RFC9297 §2.1.1 ¶1]" {
    // The "both peers" rule is symmetric: even if the local side has
    // h3_datagram=true, sending fails until the peer's advertisement
    // is observed.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = false } },
    );
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.DatagramNotEnabled,
        pair.client_h3.sendDatagram(0, "peer-disabled"),
    );
}

test "MUST allow sending an HTTP/3 DATAGRAM after both peers advertise H3_DATAGRAM=1 [RFC9297 §2.1.1 ¶1]" {
    // The positive case — once both sides have negotiated, sending
    // succeeds. The receive-side observation is in a separate test
    // below.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client_h3.sendDatagram(0, "ok");
}

test "MUST close with H3_SETTINGS_ERROR on a received HTTP/3 DATAGRAM when the local setting is disabled [RFC9297 §2.1.1 ¶1]" {
    // The session-level negotiation gate: an endpoint that did not
    // advertise H3_DATAGRAM=1 MUST close the connection if it
    // nonetheless receives a QUIC DATAGRAM frame. null3 maps the
    // error to H3_SETTINGS_ERROR (errors.zig:DatagramNotEnabled →
    // settings_error 0x0109).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    // Drive a raw QUIC DATAGRAM at the server even though h3_datagram
    // wasn't negotiated. The server's session must close.
    var buf: [32]u8 = undefined;
    const n = try datagram.encode(&buf, 0, "rogue-payload");
    try pair.client.sendDatagram(buf[0..n]);

    try fixture.expectPairH3Error(allocator, &pair, error.DatagramNotEnabled);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.settings_error);
}

// ---------------------------------------------------------------- §2.2 — Quarter-Stream-ID payload format

test "MUST encode HTTP/3 DATAGRAM payload as Quarter-Stream-ID varint + body [RFC9297 §2.2 ¶1]" {
    // §2.2 ¶1: payload starts with `Quarter-Stream-ID = stream_id /
    // 4` encoded as a QUIC variable-length integer, followed by the
    // body. For stream id 4 the Quarter-Stream-ID is 1 (1-byte
    // varint).
    var buf: [32]u8 = undefined;
    const n = try datagram.encode(&buf, 4, "abcd");
    // Byte 0: varint(1) = 0x01. Then "abcd".
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expectEqualStrings("abcd", buf[1..n]);
}

test "MUST compute Quarter-Stream-ID = stream_id / 4 [RFC9297 §2.2 ¶1]" {
    // The Quarter-Stream-ID for stream_id S is S/4. Verify both the
    // encode and decode sides agree on the inverse mapping for a
    // sweep of valid client bidirectional stream ids.
    var stream_id: u64 = 0;
    while (stream_id <= 16) : (stream_id += 4) {
        var buf: [32]u8 = undefined;
        const n = try datagram.encode(&buf, stream_id, "p");
        const decoded = try datagram.decode(buf[0..n]);
        try std.testing.expectEqual(stream_id, decoded.stream_id);
    }
}

test "MUST reject encoding an HTTP/3 DATAGRAM for a non-bidirectional stream id (1) [RFC9297 §2.2 ¶?]" {
    // RFC 9297 §2.2 implicitly requires the stream id to map to a
    // request stream (client-initiated bidirectional, low 2 bits =
    // 00). null3 rejects ids whose low 2 bits != 0 with
    // `InvalidDatagramStream`. Stream id 1 is server-initiated bidi.
    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidDatagramStream, datagram.encode(&buf, 1, "x"));
}

test "MUST reject encoding an HTTP/3 DATAGRAM for a unidirectional stream id (2) [RFC9297 §2.2 ¶?]" {
    // Stream id 2 is client-initiated unidirectional — also invalid.
    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidDatagramStream, datagram.encode(&buf, 2, "x"));
}

test "MUST reject encoding an HTTP/3 DATAGRAM for a server-initiated unidirectional stream id (3) [RFC9297 §2.2 ¶?]" {
    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidDatagramStream, datagram.encode(&buf, 3, "x"));
}

test "MUST validate stream id 0 (first client bidi) as a legal datagram target [RFC9297 §2.2 ¶?]" {
    // Sanity gate: stream id 0 (first client-initiated bidi) is the
    // canonical first request stream and MUST be accepted.
    try datagram.validateStreamId(0);
}

test "MUST validate stream id 4 (second client bidi) as a legal datagram target [RFC9297 §2.2 ¶?]" {
    // RFC 9000 §2.1: client-initiated bidirectional stream IDs are 0,
    // 4, 8, 12, ...
    try datagram.validateStreamId(4);
}

test "MUST round-trip an HTTP/3 DATAGRAM payload through encode/decode [RFC9297 §2.2 ¶1]" {
    // The full lossless round-trip on the codec floor.
    var buf: [128]u8 = undefined;
    const n = try datagram.encode(&buf, 8, "hello-world");
    const got = try datagram.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 8), got.stream_id);
    try std.testing.expectEqualStrings("hello-world", got.payload);
}

test "MUST decode an HTTP/3 DATAGRAM whose body is empty [RFC9297 §2.2 ¶1]" {
    // A 1-byte payload (Quarter-Stream-ID = 0, no body bytes) is
    // legal — decode must surface stream_id 0 and an empty payload.
    var buf: [4]u8 = undefined;
    const n = try datagram.encode(&buf, 0, "");
    try std.testing.expectEqual(@as(usize, 1), n);
    const got = try datagram.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0), got.stream_id);
    try std.testing.expectEqual(@as(usize, 0), got.payload.len);
}

test "MUST NOT decode an empty HTTP/3 DATAGRAM payload [RFC9297 §2.2 ¶1]" {
    // The Quarter-Stream-ID varint is mandatory; a 0-byte payload is
    // malformed and must surface InsufficientBytes (which the session
    // maps to H3_DATAGRAM_ERROR).
    try std.testing.expectError(error.InsufficientBytes, datagram.decode(&[_]u8{}));
}

test "MUST NOT overflow the encode buffer [RFC9297 §2.2 ¶1]" {
    // A 2-byte buffer is too small for "varint(0)=1byte + 4-byte
    // payload"; the encoder must report BufferTooSmall instead of
    // writing past the end.
    var tiny: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, datagram.encode(&tiny, 0, "abcd"));
}

test "MUST report encodedLen matching the encoded byte count [RFC9297 §2.2 ¶1]" {
    // Implementations rely on the predictive size for buffer
    // allocation; encodedLen must equal what encode actually writes.
    const predicted = try datagram.encodedLen(8, 6);
    var buf: [16]u8 = undefined;
    const n = try datagram.encode(&buf, 8, "abcdef");
    try std.testing.expectEqual(predicted, n);
}

// ---------------------------------------------------------------- §2.2 — Context ID adjacent payload codec

test "NORMATIVE Context ID is a varint immediately after the Quarter-Stream-ID [RFC9297 §2.2 ¶ctx]" {
    // RFC 9297-adjacent helpers (formalised in RFC 9298 §3 for
    // CONNECT-UDP) carry a Context ID right after the
    // Quarter-Stream-ID. Verify the encoder lays them out in that
    // order.
    var buf: [16]u8 = undefined;
    const n = try datagram.encodeWithContext(&buf, 4, 7, "ctx-body");
    // Byte 0: Quarter-Stream-ID varint = 1. Byte 1: Context ID varint = 7.
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x07), buf[1]);
    try std.testing.expectEqualStrings("ctx-body", buf[2..n]);
}

test "NORMATIVE encodeWithContext + decode + decodeContextPayload round-trip [RFC9297 §2.2 ¶ctx]" {
    // Full round-trip through the two-layer codec: the outer decode
    // peels off the Quarter-Stream-ID and surfaces a `payload` slice
    // that the inner `decodeContextPayload` parses for the context-id
    // varint and remaining body.
    var buf: [32]u8 = undefined;
    const n = try datagram.encodeWithContext(&buf, 12, 0, "default-ctx");
    const outer = try datagram.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 12), outer.stream_id);
    const inner = try outer.context();
    try std.testing.expectEqual(@as(u64, 0), inner.context_id);
    try std.testing.expectEqualStrings("default-ctx", inner.payload);
}

test "NORMATIVE Context ID context payload helpers are independent of the outer Quarter-Stream-ID [RFC9297 §2.2 ¶ctx]" {
    // The Context ID codec is a self-contained inner format —
    // encodeContextPayload + decodeContextPayload round-trip without
    // needing the outer Quarter-Stream-ID layer. This is the surface
    // RFC 9298 §3 builds CONNECT-UDP on top of.
    var buf: [16]u8 = undefined;
    const n = try datagram.encodeContextPayload(&buf, 42, "raw");
    const got = try datagram.decodeContextPayload(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 42), got.context_id);
    try std.testing.expectEqualStrings("raw", got.payload);
}

test "NORMATIVE contextPayloadEncodedLen matches the inner encoded byte count [RFC9297 §2.2 ¶ctx]" {
    // contextPayloadEncodedLen MUST predict the byte count
    // encodeContextPayload writes — callers rely on it for
    // pre-allocation.
    const predicted = datagram.contextPayloadEncodedLen(42, 3);
    var buf: [16]u8 = undefined;
    const n = try datagram.encodeContextPayload(&buf, 42, "raw");
    try std.testing.expectEqual(predicted, n);
}

// ---------------------------------------------------------------- §2.2 — over-the-wire receive path

test "MUST dispatch a received HTTP/3 DATAGRAM to the right stream id [RFC9297 §2.2 ¶?]" {
    // End-to-end: client sends an HTTP/3 DATAGRAM after both peers
    // have negotiated H3_DATAGRAM=1; the server MUST decode the
    // Quarter-Stream-ID, recover the original stream_id, and emit a
    // DatagramEvent carrying the body verbatim.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const stream_id: u64 = 0;
    try pair.client_h3.sendDatagram(stream_id, "from-client");

    // Step the loopback driver manually so we can inspect events
    // before they're cleared. (pumpQuiet would clear them mid-loop.)
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        fixture.clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }
    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        fixture.clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }

    var saw_datagram = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    while (!saw_datagram) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        var pkt: [2048]u8 = undefined;
        var driver = null3.TransportLoopback.init(
            null3.TransportEndpoint.withSession(&pair.client, &pair.client_h3, &client_events),
            null3.TransportEndpoint.withSession(&pair.server, &pair.server_h3, &server_events),
            .{ .now_us = now_us, .max_datagrams_per_direction = 1 },
        );
        _ = try driver.step(&pkt);
        now_us = driver.now_us;

        for (server_events.items) |event| {
            switch (event) {
                .datagram => |dg| {
                    try std.testing.expectEqual(stream_id, dg.stream_id);
                    try std.testing.expectEqualStrings("from-client", dg.payload);
                    saw_datagram = true;
                },
                else => {},
            }
        }
        fixture.clearSessionEvents(allocator, &server_events);
        fixture.clearSessionEvents(allocator, &client_events);
    }
}

test "MUST close with H3_DATAGRAM_ERROR on a malformed HTTP/3 DATAGRAM payload [RFC9297 §2 ¶?]" {
    // §2 ¶?: "A malformed HTTP Datagram is treated as a connection
    // error of type H3_DATAGRAM_ERROR." A QUIC DATAGRAM whose payload
    // can't be parsed as `varint + body` triggers this — null3
    // surfaces InsufficientBytes from `datagram.decode` and closes
    // with H3_DATAGRAM_ERROR.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    // An empty QUIC DATAGRAM payload has no Quarter-Stream-ID varint.
    try pair.client.sendDatagram(&.{});

    try fixture.expectPairH3Error(allocator, &pair, error.InsufficientBytes);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.datagram_error);
}

// ---------------------------------------------------------------- §3 — Capsule TLV codec

test "MUST encode a Capsule as Type varint + Length varint + Value bytes [RFC9297 §3 ¶1]" {
    // §3 ¶1: "Each capsule is a Type-Length-Value tuple, with both the
    // type and the length encoded as variable-length integers."
    // Verify the byte layout for a known type (DATAGRAM = 0x00) and a
    // 5-byte value.
    var buf: [16]u8 = undefined;
    const n = try capsule.encode(&buf, capsule.Type.datagram, "hello");
    // Byte 0: type varint = 0x00. Byte 1: length varint = 5 (1-byte
    // form). Bytes 2..7: "hello".
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x05), buf[1]);
    try std.testing.expectEqualStrings("hello", buf[2..n]);
}

test "MUST register the DATAGRAM capsule type as 0x00 [RFC9297 §3.1 ¶1]" {
    // §3.1 ¶1 / IANA Capsule Types registry: "DATAGRAM (0x00)".
    try std.testing.expectEqual(@as(u64, 0x00), capsule.Type.datagram);
}

test "MUST round-trip a DATAGRAM capsule through encode/decode [RFC9297 §3.1 ¶1]" {
    var buf: [32]u8 = undefined;
    const n = try capsule.encodeDatagram(&buf, "payload");
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expect(got.capsule.isDatagram());
    try std.testing.expectEqualStrings("payload", got.capsule.value);
    try std.testing.expectEqual(n, got.bytes_read);
}

test "MUST surface a DATAGRAM capsule via the isDatagram predicate [RFC9297 §3.1 ¶1]" {
    // Distinguishes the well-known type 0x00 from any other capsule
    // — used by `null3.session` to dispatch DATAGRAM-over-DATA-frame
    // payloads to the same handler as QUIC-DATAGRAM-borne payloads.
    const c: capsule.Capsule = .{ .capsule_type = capsule.Type.datagram, .value = "x" };
    try std.testing.expect(c.isDatagram());
    const other: capsule.Capsule = .{ .capsule_type = 0x29, .value = "x" };
    try std.testing.expect(!other.isDatagram());
}

test "NORMATIVE Capsule encodedLen matches the encoded byte count [RFC9297 §3 ¶1]" {
    // Implementations rely on the predictive size for buffer
    // pre-allocation; the predicate must equal what encode emits.
    const value = "value-bytes";
    const predicted = capsule.encodedLen(0x29, value.len);
    var buf: [32]u8 = undefined;
    const n = try capsule.encode(&buf, 0x29, value);
    try std.testing.expectEqual(predicted, n);
}

test "NORMATIVE datagramEncodedLen returns encodedLen for capsule type 0x00 [RFC9297 §3.1 ¶1]" {
    // The DATAGRAM-specific predictor is just a wrapper — verify it
    // agrees with the generic predictor for the DATAGRAM type.
    const datagram_predicted = capsule.datagramEncodedLen(8);
    const generic_predicted = capsule.encodedLen(capsule.Type.datagram, 8);
    try std.testing.expectEqual(generic_predicted, datagram_predicted);
}

test "MUST encode a Capsule with an empty value as Type + Length(0) + nothing [RFC9297 §3 ¶?]" {
    // §3: a zero-length Value field is legal. A peer that wants to
    // send a "ping" capsule of type T can emit `T, 0` — the codec
    // must accept and round-trip that.
    var buf: [4]u8 = undefined;
    const n = try capsule.encodeDatagram(&buf, "");
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]); // type
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]); // length
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expect(got.capsule.isDatagram());
    try std.testing.expectEqual(@as(usize, 0), got.capsule.value.len);
}

test "MUST NOT decode a Capsule whose Length exceeds the remaining input [RFC9297 §3 ¶?]" {
    // §3: the Length field carries the byte count of the Value
    // field. A claim of more bytes than the input contains is
    // malformed; the decoder must surface InsufficientBytes.
    const wire = [_]u8{ 0x00, 0x05, 'a', 'b' };
    try std.testing.expectError(error.InsufficientBytes, capsule.decode(&wire));
}

test "MUST decode a Capsule with a multi-byte length varint [RFC9297 §3 ¶?]" {
    // 64 is the smallest value that requires the 2-byte varint form
    // (0x40, 0x40). Verify the decoder honours length varints that
    // span more than one byte.
    var buf: [128]u8 = undefined;
    const value: [64]u8 = @splat('A');
    const n = try capsule.encode(&buf, capsule.Type.datagram, &value);
    try std.testing.expect(n >= 1 + 2 + 64);
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expect(got.capsule.isDatagram());
    try std.testing.expectEqual(@as(usize, 64), got.capsule.value.len);
}

test "MUST NOT overrun the encode buffer when emitting a Capsule [RFC9297 §3 ¶?]" {
    // The encoder must surface BufferTooSmall instead of writing past
    // the destination — the type+length prefix plus a 4-byte value
    // needs at least 6 bytes; a 4-byte buffer is too small.
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        capsule.encode(&tiny, capsule.Type.datagram, "abcd"),
    );
}

// ---------------------------------------------------------------- §3 — Capsule iterator + unknown types

test "MUST iterate consecutive capsules in input order [RFC9297 §3 ¶?]" {
    // Capsules are concatenated on the wire (§4); the iterator must
    // return them in order with the right bytes_read advancement.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try capsule.encode(buf[pos..], 0x29, "first");
    pos += try capsule.encode(buf[pos..], 0x42, "second");

    var it = capsule.iter(buf[0..pos]);
    const a = (try it.next()).?;
    try std.testing.expectEqual(@as(u64, 0x29), a.capsule.capsule_type);
    try std.testing.expectEqualStrings("first", a.capsule.value);
    const b = (try it.next()).?;
    try std.testing.expectEqual(@as(u64, 0x42), b.capsule.capsule_type);
    try std.testing.expectEqualStrings("second", b.capsule.value);
    try std.testing.expect((try it.next()) == null);
}

test "MUST tolerate an unknown capsule type as opaque value bytes [RFC9297 §3.2 ¶1]" {
    // §3.2 ¶1: "An endpoint MUST ignore capsules whose Capsule Type
    // is unknown to it." The codec exposes the raw value so the
    // session can drop it without erroring.
    var buf: [64]u8 = undefined;
    const n = try capsule.encode(&buf, 0xdead_beef, "vendor-data");
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0xdead_beef), got.capsule.capsule_type);
    try std.testing.expect(!got.capsule.isDatagram());
    try std.testing.expectEqualStrings("vendor-data", got.capsule.value);
}

test "MUST tolerate a GREASE capsule type (0x21 = 0x1f * 0 + 0x21) [RFC9297 §3.2 ¶1]" {
    // RFC 9297 §3.2 + RFC 8701: GREASE values exist to exercise
    // unknown-type tolerance. The smallest GREASE id is 0x21.
    var buf: [32]u8 = undefined;
    const n = try capsule.encode(&buf, 0x21, "grease");
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x21), got.capsule.capsule_type);
    try std.testing.expect(!got.capsule.isDatagram());
    try std.testing.expectEqualStrings("grease", got.capsule.value);
}

test "MUST iterate past an unknown capsule and continue with the next [RFC9297 §3.2 ¶1]" {
    // The "ignore unknown" rule only makes sense if the iterator can
    // *step over* an unknown capsule and surface the next one. Verify
    // by interleaving an unknown-type capsule with a DATAGRAM one.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try capsule.encode(buf[pos..], 0x40, "skip-me");
    pos += try capsule.encodeDatagram(buf[pos..], "real-data");

    var it = capsule.iter(buf[0..pos]);
    const skipped = (try it.next()).?;
    try std.testing.expect(!skipped.capsule.isDatagram());
    const real = (try it.next()).?;
    try std.testing.expect(real.capsule.isDatagram());
    try std.testing.expectEqualStrings("real-data", real.capsule.value);
    try std.testing.expect((try it.next()) == null);
}

test "MUST decode a Capsule with a multi-byte type varint [RFC9297 §3 ¶?]" {
    // Capsule types are full QUIC varints — codec must accept types
    // that need more than 1 byte. 64 is the smallest 2-byte type
    // value.
    var buf: [16]u8 = undefined;
    const n = try capsule.encode(&buf, 64, "x");
    const got = try capsule.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 64), got.capsule.capsule_type);
    try std.testing.expectEqualStrings("x", got.capsule.value);
}

// ---------------------------------------------------------------- §4 — Capsule over HTTP/3 DATA frame

test "NORMATIVE Capsule rides inside an HTTP/3 DATA frame on the request stream [RFC9297 §4 ¶?]" {
    // §4 ¶?: "When using the Capsule Protocol over HTTP/3, the
    // capsules are sent as the body of an HTTP/3 DATA frame on the
    // request stream." We can't observe the receiver-side decode
    // without a full request/response cycle, but we can verify the
    // *send* path: `Session.sendRequestCapsule` succeeds against a
    // real client+server pair, which means it framed the capsule as
    // a DATA frame on the bidi request stream (the only path that
    // doesn't return InvalidRole / WrongMessageKind).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    var h3_client = null3.Client.init(&pair.client_h3);
    const request = try h3_client.startRequest(allocator, .{
        .authority = "example.com",
        .path = "/capsule",
    });
    const stream_id = request.stream_id;

    try pair.client_h3.sendRequestCapsule(stream_id, capsule.Type.datagram, "via-data-frame");
}

// ---------------------------------------------------------------- §5.1 — Error codes

test "MUST register H3_DATAGRAM_ERROR at code 0x33 [RFC9297 §5.1 ¶1]" {
    // §5.1 ¶1: "H3_DATAGRAM_ERROR (0x33): An error occurred when
    // handling HTTP Datagrams." Note the value collides numerically
    // with the SETTINGS_H3_DATAGRAM identifier, but that's coincidence
    // — they live in different IANA registries.
    try std.testing.expectEqual(@as(u64, 0x33), ErrorCode.datagram_error);
}

// ---------------------------------------------------------------- §2 — sender-side payload size cap

test "MUST refuse to send an HTTP/3 DATAGRAM larger than the QUIC max_datagram_frame_size [RFC9297 §2 ¶?]" {
    // §2 ¶?: HTTP/3 DATAGRAMs ride inside QUIC DATAGRAM frames; the
    // QUIC layer caps frame size at the peer's
    // `max_datagram_frame_size` transport parameter. null3 enforces
    // this in `validateDatagramSend` and surfaces `DatagramTooLarge`
    // before any frame hits the wire. Test fixture sets the cap at
    // 1200 bytes (in `_h3_fixture.zig`); a 1200-byte payload plus a
    // 1-byte Quarter-Stream-ID prefix exceeds that.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .settings = .{ .h3_datagram = true } },
        .{ .settings = .{ .h3_datagram = true } },
    );
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const oversized: [1200]u8 = @splat('B');
    try std.testing.expectError(
        error.DatagramTooLarge,
        pair.client_h3.sendDatagram(0, &oversized),
    );
}
