//! RFC 6455 — The WebSocket Protocol, framing layer.
//!
//! null3 implements the RFC 6455 codec in two layers:
//!   - `null3.websocket.frame` (`src/websocket_frame.zig`) — single-frame
//!     encode/decode and the incremental `Decoder` that enforces the
//!     fragmentation invariants on a stream of bytes.
//!   - `null3.websocket.message` (`src/websocket_message.zig`) — message
//!     reassembly, UTF-8 validation on text + close-reason, and aggregate
//!     size limits.
//!
//! RFC 9220 §4.5 ¶? notes that masking is "not necessary" over HTTP/3
//! because the QUIC transport already provides reliable framing. null3's
//! codec still implements the RFC 6455 wire shape (so an HTTP/3 endpoint
//! can interop with an RFC 6455 over TCP peer through a translating
//! intermediary, and so the codec can be used for testing and tooling).
//! Both directions are exercised here.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC6455 §5.1 ¶?  MUST       client masks every frame sent to the server (encode)
//!   RFC6455 §5.1 ¶?  MUST       server-to-client frames are NOT masked (encode)
//!   RFC6455 §5.1 ¶?  MUST NOT   accept an unmasked client-to-server frame (decode policy=required)
//!   RFC6455 §5.1 ¶?  MUST NOT   accept a masked server-to-client frame (decode policy=forbidden)
//!   RFC6455 §5.2 ¶?  MUST       FIN=1 marks final frame of a message
//!   RFC6455 §5.2 ¶?  MUST NOT   accept a frame with any of RSV1/RSV2/RSV3 set
//!   RFC6455 §5.2 ¶?  MUST       payload length <= 125 fits in 7-bit length field
//!   RFC6455 §5.2 ¶?  MUST       payload length 126..65535 uses 7+16 extended length
//!   RFC6455 §5.2 ¶?  MUST       payload length > 65535 uses 7+64 extended length
//!   RFC6455 §5.2 ¶?  MUST NOT   accept a 7+16 length whose value is < 126 (non-minimal)
//!   RFC6455 §5.2 ¶?  MUST NOT   accept a 7+64 length whose value <= 65535 (non-minimal)
//!   RFC6455 §5.2 ¶?  MUST NOT   accept a 7+64 length with the high bit set
//!   RFC6455 §5.2 ¶?  MUST NOT   accept an unknown opcode
//!   RFC6455 §5.3 ¶?  MUST       masking key is exactly 4 octets
//!   RFC6455 §5.3 ¶?  MUST       masked-bit transformation is XOR over the payload
//!   RFC6455 §5.4 ¶?  MUST       first frame of a fragmented message has opcode != 0
//!   RFC6455 §5.4 ¶?  MUST       continuation frames use opcode 0
//!   RFC6455 §5.4 ¶?  MUST NOT   start a new data message while another is fragmented (interleaving)
//!   RFC6455 §5.4 ¶?  MUST NOT   accept a continuation frame with no fragmented message in progress
//!   RFC6455 §5.5 ¶?  MUST NOT   send a control frame larger than 125 bytes payload
//!   RFC6455 §5.5 ¶?  MUST NOT   fragment a control frame
//!   RFC6455 §5.5.1 ¶?  MUST     close payload of length 1 is invalid
//!   RFC6455 §5.5.1 ¶?  MUST     close payload of length 0 is valid
//!   RFC6455 §5.5.1 ¶?  MUST NOT use status codes 1004 / 1005 / 1006 on the wire
//!   RFC6455 §5.5.1 ¶?  MAY      close payload may carry a 2-byte status code with optional reason
//!   RFC6455 §5.5.2 ¶?  NORMATIVE Ping carries optional <=125-byte payload
//!   RFC6455 §5.5.3 ¶?  NORMATIVE Pong carries optional <=125-byte payload
//!   RFC6455 §5.6   ¶?  MUST     text frames carry valid UTF-8 (data-message reassembly)
//!   RFC7.4         ¶?  MUST     close codes 1000-1011 are reserved by IANA
//!   RFC7.4         ¶?  MUST NOT use code 1015 on the wire (reserved for TLS handshake failure)
//!   RFC7.4         ¶?  MAY      use codes 3000-3999 (registered apps) or 4000-4999 (private)
//!   RFC8.1         ¶?  MUST     close with 1007 on invalid UTF-8 (handled at message decoder)
//!
//! Visible debt:
//!   RFC6455 §5.5.2 ¶?  MUST     a Pong MAY be sent unsolicited (not modelled — codec is symmetric)
//!
//! Out of scope here (covered elsewhere):
//!   RFC9220 §3, §4   bootstrap handshake / SETTINGS_ENABLE_CONNECT_PROTOCOL → rfc9220_websocket_h3.zig
//!   RFC9220 §4.5 ¶?  "client-side masking is not necessary in HTTP/3"        — exercised here, both
//!                                                                             masked and unmasked paths.
//!   RFC6455 §11      Extension/subprotocol registries                        → IANA, not a codec test.

const std = @import("std");
const null3 = @import("null3");

const ws = null3.websocket;
const frame = ws.frame;
const message = ws.message;

const allocator = std.testing.allocator;

// ---------------------------------------------------------------- §5.1 client/server masking direction

test "MUST mask every client-to-server frame [RFC6455 §5.1 ¶?]" {
    // §5.1: "All frames sent from client to server have this bit set to 1."
    // Encode-side: with `mask=true`, the second header byte's high bit is 1
    // (the MASK bit) and the masking key follows.
    var buf: [16]u8 = undefined;
    const n = try frame.encodeText(&buf, "hi", .{
        .mask = true,
        .masking_key = .{ 0x01, 0x02, 0x03, 0x04 },
    });
    try std.testing.expect(n >= 6);
    try std.testing.expect((buf[1] & 0x80) != 0);
    // Bytes 2..6 are the masking key.
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, buf[2..6]);
}

test "MUST NOT mask any server-to-client frame [RFC6455 §5.1 ¶?]" {
    // §5.1: "A server MUST NOT mask any frames that it sends to the client."
    // Encode-side: `mask=false` clears the MASK bit and emits no key.
    var buf: [16]u8 = undefined;
    const n = try frame.encodeBinary(&buf, "ok", .{ .mask = false });
    try std.testing.expectEqual(@as(usize, 4), n); // 2-byte header + 2-byte payload
    try std.testing.expectEqual(@as(u8, 0), buf[1] & 0x80);
}

test "MUST NOT accept an unmasked client-to-server frame on the server's decoder [RFC6455 §5.1 ¶?]" {
    // §5.1: "The server MUST close the connection upon receiving a frame
    // that is not masked." null3 uses `mask_policy = .required` for the
    // server's incoming-frame decoder; the codec returns MaskRequired.
    const unmasked = [_]u8{ 0x81, 0x02, 'h', 'i' }; // text, len=2, no MASK bit
    try std.testing.expectError(
        frame.Error.MaskRequired,
        frame.decode(allocator, &unmasked, .{ .mask_policy = .required }),
    );
}

test "MUST NOT accept a masked server-to-client frame on the client's decoder [RFC6455 §5.1 ¶?]" {
    // The complement of the previous test — clients reject masked frames
    // from servers. null3 uses `mask_policy = .forbidden`.
    const masked = [_]u8{ 0x81, 0x82, 0, 0, 0, 0, 'h', 'i' };
    try std.testing.expectError(
        frame.Error.MaskForbidden,
        frame.decode(allocator, &masked, .{ .mask_policy = .forbidden }),
    );
}

test "MAY skip masking on a WebSocket-over-HTTP/3 client frame [RFC9220 §4.5 ¶?]" {
    // RFC 9220 §4.5: over HTTP/3, the QUIC stream provides reliable
    // framing, so client-to-server masking is "not necessary". null3's
    // codec supports unmasked frames in either direction when the
    // policy is `.any` (the default).
    var buf: [16]u8 = undefined;
    const n = try frame.encodeText(&buf, "hi", .{ .mask = false });
    try std.testing.expectEqual(@as(u8, 0), buf[1] & 0x80);

    const decoded = try frame.decode(allocator, buf[0..n], .{ .mask_policy = .any });
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("hi", decoded.frame.payload);
}

// ---------------------------------------------------------------- §5.2 base framing protocol

test "MUST set the FIN bit (high bit of byte 0) on a non-fragmented frame [RFC6455 §5.2 ¶?]" {
    // §5.2 figure: "FIN: 1 bit ... Indicates that this is the final
    // fragment in a message. The first fragment MAY also be the final
    // fragment."
    var buf: [8]u8 = undefined;
    const n = try frame.encode(&buf, .{ .fin = true, .opcode = .text, .payload = "x" }, .{});
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expect((buf[0] & 0x80) != 0);
}

test "MUST NOT set the FIN bit on a non-final fragment [RFC6455 §5.2 ¶?]" {
    var buf: [8]u8 = undefined;
    _ = try frame.encode(&buf, .{ .fin = false, .opcode = .text, .payload = "x" }, .{});
    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x80);
}

test "MUST encode the opcode in the low 4 bits of byte 0 [RFC6455 §5.2 ¶?]" {
    // §5.2: "Opcode: 4 bits ... Defines the interpretation of the
    // 'Payload data'."
    const cases = [_]struct { op: frame.Opcode, val: u4 }{
        .{ .op = .continuation, .val = 0x0 },
        .{ .op = .text, .val = 0x1 },
        .{ .op = .binary, .val = 0x2 },
        .{ .op = .close, .val = 0x8 },
        .{ .op = .ping, .val = 0x9 },
        .{ .op = .pong, .val = 0xa },
    };
    for (cases) |c| {
        var buf: [8]u8 = undefined;
        // Empty payload is OK for control opcodes too.
        const n = try frame.encode(&buf, .{ .opcode = c.op, .payload = &.{} }, .{});
        try std.testing.expect(n >= 2);
        try std.testing.expectEqual(@as(u8, c.val), buf[0] & 0x0f);
    }
}

test "MUST NOT accept a frame with RSV1 set [RFC6455 §5.2 ¶?]" {
    // §5.2: "RSV1, RSV2, RSV3: 1 bit each ... MUST be 0 unless an
    // extension is negotiated that defines meanings for non-zero values."
    // null3 has not negotiated any extension; receivers MUST reject
    // any non-zero RSV bit.
    const rsv1 = [_]u8{ 0xc1, 0x00 }; // FIN + RSV1 + text
    try std.testing.expectError(frame.Error.InvalidRsv, frame.decode(allocator, &rsv1, .{}));
}

test "MUST NOT accept a frame with RSV2 set [RFC6455 §5.2 ¶?]" {
    const rsv2 = [_]u8{ 0xa1, 0x00 }; // FIN + RSV2 + text
    try std.testing.expectError(frame.Error.InvalidRsv, frame.decode(allocator, &rsv2, .{}));
}

test "MUST NOT accept a frame with RSV3 set [RFC6455 §5.2 ¶?]" {
    const rsv3 = [_]u8{ 0x91, 0x00 }; // FIN + RSV3 + text
    try std.testing.expectError(frame.Error.InvalidRsv, frame.decode(allocator, &rsv3, .{}));
}

test "MUST encode payload length 0..125 in the 7-bit length field [RFC6455 §5.2 ¶?]" {
    // §5.2: "Payload length: 7 bits, 7+16 bits, or 7+64 bits ... If 0-125,
    // that is the payload length."
    var buf: [200]u8 = undefined;
    const n = try frame.encode(&buf, .{ .opcode = .binary, .payload = &.{ 1, 2, 3 } }, .{});
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqual(@as(u8, 3), buf[1] & 0x7f);

    // Boundary: payload of 125 bytes still fits in 7 bits.
    var payload125: [125]u8 = undefined;
    @memset(&payload125, 'a');
    const n125 = try frame.encode(&buf, .{ .opcode = .binary, .payload = &payload125 }, .{});
    try std.testing.expectEqual(@as(usize, 125 + 2), n125);
    try std.testing.expectEqual(@as(u8, 125), buf[1] & 0x7f);
}

test "MUST encode payload length 126..65535 with the 7+16 extended length [RFC6455 §5.2 ¶?]" {
    // §5.2: "If 126, the following 2 bytes interpreted as a 16-bit
    // unsigned integer are the payload length."
    var payload: [126]u8 = undefined;
    @memset(&payload, 'a');
    var buf: [256]u8 = undefined;
    const n = try frame.encode(&buf, .{ .opcode = .binary, .payload = &payload }, .{});
    try std.testing.expectEqual(@as(u8, 126), buf[1] & 0x7f);
    try std.testing.expectEqual(@as(u16, 126), std.mem.readInt(u16, buf[2..4], .big));
    try std.testing.expectEqual(@as(usize, 4 + 126), n);
}

test "MUST encode payload length > 65535 with the 7+64 extended length [RFC6455 §5.2 ¶?]" {
    // §5.2: "If 127, the following 8 bytes interpreted as a 64-bit
    // unsigned integer (the most significant bit MUST be 0) are the
    // payload length."
    const len: usize = 65536;
    const payload = try allocator.alloc(u8, len);
    defer allocator.free(payload);
    @memset(payload, 'a');

    const buf = try allocator.alloc(u8, len + 32);
    defer allocator.free(buf);
    const n = try frame.encode(buf, .{ .opcode = .binary, .payload = payload }, .{});
    try std.testing.expectEqual(@as(u8, 127), buf[1] & 0x7f);
    try std.testing.expectEqual(@as(u64, len), std.mem.readInt(u64, buf[2..10], .big));
    try std.testing.expectEqual(len + 10, n);
}

test "MUST NOT accept a 7+16 extended length whose value is < 126 [RFC6455 §5.2 ¶?]" {
    // §5.2: "the minimal number of bytes MUST be used to encode the
    // length". A 7+16 form that says 0..125 is non-minimal and MUST
    // be rejected.
    const non_minimal = [_]u8{ 0x82, 126, 0x00, 0x05, 'a', 'b', 'c', 'd', 'e' };
    try std.testing.expectError(
        frame.Error.NonMinimalLength,
        frame.decode(allocator, &non_minimal, .{}),
    );
}

test "MUST NOT accept a 7+64 extended length whose value is <= 65535 [RFC6455 §5.2 ¶?]" {
    // Same minimality rule for the 7+64 form.
    var non_minimal: [10]u8 = undefined;
    non_minimal[0] = 0x82;
    non_minimal[1] = 127;
    std.mem.writeInt(u64, non_minimal[2..10], 65535, .big);
    try std.testing.expectError(
        frame.Error.NonMinimalLength,
        frame.decode(allocator, &non_minimal, .{}),
    );
}

test "MUST NOT accept a 7+64 extended length whose high bit is set [RFC6455 §5.2 ¶?]" {
    // §5.2: "the most significant bit MUST be 0".
    var bad_length: [10]u8 = undefined;
    bad_length[0] = 0x82;
    bad_length[1] = 127;
    std.mem.writeInt(u64, bad_length[2..10], (@as(u64, 1) << 63) | 0x10000, .big);
    try std.testing.expectError(
        frame.Error.PayloadTooLarge,
        frame.decode(allocator, &bad_length, .{}),
    );
}

test "MUST NOT accept an unknown opcode value [RFC6455 §5.2 ¶?]" {
    // §5.2: "Reserved for further non-control frames" (3-7) and
    // "Reserved for further control frames" (0xb-0xf) — unsupported.
    // Receivers MUST fail the connection on an unknown opcode.
    const unknown_data = [_]u8{ 0x83, 0x00 }; // opcode 0x3
    try std.testing.expectError(frame.Error.InvalidOpcode, frame.decode(allocator, &unknown_data, .{}));

    const unknown_control = [_]u8{ 0x8b, 0x00 }; // opcode 0xb
    try std.testing.expectError(frame.Error.InvalidOpcode, frame.decode(allocator, &unknown_control, .{}));

    const unknown_high = [_]u8{ 0x8f, 0x00 }; // opcode 0xf
    try std.testing.expectError(frame.Error.InvalidOpcode, frame.decode(allocator, &unknown_high, .{}));
}

test "NORMATIVE decoder reports InsufficientBytes on a truncated 7+16 length [RFC6455 §5.2 ¶?]" {
    // §5.2 doesn't use a BCP 14 keyword for "MUST wait for the rest of
    // the frame", but the wire format is a contiguous header — a stream
    // decoder MUST not act on a truncated header. null3's incremental
    // decoder reports `InsufficientBytes`, distinct from a protocol
    // error, so the caller can resume.
    // 0x82 = FIN + binary; len marker 126 but no 16-bit length follows.
    const truncated = [_]u8{ 0x82, 126 };
    try std.testing.expectError(
        frame.Error.InsufficientBytes,
        frame.decode(allocator, &truncated, .{}),
    );
}

test "NORMATIVE decoder reports InsufficientBytes on a truncated 7+64 length [RFC6455 §5.2 ¶?]" {
    const truncated = [_]u8{ 0x82, 127, 0, 0, 0, 0 };
    try std.testing.expectError(
        frame.Error.InsufficientBytes,
        frame.decode(allocator, &truncated, .{}),
    );
}

test "NORMATIVE decoder reports InsufficientBytes when masking key is truncated [RFC6455 §5.3 ¶?]" {
    // §5.3 says the masking key follows the (extended) length and is
    // exactly 4 bytes — receivers MUST wait for all 4 bytes before
    // unmasking the payload.
    const truncated = [_]u8{ 0x81, 0x80, 0x01, 0x02 }; // 2 of 4 mask bytes
    try std.testing.expectError(
        frame.Error.InsufficientBytes,
        frame.decode(allocator, &truncated, .{}),
    );
}

test "NORMATIVE decoder reports InsufficientBytes when payload is truncated [RFC6455 §5.2 ¶?]" {
    const truncated = [_]u8{ 0x82, 0x05, 'a', 'b' }; // claims len=5, only 2 bytes
    try std.testing.expectError(
        frame.Error.InsufficientBytes,
        frame.decode(allocator, &truncated, .{}),
    );
}

// ---------------------------------------------------------------- §5.3 client-to-server masking

test "MUST use a 4-octet masking key [RFC6455 §5.3 ¶?]" {
    // §5.3: "The masking key is a 32-bit value chosen at random by the
    // client." The wire format reserves exactly 4 bytes; null3's
    // EncodeOptions.masking_key is `[4]u8`.
    const opts: frame.EncodeOptions = .{ .mask = true, .masking_key = .{ 0xa1, 0xa2, 0xa3, 0xa4 } };
    try std.testing.expectEqual(@as(usize, 4), opts.masking_key.len);

    var buf: [32]u8 = undefined;
    const n = try frame.encode(&buf, .{ .opcode = .text, .payload = "abcd" }, opts);
    // mask bytes occupy [2..6], payload at [6..10].
    try std.testing.expect(n >= 10);
    try std.testing.expectEqualSlices(u8, &.{ 0xa1, 0xa2, 0xa3, 0xa4 }, buf[2..6]);
}

test "MUST XOR each payload octet with masking_key[i % 4] [RFC6455 §5.3 ¶?]" {
    // §5.3 algorithm: "j = i MOD 4 ; transformed-octet-i = original-octet-i
    // XOR masking-key-octet-j". null3 applies the mask in-place on the
    // wire bytes; we verify by encoding then comparing the wire bytes
    // against the expected XOR pattern.
    const key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    var buf: [16]u8 = undefined;
    const n = try frame.encodeText(&buf, "Hi", .{ .mask = true, .masking_key = key });
    try std.testing.expect(n == 8);
    // Frame layout: [0x81, 0x82, key[0..4], 'H'^key[0], 'i'^key[1]]
    try std.testing.expectEqual(@as(u8, 'H' ^ key[0]), buf[6]);
    try std.testing.expectEqual(@as(u8, 'i' ^ key[1]), buf[7]);

    // Round-trip via decode unmasks in place.
    const decoded = try frame.decode(allocator, buf[0..n], .{ .mask_policy = .required });
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("Hi", decoded.frame.payload);
}

test "MUST apply XOR mask cyclically when payload exceeds 4 bytes [RFC6455 §5.3 ¶?]" {
    // The mask wraps every 4 bytes (i.e. `j = i MOD 4`).
    const key = [4]u8{ 0x10, 0x20, 0x30, 0x40 };
    const payload = "abcdefghi"; // 9 bytes — wraps over twice plus one
    var buf: [32]u8 = undefined;
    const n = try frame.encodeText(&buf, payload, .{ .mask = true, .masking_key = key });

    var i: usize = 0;
    while (i < payload.len) : (i += 1) {
        const expected = payload[i] ^ key[i & 3];
        try std.testing.expectEqual(expected, buf[6 + i]);
    }
    // Decode unmasks correctly.
    const decoded = try frame.decode(allocator, buf[0..n], .{ .mask_policy = .required });
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(payload, decoded.frame.payload);
}

// ---------------------------------------------------------------- §5.4 fragmentation

test "MUST use opcode 0 (continuation) on a continuation frame [RFC6455 §5.4 ¶?]" {
    // §5.4: "All subsequent frames in the message MUST be of opcode 0
    // (continuation frame)."
    var buf: [16]u8 = undefined;
    const n = try frame.encode(&buf, .{ .fin = true, .opcode = .continuation, .payload = "xy" }, .{});
    try std.testing.expectEqual(@as(u8, 0x0), buf[0] & 0x0f);
    _ = n;
}

test "MUST NOT accept a continuation frame with no fragmented message in progress [RFC6455 §5.4 ¶?]" {
    // §5.4: "A continuation frame ... [is] a sequence of frames where the
    // first frame's opcode is text or binary." A bare continuation
    // (FIN+continuation, payload=0) is a state-machine violation.
    var decoder = frame.Decoder.init(allocator, .{});
    defer decoder.deinit();
    try decoder.push(&[_]u8{ 0x80, 0x00 }); // FIN+continuation, len=0
    try std.testing.expectError(frame.Error.UnexpectedContinuation, decoder.next());
}

test "MUST NOT interleave a new data frame inside an open fragmented message [RFC6455 §5.4 ¶?]" {
    // §5.4: "Control frames (see Section 5.5) MAY be injected in the
    // middle of a fragmented message. ... However, a fragmented message
    // MUST NOT be interleaved between fragments of another message."
    // null3's incremental Decoder enforces that.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "ab" }, .{});
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .binary, .payload = "cd" }, .{});

    var decoder = frame.Decoder.init(allocator, .{});
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);
    const first = try decoder.next();
    defer if (first) |f| f.deinit(allocator);
    try std.testing.expect(first != null);
    try std.testing.expectError(frame.Error.FragmentedMessageInProgress, decoder.next());
}

test "MUST permit a control frame between data fragments [RFC6455 §5.4 ¶?]" {
    // §5.4 ¶?: "Control frames ... MAY be injected in the middle of a
    // fragmented message." The message-layer Decoder surfaces the
    // control event without disturbing the fragmented data state.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "hel" }, .{});
    pos += try frame.encodePing(buf[pos..], "?", .{});
    pos += try frame.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "lo" }, .{});

    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const event_a = (try decoder.next()).?;
    defer event_a.deinit(allocator);
    switch (event_a) {
        .ping => |payload| try std.testing.expectEqualStrings("?", payload),
        else => return error.UnexpectedWebSocketEvent,
    }

    const event_b = (try decoder.next()).?;
    defer event_b.deinit(allocator);
    switch (event_b) {
        .text => |payload| try std.testing.expectEqualStrings("hello", payload),
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST track FIN through a fragmented message [RFC6455 §5.4 ¶?]" {
    // The first frame has fin=false; the closing frame has fin=true.
    // The incremental Decoder reports both with their FIN flags intact.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "he" }, .{});
    pos += try frame.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "llo" }, .{});

    var decoder = frame.Decoder.init(allocator, .{});
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const first = (try decoder.next()).?;
    defer first.deinit(allocator);
    try std.testing.expectEqual(frame.Opcode.text, first.opcode);
    try std.testing.expect(!first.fin);

    const second = (try decoder.next()).?;
    defer second.deinit(allocator);
    try std.testing.expectEqual(frame.Opcode.continuation, second.opcode);
    try std.testing.expect(second.fin);
}

// ---------------------------------------------------------------- §5.5 control frames

test "MUST NOT send a control frame larger than 125 bytes [RFC6455 §5.5 ¶?]" {
    // §5.5: "All control frames MUST have a payload length of 125 bytes
    // or less and MUST NOT be fragmented." Encode-side: null3's
    // `encodedLen` / `encode` raise ControlPayloadTooLarge.
    var oversized: [126]u8 = undefined;
    @memset(&oversized, 'x');
    var buf: [256]u8 = undefined;
    try std.testing.expectError(
        frame.Error.ControlPayloadTooLarge,
        frame.encode(&buf, .{ .opcode = .ping, .payload = &oversized }, .{}),
    );
}

test "MUST NOT accept a control frame with payload > 125 bytes [RFC6455 §5.5 ¶?]" {
    // Decode-side mirror of the previous test. Build a 7+16-extended
    // PING header advertising 126 bytes; the decoder MUST reject before
    // reading the body.
    var bytes: [4]u8 = undefined;
    bytes[0] = 0x89; // FIN + ping
    bytes[1] = 126;
    std.mem.writeInt(u16, bytes[2..4], 126, .big);
    try std.testing.expectError(
        frame.Error.ControlPayloadTooLarge,
        frame.decode(allocator, &bytes, .{}),
    );
}

test "MUST NOT fragment a control frame [RFC6455 §5.5 ¶?]" {
    // §5.5: "All control frames ... MUST NOT be fragmented." A
    // close/ping/pong with FIN=0 is malformed.
    const not_final_ping = [_]u8{ 0x09, 0x00 }; // FIN clear, ping
    try std.testing.expectError(
        frame.Error.FragmentedControlFrame,
        frame.decode(allocator, &not_final_ping, .{}),
    );
}

test "MUST NOT encode a control frame with FIN clear [RFC6455 §5.5 ¶?]" {
    // Encode-side complement: null3's encoder also refuses to emit a
    // fragmented control frame.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(
        frame.Error.FragmentedControlFrame,
        frame.encode(&buf, .{ .fin = false, .opcode = .ping, .payload = "x" }, .{}),
    );
}

// ---------------------------------------------------------------- §5.5.1 close frame

test "MAY send a close frame with no payload [RFC6455 §5.5.1 ¶?]" {
    // §5.5.1: "If there is a body, the first two bytes ... MUST be a
    // 2-byte ... status code. ... If there is no such status code, the
    // closing connection MUST be considered to be 1005."
    // An empty close payload is well-formed.
    var buf: [4]u8 = undefined;
    const n = try frame.encodeClose(&buf, null, "", .{});
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x88), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);
}

test "MAY send a close frame with a 2-byte status code [RFC6455 §5.5.1 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try frame.encodeClose(&buf, 1000, "", .{});
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u8, 0x88), buf[0]);
    try std.testing.expectEqual(@as(u8, 2), buf[1]);
    try std.testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, buf[2..4], .big));
}

test "MAY send a close frame with status code + reason [RFC6455 §5.5.1 ¶?]" {
    var buf: [32]u8 = undefined;
    const n = try frame.encodeClose(&buf, 1000, "bye", .{});
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 5), buf[1]);
    try std.testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, buf[2..4], .big));
    try std.testing.expectEqualStrings("bye", buf[4..7]);
}

test "MUST NOT accept a close payload of length 1 [RFC6455 §5.5.1 ¶?]" {
    // §5.5.1: "If there is a body, the first two bytes of the body MUST
    // be a 2-byte unsigned integer." A 1-byte body is malformed.
    const bad = [_]u8{ 0x88, 0x01, 0x00 };
    try std.testing.expectError(
        frame.Error.InvalidClosePayload,
        frame.decode(allocator, &bad, .{}),
    );
}

test "MUST NOT encode a close payload with reason but no code [RFC6455 §5.5.1 ¶?]" {
    // §5.5.1: "Following the 2-byte integer the body MAY contain UTF-8-
    // encoded data with value reason." A reason without a code violates
    // the grammar.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(
        frame.Error.InvalidClosePayload,
        frame.encodeClose(&buf, null, "huh", .{}),
    );
}

test "MUST NOT use status code 1004 on the wire [RFC6455 §7.4 ¶?]" {
    // §7.4 / IANA registry: 1004 is "reserved" — implementations MUST
    // NOT send this code over the wire. (Original use was abandoned.)
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 1004, "", .{}));

    const bad = [_]u8{ 0x88, 0x02, 0x03, 0xec }; // 0x03ec = 1004
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.decode(allocator, &bad, .{}));
}

test "MUST NOT use status code 1005 on the wire [RFC6455 §7.4 ¶?]" {
    // §7.4: 1005 means "no status code was actually present" — only
    // synthesized internally; never on the wire.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 1005, "", .{}));

    const bad = [_]u8{ 0x88, 0x02, 0x03, 0xed };
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.decode(allocator, &bad, .{}));
}

test "MUST NOT use status code 1006 on the wire [RFC6455 §7.4 ¶?]" {
    // §7.4: 1006 is "abnormal closure" — only synthesized internally.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 1006, "", .{}));

    const bad = [_]u8{ 0x88, 0x02, 0x03, 0xee };
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.decode(allocator, &bad, .{}));
}

test "MUST NOT use status code 1015 on the wire [RFC6455 §7.4 ¶?]" {
    // §7.4: 1015 = "TLS handshake" — reserved, MUST NOT be on the wire.
    // null3 rejects everything outside 1000-1014 (excluding 1004/1005/
    // 1006) and 3000-4999, which catches 1015.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 1015, "", .{}));

    const bad = [_]u8{ 0x88, 0x02, 0x03, 0xf7 }; // 0x03f7 = 1015
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.decode(allocator, &bad, .{}));
}

test "MUST accept the standard close codes 1000-1003 [RFC6455 §7.4 ¶?]" {
    // §7.4 IANA registry — these are the codes a conformant peer
    // emits; null3 accepts them.
    var buf: [16]u8 = undefined;
    const codes = [_]u16{ 1000, 1001, 1002, 1003 };
    for (codes) |code| {
        const n = try frame.encodeClose(&buf, code, "", .{});
        try std.testing.expect(n >= 4);
    }
}

test "MUST accept the standard close codes 1007-1014 [RFC6455 §7.4 ¶?]" {
    var buf: [16]u8 = undefined;
    const codes = [_]u16{ 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014 };
    for (codes) |code| {
        const n = try frame.encodeClose(&buf, code, "", .{});
        try std.testing.expect(n >= 4);
    }
}

test "MAY use registered application close codes 3000-3999 [RFC6455 §7.4 ¶?]" {
    // §7.4 IANA registry: 3000-3999 is "reserved for use by libraries,
    // frameworks, and applications" — registered per the IANA process.
    var buf: [16]u8 = undefined;
    const lo = try frame.encodeClose(&buf, 3000, "", .{});
    try std.testing.expect(lo > 0);
    const hi = try frame.encodeClose(&buf, 3999, "", .{});
    try std.testing.expect(hi > 0);
}

test "MAY use private close codes 4000-4999 [RFC6455 §7.4 ¶?]" {
    // §7.4: 4000-4999 is "reserved for private use" — no IANA
    // registration required.
    var buf: [16]u8 = undefined;
    const lo = try frame.encodeClose(&buf, 4000, "", .{});
    try std.testing.expect(lo > 0);
    const hi = try frame.encodeClose(&buf, 4999, "", .{});
    try std.testing.expect(hi > 0);
}

test "MUST NOT accept a close code below 1000 [RFC6455 §7.4 ¶?]" {
    // §7.4: 0-999 are "not used" — any value below 1000 is malformed
    // on the wire.
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 999, "", .{}));
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 0, "", .{}));
}

test "MUST NOT accept a close code in the 2000-2999 reserved range [RFC6455 §7.4 ¶?]" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 2000, "", .{}));
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 2500, "", .{}));
}

test "MUST NOT accept a close code at or above 5000 [RFC6455 §7.4 ¶?]" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 5000, "", .{}));
    try std.testing.expectError(frame.Error.InvalidCloseCode, frame.encodeClose(&buf, 65535, "", .{}));
}

test "MUST NOT accept a decoded close payload with an invalid status code [RFC6455 §7.4 ¶?]" {
    // Decode-side: 0x03e7 = 999, below the registered range.
    const bad = [_]u8{ 0x88, 0x02, 0x03, 0xe7 };
    try std.testing.expectError(
        frame.Error.InvalidCloseCode,
        frame.decode(allocator, &bad, .{}),
    );
}

// ---------------------------------------------------------------- §5.5.2 / §5.5.3 ping/pong

test "NORMATIVE Ping carries an optional payload of <= 125 bytes [RFC6455 §5.5.2 ¶?]" {
    // §5.5.2: "A Ping frame MAY include 'Application data'." The size
    // limit is the §5.5 control-frame cap.
    var buf: [128]u8 = undefined;
    const empty_n = try frame.encodePing(&buf, "", .{});
    try std.testing.expectEqual(@as(usize, 2), empty_n);
    try std.testing.expectEqual(@as(u8, 0x89), buf[0]);

    var max_payload: [125]u8 = undefined;
    @memset(&max_payload, 'p');
    const max_n = try frame.encodePing(&buf, &max_payload, .{});
    try std.testing.expectEqual(@as(usize, 127), max_n);
}

test "NORMATIVE Pong carries an optional payload of <= 125 bytes [RFC6455 §5.5.3 ¶?]" {
    // §5.5.3: "A Pong frame ... MAY include 'Application data'."
    var buf: [128]u8 = undefined;
    const empty_n = try frame.encodePong(&buf, "", .{});
    try std.testing.expectEqual(@as(usize, 2), empty_n);
    try std.testing.expectEqual(@as(u8, 0x8a), buf[0]);

    var max_payload: [125]u8 = undefined;
    @memset(&max_payload, 'p');
    const max_n = try frame.encodePong(&buf, &max_payload, .{});
    try std.testing.expectEqual(@as(usize, 127), max_n);
}

test "MUST round-trip a ping payload through the codec [RFC6455 §5.5.2 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try frame.encodePing(&buf, "hi", .{});
    const decoded = try frame.decode(allocator, buf[0..n], .{});
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(frame.Opcode.ping, decoded.frame.opcode);
    try std.testing.expectEqualStrings("hi", decoded.frame.payload);
}

test "MUST round-trip a pong payload through the codec [RFC6455 §5.5.3 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try frame.encodePong(&buf, "yo", .{});
    const decoded = try frame.decode(allocator, buf[0..n], .{});
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(frame.Opcode.pong, decoded.frame.opcode);
    try std.testing.expectEqualStrings("yo", decoded.frame.payload);
}

// ---------------------------------------------------------------- §5.6 / §8.1 UTF-8 in text frames

test "MUST validate UTF-8 in a text data frame [RFC6455 §5.6 ¶?]" {
    // §5.6: "The 'Payload data' is text data ... The text MUST be encoded
    // in UTF-8." null3 enforces this at the message-decoder boundary
    // (where fragmented text frames have been reassembled).
    var buf: [16]u8 = undefined;
    const n = try frame.encodeText(&buf, "\xff", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);
    try std.testing.expectError(message.Error.InvalidUtf8, decoder.next());
}

test "MUST accept valid UTF-8 in a text data frame [RFC6455 §5.6 ¶?]" {
    var buf: [32]u8 = undefined;
    const n = try frame.encodeText(&buf, "héllo \u{1f44b}", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);
    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .text => |payload| try std.testing.expectEqualStrings("héllo \u{1f44b}", payload),
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST validate UTF-8 in a close-frame reason [RFC6455 §8.1 ¶?]" {
    // §8.1: "If an endpoint receives a Close control frame containing
    // a Payload Data section with content that is not valid UTF-8, the
    // endpoint MUST _Fail the WebSocket Connection_." null3 surfaces
    // InvalidUtf8 from the message decoder.
    var close_payload = [_]u8{ 0x03, 0xe8, 0xff }; // 1000 + invalid byte
    var buf: [16]u8 = undefined;
    const n = try frame.encode(&buf, .{ .opcode = .close, .payload = &close_payload }, .{});

    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);
    try std.testing.expectError(message.Error.InvalidUtf8, decoder.next());
}

test "MUST accept valid UTF-8 in a close-frame reason [RFC6455 §8.1 ¶?]" {
    var buf: [32]u8 = undefined;
    const n = try frame.encodeClose(&buf, 1000, "héllo", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);
    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .close => |close| {
            try std.testing.expectEqual(@as(?u16, 1000), close.code);
            try std.testing.expectEqualStrings("héllo", close.reason);
        },
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST validate UTF-8 across fragmented text frames [RFC6455 §5.6 ¶?]" {
    // The message decoder reassembles fragments before validating UTF-8,
    // so a multi-byte UTF-8 sequence split across frame boundaries still
    // validates correctly. Conversely, a sequence whose tail is corrupted
    // is detected on the *final* fragment.
    const valid = "héllo"; // 6 bytes; "h" + 2-byte "é" + "llo"
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = valid[0..2] }, .{});
    pos += try frame.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = valid[2..] }, .{});

    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);
    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .text => |payload| try std.testing.expectEqualStrings(valid, payload),
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST NOT enforce UTF-8 on binary data frames [RFC6455 §5.6 ¶?]" {
    // §5.6: "Binary frames are arbitrary octets" — the codec MUST not
    // reject a binary message that happens to contain non-UTF-8 bytes.
    var buf: [16]u8 = undefined;
    const n = try frame.encodeBinary(&buf, "\x00\xff\xfe", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);
    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .binary => |payload| try std.testing.expectEqualSlices(u8, "\x00\xff\xfe", payload),
        else => return error.UnexpectedWebSocketEvent,
    }
}

// ---------------------------------------------------------------- §5.2 round-trip & §5.3 defaults

test "MUST round-trip a non-empty masked text frame [RFC6455 §5.2, §5.3 ¶?]" {
    // The canonical positive-path test for the codec: encode + decode
    // recovers the original message bytes exactly.
    var buf: [64]u8 = undefined;
    const n = try frame.encodeText(&buf, "Hello, world", .{
        .mask = true,
        .masking_key = .{ 0x10, 0x20, 0x30, 0x40 },
    });
    const decoded = try frame.decode(allocator, buf[0..n], .{ .mask_policy = .required });
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(frame.Opcode.text, decoded.frame.opcode);
    try std.testing.expect(decoded.frame.fin);
    try std.testing.expectEqualStrings("Hello, world", decoded.frame.payload);
    try std.testing.expectEqual(n, decoded.bytes_read);
}

test "MUST round-trip a non-empty unmasked binary frame [RFC6455 §5.2 ¶?]" {
    var buf: [64]u8 = undefined;
    const n = try frame.encodeBinary(&buf, &.{ 0xde, 0xad, 0xbe, 0xef }, .{});
    const decoded = try frame.decode(allocator, buf[0..n], .{ .mask_policy = .forbidden });
    defer decoded.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, decoded.frame.payload);
}

test "MUST report the exact bytes consumed by a single decoded frame [RFC6455 §5.2 ¶?]" {
    // For stream-oriented use, the decoder must tell the caller how many
    // bytes belonged to the frame so the caller can advance the buffer.
    var buf: [64]u8 = undefined;
    const a = try frame.encodeText(&buf, "ab", .{});
    const b = try frame.encodeText(buf[a..], "cdef", .{});

    const first = try frame.decode(allocator, buf[0 .. a + b], .{});
    defer first.deinit(allocator);
    try std.testing.expectEqual(a, first.bytes_read);

    const second = try frame.decode(allocator, buf[a .. a + b], .{});
    defer second.deinit(allocator);
    try std.testing.expectEqual(b, second.bytes_read);
}

// ---------------------------------------------------------------- §5.5.2 incremental decoder buffering

test "MUST buffer a partially-received frame and emit it once complete [RFC6455 §5.2 ¶?]" {
    // null3's incremental Decoder accepts a sliding byte stream and
    // emits a frame only when its bytes have arrived in full. This
    // replicates the conditions a real wire-side reader experiences.
    var buf: [16]u8 = undefined;
    const n = try frame.encodeText(&buf, "abc", .{});

    var decoder = frame.Decoder.init(allocator, .{});
    defer decoder.deinit();
    try decoder.push(buf[0..2]);
    try std.testing.expect((try decoder.next()) == null);
    try decoder.push(buf[2..n]);
    const f = (try decoder.next()).?;
    defer f.deinit(allocator);
    try std.testing.expectEqualStrings("abc", f.payload);
}

test "MUST emit two consecutive frames from a single buffer [RFC6455 §5.2 ¶?]" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encodeText(buf[pos..], "ab", .{});
    pos += try frame.encodeText(buf[pos..], "cd", .{});

    var decoder = frame.Decoder.init(allocator, .{});
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const a = (try decoder.next()).?;
    defer a.deinit(allocator);
    try std.testing.expectEqualStrings("ab", a.payload);

    const b = (try decoder.next()).?;
    defer b.deinit(allocator);
    try std.testing.expectEqualStrings("cd", b.payload);

    try std.testing.expect((try decoder.next()) == null);
}

// ---------------------------------------------------------------- message-layer aggregation

test "MUST cap aggregate message size when configured [RFC6455 §5.4 ¶?]" {
    // §5.4 doesn't impose a specific size limit, but RFC 6455 implies
    // implementations are responsible for bounding allocation. The
    // null3 message decoder honours a configured `max_message_len`.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .text, .payload = "abc" }, .{});
    pos += try frame.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "def" }, .{});

    var decoder = message.Decoder.init(allocator, .{
        .frame = .{ .mask_policy = .forbidden },
        .max_message_len = 5,
    });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);
    try std.testing.expectError(message.Error.MessageTooLarge, decoder.next());
}

test "MUST emit a binary message after reassembly [RFC6455 §5.4 ¶?]" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try frame.encode(buf[pos..], .{ .fin = false, .opcode = .binary, .payload = "\x00\x01" }, .{});
    pos += try frame.encode(buf[pos..], .{ .fin = true, .opcode = .continuation, .payload = "\x02\x03" }, .{});

    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..pos]);

    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .binary => |payload| try std.testing.expectEqualSlices(u8, "\x00\x01\x02\x03", payload),
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST emit a close event with code and reason after decoding a close frame [RFC6455 §5.5.1 ¶?]" {
    var buf: [16]u8 = undefined;
    const n = try frame.encodeClose(&buf, 1001, "going away", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);

    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .close => |close| {
            try std.testing.expectEqual(@as(?u16, 1001), close.code);
            try std.testing.expectEqualStrings("going away", close.reason);
        },
        else => return error.UnexpectedWebSocketEvent,
    }
}

test "MUST emit a close event with no code when the close payload is empty [RFC6455 §5.5.1 ¶?]" {
    // §5.5.1: "If there is no such status code, the closing connection
    // MUST be considered to be 1005." null3 reports `code = null`,
    // letting the application substitute 1005 if it wants to mirror
    // the §5.5.1 / §7.4 mapping.
    var buf: [4]u8 = undefined;
    const n = try frame.encodeClose(&buf, null, "", .{});
    var decoder = message.Decoder.init(allocator, .{ .frame = .{ .mask_policy = .forbidden } });
    defer decoder.deinit();
    try decoder.push(buf[0..n]);

    const event = (try decoder.next()).?;
    defer event.deinit(allocator);
    switch (event) {
        .close => |close| {
            try std.testing.expectEqual(@as(?u16, null), close.code);
            try std.testing.expectEqual(@as(usize, 0), close.reason.len);
        },
        else => return error.UnexpectedWebSocketEvent,
    }
}

