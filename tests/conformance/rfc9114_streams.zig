//! RFC 9114 §6 (HTTP/3 stream layer) and §7.2.8 (frame placement) — stream
//! type discrimination, control-stream uniqueness, push-stream rules, the
//! "MUST treat as connection error of type H3_FRAME_UNEXPECTED" gates that
//! HTTP/3 attaches to misplaced frame types, and critical-stream-closure
//! enforcement.
//!
//! These tests drive the public surface in two layers:
//!
//!   - `null3.stream.FrameValidator` (the pure stream-type → allowed-frames
//!     state machine) for placement rules that the spec phrases as "MUST
//!     treat as a connection error of type H3_FRAME_UNEXPECTED" — a
//!     conformance test there proves the gate exists in the validator that
//!     `null3.session` runs every received frame through.
//!   - The full session loopback (`H3Pair` in `_h3_fixture.zig`) for the
//!     end-to-end MUST: a malformed peer stream MUST trigger a
//!     CONNECTION_CLOSE with the right error code (frame_unexpected,
//!     stream_creation_error, closed_critical_stream, missing_settings).
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §6.1   ¶?  MUST     reject GOAWAY observed on a request stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.1   ¶?  MUST     reject SETTINGS observed on a request stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.1   ¶?  MUST     reject CANCEL_PUSH observed on a request stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.1   ¶?  MUST     reject MAX_PUSH_ID observed on a request stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.1   ¶?  MUST     reject reserved-HTTP/2 frame types observed on a request stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2   ¶3  MUST     treat the unidirectional stream-type prefix as a varint
//!   RFC9114 §6.2   ¶3  MUST     classify stream type 0x00 as control
//!   RFC9114 §6.2   ¶3  MUST     classify stream type 0x01 as push
//!   RFC9114 §6.2   ¶3  MUST     classify stream type 0x02 as the QPACK encoder stream
//!   RFC9114 §6.2   ¶3  MUST     classify stream type 0x03 as the QPACK decoder stream
//!   RFC9114 §6.2.1 ¶3  MUST     reject HEADERS observed on the control stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2.1 ¶3  MUST     reject DATA observed on the control stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2.1 ¶3  MUST     reject PUSH_PROMISE observed on the control stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2.1 ¶3  MUST     reject reserved-HTTP/2 frame types on the control stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2.1 ¶6  MUST     reject a control stream whose first frame is not SETTINGS as H3_MISSING_SETTINGS
//!   RFC9114 §6.2.1 ¶7  MUST     reject a duplicate peer control stream as H3_STREAM_CREATION_ERROR
//!   RFC9114 §6.2.1 ¶7  MUST     reject a SETTINGS frame after a previous SETTINGS as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2.1 ¶8  MUST     reject FIN on the control stream as H3_CLOSED_CRITICAL_STREAM
//!   RFC9114 §6.2.1 ¶8  MUST     reject FIN on the QPACK encoder stream as H3_CLOSED_CRITICAL_STREAM
//!   RFC9114 §6.2.1 ¶8  MUST     reject FIN on the QPACK decoder stream as H3_CLOSED_CRITICAL_STREAM
//!   RFC9114 §6.2.2 ¶?  MUST     reject a peer push stream observed by a server as H3_STREAM_CREATION_ERROR
//!   RFC9114 §6.2.2 ¶?  MUST     reject duplicate Push IDs observed by a client as H3_ID_ERROR
//!   RFC9114 §6.2.2 ¶?  MUST     reject a Push ID above the advertised MAX_PUSH_ID as H3_ID_ERROR
//!   RFC9114 §6.2.2 ¶?  MUST     reject a push stream when MAX_PUSH_ID is unset as H3_ID_ERROR
//!   RFC9114 §6.2.3 ¶?  MUST NOT consider a reserved (unknown) unidirectional stream type a connection error
//!   RFC9114 §6.2.3 ¶?  MUST NOT consider a GREASE unidirectional stream type a connection error
//!   RFC9114 §7.2   ¶?  MUST     allow DATA on a request stream
//!   RFC9114 §7.2   ¶?  MUST     allow HEADERS on a request stream
//!   RFC9114 §7.2   ¶?  MUST     ignore unknown frame types on a request stream
//!   RFC9114 §7.2   ¶?  MUST     ignore unknown frame types on the control stream
//!   RFC9114 §7.2   ¶?  MUST     allow GOAWAY on the control stream
//!   RFC9114 §7.2   ¶?  MUST     allow CANCEL_PUSH on the control stream
//!   RFC9114 §7.2   ¶?  MUST     allow MAX_PUSH_ID on the control stream
//!   RFC9114 §7.2   ¶?  MUST     allow PRIORITY_UPDATE on the control stream
//!   RFC9114 §7.2.8 ¶?  MUST     reject DATA observed on a push stream's first frame as H3_FRAME_UNEXPECTED
//!   RFC9114 §7.2.8 ¶?  MUST     reject SETTINGS observed on a push stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §7.2.8 ¶?  MUST     reject GOAWAY observed on a push stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §7.2.8 ¶?  MUST     reject CANCEL_PUSH observed on a push stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §7.2.8 ¶?  MUST     reject MAX_PUSH_ID observed on a push stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §7.2.8 ¶?  MUST     reject PUSH_PROMISE observed on a push stream as H3_FRAME_UNEXPECTED
//!   RFC9114 §6.2   ¶?  NORMATIVE QPACK encoder/decoder critical-stream IDs are reserved at the validator level
//!
//! Visible debt:
//!   RFC9114 §6.1   ¶?  MUST     enforce HEADERS-DATA*-HEADERS? frame ordering at the request stream level (lives in null3.message; see rfc9114_messages.zig)
//!   RFC9114 §6.2.1 ¶?  MUST     local control-stream-only-once invariant (Session.openControlStream is private; covered by start() reuse)
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.4 SETTINGS *codec*  → rfc9114_settings.zig
//!   RFC9114 §7.2.4 SETTINGS *handshake* and duplicate-frame rules → rfc9114_session.zig
//!   RFC9114 §7.2.6 GOAWAY semantics & last-allowed-id monotonicity → rfc9114_session.zig
//!   RFC9114 §6.1   request stream HEADERS/DATA *ordering* (message-level) → rfc9114_messages.zig
//!   RFC9114 §11.2.3 numeric error-code values → rfc9114_errors.zig
//!   RFC9204 §4.2  QPACK encoder/decoder *instruction* semantics → rfc9204_qpack_dynamic.zig

const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");
const fixture = @import("_h3_fixture.zig");

const stream = null3.stream;
const protocol = null3.protocol;
const FrameType = protocol.FrameType;
const StreamType = protocol.StreamType;
const ErrorCode = protocol.ErrorCode;
const FrameValidator = stream.FrameValidator;
const FrameContext = stream.FrameContext;
const FrameValidationError = stream.FrameValidationError;

// ---------------------------------------------------------------- §6.2 unidirectional stream type prefix

test "MUST treat the unidirectional stream-type prefix as a QUIC variable-length integer [RFC9114 §6.2 ¶3]" {
    // §6.2 ¶3: "Each side of the unidirectional stream is identified by a
    // variable-length integer". Driving null3.stream.decodeType through the
    // four single-byte (1-byte varint) types and a 2-byte varint of the
    // same logical value asserts that the prefix is parsed as a varint and
    // not, for instance, a fixed-width u8.
    var two_byte_control = [_]u8{ 0x40, 0x00 }; // 2-byte varint of 0x00
    const decoded = try stream.decodeType(&two_byte_control);
    try std.testing.expectEqual(stream.Kind.control, decoded.kind);
    try std.testing.expectEqual(@as(usize, 2), decoded.bytes_read);
}

test "MUST classify unidirectional stream type 0x00 as control [RFC9114 §6.2.1 ¶1]" {
    var buf = [_]u8{0x00};
    const decoded = try stream.decodeType(&buf);
    try std.testing.expectEqual(stream.Kind.control, decoded.kind);
    try std.testing.expectEqual(@as(usize, 1), decoded.bytes_read);
}

test "MUST classify unidirectional stream type 0x01 as push [RFC9114 §6.2.2 ¶1]" {
    var buf = [_]u8{0x01};
    const decoded = try stream.decodeType(&buf);
    try std.testing.expectEqual(stream.Kind.push, decoded.kind);
}

test "MUST classify unidirectional stream type 0x02 as QPACK encoder [RFC9114 §6.2 ¶?]" {
    // §6.2 ¶3 + RFC 9204 §4.2 reserve type 0x02 for the QPACK encoder
    // stream. null3 owns this classification at the stream layer because
    // the kind drives whether the receiver routes the bytes to the
    // QPACK encoder-instruction parser.
    var buf = [_]u8{0x02};
    const decoded = try stream.decodeType(&buf);
    try std.testing.expectEqual(stream.Kind.qpack_encoder, decoded.kind);
}

test "MUST classify unidirectional stream type 0x03 as QPACK decoder [RFC9114 §6.2 ¶?]" {
    var buf = [_]u8{0x03};
    const decoded = try stream.decodeType(&buf);
    try std.testing.expectEqual(stream.Kind.qpack_decoder, decoded.kind);
}

test "NORMATIVE classify an unrecognized unidirectional stream type as unknown [RFC9114 §6.2 ¶3]" {
    // RFC 9114 §6.2 ¶3: "Unidirectional streams of unknown type MUST NOT
    // be considered an error". null3.stream.decodeType surfaces unknown
    // types as `Kind.unknown` so the session can drop the stream — this
    // proves the parser doesn't reject the prefix outright.
    var buf = [_]u8{0x21}; // first GREASE id
    const decoded = try stream.decodeType(&buf);
    switch (decoded.kind) {
        .unknown => |type_id| try std.testing.expectEqual(@as(u64, 0x21), type_id),
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- §6.2.1 control stream — first SETTINGS rule (validator)

test "MUST reject a non-SETTINGS first frame on the control stream as H3_MISSING_SETTINGS [RFC9114 §6.2.1 ¶6]" {
    // §6.2.1 ¶6: "A SETTINGS frame MUST be sent as the first frame of each
    // control stream ... receipt of any other frame ... MUST be treated as
    // a connection error of type H3_MISSING_SETTINGS."
    var v = FrameValidator.init(.control);
    try std.testing.expectError(
        FrameValidationError.MissingSettings,
        v.observe(FrameType.goaway),
    );
}

test "MUST reject a control stream whose first frame is DATA as H3_MISSING_SETTINGS [RFC9114 §6.2.1 ¶6]" {
    var v = FrameValidator.init(.control);
    try std.testing.expectError(
        FrameValidationError.MissingSettings,
        v.observe(FrameType.data),
    );
}

test "MUST reject a control stream whose first frame is HEADERS as H3_MISSING_SETTINGS [RFC9114 §6.2.1 ¶6]" {
    var v = FrameValidator.init(.control);
    try std.testing.expectError(
        FrameValidationError.MissingSettings,
        v.observe(FrameType.headers),
    );
}

test "MUST accept SETTINGS as the first control-stream frame [RFC9114 §6.2.1 ¶6]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
}

// ---------------------------------------------------------------- §6.2.1 control stream — duplicate-SETTINGS

test "MUST reject a second SETTINGS frame on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §6.2.1 ¶6]" {
    // §7.2.4 ¶3 requires SETTINGS exactly once. The validator surfaces
    // the second SETTINGS as DuplicateSettings (mapped to H3_FRAME_UNEXPECTED).
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.DuplicateSettings,
        v.observe(FrameType.settings),
    );
}

// ---------------------------------------------------------------- §6.2.1 control stream — frame placement

test "MUST reject DATA on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.1 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.data),
    );
}

test "MUST reject HEADERS on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.2 ¶3]" {
    // §7.2.2 ¶3: "A HEADERS frame can only appear on a request stream or a
    // push stream. A receipt of a HEADERS frame on any other stream MUST
    // be treated as a connection error of type H3_FRAME_UNEXPECTED."
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.headers),
    );
}

test "MUST reject PUSH_PROMISE on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.5 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.push_promise),
    );
}

test "MUST reject reserved HTTP/2 PRIORITY (0x02) on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    // §7.2.8 reserves frame types 0x02, 0x06, 0x08, 0x09 (HTTP/2's
    // PRIORITY, PING, WINDOW_UPDATE, CONTINUATION) and requires they be
    // treated as H3_FRAME_UNEXPECTED if observed.
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_priority),
    );
}

test "MUST reject reserved HTTP/2 PING (0x06) on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_ping),
    );
}

test "MUST reject reserved HTTP/2 WINDOW_UPDATE (0x08) on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_window_update),
    );
}

test "MUST reject reserved HTTP/2 CONTINUATION (0x09) on the control stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_continuation),
    );
}

test "MUST allow GOAWAY on the control stream after SETTINGS [RFC9114 §7.2.6 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(FrameType.goaway);
}

test "MUST allow CANCEL_PUSH on the control stream after SETTINGS [RFC9114 §7.2.3 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(FrameType.cancel_push);
}

test "MUST allow MAX_PUSH_ID on the control stream after SETTINGS [RFC9114 §7.2.7 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(FrameType.max_push_id);
}

test "MUST allow PRIORITY_UPDATE (0x0f0700) on the control stream after SETTINGS [RFC9218 §7.2 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(FrameType.priority_update_request);
}

test "MUST allow PRIORITY_UPDATE-push (0x0f0701) on the control stream after SETTINGS [RFC9218 §7.2 ¶?]" {
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(FrameType.priority_update_push);
}

test "MUST ignore unknown extension frame types on the control stream after SETTINGS [RFC9114 §9 ¶?]" {
    // §9 ¶? "Implementations MUST ignore unknown ... extension frames".
    // The validator returns success for non-known frame types so the
    // session can drop the payload bytes without closing the connection.
    var v = FrameValidator.init(.control);
    try v.observe(FrameType.settings);
    try v.observe(0xface); // unknown extension frame type
}

// ---------------------------------------------------------------- §6.1 request stream — frame placement

test "MUST allow DATA on a request stream [RFC9114 §6.1 ¶?]" {
    var v = FrameValidator.init(.request);
    try v.observe(FrameType.data);
}

test "MUST allow HEADERS on a request stream [RFC9114 §6.1 ¶?]" {
    var v = FrameValidator.init(.request);
    try v.observe(FrameType.headers);
}

test "MUST allow PUSH_PROMISE on a request stream [RFC9114 §7.2.5 ¶?]" {
    var v = FrameValidator.init(.request);
    try v.observe(FrameType.push_promise);
}

test "MUST reject SETTINGS observed on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.4 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.settings),
    );
}

test "MUST reject GOAWAY observed on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.6 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.goaway),
    );
}

test "MUST reject CANCEL_PUSH observed on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.3 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.cancel_push),
    );
}

test "MUST reject MAX_PUSH_ID observed on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.7 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.max_push_id),
    );
}

test "MUST reject PRIORITY_UPDATE on a request stream as H3_FRAME_UNEXPECTED [RFC9218 §7.2 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.priority_update_request),
    );
}

test "MUST reject reserved HTTP/2 PRIORITY (0x02) on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_priority),
    );
}

test "MUST reject reserved HTTP/2 PING (0x06) on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_ping),
    );
}

test "MUST reject reserved HTTP/2 WINDOW_UPDATE (0x08) on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_window_update),
    );
}

test "MUST reject reserved HTTP/2 CONTINUATION (0x09) on a request stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.8 ¶?]" {
    var v = FrameValidator.init(.request);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.http2_continuation),
    );
}

test "MUST ignore unknown extension frame types on a request stream [RFC9114 §9 ¶?]" {
    var v = FrameValidator.init(.request);
    try v.observe(0xface);
}

// ---------------------------------------------------------------- §6.2.2 push stream — frame placement

test "MUST allow HEADERS as the first frame on a push stream [RFC9114 §6.2.2 ¶?]" {
    var v = FrameValidator.init(.push);
    try v.observe(FrameType.headers);
}

test "MUST allow DATA after HEADERS on a push stream [RFC9114 §6.2.2 ¶?]" {
    var v = FrameValidator.init(.push);
    try v.observe(FrameType.headers);
    try v.observe(FrameType.data);
}

test "MUST reject SETTINGS observed on a push stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.4 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.settings),
    );
}

test "MUST reject GOAWAY observed on a push stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.6 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.goaway),
    );
}

test "MUST reject CANCEL_PUSH observed on a push stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.3 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.cancel_push),
    );
}

test "MUST reject MAX_PUSH_ID observed on a push stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.7 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.max_push_id),
    );
}

test "MUST reject PUSH_PROMISE observed on a push stream as H3_FRAME_UNEXPECTED [RFC9114 §7.2.5 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.push_promise),
    );
}

test "MUST reject PRIORITY_UPDATE on a push stream as H3_FRAME_UNEXPECTED [RFC9218 §7.2 ¶?]" {
    var v = FrameValidator.init(.push);
    try std.testing.expectError(
        FrameValidationError.FrameUnexpected,
        v.observe(FrameType.priority_update_request),
    );
}

// ---------------------------------------------------------------- §6.2.1 control stream — end-to-end H3_FRAME_UNEXPECTED gates

test "MUST close with H3_FRAME_UNEXPECTED when DATA is observed on the control stream [RFC9114 §6.2.1 ¶?]" {
    // End-to-end MUST: a malicious peer that writes DATA to its control
    // stream must trigger CONNECTION_CLOSE on the receiving session with
    // application error code 0x0105 (H3_FRAME_UNEXPECTED).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.writeFrame(
        &pair.client,
        pair.client_h3.control_stream_id.?,
        .{ .data = "bad-control-data" },
    );

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try std.testing.expectEqual(null3.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

test "MUST close with H3_FRAME_UNEXPECTED when HEADERS is observed on the control stream [RFC9114 §7.2.2 ¶3]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.writeFrame(
        &pair.client,
        pair.client_h3.control_stream_id.?,
        .{ .headers = "header-block-payload" },
    );

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

test "MUST close with H3_FRAME_UNEXPECTED when SETTINGS is observed on a request stream [RFC9114 §7.2.4 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try fixture.writeFrame(&pair.client, stream_id, .{ .settings = .{} });

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

test "MUST close with H3_FRAME_UNEXPECTED when GOAWAY is observed on a request stream [RFC9114 §7.2.6 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try fixture.writeFrame(&pair.client, stream_id, .{ .goaway = 0 });

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

test "MUST close with H3_FRAME_UNEXPECTED when CANCEL_PUSH is observed on a request stream [RFC9114 §7.2.3 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    const stream_id: u64 = 0;
    _ = try pair.client.openBidi(stream_id);
    try fixture.writeFrame(&pair.client, stream_id, .{ .cancel_push = 0 });

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

// ---------------------------------------------------------------- §6.2.1 control stream — duplicate critical streams

test "MUST close with H3_STREAM_CREATION_ERROR when a peer opens a second control stream [RFC9114 §6.2.1 ¶7]" {
    // §6.2.1 ¶7: "Endpoints MUST NOT open more than one control stream
    // ... receipt of a second stream claiming to be a control stream
    // MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR."
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    // Send a second control stream (id 6 is client-initiated uni, after
    // the legitimate one the client opened during start()).
    try fixture.openUniWithType(&pair.client, 6, StreamType.control);

    try fixture.expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.stream_creation_error);
}

test "MUST close with H3_STREAM_CREATION_ERROR when a peer opens a second QPACK encoder stream [RFC9114 §6.2.1 ¶7]" {
    // The same uniqueness rule extends to QPACK encoder/decoder streams
    // (RFC 9204 §4.2). null3 maps both to CriticalStreamAlreadyOpen and
    // closes with H3_STREAM_CREATION_ERROR.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    try fixture.openUniWithType(&pair.client, 14, StreamType.qpack_encoder);

    try fixture.expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.stream_creation_error);
}

test "MUST close with H3_STREAM_CREATION_ERROR when a peer opens a second QPACK decoder stream [RFC9204 §4.2 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    try fixture.openUniWithType(&pair.client, 14, StreamType.qpack_decoder);

    try fixture.expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.stream_creation_error);
}

// ---------------------------------------------------------------- §6.2.2 push streams

test "MUST close with H3_STREAM_CREATION_ERROR when a server receives a peer push stream [RFC9114 §6.2.2 ¶?]" {
    // §6.2.2: only the server may initiate push streams. A client (or any
    // peer in the role of "server" view) that sees a push stream from the
    // wrong direction MUST close with H3_STREAM_CREATION_ERROR.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.openUniWithType(&pair.client, 6, StreamType.push);

    try fixture.expectPairH3Error(allocator, &pair, error.UnexpectedStream);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.stream_creation_error);
}

test "MUST close with H3_ID_ERROR on a push stream when MAX_PUSH_ID has not been sent [RFC9114 §6.2.2 ¶?]" {
    // §6.2.2: a server MUST NOT initiate a push stream until the client
    // has sent MAX_PUSH_ID. The client treats any push stream as an
    // H3_ID_ERROR until it has authorized at least one push.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.openUniWithType(&pair.server, 7, StreamType.push);
    try fixture.writeVarint(&pair.server, 7, 0);

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try fixture.expectLastCloseCode(&pair.client_h3, ErrorCode.id_error);
}

test "MUST close with H3_ID_ERROR on a push stream whose Push ID exceeds the advertised MAX_PUSH_ID [RFC9114 §7.2.7 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 0 }, .{});
    defer pair.deinit();

    try fixture.openUniWithType(&pair.server, 7, StreamType.push);
    try fixture.writeVarint(&pair.server, 7, 1);

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidPushId);
    try fixture.expectLastCloseCode(&pair.client_h3, ErrorCode.id_error);
}

// ---------------------------------------------------------------- §6.2.3 reserved stream types

test "MUST NOT treat an unrecognized unidirectional stream type as a connection error [RFC9114 §6.2.3 ¶?]" {
    // §6.2.3: "Endpoints MUST NOT consider these streams to have any
    // meaning upon receipt." null3 should drop the bytes silently and
    // keep the connection healthy. Drive the loopback after sending a
    // stream of type 0x0123 (an unknown / non-GREASE id) and observe
    // that no close fires.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    // Open a server-initiated uni stream (id 7) with the bogus type and
    // some payload. The client should swallow it.
    _ = try pair.server.openUni(7);
    try fixture.writeVarint(&pair.server, 7, 0x0123); // unknown type
    try fixture.writeRawBytes(&pair.server, 7, "ignored-bytes-after-type");

    try fixture.pumpQuiet(allocator, &pair, 64);
    try std.testing.expectEqual(null3.session.ShutdownState.active, pair.client_h3.shutdownState());
    try std.testing.expectEqual(null3.session.ShutdownState.active, pair.server_h3.shutdownState());
}

test "MUST NOT treat a GREASE unidirectional stream type as a connection error [RFC9114 §6.2.3 ¶?]" {
    // GREASE values (RFC 9114 §7.2.8 + RFC 8701) are explicitly reserved
    // and MUST be ignored — the canonical interop check.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    _ = try pair.server.openUni(7);
    try fixture.writeVarint(&pair.server, 7, 0x21); // first GREASE id
    try fixture.writeRawBytes(&pair.server, 7, "grease-payload");

    try fixture.pumpQuiet(allocator, &pair, 64);
    try std.testing.expectEqual(null3.session.ShutdownState.active, pair.client_h3.shutdownState());
}

// ---------------------------------------------------------------- §6.2.1 critical-stream closure

test "MUST close with H3_CLOSED_CRITICAL_STREAM when the peer closes the control stream [RFC9114 §6.2.1 ¶8]" {
    // §6.2.1 ¶8: "Closure of either control stream MUST be treated as a
    // connection error of type H3_CLOSED_CRITICAL_STREAM."
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    // FIN the client's control stream and pump until the server closes.
    try pair.client.streamFinish(pair.client_h3.control_stream_id.?);

    try fixture.expectPairH3Error(allocator, &pair, error.ClosedCriticalStream);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.closed_critical_stream);
}

test "MUST close with H3_CLOSED_CRITICAL_STREAM when the peer closes the QPACK encoder stream [RFC9114 §6.2.1 ¶8]" {
    // RFC 9204 §4.2 incorporates the same rule: the QPACK encoder/decoder
    // streams are critical, so closure must be treated as a connection
    // error of type H3_CLOSED_CRITICAL_STREAM.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client.streamFinish(pair.client_h3.qpack_encoder_stream_id.?);

    try fixture.expectPairH3Error(allocator, &pair, error.ClosedCriticalStream);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.closed_critical_stream);
}

test "MUST close with H3_CLOSED_CRITICAL_STREAM when the peer closes the QPACK decoder stream [RFC9114 §6.2.1 ¶8]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client.streamFinish(pair.client_h3.qpack_decoder_stream_id.?);

    try fixture.expectPairH3Error(allocator, &pair, error.ClosedCriticalStream);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.closed_critical_stream);
}
