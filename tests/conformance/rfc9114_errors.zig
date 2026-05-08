//! RFC 9114 §8 — Error Handling, and §11.2.3 — HTTP/3 Error Codes registry.
//!
//! HTTP/3 carries error codes as QUIC application error codes. The numeric
//! values are listed in RFC 9114 §8.1 and registered in §11.2.3, with QPACK
//! extensions defined in RFC 9204 §6 (registered in §8.3) and the
//! H3_DATAGRAM_ERROR addition in RFC 9297 §5.2 (referenced by §2 and §2.1).
//! http3_zig hosts the constants in `src/protocol.zig` (`protocol.ErrorCode.*`)
//! and the classification helpers (`Scope`, `Source`, `Category`,
//! `applicationError`, `classify`, …) in `src/errors.zig`.
//!
//! This suite is the auditor-facing record that:
//!   * every defined code carries the exact value from the IANA registry;
//!   * classification helpers map known codes to the right name + category;
//!   * local-cause classification routes representative errors into the
//!     code the RFC requires for that condition;
//!   * H3_VERSION_FALLBACK is present and routable.
//!
//! ## Coverage
//!
//! Covered (RFC 9114 §11.2.3 HTTP/3 Error Codes registry):
//!   RFC9114 §11.2.3  H3_NO_ERROR                     0x0100
//!   RFC9114 §11.2.3  H3_GENERAL_PROTOCOL_ERROR       0x0101
//!   RFC9114 §11.2.3  H3_INTERNAL_ERROR               0x0102
//!   RFC9114 §11.2.3  H3_STREAM_CREATION_ERROR        0x0103
//!   RFC9114 §11.2.3  H3_CLOSED_CRITICAL_STREAM       0x0104
//!   RFC9114 §11.2.3  H3_FRAME_UNEXPECTED             0x0105
//!   RFC9114 §11.2.3  H3_FRAME_ERROR                  0x0106
//!   RFC9114 §11.2.3  H3_EXCESSIVE_LOAD               0x0107
//!   RFC9114 §11.2.3  H3_ID_ERROR                     0x0108
//!   RFC9114 §11.2.3  H3_SETTINGS_ERROR               0x0109
//!   RFC9114 §11.2.3  H3_MISSING_SETTINGS             0x010a
//!   RFC9114 §11.2.3  H3_REQUEST_REJECTED             0x010b
//!   RFC9114 §11.2.3  H3_REQUEST_CANCELLED            0x010c
//!   RFC9114 §11.2.3  H3_REQUEST_INCOMPLETE           0x010d
//!   RFC9114 §11.2.3  H3_MESSAGE_ERROR                0x010e
//!   RFC9114 §11.2.3  H3_CONNECT_ERROR                0x010f
//!   RFC9114 §11.2.3  H3_VERSION_FALLBACK             0x0110
//!
//! Covered (RFC 9204 §6 + §8.3 QPACK Error Codes):
//!   RFC9204 §6       QPACK_DECOMPRESSION_FAILED      0x0200
//!   RFC9204 §6       QPACK_ENCODER_STREAM_ERROR      0x0201
//!   RFC9204 §6       QPACK_DECODER_STREAM_ERROR      0x0202
//!
//! Covered (RFC 9297 §5.2 HTTP Datagrams Error Code):
//!   RFC9297 §5.2     H3_DATAGRAM_ERROR               0x33
//!
//! Covered (RFC 9114 §8 error-handling semantics):
//!   RFC9114 §8.1   ¶?  NORMATIVE  applicationError(known) returns IANA name + category
//!   RFC9114 §8.1   ¶?  NORMATIVE  applicationError(unknown) marks `known() == false`
//!   RFC9114 §8.1   ¶?  NORMATIVE  request-scoped codes default to stream scope
//!   RFC9114 §8.1   ¶?  NORMATIVE  every other defined code defaults to connection scope
//!   RFC9114 §8.1   ¶?  NORMATIVE  QPACK codes are categorised as Category.qpack
//!   RFC9114 §8.1   ¶?  NORMATIVE  H3_DATAGRAM_ERROR is categorised as Category.datagram
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(MissingSettings)         → H3_MISSING_SETTINGS
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(DuplicateSetting)        → H3_SETTINGS_ERROR
//!   RFC9114 §7.2.4 ¶3  NORMATIVE  classify(DuplicateSettings)       → H3_FRAME_UNEXPECTED
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(FrameUnexpected)         → H3_FRAME_UNEXPECTED
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(InvalidFramePayload)     → H3_FRAME_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(MissingPseudoHeader)     → H3_MESSAGE_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(ClosedCriticalStream)    → H3_CLOSED_CRITICAL_STREAM
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(StreamAlreadyOpen)       → H3_STREAM_CREATION_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(InvalidGoawayId)         → H3_ID_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(InvalidPushId)           → H3_ID_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(InvalidDatagramStream)   → H3_ID_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(PushNotEnabled)          → H3_ID_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(RequestBlockedByGoaway)  → H3_REQUEST_REJECTED + stream scope
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(InvalidConnectUdpPath)   → H3_CONNECT_ERROR + stream scope
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(OutOfMemory)             → H3_INTERNAL_ERROR + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(SendBufferFull)          → H3_INTERNAL_ERROR + stream scope + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(BodyTooLarge)            → H3_INTERNAL_ERROR + stream scope + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(EventQueueFull)          → H3_INTERNAL_ERROR + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(DecodedFieldSectionTooLarge) → H3_MESSAGE_ERROR + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(unmapped)                → H3_GENERAL_PROTOCOL_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(DatagramNotEnabled)      → H3_SETTINGS_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(MalformedEncoderInstr.)  → QPACK_ENCODER_STREAM_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(MalformedDecoderInstr.)  → QPACK_DECODER_STREAM_ERROR
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(MalformedFieldSection)   → QPACK_DECOMPRESSION_FAILED
//!   RFC9297 §2.1   ¶6  MUST       classify(UdpPayloadTooLarge)      → H3_CONNECT_ERROR + stream scope
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(ContextBufferFull)       → H3_CONNECT_ERROR + stream scope + Category.resource
//!   RFC9114 §8.1   ¶?  NORMATIVE  classify(CapsuleTooLarge)         → H3_INTERNAL_ERROR + stream scope + Category.resource
//!   RFC9114 §8     ¶?  NORMATIVE  peerConnectionError carries Source.peer
//!   RFC9114 §8     ¶?  NORMATIVE  localConnectionError carries Source.local + cause name
//!   RFC9114 §8     ¶?  NORMATIVE  localConnectionCode produces a Source.local close
//!   RFC9114 §8     ¶?  NORMATIVE  peerStreamError carries stream id + final size
//!   RFC9114 §8.1   ¶?  NORMATIVE  ApplicationError.isQpack identifies QPACK codes
//!   RFC9114 §8.1   ¶?  NORMATIVE  ApplicationError.isRequestScoped identifies request-stream codes
//!
//! Visible debt:
//!   none — the module exposes every defined code as a named constant.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §5.2    GOAWAY semantics                  → rfc9114_session.zig
//!   RFC9114 §6.2.1  closed-critical-stream detection  → rfc9114_streams.zig
//!   RFC9000 §20.2   QUIC application error encoding   → quic_zig conformance suites

const std = @import("std");
const http3_zig = @import("http3_zig");

const protocol = http3_zig.protocol;
const ErrorCode = protocol.ErrorCode;
const errors = http3_zig.errors;

// ---------------------------------------------------------------- §11.2.3 numeric values

test "MUST encode H3_NO_ERROR as 0x0100 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0100), ErrorCode.no_error);
}

test "MUST encode H3_GENERAL_PROTOCOL_ERROR as 0x0101 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0101), ErrorCode.general_protocol_error);
}

test "MUST encode H3_INTERNAL_ERROR as 0x0102 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0102), ErrorCode.internal_error);
}

test "MUST encode H3_STREAM_CREATION_ERROR as 0x0103 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0103), ErrorCode.stream_creation_error);
}

test "MUST encode H3_CLOSED_CRITICAL_STREAM as 0x0104 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0104), ErrorCode.closed_critical_stream);
}

test "MUST encode H3_FRAME_UNEXPECTED as 0x0105 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0105), ErrorCode.frame_unexpected);
}

test "MUST encode H3_FRAME_ERROR as 0x0106 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0106), ErrorCode.frame_error);
}

test "MUST encode H3_EXCESSIVE_LOAD as 0x0107 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0107), ErrorCode.excess_load);
}

test "MUST encode H3_ID_ERROR as 0x0108 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0108), ErrorCode.id_error);
}

test "MUST encode H3_SETTINGS_ERROR as 0x0109 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0109), ErrorCode.settings_error);
}

test "MUST encode H3_MISSING_SETTINGS as 0x010a [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010a), ErrorCode.missing_settings);
}

test "MUST encode H3_REQUEST_REJECTED as 0x010b [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010b), ErrorCode.request_rejected);
}

test "MUST encode H3_REQUEST_CANCELLED as 0x010c [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010c), ErrorCode.request_cancelled);
}

test "MUST encode H3_REQUEST_INCOMPLETE as 0x010d [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010d), ErrorCode.request_incomplete);
}

test "MUST encode H3_MESSAGE_ERROR as 0x010e [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010e), ErrorCode.message_error);
}

test "MUST encode H3_CONNECT_ERROR as 0x010f [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x010f), ErrorCode.connect_error);
}

test "MUST encode H3_VERSION_FALLBACK as 0x0110 [RFC9114 §11.2.3]" {
    try std.testing.expectEqual(@as(u64, 0x0110), ErrorCode.version_fallback);
}

// ---------------------------------------------------------------- RFC 9204 §6 QPACK

test "MUST encode QPACK_DECOMPRESSION_FAILED as 0x0200 [RFC9204 §6]" {
    try std.testing.expectEqual(@as(u64, 0x0200), ErrorCode.qpack_decompression_failed);
}

test "MUST encode QPACK_ENCODER_STREAM_ERROR as 0x0201 [RFC9204 §6]" {
    try std.testing.expectEqual(@as(u64, 0x0201), ErrorCode.qpack_encoder_stream_error);
}

test "MUST encode QPACK_DECODER_STREAM_ERROR as 0x0202 [RFC9204 §6]" {
    try std.testing.expectEqual(@as(u64, 0x0202), ErrorCode.qpack_decoder_stream_error);
}

// ---------------------------------------------------------------- RFC 9297 §5.2 datagrams

test "MUST encode H3_DATAGRAM_ERROR as 0x33 [RFC9297 §5.2]" {
    try std.testing.expectEqual(@as(u64, 0x33), ErrorCode.datagram_error);
}

// ---------------------------------------------------------------- §8.1 ApplicationError naming

test "NORMATIVE applicationError names H3_NO_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.no_error);
    try std.testing.expectEqualStrings("H3_NO_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.no_error, a.category);
    try std.testing.expect(a.known());
}

test "NORMATIVE applicationError names H3_GENERAL_PROTOCOL_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.general_protocol_error);
    try std.testing.expectEqualStrings("H3_GENERAL_PROTOCOL_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.general, a.category);
    try std.testing.expectEqual(errors.Scope.connection, a.default_scope);
}

test "NORMATIVE applicationError names H3_INTERNAL_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.internal_error);
    try std.testing.expectEqualStrings("H3_INTERNAL_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.internal, a.category);
}

test "NORMATIVE applicationError names H3_STREAM_CREATION_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.stream_creation_error);
    try std.testing.expectEqualStrings("H3_STREAM_CREATION_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.stream_creation, a.category);
}

test "NORMATIVE applicationError names H3_CLOSED_CRITICAL_STREAM [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.closed_critical_stream);
    try std.testing.expectEqualStrings("H3_CLOSED_CRITICAL_STREAM", a.name);
    try std.testing.expectEqual(errors.Category.critical_stream, a.category);
}

test "NORMATIVE applicationError names H3_FRAME_UNEXPECTED [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.frame_unexpected);
    try std.testing.expectEqualStrings("H3_FRAME_UNEXPECTED", a.name);
    try std.testing.expectEqual(errors.Category.frame, a.category);
}

test "NORMATIVE applicationError names H3_FRAME_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.frame_error);
    try std.testing.expectEqualStrings("H3_FRAME_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.frame, a.category);
}

test "NORMATIVE applicationError names H3_EXCESSIVE_LOAD [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.excess_load);
    try std.testing.expectEqualStrings("H3_EXCESSIVE_LOAD", a.name);
    try std.testing.expectEqual(errors.Category.general, a.category);
}

test "NORMATIVE applicationError names H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.id_error);
    try std.testing.expectEqualStrings("H3_ID_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.id, a.category);
}

test "NORMATIVE applicationError names H3_SETTINGS_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.settings_error);
    try std.testing.expectEqualStrings("H3_SETTINGS_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.settings, a.category);
}

test "NORMATIVE applicationError names H3_MISSING_SETTINGS [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.missing_settings);
    try std.testing.expectEqualStrings("H3_MISSING_SETTINGS", a.name);
    try std.testing.expectEqual(errors.Category.settings, a.category);
}

test "NORMATIVE applicationError names H3_REQUEST_REJECTED [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.request_rejected);
    try std.testing.expectEqualStrings("H3_REQUEST_REJECTED", a.name);
    try std.testing.expectEqual(errors.Category.request, a.category);
    try std.testing.expectEqual(errors.Scope.stream, a.default_scope);
    try std.testing.expect(a.isRequestScoped());
}

test "NORMATIVE applicationError names H3_REQUEST_CANCELLED [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.request_cancelled);
    try std.testing.expectEqualStrings("H3_REQUEST_CANCELLED", a.name);
    try std.testing.expectEqual(errors.Category.request, a.category);
    try std.testing.expectEqual(errors.Scope.stream, a.default_scope);
    try std.testing.expect(a.isRequestScoped());
}

test "NORMATIVE applicationError names H3_REQUEST_INCOMPLETE [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.request_incomplete);
    try std.testing.expectEqualStrings("H3_REQUEST_INCOMPLETE", a.name);
    try std.testing.expectEqual(errors.Category.request, a.category);
    try std.testing.expectEqual(errors.Scope.stream, a.default_scope);
}

test "NORMATIVE applicationError names H3_MESSAGE_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.message_error);
    try std.testing.expectEqualStrings("H3_MESSAGE_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.message, a.category);
}

test "NORMATIVE applicationError names H3_CONNECT_ERROR [RFC9114 §8.1 ¶?]" {
    const a = errors.applicationError(ErrorCode.connect_error);
    try std.testing.expectEqualStrings("H3_CONNECT_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.connect, a.category);
    try std.testing.expectEqual(errors.Scope.stream, a.default_scope);
}

test "NORMATIVE applicationError names H3_VERSION_FALLBACK [RFC9114 §8.1]" {
    // §8.1 defines H3_VERSION_FALLBACK (0x0110) — "the requested operation
    // cannot be served over HTTP/3. The peer should retry over HTTP/1.1."
    // The category in our taxonomy is `general` because it's a connection-
    // close signal rather than a behavioural class, and the default scope
    // is connection because the negotiated downgrade necessarily aborts
    // the whole HTTP/3 session.
    const a = errors.applicationError(ErrorCode.version_fallback);
    try std.testing.expectEqualStrings("H3_VERSION_FALLBACK", a.name);
    try std.testing.expectEqual(errors.Category.general, a.category);
    try std.testing.expectEqual(errors.Scope.connection, a.default_scope);
}

// ---------------------------------------------------------------- RFC 9204 §6 + RFC 9297 §5.2 naming

test "NORMATIVE applicationError names QPACK_DECOMPRESSION_FAILED [RFC9204 §6]" {
    const a = errors.applicationError(ErrorCode.qpack_decompression_failed);
    try std.testing.expectEqualStrings("QPACK_DECOMPRESSION_FAILED", a.name);
    try std.testing.expectEqual(errors.Category.qpack, a.category);
    try std.testing.expect(a.isQpack());
}

test "NORMATIVE applicationError names QPACK_ENCODER_STREAM_ERROR [RFC9204 §6]" {
    const a = errors.applicationError(ErrorCode.qpack_encoder_stream_error);
    try std.testing.expectEqualStrings("QPACK_ENCODER_STREAM_ERROR", a.name);
    try std.testing.expect(a.isQpack());
}

test "NORMATIVE applicationError names QPACK_DECODER_STREAM_ERROR [RFC9204 §6]" {
    const a = errors.applicationError(ErrorCode.qpack_decoder_stream_error);
    try std.testing.expectEqualStrings("QPACK_DECODER_STREAM_ERROR", a.name);
    try std.testing.expect(a.isQpack());
}

test "NORMATIVE applicationError names H3_DATAGRAM_ERROR [RFC9297 §5.2]" {
    const a = errors.applicationError(ErrorCode.datagram_error);
    try std.testing.expectEqualStrings("H3_DATAGRAM_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.datagram, a.category);
}

// ---------------------------------------------------------------- §8.1 unknown / classification

test "NORMATIVE applicationError marks an unknown code as unknown [RFC9114 §8.1 ¶?]" {
    // §8.1: receivers MUST NOT generate errors not defined by the
    // protocol, but they can encounter unknown codes from peers. The
    // helper preserves the raw code while flagging unknown.
    const a = errors.applicationError(0xface);
    try std.testing.expect(!a.known());
    try std.testing.expectEqual(errors.Category.unknown, a.category);
    try std.testing.expectEqual(@as(u64, 0xface), a.code);
}

test "NORMATIVE peerConnectionError carries Source.peer [RFC9114 §8 ¶?]" {
    const e = errors.peerConnectionError(ErrorCode.frame_error);
    try std.testing.expectEqual(errors.Source.peer, e.source);
    try std.testing.expectEqual(@as(u64, 0x0106), e.application.code);
}

test "NORMATIVE localConnectionError carries Source.local and cause name [RFC9114 §8 ¶?]" {
    const e = errors.localConnectionError(error.MissingSettings);
    try std.testing.expectEqual(errors.Source.local, e.source);
    try std.testing.expectEqual(@as(u64, 0x010a), e.application.code);
    try std.testing.expect(e.cause != null);
    try std.testing.expectEqualStrings("MissingSettings", e.cause_name.?);
}

test "NORMATIVE localConnectionCode produces a LocalSource ConnectionError [RFC9114 §8 ¶?]" {
    const e = errors.localConnectionCode(ErrorCode.excess_load);
    try std.testing.expectEqual(errors.Source.local, e.source);
    try std.testing.expectEqualStrings("H3_EXCESSIVE_LOAD", e.application.name);
    try std.testing.expect(e.cause == null);
}

test "NORMATIVE peerStreamError preserves stream id and final size [RFC9114 §8 ¶?]" {
    const e = errors.peerStreamError(@as(u64, 4), ErrorCode.request_cancelled, @as(?u64, 17));
    try std.testing.expectEqual(errors.Source.peer, e.source);
    try std.testing.expectEqual(@as(u64, 4), e.stream_id);
    try std.testing.expectEqual(@as(?u64, 17), e.final_size);
    try std.testing.expectEqual(@as(u64, 0x010c), e.application.code);
}

// ---------------------------------------------------------------- §8.1 cause routing (codeForError / classify)

test "NORMATIVE classify(MissingSettings) maps to H3_MISSING_SETTINGS [RFC9114 §8.1 ¶?]" {
    // §6.2.1: the receipt of a non-SETTINGS first frame on the control
    // stream is H3_MISSING_SETTINGS.
    const c = errors.classify(error.MissingSettings);
    try std.testing.expectEqual(ErrorCode.missing_settings, c.application.code);
    try std.testing.expectEqual(errors.Category.settings, c.category);
}

test "NORMATIVE classify(DuplicateSetting) maps to H3_SETTINGS_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.DuplicateSetting);
    try std.testing.expectEqual(ErrorCode.settings_error, c.application.code);
}

test "NORMATIVE classify(InvalidSettingValue) maps to H3_SETTINGS_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InvalidSettingValue);
    try std.testing.expectEqual(ErrorCode.settings_error, c.application.code);
}

test "NORMATIVE classify(FrameUnexpected) maps to H3_FRAME_UNEXPECTED [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.FrameUnexpected);
    try std.testing.expectEqual(ErrorCode.frame_unexpected, c.application.code);
    try std.testing.expectEqual(errors.Category.frame, c.category);
}

test "NORMATIVE classify(InvalidFramePayload) maps to H3_FRAME_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InvalidFramePayload);
    try std.testing.expectEqual(ErrorCode.frame_error, c.application.code);
}

test "NORMATIVE classify(InsufficientBytes) maps to H3_FRAME_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InsufficientBytes);
    try std.testing.expectEqual(ErrorCode.frame_error, c.application.code);
}

test "NORMATIVE classify(MissingPseudoHeader) maps to H3_MESSAGE_ERROR [RFC9114 §8.1 ¶?]" {
    // §4.6: malformed messages (including missing pseudo-headers) map to
    // H3_MESSAGE_ERROR.
    const c = errors.classify(error.MissingPseudoHeader);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
    try std.testing.expectEqual(errors.Category.message, c.category);
}

test "NORMATIVE classify(ConnectionSpecificField) maps to H3_MESSAGE_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.ConnectionSpecificField);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
}

test "NORMATIVE classify(UppercaseFieldName) maps to H3_MESSAGE_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.UppercaseFieldName);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
}

test "NORMATIVE classify(ClosedCriticalStream) maps to H3_CLOSED_CRITICAL_STREAM [RFC9114 §8.1 ¶?]" {
    // §6.2: closing one of the critical unidirectional streams is a
    // connection error of type H3_CLOSED_CRITICAL_STREAM.
    const c = errors.classify(error.ClosedCriticalStream);
    try std.testing.expectEqual(ErrorCode.closed_critical_stream, c.application.code);
}

test "NORMATIVE classify(StreamAlreadyOpen) maps to H3_STREAM_CREATION_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.StreamAlreadyOpen);
    try std.testing.expectEqual(ErrorCode.stream_creation_error, c.application.code);
}

test "NORMATIVE classify(CriticalStreamAlreadyOpen) maps to H3_STREAM_CREATION_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(ErrorCode.stream_creation_error, c.application.code);
}

test "NORMATIVE classify(InvalidGoawayId) maps to H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    // §5.2: a GOAWAY id that grows is H3_ID_ERROR.
    const c = errors.classify(error.InvalidGoawayId);
    try std.testing.expectEqual(ErrorCode.id_error, c.application.code);
}

test "NORMATIVE classify(InvalidPushId) maps to H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InvalidPushId);
    try std.testing.expectEqual(ErrorCode.id_error, c.application.code);
}

test "NORMATIVE classify(RequestBlockedByGoaway) maps to H3_REQUEST_REJECTED with stream scope [RFC9114 §8.1 ¶?]" {
    // §5.2: requests beyond the GOAWAY id are rejected at stream scope so
    // the client may retry on a new connection.
    const c = errors.classify(error.RequestBlockedByGoaway);
    try std.testing.expectEqual(ErrorCode.request_rejected, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
}

test "NORMATIVE classify(InvalidConnectUdpPath) maps to H3_CONNECT_ERROR with stream scope [RFC9114 §8.1 ¶?]" {
    // RFC 9298 §5: bad CONNECT-UDP target path ⇒ stream-scoped H3_CONNECT_ERROR.
    const c = errors.classify(error.InvalidConnectUdpPath);
    try std.testing.expectEqual(ErrorCode.connect_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.connect, c.category);
}

test "NORMATIVE classify(OutOfMemory) maps to H3_INTERNAL_ERROR with Category.resource [RFC9114 §8.1 ¶?]" {
    // §8.1: a local internal failure (memory exhaustion, …) is reported
    // as H3_INTERNAL_ERROR; the cause category is `resource` so callers
    // can apply back-pressure rather than treating it as a protocol bug.
    const c = errors.classify(error.OutOfMemory);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(BufferTooSmall) maps to H3_INTERNAL_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.BufferTooSmall);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
}

test "NORMATIVE classify(unmapped error) maps to H3_GENERAL_PROTOCOL_ERROR [RFC9114 §8.1 ¶?]" {
    // §8.1: unknown / unmapped causes default to H3_GENERAL_PROTOCOL_ERROR.
    const Sentinel = error{NotMappedAtAll};
    const c = errors.classify(Sentinel.NotMappedAtAll);
    try std.testing.expectEqual(ErrorCode.general_protocol_error, c.application.code);
}

test "NORMATIVE classify(DatagramNotEnabled) maps to H3_SETTINGS_ERROR [RFC9114 §8.1 ¶?]" {
    // RFC 9297 §2.1: sending HTTP/3 datagrams without negotiating
    // SETTINGS_H3_DATAGRAM is a settings error.
    const c = errors.classify(error.DatagramNotEnabled);
    try std.testing.expectEqual(ErrorCode.settings_error, c.application.code);
}

test "NORMATIVE classify(MalformedEncoderInstruction) maps to QPACK_ENCODER_STREAM_ERROR [RFC9204 §6]" {
    const c = errors.classify(error.MalformedEncoderInstruction);
    try std.testing.expectEqual(ErrorCode.qpack_encoder_stream_error, c.application.code);
    try std.testing.expectEqual(errors.Category.qpack, c.application.category);
}

test "NORMATIVE classify(MalformedDecoderInstruction) maps to QPACK_DECODER_STREAM_ERROR [RFC9204 §6]" {
    const c = errors.classify(error.MalformedDecoderInstruction);
    try std.testing.expectEqual(ErrorCode.qpack_decoder_stream_error, c.application.code);
}

test "NORMATIVE classify(InsertCountIncrementZero) maps to QPACK_DECODER_STREAM_ERROR [RFC9204 §4.4.3]" {
    // §4.4.3 ¶4: an Insert Count Increment of zero is a connection error
    // of type QPACK_DECODER_STREAM_ERROR.
    const c = errors.classify(error.InsertCountIncrementZero);
    try std.testing.expectEqual(ErrorCode.qpack_decoder_stream_error, c.application.code);
}

test "NORMATIVE classify(MalformedFieldSection) maps to QPACK_DECOMPRESSION_FAILED [RFC9204 §6]" {
    const c = errors.classify(error.MalformedFieldSection);
    try std.testing.expectEqual(ErrorCode.qpack_decompression_failed, c.application.code);
}

test "NORMATIVE classify(InvalidStaticIndex) maps to QPACK_DECOMPRESSION_FAILED [RFC9204 §6]" {
    const c = errors.classify(error.InvalidStaticIndex);
    try std.testing.expectEqual(ErrorCode.qpack_decompression_failed, c.application.code);
}

test "NORMATIVE classify(HuffmanEos) maps to QPACK_DECOMPRESSION_FAILED [RFC9204 §6]" {
    const c = errors.classify(error.HuffmanEos);
    try std.testing.expectEqual(ErrorCode.qpack_decompression_failed, c.application.code);
}

// ---------------------------------------------------------------- §7.2.4 ¶3 + §8.1 additional code-only mappings

test "NORMATIVE classify(DuplicateSettings) maps to H3_FRAME_UNEXPECTED [RFC9114 §7.2.4 ¶3]" {
    // §7.2.4 ¶3: receipt of a second SETTINGS frame on the control stream
    // is a connection error of type H3_FRAME_UNEXPECTED. (The in-frame
    // duplicate-identifier case `DuplicateSetting` (singular) instead
    // maps to H3_SETTINGS_ERROR per §7.2.4 ¶5.)
    const c = errors.classify(error.DuplicateSettings);
    try std.testing.expectEqual(ErrorCode.frame_unexpected, c.application.code);
    try std.testing.expectEqual(errors.Category.frame, c.category);
    try std.testing.expectEqual(errors.Scope.connection, c.scope);
}

test "NORMATIVE classify(InvalidDatagramStream) maps to H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    // RFC 9297 §2.1 ¶12: when an HTTP/3 Datagram references a stream id
    // that exceeds bidirectional-stream limits, the connection SHOULD
    // close with H3_ID_ERROR.
    const c = errors.classify(error.InvalidDatagramStream);
    try std.testing.expectEqual(ErrorCode.id_error, c.application.code);
    try std.testing.expectEqual(errors.Category.id, c.category);
}

test "NORMATIVE classify(PushNotEnabled) maps to H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    // §7.2.5 ¶3 / §6.2.2 ¶6: a PUSH_PROMISE or push-id usage when push
    // has not been negotiated is an H3_ID_ERROR.
    const c = errors.classify(error.PushNotEnabled);
    try std.testing.expectEqual(ErrorCode.id_error, c.application.code);
}

test "NORMATIVE classify(InvalidPriorityTarget) maps to H3_ID_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InvalidPriorityTarget);
    try std.testing.expectEqual(ErrorCode.id_error, c.application.code);
}

test "NORMATIVE classify(ReservedSetting) maps to H3_SETTINGS_ERROR [RFC9114 §7.2.4.1 ¶5]" {
    // §7.2.4.1 ¶5: receiving an HTTP/2-reserved setting id is an
    // H3_SETTINGS_ERROR.
    const c = errors.classify(error.ReservedSetting);
    try std.testing.expectEqual(ErrorCode.settings_error, c.application.code);
    try std.testing.expectEqual(errors.Category.settings, c.category);
}

test "NORMATIVE classify(InvalidLength) maps to H3_FRAME_ERROR [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.InvalidLength);
    try std.testing.expectEqual(ErrorCode.frame_error, c.application.code);
    try std.testing.expectEqual(errors.Category.frame, c.category);
}

test "NORMATIVE classify(DataAfterTrailers) maps to H3_MESSAGE_ERROR [RFC9114 §4.1 ¶14]" {
    // §4.1 ¶14: trailers terminate the message; further DATA is malformed.
    const c = errors.classify(error.DataAfterTrailers);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
}

test "NORMATIVE classify(DuplicatePseudoHeader) maps to H3_MESSAGE_ERROR [RFC9114 §4.3 ¶?]" {
    const c = errors.classify(error.DuplicatePseudoHeader);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
}

test "NORMATIVE classify(PseudoHeaderAfterRegular) maps to H3_MESSAGE_ERROR [RFC9114 §4.3 ¶?]" {
    const c = errors.classify(error.PseudoHeaderAfterRegular);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
}

// ---------------------------------------------------------------- §8.1 + RFC 9297 §2.1 scope/category mappings

test "NORMATIVE classify(SendBufferFull) maps to H3_INTERNAL_ERROR with stream scope and Category.resource [RFC9114 §8.1 ¶?]" {
    // Local back-pressure: callers can recover by retrying without
    // tearing the connection down, so the scope is stream and the
    // category is resource.
    const c = errors.classify(error.SendBufferFull);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(BodyTooLarge) maps to H3_INTERNAL_ERROR with stream scope and Category.resource [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.BodyTooLarge);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(EventQueueFull) maps to H3_INTERNAL_ERROR with Category.resource [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.EventQueueFull);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(CapsuleTooLarge) maps to H3_INTERNAL_ERROR with stream scope and Category.resource [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.CapsuleTooLarge);
    try std.testing.expectEqual(ErrorCode.internal_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(DecodedFieldSectionTooLarge) maps to H3_MESSAGE_ERROR with Category.resource [RFC9114 §4.2.2 ¶?]" {
    // §4.2.2: an overly large decoded field section is treated as a
    // malformed message; the resource flavour distinguishes it from
    // structurally invalid headers.
    const c = errors.classify(error.DecodedFieldSectionTooLarge);
    try std.testing.expectEqual(ErrorCode.message_error, c.application.code);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(UdpPayloadTooLarge) maps to H3_CONNECT_ERROR with stream scope [RFC9297 §2.1 ¶6]" {
    // RFC 9298 / RFC 9297: a CONNECT-UDP payload that exceeds the
    // negotiated MTU is a stream-scoped H3_CONNECT_ERROR.
    const c = errors.classify(error.UdpPayloadTooLarge);
    try std.testing.expectEqual(ErrorCode.connect_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.connect, c.category);
}

test "NORMATIVE classify(ContextBufferFull) maps to H3_CONNECT_ERROR with stream scope and Category.resource [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.ContextBufferFull);
    try std.testing.expectEqual(ErrorCode.connect_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

test "NORMATIVE classify(CapsuleTypeLimitExceeded) maps to H3_CONNECT_ERROR with stream scope and Category.resource [RFC9114 §8.1 ¶?]" {
    const c = errors.classify(error.CapsuleTypeLimitExceeded);
    try std.testing.expectEqual(ErrorCode.connect_error, c.application.code);
    try std.testing.expectEqual(errors.Scope.stream, c.scope);
    try std.testing.expectEqual(errors.Category.resource, c.category);
}

// ---------------------------------------------------------------- §8 unknown-code MUST treat as H3_NO_ERROR

test "NORMATIVE applicationError preserves the raw value of an unknown code [RFC9114 §8 ¶?]" {
    // §8 ¶5: receivers MUST treat an unknown code as equivalent to
    // H3_NO_ERROR. The classifier preserves the raw value so the caller
    // can decide how to handle the close, but flags the code as
    // unrecognised so behaviour layers can apply that rule.
    const a = errors.applicationError(0x4242);
    try std.testing.expect(!a.known());
    try std.testing.expectEqual(@as(u64, 0x4242), a.code);
    try std.testing.expectEqualStrings("UNKNOWN_APPLICATION_ERROR", a.name);
    try std.testing.expectEqual(errors.Category.unknown, a.category);
}

// ---------------------------------------------------------------- §8.1 helpers on ApplicationError

test "NORMATIVE ApplicationError.isQpack identifies QPACK codes [RFC9114 §8.1 ¶?]" {
    try std.testing.expect(errors.applicationError(ErrorCode.qpack_decompression_failed).isQpack());
    try std.testing.expect(errors.applicationError(ErrorCode.qpack_encoder_stream_error).isQpack());
    try std.testing.expect(errors.applicationError(ErrorCode.qpack_decoder_stream_error).isQpack());
    try std.testing.expect(!errors.applicationError(ErrorCode.frame_error).isQpack());
    try std.testing.expect(!errors.applicationError(ErrorCode.no_error).isQpack());
}

test "NORMATIVE ApplicationError.isRequestScoped identifies request-stream codes [RFC9114 §8.1 ¶?]" {
    try std.testing.expect(errors.applicationError(ErrorCode.request_rejected).isRequestScoped());
    try std.testing.expect(errors.applicationError(ErrorCode.request_cancelled).isRequestScoped());
    try std.testing.expect(errors.applicationError(ErrorCode.request_incomplete).isRequestScoped());
    try std.testing.expect(!errors.applicationError(ErrorCode.frame_error).isRequestScoped());
    try std.testing.expect(!errors.applicationError(ErrorCode.connect_error).isRequestScoped());
}

test "NORMATIVE ConnectionError.reason falls back to application name when no cause [RFC9114 §8.1 ¶?]" {
    const e = errors.peerConnectionError(ErrorCode.message_error);
    try std.testing.expectEqualStrings("H3_MESSAGE_ERROR", e.reason());
}

test "NORMATIVE ConnectionError.reason prefers the cause name when present [RFC9114 §8.1 ¶?]" {
    const e = errors.localConnectionError(error.UppercaseFieldName);
    try std.testing.expectEqualStrings("UppercaseFieldName", e.reason());
}

// ---------------------------------------------------------------- §8.1 default scope coverage

test "NORMATIVE all non-request HTTP/3 codes default to connection scope [RFC9114 §8.1 ¶?]" {
    // §8.1: all defined HTTP/3 codes other than the request-stream trio
    // (REJECTED / CANCELLED / INCOMPLETE) plus H3_CONNECT_ERROR (stream
    // for CONNECT semantics) default to connection scope.
    const connection_codes = [_]u64{
        ErrorCode.no_error, // application/connection — see specific test
        ErrorCode.general_protocol_error,
        ErrorCode.internal_error,
        ErrorCode.stream_creation_error,
        ErrorCode.closed_critical_stream,
        ErrorCode.frame_unexpected,
        ErrorCode.frame_error,
        ErrorCode.excess_load,
        ErrorCode.id_error,
        ErrorCode.settings_error,
        ErrorCode.missing_settings,
        ErrorCode.message_error,
        ErrorCode.version_fallback,
        ErrorCode.qpack_decompression_failed,
        ErrorCode.qpack_encoder_stream_error,
        ErrorCode.qpack_decoder_stream_error,
        ErrorCode.datagram_error,
    };
    for (connection_codes) |code| {
        const a = errors.applicationError(code);
        if (code == ErrorCode.no_error) {
            // H3_NO_ERROR is application-scoped (graceful close).
            try std.testing.expectEqual(errors.Scope.application, a.default_scope);
        } else {
            try std.testing.expectEqual(errors.Scope.connection, a.default_scope);
        }
    }
}
