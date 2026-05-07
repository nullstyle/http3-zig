//! RFC 9114 §6, §7.2, §11.2 — HTTP/3 protocol constants and IANA
//! registries: frame-type IDs, unidirectional stream-type IDs,
//! SETTINGS-ID space, error-code space, and the GREASE rule that
//! reserves a uniform infinite subset of every registry.
//!
//! The implementation under test lives in `src/protocol.zig`, surfaced
//! as `null3.protocol`. This suite is the auditor-facing record of the
//! values nullq's HTTP/3 layer recognises and the classification
//! helpers it ships.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §7.2.1 ¶1   MUST     DATA frame type ID is 0x00
//!   RFC9114 §7.2.2 ¶1   MUST     HEADERS frame type ID is 0x01
//!   RFC9114 §7.2.3 ¶1   MUST     CANCEL_PUSH frame type ID is 0x03
//!   RFC9114 §7.2.4 ¶1   MUST     SETTINGS frame type ID is 0x04
//!   RFC9114 §7.2.5 ¶1   MUST     PUSH_PROMISE frame type ID is 0x05
//!   RFC9114 §7.2.6 ¶1   MUST     GOAWAY frame type ID is 0x07
//!   RFC9114 §7.2.7 ¶1   MUST     MAX_PUSH_ID frame type ID is 0x0d
//!   RFC9218 §7.2  ¶3    MUST     PRIORITY_UPDATE Request frame type ID is 0xF0700
//!   RFC9218 §7.2  ¶3    MUST     PRIORITY_UPDATE Push frame type ID is 0xF0701
//!   RFC9114 §7.2.8 ¶3   MUST NOT permit reserved HTTP/2 frame types 0x02/0x06/0x08/0x09 as defined H3 frames
//!   RFC9114 §6.2.1 ¶1   MUST     control stream type ID is 0x00
//!   RFC9114 §6.2.2 ¶2   MUST     push stream type ID is 0x01
//!   RFC9204 §4.2   ¶1   MUST     QPACK encoder stream type ID is 0x02
//!   RFC9204 §4.2   ¶1   MUST     QPACK decoder stream type ID is 0x03
//!   RFC9114 §7.2.4.1¶3  MUST     SETTINGS_QPACK_MAX_TABLE_CAPACITY ID is 0x01
//!   RFC9114 §7.2.4.1¶3  MUST     SETTINGS_MAX_FIELD_SECTION_SIZE ID is 0x06
//!   RFC9114 §7.2.4.1¶3  MUST     SETTINGS_QPACK_BLOCKED_STREAMS ID is 0x07
//!   RFC9220 §3     ¶1   MUST     SETTINGS_ENABLE_CONNECT_PROTOCOL ID is 0x08
//!   RFC9297 §2.1   ¶1   MUST     SETTINGS_H3_DATAGRAM ID is 0x33
//!   RFC9114 §7.2.4.1¶8  MUST NOT honour HTTP/2 reserved SETTINGS IDs 0x00, 0x02–0x05 at the codec
//!   RFC9114 §8.1   ¶1   MUST     H3_NO_ERROR error code is 0x0100
//!   RFC9114 §8.1   ¶1   MUST     H3_GENERAL_PROTOCOL_ERROR error code is 0x0101
//!   RFC9114 §8.1   ¶1   MUST     H3_INTERNAL_ERROR error code is 0x0102
//!   RFC9114 §8.1   ¶1   MUST     H3_STREAM_CREATION_ERROR error code is 0x0103
//!   RFC9114 §8.1   ¶1   MUST     H3_CLOSED_CRITICAL_STREAM error code is 0x0104
//!   RFC9114 §8.1   ¶1   MUST     H3_FRAME_UNEXPECTED error code is 0x0105
//!   RFC9114 §8.1   ¶1   MUST     H3_FRAME_ERROR error code is 0x0106
//!   RFC9114 §8.1   ¶1   MUST     H3_EXCESSIVE_LOAD error code is 0x0107
//!   RFC9114 §8.1   ¶1   MUST     H3_ID_ERROR error code is 0x0108
//!   RFC9114 §8.1   ¶1   MUST     H3_SETTINGS_ERROR error code is 0x0109
//!   RFC9114 §8.1   ¶1   MUST     H3_MISSING_SETTINGS error code is 0x010a
//!   RFC9114 §8.1   ¶1   MUST     H3_REQUEST_REJECTED error code is 0x010b
//!   RFC9114 §8.1   ¶1   MUST     H3_REQUEST_CANCELLED error code is 0x010c
//!   RFC9114 §8.1   ¶1   MUST     H3_REQUEST_INCOMPLETE error code is 0x010d
//!   RFC9114 §8.1   ¶1   MUST     H3_MESSAGE_ERROR error code is 0x010e
//!   RFC9114 §8.1   ¶1   MUST     H3_CONNECT_ERROR error code is 0x010f
//!   RFC9114 §8.1   ¶1   MUST     H3_VERSION_FALLBACK error code is 0x0110
//!   RFC9204 §6     ¶1   MUST     QPACK_DECOMPRESSION_FAILED error code is 0x0200
//!   RFC9204 §6     ¶1   MUST     QPACK_ENCODER_STREAM_ERROR error code is 0x0201
//!   RFC9204 §6     ¶1   MUST     QPACK_DECODER_STREAM_ERROR error code is 0x0202
//!   RFC9297 §5.2   ¶1   MUST     H3_DATAGRAM_ERROR error code is 0x33
//!   RFC9114 §7.2.8 ¶1   MUST     reserve `0x1f * N + 0x21` values as GREASE in every registry
//!   RFC9114 §3.1   ¶3   MUST     ALPN identifier is "h3"
//!
//! Visible debt:
//!   none — every constant the public API exposes has an audit test here.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9114 §7.2.4 SETTINGS frame codec               → rfc9114_settings.zig
//!   RFC9114 §7.2.* individual frame codecs            → rfc9114_frames.zig
//!   RFC9114 §6.2  control-stream / push-stream rules  → rfc9114_streams.zig
//!   RFC9114 §8    error-code escalation semantics     → rfc9114_errors.zig

const std = @import("std");
const null3 = @import("null3");

const protocol = null3.protocol;

// ---------------------------------------------------------------- §6.1 ALPN

test "MUST advertise the ALPN identifier \"h3\" for HTTP/3 over QUIC v1 [RFC9114 §3.1 ¶3]" {
    // §3.1 ¶3: "This document creates a new registration for the
    // identification of HTTP/3 ('h3') in the 'TLS Application-Layer
    // Protocol Negotiation (ALPN) Protocol IDs' registry."
    try std.testing.expectEqualStrings("h3", protocol.alpn_h3);
    try std.testing.expectEqual(@as(usize, 1), protocol.alpn_protocols.len);
    try std.testing.expectEqualStrings("h3", protocol.alpn_protocols[0]);
}

// ---------------------------------------------------------------- §7.2.* frame-type IDs

test "MUST register the DATA frame type at value 0x00 [RFC9114 §7.2.1 ¶1]" {
    // §7.2.1 ¶1: "DATA frames (type=0x00) convey arbitrary, variable-
    // length sequences of bytes associated with HTTP request or
    // response content."
    try std.testing.expectEqual(@as(u64, 0x00), protocol.FrameType.data);
}

test "MUST register the HEADERS frame type at value 0x01 [RFC9114 §7.2.2 ¶1]" {
    // §7.2.2 ¶1: "The HEADERS frame (type=0x01) is used to carry an
    // HTTP field section that is encoded using QPACK."
    try std.testing.expectEqual(@as(u64, 0x01), protocol.FrameType.headers);
}

test "MUST register the CANCEL_PUSH frame type at value 0x03 [RFC9114 §7.2.3 ¶1]" {
    // §7.2.3 ¶1: "The CANCEL_PUSH frame (type=0x03) is used to request
    // cancellation of a server push prior to the push stream being
    // received."
    try std.testing.expectEqual(@as(u64, 0x03), protocol.FrameType.cancel_push);
}

test "MUST register the SETTINGS frame type at value 0x04 [RFC9114 §7.2.4 ¶1]" {
    // §7.2.4 ¶1: "The SETTINGS frame (type=0x04) conveys configuration
    // parameters that affect how endpoints communicate."
    try std.testing.expectEqual(@as(u64, 0x04), protocol.FrameType.settings);
}

test "MUST register the PUSH_PROMISE frame type at value 0x05 [RFC9114 §7.2.5 ¶1]" {
    // §7.2.5 ¶1: "The PUSH_PROMISE frame (type=0x05) is used to carry
    // a promised request header section from server to client on a
    // request stream."
    try std.testing.expectEqual(@as(u64, 0x05), protocol.FrameType.push_promise);
}

test "MUST register the GOAWAY frame type at value 0x07 [RFC9114 §7.2.6 ¶1]" {
    // §7.2.6 ¶1: "The GOAWAY frame (type=0x07) is used to initiate
    // graceful shutdown of an HTTP/3 connection by either endpoint."
    try std.testing.expectEqual(@as(u64, 0x07), protocol.FrameType.goaway);
}

test "MUST register the MAX_PUSH_ID frame type at value 0x0d [RFC9114 §7.2.7 ¶1]" {
    // §7.2.7 ¶1: "The MAX_PUSH_ID frame (type=0x0D) is used by clients
    // to control the number of server pushes that the server can
    // initiate."
    try std.testing.expectEqual(@as(u64, 0x0d), protocol.FrameType.max_push_id);
}

test "MUST register the PRIORITY_UPDATE Request frame type at value 0xF0700 [RFC9218 §7.2 ¶3]" {
    // RFC 9218 §7.2 ¶3 / IANA: "PRIORITY_UPDATE (request)" carries the
    // type 0xF0700, identifying a priority update for a request
    // stream's prioritized element ID.
    try std.testing.expectEqual(@as(u64, 0xF0700), protocol.FrameType.priority_update_request);
}

test "MUST register the PRIORITY_UPDATE Push frame type at value 0xF0701 [RFC9218 §7.2 ¶3]" {
    // RFC 9218 §7.2 ¶3 / IANA: "PRIORITY_UPDATE (push)" carries the
    // type 0xF0701, identifying a priority update for a push stream's
    // prioritized element ID.
    try std.testing.expectEqual(@as(u64, 0xF0701), protocol.FrameType.priority_update_push);
}

// ---------------------------------------------------------------- §7.2.8 reserved HTTP/2 frame types

test "MUST treat HTTP/2 PRIORITY (0x02) as a reserved frame type [RFC9114 §7.2.8 ¶3]" {
    // §7.2.8 ¶3: "Frame types that were used in HTTP/2 where there is
    // no corresponding HTTP/3 frame have also been reserved (Section
    // 11.2.1). These frame types MUST NOT be sent, and their receipt
    // MUST be treated as a connection error of type
    // H3_FRAME_UNEXPECTED." 0x02 is HTTP/2 PRIORITY.
    try std.testing.expect(protocol.isReservedHttp2FrameType(0x02));
}

test "MUST treat HTTP/2 PING (0x06) as a reserved frame type [RFC9114 §7.2.8 ¶3]" {
    try std.testing.expect(protocol.isReservedHttp2FrameType(0x06));
}

test "MUST treat HTTP/2 WINDOW_UPDATE (0x08) as a reserved frame type [RFC9114 §7.2.8 ¶3]" {
    try std.testing.expect(protocol.isReservedHttp2FrameType(0x08));
}

test "MUST treat HTTP/2 CONTINUATION (0x09) as a reserved frame type [RFC9114 §7.2.8 ¶3]" {
    try std.testing.expect(protocol.isReservedHttp2FrameType(0x09));
}

test "MUST NOT classify defined HTTP/3 frame types as reserved HTTP/2 types [RFC9114 §7.2.8 ¶3]" {
    // The defined HTTP/3 frame types (DATA, HEADERS, CANCEL_PUSH, ...)
    // are categorically distinct from the §7.2.8 reservation set.
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.data));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.headers));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.cancel_push));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.settings));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.push_promise));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.goaway));
    try std.testing.expect(!protocol.isReservedHttp2FrameType(protocol.FrameType.max_push_id));
}

test "MUST classify all defined HTTP/3 frame types as known [RFC9114 §7.2 ¶1]" {
    // §7.2 ¶1: "This section describes HTTP/3 frame types defined in
    // this document". A receiver's "is this a frame I know?" gate must
    // return true for every defined frame, including the RFC 9218
    // PRIORITY_UPDATE pair.
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.data));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.headers));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.cancel_push));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.settings));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.push_promise));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.goaway));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.max_push_id));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.priority_update_request));
    try std.testing.expect(protocol.isKnownFrameType(protocol.FrameType.priority_update_push));
}

test "MUST NOT classify reserved HTTP/2 frame types as known HTTP/3 frame types [RFC9114 §7.2.8 ¶3]" {
    // §7.2.8 ¶3 reserves these IDs; they have no HTTP/3 semantics so
    // `isKnownFrameType` MUST return false. (The receive-side rule —
    // close the connection if such a frame arrives — is exercised in
    // rfc9114_streams.zig / rfc9114_errors.zig.)
    try std.testing.expect(!protocol.isKnownFrameType(0x02));
    try std.testing.expect(!protocol.isKnownFrameType(0x06));
    try std.testing.expect(!protocol.isKnownFrameType(0x08));
    try std.testing.expect(!protocol.isKnownFrameType(0x09));
}

test "MUST NOT classify an unallocated frame type ID as known [RFC9114 §7.2 ¶3]" {
    // §7.2 ¶3: "Implementations MUST ignore unknown or unsupported
    // values in all extensible protocol elements." The classification
    // helper backs that rule by saying "unknown".
    try std.testing.expect(!protocol.isKnownFrameType(0xdead_beef));
    try std.testing.expect(!protocol.isKnownFrameType(0x4242));
}

// ---------------------------------------------------------------- §6.2 unidirectional stream-type IDs

test "MUST register the control stream type at value 0x00 [RFC9114 §6.2.1 ¶1]" {
    // §6.2.1 ¶1: "A control stream is indicated by a stream type of
    // 0x00."
    try std.testing.expectEqual(@as(u64, 0x00), protocol.StreamType.control);
}

test "MUST register the push stream type at value 0x01 [RFC9114 §6.2.2 ¶2]" {
    // §6.2.2 ¶2: "A push stream is indicated by a stream type of 0x01,
    // followed by the push ID of the promise that it fulfills, encoded
    // as a variable-length integer."
    try std.testing.expectEqual(@as(u64, 0x01), protocol.StreamType.push);
}

test "MUST register the QPACK encoder stream type at value 0x02 [RFC9204 §4.2 ¶1]" {
    // RFC 9204 §4.2: "The encoder stream is unidirectional; it is
    // identified by a stream type of 0x02."
    try std.testing.expectEqual(@as(u64, 0x02), protocol.StreamType.qpack_encoder);
}

test "MUST register the QPACK decoder stream type at value 0x03 [RFC9204 §4.2 ¶1]" {
    // RFC 9204 §4.2: "The decoder stream is unidirectional; it is
    // identified by a stream type of 0x03."
    try std.testing.expectEqual(@as(u64, 0x03), protocol.StreamType.qpack_decoder);
}

// ---------------------------------------------------------------- §7.2.4.1 SETTINGS-ID values

test "MUST register SETTINGS_QPACK_MAX_TABLE_CAPACITY at ID 0x01 [RFC9204 §5 ¶3]" {
    // RFC 9204 §5 / IANA: "QPACK_MAX_TABLE_CAPACITY (0x01)" — note this
    // sits in the HTTP/3 SETTINGS-ID registry per RFC 9114 §11.2.2.
    try std.testing.expectEqual(@as(u64, 0x01), protocol.SettingId.qpack_max_table_capacity);
}

test "MUST register SETTINGS_MAX_FIELD_SECTION_SIZE at ID 0x06 [RFC9114 §7.2.4.1 ¶3]" {
    // §7.2.4.1 ¶3: "SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): The
    // default value is unlimited."
    try std.testing.expectEqual(@as(u64, 0x06), protocol.SettingId.max_field_section_size);
}

test "MUST register SETTINGS_QPACK_BLOCKED_STREAMS at ID 0x07 [RFC9204 §5 ¶3]" {
    try std.testing.expectEqual(@as(u64, 0x07), protocol.SettingId.qpack_blocked_streams);
}

test "MUST register SETTINGS_ENABLE_CONNECT_PROTOCOL at ID 0x08 [RFC9220 §3 ¶1]" {
    // RFC 9220 §3 ¶1: "This document defines the
    // SETTINGS_ENABLE_CONNECT_PROTOCOL setting (with identifier 0x08)."
    try std.testing.expectEqual(@as(u64, 0x08), protocol.SettingId.enable_connect_protocol);
}

test "MUST register SETTINGS_H3_DATAGRAM at ID 0x33 [RFC9297 §2.1 ¶1]" {
    // RFC 9297 §2.1 ¶1: "An HTTP/3 endpoint indicates support of HTTP
    // Datagrams using the SETTINGS_H3_DATAGRAM (0x33) HTTP/3 SETTINGS
    // parameter."
    try std.testing.expectEqual(@as(u64, 0x33), protocol.SettingId.h3_datagram);
}

// ---------------------------------------------------------------- §7.2.4.1 reserved HTTP/2 SETTINGS

test "MUST treat SETTINGS ID 0x00 as reserved (HTTP/2 collision) [RFC9114 §7.2.4.1 ¶8]" {
    // §7.2.4.1 ¶8: "Setting identifiers of the format `0x1f * N + 0x21`
    // ... Setting identifiers that were defined in HTTP/2 ... [0x02
    // through 0x05] MUST NOT be sent, and a value with this identifier
    // MUST be treated as a connection error of type
    // H3_SETTINGS_ERROR." 0x00 is unused in HTTP/2 SETTINGS, but
    // nullq's classification helper groups it with the reserved set so
    // the codec rejects it identically.
    try std.testing.expect(protocol.isReservedHttp2Setting(0x00));
}

test "MUST treat HTTP/2 SETTINGS_HEADER_TABLE_SIZE (0x02) as reserved [RFC9114 §7.2.4.1 ¶8]" {
    // §7.2.4.1 ¶8: HTTP/2 setting 0x02 MUST NOT be sent over HTTP/3.
    try std.testing.expect(protocol.isReservedHttp2Setting(0x02));
}

test "MUST treat HTTP/2 SETTINGS_ENABLE_PUSH (0x03) as reserved [RFC9114 §7.2.4.1 ¶8]" {
    try std.testing.expect(protocol.isReservedHttp2Setting(0x03));
}

test "MUST treat HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS (0x04) as reserved [RFC9114 §7.2.4.1 ¶8]" {
    try std.testing.expect(protocol.isReservedHttp2Setting(0x04));
}

test "MUST treat HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE (0x05) as reserved [RFC9114 §7.2.4.1 ¶8]" {
    try std.testing.expect(protocol.isReservedHttp2Setting(0x05));
}

test "MUST NOT treat defined HTTP/3 SETTINGS IDs as reserved-HTTP/2 [RFC9114 §7.2.4.1 ¶8]" {
    // The §7.2.4.1 reservation set excludes IDs that HTTP/3 defines
    // for itself (0x01, 0x06, 0x07, 0x08, 0x33). nullq's classifier
    // must keep them disjoint.
    try std.testing.expect(!protocol.isReservedHttp2Setting(protocol.SettingId.qpack_max_table_capacity));
    try std.testing.expect(!protocol.isReservedHttp2Setting(protocol.SettingId.max_field_section_size));
    try std.testing.expect(!protocol.isReservedHttp2Setting(protocol.SettingId.qpack_blocked_streams));
    try std.testing.expect(!protocol.isReservedHttp2Setting(protocol.SettingId.enable_connect_protocol));
    try std.testing.expect(!protocol.isReservedHttp2Setting(protocol.SettingId.h3_datagram));
}

test "MUST NOT treat ID 0x06 (MAX_FIELD_SECTION_SIZE) as a reserved HTTP/2 setting [RFC9114 §7.2.4.1 ¶3]" {
    // 0x06 was assigned in HTTP/2 (SETTINGS_MAX_HEADER_LIST_SIZE), but
    // RFC 9114 §7.2.4.1 ¶3 defines its HTTP/3 successor — so it must
    // pass the codec's reserved-HTTP/2 gate.
    try std.testing.expect(!protocol.isReservedHttp2Setting(0x06));
}

// ---------------------------------------------------------------- §8.1 / §11.2.3 error codes

test "MUST register H3_NO_ERROR at code 0x0100 [RFC9114 §8.1 ¶1]" {
    // §8.1 ¶1 / Table 5: "H3_NO_ERROR (0x0100): No error. This is used
    // when the connection or stream needs to be closed, but there is
    // no error to signal."
    try std.testing.expectEqual(@as(u64, 0x0100), protocol.ErrorCode.no_error);
}

test "MUST register H3_GENERAL_PROTOCOL_ERROR at code 0x0101 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0101), protocol.ErrorCode.general_protocol_error);
}

test "MUST register H3_INTERNAL_ERROR at code 0x0102 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0102), protocol.ErrorCode.internal_error);
}

test "MUST register H3_STREAM_CREATION_ERROR at code 0x0103 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0103), protocol.ErrorCode.stream_creation_error);
}

test "MUST register H3_CLOSED_CRITICAL_STREAM at code 0x0104 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0104), protocol.ErrorCode.closed_critical_stream);
}

test "MUST register H3_FRAME_UNEXPECTED at code 0x0105 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0105), protocol.ErrorCode.frame_unexpected);
}

test "MUST register H3_FRAME_ERROR at code 0x0106 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0106), protocol.ErrorCode.frame_error);
}

test "MUST register H3_EXCESSIVE_LOAD at code 0x0107 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0107), protocol.ErrorCode.excess_load);
}

test "MUST register H3_ID_ERROR at code 0x0108 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0108), protocol.ErrorCode.id_error);
}

test "MUST register H3_SETTINGS_ERROR at code 0x0109 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0109), protocol.ErrorCode.settings_error);
}

test "MUST register H3_MISSING_SETTINGS at code 0x010a [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010a), protocol.ErrorCode.missing_settings);
}

test "MUST register H3_REQUEST_REJECTED at code 0x010b [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010b), protocol.ErrorCode.request_rejected);
}

test "MUST register H3_REQUEST_CANCELLED at code 0x010c [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010c), protocol.ErrorCode.request_cancelled);
}

test "MUST register H3_REQUEST_INCOMPLETE at code 0x010d [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010d), protocol.ErrorCode.request_incomplete);
}

test "MUST register H3_MESSAGE_ERROR at code 0x010e [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010e), protocol.ErrorCode.message_error);
}

test "MUST register H3_CONNECT_ERROR at code 0x010f [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x010f), protocol.ErrorCode.connect_error);
}

test "MUST register H3_VERSION_FALLBACK at code 0x0110 [RFC9114 §8.1 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0110), protocol.ErrorCode.version_fallback);
}

test "MUST register QPACK_DECOMPRESSION_FAILED at code 0x0200 [RFC9204 §6 ¶1]" {
    // RFC 9204 §6: QPACK_DECOMPRESSION_FAILED (0x0200) is registered
    // in the HTTP/3 application error-code space.
    try std.testing.expectEqual(@as(u64, 0x0200), protocol.ErrorCode.qpack_decompression_failed);
}

test "MUST register QPACK_ENCODER_STREAM_ERROR at code 0x0201 [RFC9204 §6 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0201), protocol.ErrorCode.qpack_encoder_stream_error);
}

test "MUST register QPACK_DECODER_STREAM_ERROR at code 0x0202 [RFC9204 §6 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x0202), protocol.ErrorCode.qpack_decoder_stream_error);
}

test "MUST register H3_DATAGRAM_ERROR at code 0x33 [RFC9297 §5.2 ¶1]" {
    // RFC 9297 §5.2 ¶1: "H3_DATAGRAM_ERROR (0x33): An error occurred
    // when handling HTTP Datagrams." Registered in the HTTP/3
    // application error-code space.
    try std.testing.expectEqual(@as(u64, 0x33), protocol.ErrorCode.datagram_error);
}

// ---------------------------------------------------------------- §7.2.8 / RFC 8701 GREASE rule

test "MUST classify the GREASE base value 0x21 as reserved-for-greasing [RFC9114 §7.2.8 ¶1]" {
    // §7.2.8 ¶1 / RFC 8701: "Frame types of the format `0x1f * N +
    // 0x21` for non-negative integer values of N are reserved to
    // exercise the requirement that unknown types be ignored." N=0
    // gives 0x21.
    try std.testing.expect(protocol.isGreaseValue(0x21));
}

test "MUST classify GREASE values for N=1..4 as reserved-for-greasing [RFC9114 §7.2.8 ¶1]" {
    // 0x1f * 1 + 0x21 = 0x40
    // 0x1f * 2 + 0x21 = 0x5f
    // 0x1f * 3 + 0x21 = 0x7e
    // 0x1f * 4 + 0x21 = 0x9d
    try std.testing.expect(protocol.isGreaseValue(0x40));
    try std.testing.expect(protocol.isGreaseValue(0x5f));
    try std.testing.expect(protocol.isGreaseValue(0x7e));
    try std.testing.expect(protocol.isGreaseValue(0x9d));
}

test "MUST classify a high-N GREASE value as reserved-for-greasing [RFC9114 §7.2.8 ¶1]" {
    // Pick a value far up the curve to exercise the modulo arithmetic
    // in the classifier — N=1000 → 0x1f * 1000 + 0x21 = 31_000 + 33 =
    // 31_033 = 0x7939.
    const grease_n_1000: u64 = 0x1f * 1000 + 0x21;
    try std.testing.expect(protocol.isGreaseValue(grease_n_1000));
}

test "MUST NOT classify defined HTTP/3 frame types as GREASE [RFC9114 §7.2.8 ¶1]" {
    // The defined frame-type IDs 0x00, 0x01, 0x03, 0x04, 0x05, 0x07,
    // 0x0d, 0xF0700, 0xF0701 must all fail the GREASE predicate so the
    // codec doesn't accidentally elect them for unknown-type
    // tolerance.
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.data));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.headers));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.cancel_push));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.settings));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.push_promise));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.goaway));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.max_push_id));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.priority_update_request));
    try std.testing.expect(!protocol.isGreaseValue(protocol.FrameType.priority_update_push));
}

test "MUST NOT classify defined HTTP/3 SETTINGS IDs as GREASE [RFC9114 §7.2.4.1 ¶7]" {
    // §7.2.4.1 ¶7 reserves GREASE setting identifiers identically;
    // the IDs HTTP/3 uses MUST stay outside that set.
    try std.testing.expect(!protocol.isGreaseValue(protocol.SettingId.qpack_max_table_capacity));
    try std.testing.expect(!protocol.isGreaseValue(protocol.SettingId.max_field_section_size));
    try std.testing.expect(!protocol.isGreaseValue(protocol.SettingId.qpack_blocked_streams));
    try std.testing.expect(!protocol.isGreaseValue(protocol.SettingId.enable_connect_protocol));
    try std.testing.expect(!protocol.isGreaseValue(protocol.SettingId.h3_datagram));
}

test "MUST NOT classify a value below 0x21 as GREASE [RFC9114 §7.2.8 ¶1]" {
    // 0x21 is the smallest GREASE value; everything below cannot
    // satisfy `0x1f * N + 0x21` with N >= 0.
    try std.testing.expect(!protocol.isGreaseValue(0x00));
    try std.testing.expect(!protocol.isGreaseValue(0x20));
    try std.testing.expect(!protocol.isGreaseValue(0x10));
}

test "MUST NOT classify a value just past a GREASE point as GREASE [RFC9114 §7.2.8 ¶1]" {
    // 0x21 is GREASE, 0x22 is not — the modulo gate must be exact.
    try std.testing.expect(!protocol.isGreaseValue(0x22));
    try std.testing.expect(!protocol.isGreaseValue(0x41)); // just past 0x40 GREASE
    try std.testing.expect(!protocol.isGreaseValue(0x60)); // just past 0x5f GREASE
}
