//! WebTransport-over-HTTP/3 helpers
//! (draft-ietf-webtrans-http3-15, July 2025 revision).
//!
//! This module covers the protocol primitives that sit on top of the
//! existing Extended CONNECT, HTTP/3 Datagrams, and Capsule Protocol
//! plumbing:
//!
//! - Handshake classification (`:protocol = webtransport`).
//! - Settings advertisement (`SETTINGS_WT_ENABLED`, draft-15 §9.2).
//! - Per-stream framing prefix (uni stream type 0x54, bidi frame type 0x41,
//!   each followed by the WebTransport Session ID).
//! - `CLOSE_WEBTRANSPORT_SESSION` (0x2843) and
//!   `DRAIN_WEBTRANSPORT_SESSION` (0x78ae) capsules.
//! - Stream error-code mapping between the application's 32-bit WebTransport
//!   error code and the underlying QUIC stream error code.
//!
//! WebTransport datagrams use the existing HTTP/3 DATAGRAM payload codec
//! unchanged: the request stream that opened the WebTransport session
//! supplies the Quarter Stream ID, exactly as for any other Extended CONNECT
//! tunnel.

const std = @import("std");
const quic_zig = @import("quic_zig");

const capsule_mod = @import("capsule.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const settings_mod = @import("settings.zig");

const varint = quic_zig.wire.varint;

pub const protocol_token = "webtransport";

/// HTTP field name (lowercased per RFC 9114 §4.2) for the client-offered
/// list of WebTransport subprotocols. Per draft-ietf-webtrans-http3 §3.4
/// the value is a structured-fields sf-list of tokens.
pub const available_protocols_header = "wt-available-protocols";

/// HTTP field name for the server-selected WebTransport subprotocol
/// (draft-ietf-webtrans-http3 §3.4). Value is a single sf-token.
pub const protocol_header = "wt-protocol";

/// Maximum reason-phrase length carried in a `CLOSE_WEBTRANSPORT_SESSION`
/// capsule (draft-ietf-webtrans-http3 §5.4): the encoded value MUST NOT
/// exceed 4 + 1024 = 1028 bytes, so the reason phrase has at most 1024 UTF-8
/// bytes.
pub const max_close_reason_len: usize = 1024;

/// Soft cap on the number of subprotocols an incoming WebTransport
/// request may offer before we surface a parser error. Bounds the
/// allocation `parseAvailableProtocols` performs.
pub const max_subprotocol_count: usize = 64;

/// Soft cap on the on-wire length of a single subprotocol token.
/// Tokens above this are treated as malformed.
pub const max_subprotocol_len: usize = 128;

/// The peer SHOULD reset a buffered WebTransport stream with this code when
/// the corresponding session has been closed (draft-ietf-webtrans-http3 §4.6).
pub const buffered_stream_rejected_code: u64 = 0x3994bd84;

/// The peer SHOULD reset a stream associated with a session that no longer
/// exists with this code (draft-ietf-webtrans-http3 §4.6).
pub const session_gone_code: u64 = 0x170d7b68;

/// `WT_FLOW_CONTROL_ERROR` from draft-ietf-webtrans-http3-15 §9.5.
/// Sent by an endpoint that detects a flow-control violation in the
/// session (peer sent more bytes than `local_max_data`, or opened more
/// streams than `local_max_streams_*`). Maps to a WebTransport
/// application error code via `appErrorToHttp3`.
pub const flow_control_error_code: u64 = 0x045d4487;

/// `WT_ALPN_ERROR` from draft-ietf-webtrans-http3-15 §9.5.
/// Sent on the CONNECT stream's RESET when application-protocol
/// negotiation (the `wt-available-protocols` / `wt-protocol` exchange)
/// fails — e.g. the server can't honor any client-offered subprotocol.
pub const alpn_error_code: u64 = 0x0817b3dd;

/// `WT_REQUIREMENTS_NOT_MET` from draft-ietf-webtrans-http3-15 §9.5.
/// Sent when the peer's SETTINGS or transport parameters fail to meet
/// a requirement the application needed (e.g. a WT extension setting
/// the peer didn't advertise). The session-bootstrap path returns
/// `error.WebTransportSettingsMissing` internally; this is the
/// matching wire code for closing in that scenario.
pub const requirements_not_met_code: u64 = 0x212c0d48;

pub const SettingId = struct {
    pub const wt_enabled: u64 = protocol.SettingId.wt_enabled;
    /// Initial peer-bound `WT_MAX_DATA` value (bytes). See
    /// `protocol.SettingId.wt_initial_max_data`.
    pub const wt_initial_max_data: u64 = protocol.SettingId.wt_initial_max_data;
    /// Initial peer-bound `WT_MAX_STREAMS_UNI` value. See
    /// `protocol.SettingId.wt_initial_max_streams_uni`.
    pub const wt_initial_max_streams_uni: u64 = protocol.SettingId.wt_initial_max_streams_uni;
    /// Initial peer-bound `WT_MAX_STREAMS_BIDI` value. See
    /// `protocol.SettingId.wt_initial_max_streams_bidi`.
    pub const wt_initial_max_streams_bidi: u64 = protocol.SettingId.wt_initial_max_streams_bidi;
};

pub const StreamPrefix = struct {
    /// Unidirectional WebTransport stream type (draft-ietf-webtrans-http3 §4.1).
    pub const uni_stream_type: u64 = protocol.StreamType.webtransport_uni_stream;
    /// Bidirectional WebTransport stream-frame type (draft-ietf-webtrans-http3 §4.2).
    pub const bidi_frame_type: u64 = protocol.FrameType.webtransport_bidi_stream;
};

pub const CapsuleType = struct {
    pub const close_session: u64 = 0x2843;
    pub const drain_session: u64 = 0x78ae;
    /// WT_MAX_DATA capsule (draft-ietf-webtrans-http3-13 §5.6.4 / §9.6).
    /// Verified against the IANA "Capsule Types" registry table in
    /// the draft published 2025-09-25.
    pub const max_data: u64 = 0x190b4d3d;
    /// WT_MAX_STREAMS_BIDI capsule (draft-ietf-webtrans-http3-13 §5.6.2).
    pub const max_streams_bidi: u64 = 0x190b4d3f;
    /// WT_MAX_STREAMS_UNI capsule (draft-ietf-webtrans-http3-13 §5.6.2).
    pub const max_streams_uni: u64 = 0x190b4d40;
    /// WT_DATA_BLOCKED capsule (draft-ietf-webtrans-http3-13 §5.6.5).
    pub const data_blocked: u64 = 0x190b4d41;
    /// WT_STREAMS_BLOCKED_BIDI capsule (draft-ietf-webtrans-http3-13 §5.6.3).
    pub const streams_blocked_bidi: u64 = 0x190b4d43;
    /// WT_STREAMS_BLOCKED_UNI capsule (draft-ietf-webtrans-http3-13 §5.6.3).
    pub const streams_blocked_uni: u64 = 0x190b4d44;
};

pub const Error = error{
    NotWebTransport,
    InvalidAcceptStatus,
    InvalidStreamPrefix,
    InvalidCloseCapsule,
    InvalidDrainCapsule,
    InvalidWebTransportSessionId,
    UnknownWebTransportCapsule,
    WebTransportSettingsMissing,
    CloseReasonTooLarge,
    BufferTooSmall,
    /// One of the offered subprotocols is empty, contains
    /// HTTP-disallowed characters, or exceeds `max_subprotocol_len`.
    InvalidSubprotocolToken,
    /// `wt-available-protocols` listed more than `max_subprotocol_count`
    /// distinct entries.
    TooManySubprotocols,
    /// `acceptWebTransport` was given a subprotocol that the client did
    /// not offer in `wt-available-protocols`.
    SubprotocolNotOffered,
    /// The peer's SETTINGS do not advertise WebTransport support
    /// (`SETTINGS_WT_ENABLED`, `H3_DATAGRAM`, and
    /// `ENABLE_CONNECT_PROTOCOL` are all required per
    /// draft-ietf-webtrans-http3-15 §9.2). Returned eagerly from
    /// `Client.startWebTransport` and `Server.acceptWebTransport`
    /// so the application doesn't commit to a session the peer
    /// cannot drive.
    PeerDidNotEnableWebTransport,
    /// The peer's SETTINGS frame has not yet arrived. WebTransport
    /// bootstrap is gated on having received the peer's SETTINGS
    /// (so we can inspect `peerEnabled`), per RFC 9114 §7.2.4 and
    /// draft-ietf-webtrans-http3-15 §9.2. Caller should pump the
    /// session loop until `Session.peer_settings != null` and retry.
    PeerSettingsNotReceived,
};

pub const ConnectOptions = struct {
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    headers: []const qpack.FieldLine = &.{},
    /// Optional list of WebTransport subprotocols the client is willing
    /// to use, in preference order
    /// (draft-ietf-webtrans-http3 §3.4). Tokens MUST match the HTTP token
    /// grammar (RFC 9110 §5.6.2); validation is enforced when the
    /// `wt-available-protocols` header is built.
    subprotocols: []const []const u8 = &.{},
};

pub const AcceptOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    /// Server-selected WebTransport subprotocol. When present, MUST be a
    /// member of the client's `wt-available-protocols` list — the
    /// `acceptWebTransport` helper enforces this with
    /// `error.SubprotocolNotOffered`.
    subprotocol: ?[]const u8 = null,
};

pub fn isProtocolToken(value: []const u8) bool {
    return std.mem.eql(u8, value, protocol_token);
}

pub fn requestProtocol(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, ":protocol");
}

pub fn isRequest(fields: []const qpack.FieldLine) bool {
    const method = fieldValue(fields, ":method") orelse return false;
    const token = requestProtocol(fields) orelse return false;
    return std.mem.eql(u8, method, "CONNECT") and isProtocolToken(token);
}

pub fn isAcceptedStatus(status: []const u8) bool {
    if (status.len != 3 or status[0] != '2') return false;
    return std.ascii.isDigit(status[1]) and std.ascii.isDigit(status[2]);
}

pub fn responseAccepted(fields: []const qpack.FieldLine) bool {
    const status = fieldValue(fields, ":status") orelse return false;
    return isAcceptedStatus(status);
}

/// Returns true if the peer's SETTINGS advertise WebTransport per
/// draft-ietf-webtrans-http3-15 §3.1: extended CONNECT enabled, HTTP/3
/// datagrams enabled, and the draft-15 `SETTINGS_WT_ENABLED` codepoint
/// (`0x2c7cf000`) sent with a non-zero value.
pub fn peerEnabled(s: settings_mod.Settings) bool {
    if (!s.enable_connect_protocol) return false;
    if (!s.h3_datagram) return false;
    return s.wt_enabled;
}

/// Validates that the given local settings are sufficient to bootstrap a
/// WebTransport session. The client and server both need
/// `H3_DATAGRAM` and `SETTINGS_WT_ENABLED`; the server additionally
/// needs `ENABLE_CONNECT_PROTOCOL`. (Per draft-ietf-webtrans-http3-15
/// §3.1, both endpoints MUST send `SETTINGS_WT_ENABLED > 0`.)
pub fn validateLocalSettings(role: protocol.Role, s: settings_mod.Settings) Error!void {
    if (!s.h3_datagram) return error.WebTransportSettingsMissing;
    if (!s.wt_enabled) return error.WebTransportSettingsMissing;
    switch (role) {
        .client => {},
        .server => {
            if (!s.enable_connect_protocol) return error.WebTransportSettingsMissing;
        },
    }
}

// ---------------------------------------------------------------------------
// Subprotocol negotiation (draft-ietf-webtrans-http3 §3.4)
// ---------------------------------------------------------------------------

/// Returns the value of the `wt-available-protocols` request header (case-
/// folded by RFC 9114 §4.2 to lowercase) if present.
pub fn requestAvailableProtocolsRaw(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, available_protocols_header);
}

/// Returns the value of the `wt-protocol` response header if present.
pub fn responseSelectedProtocolRaw(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, protocol_header);
}

/// Validates a single WebTransport subprotocol token. Tokens MUST match the
/// HTTP token grammar (RFC 9110 §5.6.2): a non-empty sequence of `tchar`
/// bytes. Anything wider would not survive the structured-fields encoding
/// the spec defines for `wt-available-protocols` / `wt-protocol`.
pub fn validateSubprotocolToken(token: []const u8) Error!void {
    if (token.len == 0 or token.len > max_subprotocol_len) return error.InvalidSubprotocolToken;
    for (token) |c| {
        if (!isHttpTchar(c)) return error.InvalidSubprotocolToken;
    }
}

/// Computes the encoded length of a `wt-available-protocols` value built
/// from `tokens`, assuming the comma-separated, no-whitespace encoding used
/// by `formatAvailableProtocols`. Returns
/// `error.InvalidSubprotocolToken` for malformed entries.
pub fn availableProtocolsEncodedLen(tokens: []const []const u8) Error!usize {
    if (tokens.len == 0) return 0;
    if (tokens.len > max_subprotocol_count) return error.TooManySubprotocols;
    var total: usize = 0;
    for (tokens, 0..) |token, i| {
        try validateSubprotocolToken(token);
        if (i != 0) total += 1; // comma separator
        total += token.len;
    }
    return total;
}

/// Encodes `tokens` into `dst` as a comma-separated list, the simplest
/// form of the structured-fields sf-list grammar that the
/// `wt-available-protocols` header accepts. Each token is validated.
pub fn formatAvailableProtocols(dst: []u8, tokens: []const []const u8) Error!usize {
    const total = try availableProtocolsEncodedLen(tokens);
    if (dst.len < total) return error.BufferTooSmall;
    var pos: usize = 0;
    for (tokens, 0..) |token, i| {
        if (i != 0) {
            dst[pos] = ',';
            pos += 1;
        }
        @memcpy(dst[pos .. pos + token.len], token);
        pos += token.len;
    }
    return pos;
}

/// Allocator-flavoured form of `formatAvailableProtocols`. The returned
/// slice is owned by the caller.
pub fn allocAvailableProtocols(
    allocator: std.mem.Allocator,
    tokens: []const []const u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    const total = try availableProtocolsEncodedLen(tokens);
    if (total == 0) return allocator.alloc(u8, 0);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    _ = try formatAvailableProtocols(buf, tokens);
    return buf;
}

pub const ParsedAvailableProtocols = struct {
    /// Owned slice of borrowed sub-slices into the input header value.
    /// Caller frees the outer slice; the inner []const u8 do not need
    /// freeing.
    tokens: [][]const u8,

    pub fn deinit(self: ParsedAvailableProtocols, allocator: std.mem.Allocator) void {
        allocator.free(self.tokens);
    }
};

/// Parses a `wt-available-protocols` value into individual subprotocol
/// tokens. Borrows from `value` — callers must keep that buffer alive
/// (typically via the request reader's `headers()` slice). Splits on
/// commas, trims surrounding whitespace, and rejects malformed tokens.
pub fn parseAvailableProtocols(
    allocator: std.mem.Allocator,
    value: []const u8,
) (Error || std.mem.Allocator.Error)!ParsedAvailableProtocols {
    var count: usize = 0;
    {
        var it = std.mem.splitScalar(u8, value, ',');
        while (it.next()) |raw| {
            const token = std.mem.trim(u8, raw, " \t");
            if (token.len == 0 and value.len == 0 and count == 0) break;
            count += 1;
            if (count > max_subprotocol_count) return error.TooManySubprotocols;
        }
    }

    if (count == 0) {
        return .{ .tokens = try allocator.alloc([]const u8, 0) };
    }

    const tokens = try allocator.alloc([]const u8, count);
    errdefer allocator.free(tokens);

    var idx: usize = 0;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        try validateSubprotocolToken(token);
        tokens[idx] = token;
        idx += 1;
    }

    return .{ .tokens = tokens };
}

/// Returns true if `selected` appears in the comma-separated
/// `wt-available-protocols` value.
pub fn isOfferedProtocol(available_value: []const u8, selected: []const u8) bool {
    var it = std.mem.splitScalar(u8, available_value, ',');
    while (it.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, token, selected)) return true;
    }
    return false;
}

fn isHttpTchar(c: u8) bool {
    if (std.ascii.isAlphanumeric(c)) return true;
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Stream framing prefix
// ---------------------------------------------------------------------------

pub const StreamKind = enum { uni, bidi };

pub const StreamHeader = struct {
    kind: StreamKind,
    session_id: u64,
};

pub const StreamHeaderDecoded = struct {
    header: StreamHeader,
    bytes_read: usize,
};

pub fn streamPrefixEncodedLen(kind: StreamKind, session_id: u64) usize {
    const prefix_type: u64 = switch (kind) {
        .uni => StreamPrefix.uni_stream_type,
        .bidi => StreamPrefix.bidi_frame_type,
    };
    return varint.encodedLen(prefix_type) + varint.encodedLen(session_id);
}

pub fn encodeStreamPrefix(dst: []u8, kind: StreamKind, session_id: u64) Error!usize {
    const prefix_type: u64 = switch (kind) {
        .uni => StreamPrefix.uni_stream_type,
        .bidi => StreamPrefix.bidi_frame_type,
    };
    var pos: usize = 0;
    pos += varint.encode(dst[pos..], prefix_type) catch |err| return mapVarintError(err);
    pos += varint.encode(dst[pos..], session_id) catch |err| return mapVarintError(err);
    return pos;
}

pub fn encodeUniStreamPrefix(dst: []u8, session_id: u64) Error!usize {
    return encodeStreamPrefix(dst, .uni, session_id);
}

pub fn encodeBidiStreamPrefix(dst: []u8, session_id: u64) Error!usize {
    return encodeStreamPrefix(dst, .bidi, session_id);
}

pub fn decodeStreamHeader(kind: StreamKind, src: []const u8) Error!StreamHeaderDecoded {
    const expected_type: u64 = switch (kind) {
        .uni => StreamPrefix.uni_stream_type,
        .bidi => StreamPrefix.bidi_frame_type,
    };
    var pos: usize = 0;
    const type_dec = varint.decode(src) catch |err| return mapVarintError(err);
    if (type_dec.value != expected_type) return error.InvalidStreamPrefix;
    pos += type_dec.bytes_read;
    const sid_dec = varint.decode(src[pos..]) catch |err| return mapVarintError(err);
    pos += sid_dec.bytes_read;
    return .{
        .header = .{ .kind = kind, .session_id = sid_dec.value },
        .bytes_read = pos,
    };
}

/// Decodes a WebTransport stream prefix without prior knowledge of the kind
/// (caller already knows the underlying QUIC stream is uni vs. bidi by
/// stream-id parity).
pub fn decodeAnyStreamHeader(src: []const u8) Error!StreamHeaderDecoded {
    const type_dec = varint.decode(src) catch |err| return mapVarintError(err);
    const kind: StreamKind = switch (type_dec.value) {
        StreamPrefix.uni_stream_type => .uni,
        StreamPrefix.bidi_frame_type => .bidi,
        else => return error.InvalidStreamPrefix,
    };
    const sid_dec = varint.decode(src[type_dec.bytes_read..]) catch |err| return mapVarintError(err);
    return .{
        .header = .{ .kind = kind, .session_id = sid_dec.value },
        .bytes_read = type_dec.bytes_read + sid_dec.bytes_read,
    };
}

// ---------------------------------------------------------------------------
// CLOSE_WEBTRANSPORT_SESSION / DRAIN_WEBTRANSPORT_SESSION capsules
// ---------------------------------------------------------------------------

pub const CloseSession = struct {
    code: u32,
    reason: []const u8,
};

pub fn closeSessionValueLen(reason_len: usize) Error!usize {
    if (reason_len > max_close_reason_len) return error.CloseReasonTooLarge;
    return 4 + reason_len;
}

pub fn closeSessionEncodedLen(reason_len: usize) Error!usize {
    const value_len = try closeSessionValueLen(reason_len);
    return capsule_mod.encodedLen(CapsuleType.close_session, value_len);
}

pub fn encodeCloseSessionValue(dst: []u8, code: u32, reason: []const u8) Error!usize {
    if (reason.len > max_close_reason_len) return error.CloseReasonTooLarge;
    if (dst.len < 4 + reason.len) return error.BufferTooSmall;
    std.mem.writeInt(u32, dst[0..4], code, .big);
    @memcpy(dst[4 .. 4 + reason.len], reason);
    return 4 + reason.len;
}

pub fn encodeCloseSession(dst: []u8, code: u32, reason: []const u8) Error!usize {
    if (reason.len > max_close_reason_len) return error.CloseReasonTooLarge;
    var value_buf: [4 + max_close_reason_len]u8 = undefined;
    const value_len = encodeCloseSessionValue(&value_buf, code, reason) catch |err| return err;
    return capsule_mod.encode(dst, CapsuleType.close_session, value_buf[0..value_len]) catch |err| switch (err) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => |e| mapVarintError(e),
    };
}

pub fn decodeCloseSessionValue(src: []const u8) Error!CloseSession {
    if (src.len < 4) return error.InvalidCloseCapsule;
    if (src.len > 4 + max_close_reason_len) return error.InvalidCloseCapsule;
    const reason = src[4..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidCloseCapsule;
    return .{
        .code = std.mem.readInt(u32, src[0..4], .big),
        .reason = reason,
    };
}

pub fn drainSessionValueLen() usize {
    return 0;
}

pub fn drainSessionEncodedLen() usize {
    return capsule_mod.encodedLen(CapsuleType.drain_session, 0);
}

pub fn encodeDrainSession(dst: []u8) Error!usize {
    return capsule_mod.encode(dst, CapsuleType.drain_session, &.{}) catch |err| switch (err) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => |e| mapVarintError(e),
    };
}

// ---------------------------------------------------------------------------
// Flow-control capsules (draft-ietf-webtrans-http3-13 §5.6)
// ---------------------------------------------------------------------------
//
// Each of WT_MAX_DATA, WT_DATA_BLOCKED, WT_MAX_STREAMS_{BIDI,UNI}, and
// WT_STREAMS_BLOCKED_{BIDI,UNI} carries a single QUIC varint as its value
// (Maximum Data or Maximum Streams). The codec helpers here mirror the
// CLOSE / DRAIN style: a `*ValueLen`/`*EncodedLen` pair plus
// `encode<Capsule>` / `decode<Capsule>Value`. Decoders consume only the
// capsule VALUE bytes (the framed type/length envelope is stripped by
// `capsule_mod.decode`).

/// Length of the on-wire VALUE for a single-varint flow-control capsule.
pub fn flowControlValueLen(value: u64) usize {
    return varint.encodedLen(value);
}

/// Length of a fully-framed single-varint flow-control capsule.
fn flowControlEncodedLen(capsule_type: u64, value: u64) usize {
    return capsule_mod.encodedLen(capsule_type, varint.encodedLen(value));
}

fn encodeFlowControlValue(dst: []u8, value: u64) Error!usize {
    return varint.encode(dst, value) catch |err| switch (err) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => |e| mapVarintError(e),
    };
}

fn encodeFlowControlCapsule(dst: []u8, capsule_type: u64, value: u64) Error!usize {
    var value_buf: [varint.max_len]u8 = undefined;
    const value_len = encodeFlowControlValue(&value_buf, value) catch |err| return err;
    return capsule_mod.encode(dst, capsule_type, value_buf[0..value_len]) catch |err| switch (err) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => |e| mapVarintError(e),
    };
}

/// Decodes the VALUE of a single-varint flow-control capsule. The input
/// MUST be exactly the encoded varint with no trailing bytes
/// (draft-ietf-webtrans-http3-13 §5.6.{2..5}). Returns
/// `error.InvalidCloseCapsule` for any malformed value, mirroring the
/// catch-all malformed-WT-capsule mapping used for CLOSE_WEBTRANSPORT_SESSION.
fn decodeFlowControlValue(src: []const u8) Error!u64 {
    if (src.len == 0) return error.InvalidCloseCapsule;
    const decoded = varint.decode(src) catch return error.InvalidCloseCapsule;
    if (decoded.bytes_read != src.len) return error.InvalidCloseCapsule;
    return decoded.value;
}

pub fn maxDataValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn maxDataEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.max_data, value);
}

pub fn encodeMaxDataValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeMaxData(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.max_data, value);
}

pub fn decodeMaxDataValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

pub fn dataBlockedValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn dataBlockedEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.data_blocked, value);
}

pub fn encodeDataBlockedValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeDataBlocked(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.data_blocked, value);
}

pub fn decodeDataBlockedValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

pub fn maxStreamsBidiValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn maxStreamsBidiEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.max_streams_bidi, value);
}

pub fn encodeMaxStreamsBidiValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeMaxStreamsBidi(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.max_streams_bidi, value);
}

pub fn decodeMaxStreamsBidiValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

pub fn streamsBlockedBidiValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn streamsBlockedBidiEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.streams_blocked_bidi, value);
}

pub fn encodeStreamsBlockedBidiValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeStreamsBlockedBidi(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.streams_blocked_bidi, value);
}

pub fn decodeStreamsBlockedBidiValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

pub fn maxStreamsUniValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn maxStreamsUniEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.max_streams_uni, value);
}

pub fn encodeMaxStreamsUniValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeMaxStreamsUni(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.max_streams_uni, value);
}

pub fn decodeMaxStreamsUniValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

pub fn streamsBlockedUniValueLen(value: u64) usize {
    return flowControlValueLen(value);
}

pub fn streamsBlockedUniEncodedLen(value: u64) usize {
    return flowControlEncodedLen(CapsuleType.streams_blocked_uni, value);
}

pub fn encodeStreamsBlockedUniValue(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlValue(dst, value);
}

pub fn encodeStreamsBlockedUni(dst: []u8, value: u64) Error!usize {
    return encodeFlowControlCapsule(dst, CapsuleType.streams_blocked_uni, value);
}

pub fn decodeStreamsBlockedUniValue(src: []const u8) Error!u64 {
    return decodeFlowControlValue(src);
}

/// Classified WebTransport capsule. Capsules outside the WebTransport
/// registry are surfaced as `.other` so callers can pass them along unchanged.
pub const CapsuleEvent = union(enum) {
    close_session: CloseSession,
    drain_session: void,
    /// WT_MAX_DATA value (bytes the receiver is willing to accept on the
    /// session, draft-ietf-webtrans-http3-13 §5.6.4).
    max_data: u64,
    /// WT_DATA_BLOCKED value (the session-level limit at which the sender
    /// blocked, draft-ietf-webtrans-http3-13 §5.6.5).
    data_blocked: u64,
    /// WT_MAX_STREAMS_BIDI value (cumulative bidi streams allowed,
    /// draft-ietf-webtrans-http3-13 §5.6.2).
    max_streams_bidi: u64,
    /// WT_STREAMS_BLOCKED_BIDI value (the bidi stream limit at which the
    /// sender blocked, draft-ietf-webtrans-http3-13 §5.6.3).
    streams_blocked_bidi: u64,
    /// WT_MAX_STREAMS_UNI value (cumulative uni streams allowed,
    /// draft-ietf-webtrans-http3-13 §5.6.2).
    max_streams_uni: u64,
    /// WT_STREAMS_BLOCKED_UNI value (the uni stream limit at which the
    /// sender blocked, draft-ietf-webtrans-http3-13 §5.6.3).
    streams_blocked_uni: u64,
    other: capsule_mod.Capsule,

    pub fn isClose(self: CapsuleEvent) bool {
        return switch (self) {
            .close_session => true,
            else => false,
        };
    }

    pub fn isDrain(self: CapsuleEvent) bool {
        return switch (self) {
            .drain_session => true,
            else => false,
        };
    }
};

pub fn classifyCapsule(c: capsule_mod.Capsule) Error!CapsuleEvent {
    return switch (c.capsule_type) {
        CapsuleType.close_session => .{ .close_session = try decodeCloseSessionValue(c.value) },
        CapsuleType.drain_session => blk: {
            if (c.value.len != 0) return error.InvalidDrainCapsule;
            break :blk .{ .drain_session = {} };
        },
        CapsuleType.max_data => .{ .max_data = try decodeMaxDataValue(c.value) },
        CapsuleType.data_blocked => .{ .data_blocked = try decodeDataBlockedValue(c.value) },
        CapsuleType.max_streams_bidi => .{ .max_streams_bidi = try decodeMaxStreamsBidiValue(c.value) },
        CapsuleType.streams_blocked_bidi => .{ .streams_blocked_bidi = try decodeStreamsBlockedBidiValue(c.value) },
        CapsuleType.max_streams_uni => .{ .max_streams_uni = try decodeMaxStreamsUniValue(c.value) },
        CapsuleType.streams_blocked_uni => .{ .streams_blocked_uni = try decodeStreamsBlockedUniValue(c.value) },
        else => .{ .other = c },
    };
}

// ---------------------------------------------------------------------------
// Error-code mapping for streams within a WebTransport session
// (draft-ietf-webtrans-http3 §4.6)
// ---------------------------------------------------------------------------

const wt_error_first: u64 = 0x52e4a40fa8db;
/// One stride is 30 application codes mapped to 31 wire codes (the extra slot
/// preserves a GREASE-like gap so reserved QUIC codes never collide with WT).
const wt_error_stride_app: u64 = 30;
const wt_error_stride_wire: u64 = 31;
const wt_app_max: u64 = std.math.maxInt(u32);
const wt_error_last: u64 = blk: {
    const last_app = wt_app_max;
    break :blk wt_error_first + last_app + (last_app / wt_error_stride_app);
};

/// Maps a 32-bit application WebTransport stream error code to the
/// corresponding QUIC stream error code on the wire.
pub fn appErrorToHttp3(app_code: u32) u64 {
    const n: u64 = app_code;
    return wt_error_first + n + (n / wt_error_stride_app);
}

/// Reverse of `appErrorToHttp3`. Returns null if the QUIC error code does
/// not fall inside the WebTransport range or lands on a stride boundary
/// reserved by the spec.
pub fn http3ToAppError(wire_code: u64) ?u32 {
    if (wire_code < wt_error_first) return null;
    if (wire_code > wt_error_last) return null;
    const offset = wire_code - wt_error_first;
    // Boundary: (offset+1) % 31 == 0 — reserved gap; not a valid app code.
    if ((offset + 1) % wt_error_stride_wire == 0) return null;
    const n = offset - (offset / wt_error_stride_wire);
    if (n > wt_app_max) return null;
    return @intCast(n);
}

pub fn isReservedStreamCode(wire_code: u64) bool {
    return wire_code == buffered_stream_rejected_code or wire_code == session_gone_code;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn mapVarintError(err: anyerror) Error {
    return switch (err) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => error.InvalidStreamPrefix,
    };
}

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "WebTransport request classification" {
    const request = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
        .{ .name = ":protocol", .value = protocol_token },
    };
    try std.testing.expect(isRequest(&request));
    try std.testing.expectEqualStrings(protocol_token, requestProtocol(&request).?);

    const accepted = [_]qpack.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expect(responseAccepted(&accepted));
    try std.testing.expect(isAcceptedStatus("204"));
    try std.testing.expect(!isAcceptedStatus("101"));
    try std.testing.expect(!isAcceptedStatus("404"));
}

test "peerEnabled requires datagrams, extended CONNECT, and SETTINGS_WT_ENABLED" {
    try std.testing.expect(peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    }));
    try std.testing.expect(!peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = false,
    }));
    try std.testing.expect(!peerEnabled(.{
        .enable_connect_protocol = true,
        .h3_datagram = false,
        .wt_enabled = true,
    }));
    try std.testing.expect(!peerEnabled(.{
        .enable_connect_protocol = false,
        .h3_datagram = true,
        .wt_enabled = true,
    }));
    try std.testing.expect(!peerEnabled(.{}));
}

test "validateLocalSettings enforces role-specific minima" {
    // Client must send SETTINGS_WT_ENABLED + H3_DATAGRAM. The
    // server-only `enable_connect_protocol` setting isn't required
    // on the client side.
    try validateLocalSettings(.client, .{ .h3_datagram = true, .wt_enabled = true });
    try std.testing.expectError(
        error.WebTransportSettingsMissing,
        validateLocalSettings(.client, .{ .h3_datagram = true, .wt_enabled = false }),
    );
    try std.testing.expectError(
        error.WebTransportSettingsMissing,
        validateLocalSettings(.client, .{ .h3_datagram = false, .wt_enabled = true }),
    );

    // Server additionally needs `enable_connect_protocol`.
    try validateLocalSettings(.server, .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    });
    try std.testing.expectError(
        error.WebTransportSettingsMissing,
        validateLocalSettings(.server, .{
            .h3_datagram = true,
            .wt_enabled = true,
        }),
    );
    try std.testing.expectError(
        error.WebTransportSettingsMissing,
        validateLocalSettings(.server, .{
            .enable_connect_protocol = true,
            .h3_datagram = true,
            .wt_enabled = false,
        }),
    );
}

test "WebTransport stream prefix round-trip (uni)" {
    var buf: [16]u8 = undefined;
    const n = try encodeUniStreamPrefix(&buf, 4);
    try std.testing.expectEqual(streamPrefixEncodedLen(.uni, 4), n);

    const decoded = try decodeStreamHeader(.uni, buf[0..n]);
    try std.testing.expectEqual(StreamKind.uni, decoded.header.kind);
    try std.testing.expectEqual(@as(u64, 4), decoded.header.session_id);
    try std.testing.expectEqual(n, decoded.bytes_read);

    const any = try decodeAnyStreamHeader(buf[0..n]);
    try std.testing.expectEqual(StreamKind.uni, any.header.kind);
    try std.testing.expectEqual(@as(u64, 4), any.header.session_id);
}

test "WebTransport stream prefix round-trip (bidi)" {
    var buf: [16]u8 = undefined;
    const n = try encodeBidiStreamPrefix(&buf, 16);
    try std.testing.expectEqual(streamPrefixEncodedLen(.bidi, 16), n);

    const decoded = try decodeStreamHeader(.bidi, buf[0..n]);
    try std.testing.expectEqual(StreamKind.bidi, decoded.header.kind);
    try std.testing.expectEqual(@as(u64, 16), decoded.header.session_id);

    const any = try decodeAnyStreamHeader(buf[0..n]);
    try std.testing.expectEqual(StreamKind.bidi, any.header.kind);
}

test "WebTransport stream prefix rejects mismatched type" {
    var buf: [16]u8 = undefined;
    const n = try encodeUniStreamPrefix(&buf, 4);
    try std.testing.expectError(error.InvalidStreamPrefix, decodeStreamHeader(.bidi, buf[0..n]));
}

test "CLOSE_WEBTRANSPORT_SESSION capsule round-trip" {
    var buf: [128]u8 = undefined;
    const n = try encodeCloseSession(&buf, 0xdeadbeef, "bye");
    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.close_session), decoded.capsule.capsule_type);

    const close = try decodeCloseSessionValue(decoded.capsule.value);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), close.code);
    try std.testing.expectEqualStrings("bye", close.reason);

    const event = try classifyCapsule(decoded.capsule);
    try std.testing.expect(event.isClose());
}

test "CLOSE_WEBTRANSPORT_SESSION rejects oversized reasons and invalid UTF-8" {
    var huge: [max_close_reason_len + 1]u8 = undefined;
    @memset(&huge, 'x');
    var buf: [max_close_reason_len + 32]u8 = undefined;
    try std.testing.expectError(error.CloseReasonTooLarge, encodeCloseSession(&buf, 0, &huge));

    var bad_utf8 = [_]u8{ 0, 0, 0, 0, 0xff, 0xff };
    try std.testing.expectError(error.InvalidCloseCapsule, decodeCloseSessionValue(&bad_utf8));
}

test "DRAIN_WEBTRANSPORT_SESSION capsule round-trip" {
    var buf: [16]u8 = undefined;
    const n = try encodeDrainSession(&buf);
    try std.testing.expectEqual(drainSessionEncodedLen(), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.drain_session), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(usize, 0), decoded.capsule.value.len);

    const event = try classifyCapsule(decoded.capsule);
    try std.testing.expect(event.isDrain());
}

test "classifyCapsule treats unrelated capsules as opaque" {
    const datagram_capsule = capsule_mod.Capsule{
        .capsule_type = capsule_mod.Type.datagram,
        .value = "raw",
    };
    const event = try classifyCapsule(datagram_capsule);
    switch (event) {
        .other => |c| try std.testing.expectEqualStrings("raw", c.value),
        else => return error.UnexpectedClassification,
    }
}

test "appErrorToHttp3 / http3ToAppError round-trip on sample codes" {
    const samples = [_]u32{ 0, 1, 29, 30, 31, 100, std.math.maxInt(u32) };
    for (samples) |app| {
        const wire = appErrorToHttp3(app);
        try std.testing.expectEqual(@as(?u32, app), http3ToAppError(wire));
    }
    try std.testing.expectEqual(@as(?u32, null), http3ToAppError(0));
    try std.testing.expectEqual(@as(?u32, null), http3ToAppError(wt_error_first - 1));
    // The reserved boundary slot one above `f(29)` MUST NOT decode back to an
    // app code (draft-ietf-webtrans-http3 §4.6).
    try std.testing.expectEqual(@as(?u32, null), http3ToAppError(wt_error_first + 30));
}

test "isReservedStreamCode classifies session/buffered codes" {
    try std.testing.expect(isReservedStreamCode(buffered_stream_rejected_code));
    try std.testing.expect(isReservedStreamCode(session_gone_code));
    try std.testing.expect(!isReservedStreamCode(0));
    try std.testing.expect(!isReservedStreamCode(appErrorToHttp3(0)));
}

test "WT_MAX_DATA capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.4)" {
    var buf: [32]u8 = undefined;
    const n = try encodeMaxData(&buf, 0x1234_5678);
    try std.testing.expectEqual(maxDataEncodedLen(0x1234_5678), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.max_data), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 0x1234_5678), try decodeMaxDataValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .max_data => |v| try std.testing.expectEqual(@as(u64, 0x1234_5678), v),
        else => return error.UnexpectedClassification,
    }
}

test "WT_DATA_BLOCKED capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.5)" {
    var buf: [32]u8 = undefined;
    const n = try encodeDataBlocked(&buf, 42);
    try std.testing.expectEqual(dataBlockedEncodedLen(42), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.data_blocked), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 42), try decodeDataBlockedValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .data_blocked => |v| try std.testing.expectEqual(@as(u64, 42), v),
        else => return error.UnexpectedClassification,
    }
}

test "WT_MAX_STREAMS_BIDI capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.2)" {
    var buf: [32]u8 = undefined;
    const n = try encodeMaxStreamsBidi(&buf, 99);
    try std.testing.expectEqual(maxStreamsBidiEncodedLen(99), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.max_streams_bidi), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 99), try decodeMaxStreamsBidiValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .max_streams_bidi => |v| try std.testing.expectEqual(@as(u64, 99), v),
        else => return error.UnexpectedClassification,
    }
}

test "WT_STREAMS_BLOCKED_BIDI capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.3)" {
    var buf: [32]u8 = undefined;
    const n = try encodeStreamsBlockedBidi(&buf, 7);
    try std.testing.expectEqual(streamsBlockedBidiEncodedLen(7), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.streams_blocked_bidi), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 7), try decodeStreamsBlockedBidiValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .streams_blocked_bidi => |v| try std.testing.expectEqual(@as(u64, 7), v),
        else => return error.UnexpectedClassification,
    }
}

test "WT_MAX_STREAMS_UNI capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.2)" {
    var buf: [32]u8 = undefined;
    const n = try encodeMaxStreamsUni(&buf, 1024);
    try std.testing.expectEqual(maxStreamsUniEncodedLen(1024), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.max_streams_uni), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 1024), try decodeMaxStreamsUniValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .max_streams_uni => |v| try std.testing.expectEqual(@as(u64, 1024), v),
        else => return error.UnexpectedClassification,
    }
}

test "WT_STREAMS_BLOCKED_UNI capsule round-trip (draft-ietf-webtrans-http3-13 §5.6.3)" {
    var buf: [32]u8 = undefined;
    const n = try encodeStreamsBlockedUni(&buf, 3);
    try std.testing.expectEqual(streamsBlockedUniEncodedLen(3), n);

    const decoded = try capsule_mod.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, CapsuleType.streams_blocked_uni), decoded.capsule.capsule_type);
    try std.testing.expectEqual(@as(u64, 3), try decodeStreamsBlockedUniValue(decoded.capsule.value));

    const event = try classifyCapsule(decoded.capsule);
    switch (event) {
        .streams_blocked_uni => |v| try std.testing.expectEqual(@as(u64, 3), v),
        else => return error.UnexpectedClassification,
    }
}

test "flow-control capsule decoders reject empty and trailing-garbage values" {
    // Empty value rejected.
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxDataValue(&.{}));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeDataBlockedValue(&.{}));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxStreamsBidiValue(&.{}));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeStreamsBlockedBidiValue(&.{}));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxStreamsUniValue(&.{}));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeStreamsBlockedUniValue(&.{}));

    // Trailing bytes after the varint are rejected: 0x00 is a 1-byte
    // varint for 0, so an extra byte must be a parse error.
    const trailing = [_]u8{ 0x00, 0x00 };
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxDataValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeDataBlockedValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxStreamsBidiValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeStreamsBlockedBidiValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeMaxStreamsUniValue(&trailing));
    try std.testing.expectError(error.InvalidCloseCapsule, decodeStreamsBlockedUniValue(&trailing));
}

test "flow-control capsule encoders surface BufferTooSmall" {
    var buf: [1]u8 = undefined; // 1 byte cannot hold even the type varint.
    try std.testing.expectError(error.BufferTooSmall, encodeMaxData(&buf, 0));
    try std.testing.expectError(error.BufferTooSmall, encodeDataBlocked(&buf, 0));
    try std.testing.expectError(error.BufferTooSmall, encodeMaxStreamsBidi(&buf, 0));
    try std.testing.expectError(error.BufferTooSmall, encodeStreamsBlockedBidi(&buf, 0));
    try std.testing.expectError(error.BufferTooSmall, encodeMaxStreamsUni(&buf, 0));
    try std.testing.expectError(error.BufferTooSmall, encodeStreamsBlockedUni(&buf, 0));
}
