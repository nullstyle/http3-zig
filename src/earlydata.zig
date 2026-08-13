//! HTTP/3 0-RTT remembered state (RFC 9114 §7.2.4.2).
//!
//! quic's resumption envelope (`QZRS`, `quic.tls.resumption_state`) carries
//! the TLS session ticket plus the remembered transport parameters. HTTP/3
//! early data additionally needs the peer's remembered SETTINGS: a client
//! sending requests before the server's real SETTINGS frame arrives MUST
//! comply with the settings it remembers from the connection that issued
//! the ticket (§7.2.4.2 ¶5). This module freezes the http3-owned envelope
//! that pairs the two, plus the pure validation helpers both roles need:
//!
//!   H3RS || version(1) || flags(1) || settings_len(u32) ||
//!   quic_envelope_len(u32) || canonical_settings || quic_envelope
//!
//! Integers are big-endian, mirroring the quic envelope. Version 1 has no
//! flags; non-zero flags and unknown versions are rejected. The library
//! defines the codec and the validation functions only — the embedder owns
//! the origin-keyed store (a hash map, a file, a database row), exactly as
//! it owns persistence of the quic envelope itself.
//!
//! Unknown peer settings are inherently not remembered: the canonical
//! `Settings` codec materializes only ids it understands, which is correct
//! — a client can only "comply with" settings it understands, and unknown
//! ids are ignored on receipt anyway (§7.2.4.1 ¶7).

const std = @import("std");
const settings_mod = @import("settings.zig");

pub const Settings = settings_mod.Settings;

pub const Error = error{
    BufferTooSmall,
    InvalidFormat,
    UnsupportedVersion,
    InvalidFlags,
    ValueTooLarge,
    TrailingBytes,
} || settings_mod.Error;

pub const magic = "H3RS".*;
pub const version: u8 = 1;
pub const flags: u8 = 0;
pub const header_len: usize = 4 + 1 + 1 + 4 + 4;

pub const Decoded = struct {
    /// Settings remembered from the connection that issued the ticket.
    settings: Settings,
    /// The quic `QZRS` resumption envelope, ready for
    /// `quic.Client.Config.resumption_state`. Borrows from the buffer
    /// passed to `decode`.
    quic_resumption_state: []const u8,
};

pub fn encodedLen(remembered: Settings, quic_envelope: []const u8) Error!usize {
    const settings_len = remembered.encodedLen();
    if (settings_len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    if (quic_envelope.len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    return header_len + settings_len + quic_envelope.len;
}

pub fn encode(dst: []u8, remembered: Settings, quic_envelope: []const u8) Error!usize {
    const settings_len = remembered.encodedLen();
    if (settings_len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    if (quic_envelope.len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    const needed = header_len + settings_len + quic_envelope.len;
    if (dst.len < needed) return Error.BufferTooSmall;

    @memcpy(dst[0..4], &magic);
    dst[4] = version;
    dst[5] = flags;
    std.mem.writeInt(u32, dst[6..10], @intCast(settings_len), .big);
    std.mem.writeInt(u32, dst[10..14], @intCast(quic_envelope.len), .big);

    const settings_start = header_len;
    const settings_end = settings_start + settings_len;
    const written = try remembered.encode(dst[settings_start..settings_end]);
    std.debug.assert(written == settings_len);
    @memcpy(dst[settings_end..needed], quic_envelope);
    return needed;
}

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    remembered: Settings,
    quic_envelope: []const u8,
) (std.mem.Allocator.Error || Error)![]u8 {
    const len = try encodedLen(remembered, quic_envelope);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    const written = try encode(out, remembered, quic_envelope);
    std.debug.assert(written == len);
    return out;
}

pub fn decode(src: []const u8) Error!Decoded {
    if (src.len < header_len) return Error.InvalidFormat;
    if (!std.mem.eql(u8, src[0..4], &magic)) return Error.InvalidFormat;
    if (src[4] != version) return Error.UnsupportedVersion;
    if (src[5] != flags) return Error.InvalidFlags;
    const settings_len = std.mem.readInt(u32, src[6..10], .big);
    const envelope_len = std.mem.readInt(u32, src[10..14], .big);
    const settings_start = header_len;
    const settings_end = settings_start +| @as(usize, settings_len);
    const total = settings_end +| @as(usize, envelope_len);
    if (src.len < total) return Error.InvalidFormat;
    if (src.len > total) return Error.TrailingBytes;
    return .{
        .settings = try Settings.decode(src[settings_start..settings_end]),
        .quic_resumption_state = src[settings_end..total],
    };
}

/// The first §7.2.4.2 incompatibility found between the settings a client
/// remembers and the server's actual SETTINGS on the resumed connection —
/// or null when the actual settings are compatible ("a client complying
/// with the remembered settings would not violate the actual ones").
/// Reductions and disables violate; increases are compatible. The ¶6
/// omission rule needs no special case: `Settings.decode` materializes
/// defaults, so an omitted setting evaluates as its default and trips the
/// same checks.
pub const SettingsViolation = enum {
    qpack_max_table_capacity_reduced,
    qpack_blocked_streams_reduced,
    max_field_section_size_reduced,
    enable_connect_protocol_disabled,
    h3_datagram_disabled,
    wt_enabled_disabled,
    wt_initial_max_data_reduced,
    wt_initial_max_streams_uni_reduced,
    wt_initial_max_streams_bidi_reduced,
};

pub fn validateRememberedSettings(remembered: Settings, actual: Settings) ?SettingsViolation {
    if (actual.qpack_max_table_capacity < remembered.qpack_max_table_capacity)
        return .qpack_max_table_capacity_reduced;
    if (actual.qpack_blocked_streams < remembered.qpack_blocked_streams)
        return .qpack_blocked_streams_reduced;
    // null = unlimited (§7.2.4.1 ¶3): remembered-unlimited shrinks under
    // any actual limit; a remembered limit only grows to unlimited.
    if (remembered.max_field_section_size) |remembered_limit| {
        if (actual.max_field_section_size) |actual_limit| {
            if (actual_limit < remembered_limit) return .max_field_section_size_reduced;
        }
    } else if (actual.max_field_section_size != null) {
        return .max_field_section_size_reduced;
    }
    if (remembered.enable_connect_protocol and !actual.enable_connect_protocol)
        return .enable_connect_protocol_disabled;
    if (remembered.h3_datagram and !actual.h3_datagram)
        return .h3_datagram_disabled;
    if (remembered.wt_enabled and !actual.wt_enabled)
        return .wt_enabled_disabled;
    // WT initial credits: null = no credit advertised, so a remembered
    // credit that disappears (or shrinks) is a reduction.
    inline for (.{
        .{ "wt_initial_max_data", SettingsViolation.wt_initial_max_data_reduced },
        .{ "wt_initial_max_streams_uni", SettingsViolation.wt_initial_max_streams_uni_reduced },
        .{ "wt_initial_max_streams_bidi", SettingsViolation.wt_initial_max_streams_bidi_reduced },
    }) |axis| {
        if (@field(remembered, axis[0])) |remembered_credit| {
            const actual_credit = @field(actual, axis[0]) orelse return axis[1];
            if (actual_credit < remembered_credit) return axis[1];
        }
    }
    return null;
}

/// Prefix of the server-side early-data application context. The full
/// context is `prefix ++ canonical settings bytes`; quic hashes it (with
/// ALPN and transport params) into the `quic_early_data_context` digest
/// BoringSSL compares FOR EQUALITY on resumption. A ticket minted under
/// different bytes ⇒ 0-RTT silently rejected, connection completes 1-RTT.
/// Compatible-iff-identical is the conservative posture §7.2.4.2 ¶3
/// permits; the documented trade-off is that raising a limit (compatible
/// per the RFC) still rejects 0-RTT — always the safe side. Because an
/// accepting server's live SETTINGS are byte-identical to the remembered
/// ones by construction, ¶4's "MUST NOT reduce limits after accepting" is
/// satisfied structurally.
pub const application_context_prefix = "http3-zig h3 early-data settings v1";

pub fn applicationContextLen(s: Settings) usize {
    return application_context_prefix.len + s.encodedLen();
}

pub fn applicationContext(dst: []u8, s: Settings) Error![]u8 {
    const needed = applicationContextLen(s);
    if (dst.len < needed) return Error.BufferTooSmall;
    @memcpy(dst[0..application_context_prefix.len], application_context_prefix);
    const written = try s.encode(dst[application_context_prefix.len..needed]);
    std.debug.assert(application_context_prefix.len + written == needed);
    return dst[0..needed];
}

pub fn applicationContextAlloc(
    allocator: std.mem.Allocator,
    s: Settings,
) (std.mem.Allocator.Error || Error)![]u8 {
    const out = try allocator.alloc(u8, applicationContextLen(s));
    errdefer allocator.free(out);
    return try applicationContext(out, s);
}

/// Pairs the two halves of the client-side capture flow, which arrive in
/// either order: the quic resumption envelope (via
/// `Client.Config.new_session_callback`, possibly several times — servers
/// may issue multiple NewSessionTickets; latest wins) and the peer's
/// SETTINGS (via the session's `peer_settings` event). `tryEncode` yields
/// the combined `H3RS` envelope once both halves are present. Embedders
/// can ignore this and combine by hand; it exists because the callback
/// borrows its bytes and the pairing is easy to get subtly wrong.
pub const TicketBinder = struct {
    allocator: std.mem.Allocator,
    quic_envelope: ?[]u8 = null,
    remembered: ?Settings = null,

    pub fn init(allocator: std.mem.Allocator) TicketBinder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TicketBinder) void {
        if (self.quic_envelope) |env| self.allocator.free(env);
        self.* = undefined;
    }

    /// Latch a quic resumption envelope (borrowed; copied out). Latest
    /// ticket wins.
    pub fn onSessionTicket(self: *TicketBinder, quic_envelope: []const u8) std.mem.Allocator.Error!void {
        const copy = try self.allocator.dupe(u8, quic_envelope);
        if (self.quic_envelope) |old| self.allocator.free(old);
        self.quic_envelope = copy;
    }

    /// Latch the peer SETTINGS to remember. Latest wins (a peer sends
    /// SETTINGS once; re-latching is harmless).
    pub fn onPeerSettings(self: *TicketBinder, remembered: Settings) void {
        self.remembered = remembered;
    }

    pub fn ready(self: *const TicketBinder) bool {
        return self.quic_envelope != null and self.remembered != null;
    }

    /// The combined `H3RS` envelope once both halves are present, else
    /// null. Caller owns the returned bytes.
    pub fn tryEncode(
        self: *const TicketBinder,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || Error)!?[]u8 {
        const envelope = self.quic_envelope orelse return null;
        const remembered = self.remembered orelse return null;
        return try encodeAlloc(allocator, remembered, envelope);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn sampleSettings() Settings {
    return .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 1 << 20,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
        .wt_initial_max_data = 2000,
        .wt_initial_max_streams_uni = 7,
        .wt_initial_max_streams_bidi = 4,
    };
}

test "H3RS envelope round-trips settings and quic envelope" {
    const quic_envelope = "QZRS-opaque-bytes-stand-in";
    const buf = try encodeAlloc(testing.allocator, sampleSettings(), quic_envelope);
    defer testing.allocator.free(buf);

    const decoded = try decode(buf);
    try testing.expect(std.meta.eql(sampleSettings(), decoded.settings));
    try testing.expectEqualStrings(quic_envelope, decoded.quic_resumption_state);
}

test "H3RS decode rejects bad magic, version, flags, truncation, trailing" {
    const buf = try encodeAlloc(testing.allocator, sampleSettings(), "ticket");
    defer testing.allocator.free(buf);

    var bad_magic = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] = 'X';
    try testing.expectError(Error.InvalidFormat, decode(bad_magic));

    var bad_version = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(bad_version);
    bad_version[4] = 2;
    try testing.expectError(Error.UnsupportedVersion, decode(bad_version));

    var bad_flags = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(bad_flags);
    bad_flags[5] = 1;
    try testing.expectError(Error.InvalidFlags, decode(bad_flags));

    try testing.expectError(Error.InvalidFormat, decode(buf[0 .. buf.len - 1]));
    try testing.expectError(Error.InvalidFormat, decode(buf[0 .. header_len - 1]));

    const padded = try std.mem.concat(testing.allocator, u8, &.{ buf, "x" });
    defer testing.allocator.free(padded);
    try testing.expectError(Error.TrailingBytes, decode(padded));
}

test "validateRememberedSettings accepts identical and increased settings" {
    const remembered = sampleSettings();
    try testing.expectEqual(@as(?SettingsViolation, null), validateRememberedSettings(remembered, remembered));

    var increased = remembered;
    increased.qpack_max_table_capacity = 512;
    increased.max_field_section_size = null; // limit -> unlimited
    increased.wt_initial_max_data = 4000;
    try testing.expectEqual(@as(?SettingsViolation, null), validateRememberedSettings(remembered, increased));
}

test "validateRememberedSettings flags every reduction axis" {
    const remembered = sampleSettings();

    var v = remembered;
    v.qpack_max_table_capacity = 128;
    try testing.expectEqual(SettingsViolation.qpack_max_table_capacity_reduced, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.qpack_blocked_streams = 0;
    try testing.expectEqual(SettingsViolation.qpack_blocked_streams_reduced, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.max_field_section_size = 100;
    try testing.expectEqual(SettingsViolation.max_field_section_size_reduced, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.enable_connect_protocol = false;
    try testing.expectEqual(SettingsViolation.enable_connect_protocol_disabled, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.h3_datagram = false;
    try testing.expectEqual(SettingsViolation.h3_datagram_disabled, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.wt_enabled = false;
    try testing.expectEqual(SettingsViolation.wt_enabled_disabled, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.wt_initial_max_data = null;
    try testing.expectEqual(SettingsViolation.wt_initial_max_data_reduced, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.wt_initial_max_streams_uni = 1;
    try testing.expectEqual(SettingsViolation.wt_initial_max_streams_uni_reduced, validateRememberedSettings(remembered, v).?);

    v = remembered;
    v.wt_initial_max_streams_bidi = 1;
    try testing.expectEqual(SettingsViolation.wt_initial_max_streams_bidi_reduced, validateRememberedSettings(remembered, v).?);
}

test "omission of a remembered non-default setting is a reduction (decode materializes defaults)" {
    // A server that previously advertised ENABLE_CONNECT_PROTOCOL and now
    // omits it: the decoded actual settings carry the default (false),
    // which the disable check flags — ¶6 without a special case.
    var remembered: Settings = .{};
    remembered.enable_connect_protocol = true;

    const omitted_wire: Settings = .{};
    var buf: [64]u8 = undefined;
    const n = try omitted_wire.encode(&buf);
    const actual = try Settings.decode(buf[0..n]);
    try testing.expectEqual(SettingsViolation.enable_connect_protocol_disabled, validateRememberedSettings(remembered, actual).?);
}

test "applicationContext is prefix plus canonical settings and tracks changes" {
    var a_buf: [256]u8 = undefined;
    var b_buf: [256]u8 = undefined;
    const a = try applicationContext(&a_buf, sampleSettings());
    try testing.expect(std.mem.startsWith(u8, a, application_context_prefix));

    var changed = sampleSettings();
    changed.wt_initial_max_data = 2001;
    const b = try applicationContext(&b_buf, changed);
    try testing.expect(!std.mem.eql(u8, a, b));

    const again = try applicationContextAlloc(testing.allocator, sampleSettings());
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, a, again);
}

test "TicketBinder pairs halves in either order and keeps the latest ticket" {
    var binder = TicketBinder.init(testing.allocator);
    defer binder.deinit();

    try testing.expectEqual(@as(?[]u8, null), try binder.tryEncode(testing.allocator));

    // Settings first, ticket second.
    binder.onPeerSettings(sampleSettings());
    try testing.expect(!binder.ready());
    try binder.onSessionTicket("ticket-1");
    try testing.expect(binder.ready());

    // A later NewSessionTicket replaces the first.
    try binder.onSessionTicket("ticket-2-longer");
    const combined = (try binder.tryEncode(testing.allocator)).?;
    defer testing.allocator.free(combined);

    const decoded = try decode(combined);
    try testing.expect(std.meta.eql(sampleSettings(), decoded.settings));
    try testing.expectEqualStrings("ticket-2-longer", decoded.quic_resumption_state);
}
