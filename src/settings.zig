//! HTTP/3 SETTINGS frame payload codec.

const quic_zig = @import("quic_zig");
const protocol = @import("protocol.zig");

const varint = quic_zig.wire.varint;

pub const Error = varint.Error || error{
    DuplicateSetting,
    ReservedSetting,
    InvalidSettingValue,
};

pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: ?u64 = null,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    /// `SETTINGS_WT_ENABLED` from draft-ietf-webtrans-http3-15 §9.2.
    /// Boolean: when true, the endpoint advertises support for
    /// WebTransport over HTTP/3 with the codepoint specific to the
    /// draft revision this implementation pins to (`0x2c7cf000`).
    /// Both peers MUST send this for a session to bootstrap.
    wt_enabled: bool = false,
    /// `SETTINGS_WT_INITIAL_MAX_DATA` (draft-ietf-webtrans-http3-15 §9.2):
    /// the initial session-level `WT_MAX_DATA` this endpoint grants on
    /// every WebTransport session, so the peer may send that many bytes
    /// before an explicit `WT_MAX_DATA` capsule arrives — saving the
    /// bootstrap round-trip. `null` = not advertised (no initial credit;
    /// the peer must wait for a capsule).
    wt_initial_max_data: ?u64 = null,
    /// `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (§9.2): initial limit on
    /// peer-initiated unidirectional WT streams per session. `null` = not
    /// advertised.
    wt_initial_max_streams_uni: ?u64 = null,
    /// `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (§9.2): initial limit on
    /// peer-initiated bidirectional WT streams per session. `null` = not
    /// advertised.
    wt_initial_max_streams_bidi: ?u64 = null,

    pub fn encodedLen(self: Settings) usize {
        var n: usize = 0;
        n += settingEncodedLen(protocol.SettingId.qpack_max_table_capacity, self.qpack_max_table_capacity);
        n += settingEncodedLen(protocol.SettingId.qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.max_field_section_size) |v| {
            n += settingEncodedLen(protocol.SettingId.max_field_section_size, v);
        }
        if (self.enable_connect_protocol) {
            n += settingEncodedLen(protocol.SettingId.enable_connect_protocol, 1);
        }
        if (self.h3_datagram) {
            n += settingEncodedLen(protocol.SettingId.h3_datagram, 1);
        }
        if (self.wt_enabled) {
            n += settingEncodedLen(protocol.SettingId.wt_enabled, 1);
        }
        if (self.wt_initial_max_data) |v| {
            n += settingEncodedLen(protocol.SettingId.wt_initial_max_data, v);
        }
        if (self.wt_initial_max_streams_uni) |v| {
            n += settingEncodedLen(protocol.SettingId.wt_initial_max_streams_uni, v);
        }
        if (self.wt_initial_max_streams_bidi) |v| {
            n += settingEncodedLen(protocol.SettingId.wt_initial_max_streams_bidi, v);
        }
        return n;
    }

    pub fn encode(self: Settings, dst: []u8) Error!usize {
        var pos: usize = 0;
        pos += try put(dst[pos..], protocol.SettingId.qpack_max_table_capacity, self.qpack_max_table_capacity);
        pos += try put(dst[pos..], protocol.SettingId.qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.max_field_section_size) |v| {
            pos += try put(dst[pos..], protocol.SettingId.max_field_section_size, v);
        }
        if (self.enable_connect_protocol) {
            pos += try put(dst[pos..], protocol.SettingId.enable_connect_protocol, 1);
        }
        if (self.h3_datagram) {
            pos += try put(dst[pos..], protocol.SettingId.h3_datagram, 1);
        }
        if (self.wt_enabled) {
            pos += try put(dst[pos..], protocol.SettingId.wt_enabled, 1);
        }
        if (self.wt_initial_max_data) |v| {
            pos += try put(dst[pos..], protocol.SettingId.wt_initial_max_data, v);
        }
        if (self.wt_initial_max_streams_uni) |v| {
            pos += try put(dst[pos..], protocol.SettingId.wt_initial_max_streams_uni, v);
        }
        if (self.wt_initial_max_streams_bidi) |v| {
            pos += try put(dst[pos..], protocol.SettingId.wt_initial_max_streams_bidi, v);
        }
        return pos;
    }

    pub fn decode(src: []const u8) Error!Settings {
        var out: Settings = .{};
        var seen_qpack_max = false;
        var seen_qpack_blocked = false;
        var seen_max_field = false;
        var seen_enable_connect_protocol = false;
        var seen_h3_datagram = false;
        var seen_wt_enabled = false;
        var seen_wt_initial_max_data = false;
        var seen_wt_initial_max_streams_uni = false;
        var seen_wt_initial_max_streams_bidi = false;

        var pos: usize = 0;
        while (pos < src.len) {
            const id_dec = try varint.decode(src[pos..]);
            pos += id_dec.bytes_read;
            const value_dec = try varint.decode(src[pos..]);
            pos += value_dec.bytes_read;

            const id = id_dec.value;
            const value = value_dec.value;
            if (protocol.isReservedHttp2Setting(id)) return Error.ReservedSetting;

            switch (id) {
                protocol.SettingId.qpack_max_table_capacity => {
                    if (seen_qpack_max) return Error.DuplicateSetting;
                    seen_qpack_max = true;
                    out.qpack_max_table_capacity = value;
                },
                protocol.SettingId.qpack_blocked_streams => {
                    if (seen_qpack_blocked) return Error.DuplicateSetting;
                    seen_qpack_blocked = true;
                    out.qpack_blocked_streams = value;
                },
                protocol.SettingId.max_field_section_size => {
                    if (seen_max_field) return Error.DuplicateSetting;
                    seen_max_field = true;
                    out.max_field_section_size = value;
                },
                protocol.SettingId.enable_connect_protocol => {
                    if (seen_enable_connect_protocol) return Error.DuplicateSetting;
                    if (value > 1) return Error.InvalidSettingValue;
                    seen_enable_connect_protocol = true;
                    out.enable_connect_protocol = value == 1;
                },
                protocol.SettingId.h3_datagram => {
                    if (seen_h3_datagram) return Error.DuplicateSetting;
                    if (value > 1) return Error.InvalidSettingValue;
                    seen_h3_datagram = true;
                    out.h3_datagram = value == 1;
                },
                protocol.SettingId.wt_enabled => {
                    if (seen_wt_enabled) return Error.DuplicateSetting;
                    // Draft-15 §3.2 ¶? defines this as a boolean: any
                    // value > 0 advertises support. We keep the >1
                    // bytes legal so peers can pin to the same
                    // codepoint with future-tagged values without us
                    // failing the connection.
                    seen_wt_enabled = true;
                    out.wt_enabled = value >= 1;
                },
                protocol.SettingId.wt_initial_max_data => {
                    if (seen_wt_initial_max_data) return Error.DuplicateSetting;
                    seen_wt_initial_max_data = true;
                    out.wt_initial_max_data = value;
                },
                protocol.SettingId.wt_initial_max_streams_uni => {
                    if (seen_wt_initial_max_streams_uni) return Error.DuplicateSetting;
                    seen_wt_initial_max_streams_uni = true;
                    out.wt_initial_max_streams_uni = value;
                },
                protocol.SettingId.wt_initial_max_streams_bidi => {
                    if (seen_wt_initial_max_streams_bidi) return Error.DuplicateSetting;
                    seen_wt_initial_max_streams_bidi = true;
                    out.wt_initial_max_streams_bidi = value;
                },
                else => {},
            }
        }
        return out;
    }
};

fn settingEncodedLen(id: u64, value: u64) usize {
    return varint.encodedLen(id) + varint.encodedLen(value);
}

fn put(dst: []u8, id: u64, value: u64) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(dst[pos..], id);
    pos += try varint.encode(dst[pos..], value);
    return pos;
}

test "SETTINGS round-trip" {
    const std = @import("std");
    const s: Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 16,
        .max_field_section_size = 65536,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
        .wt_initial_max_data = 262144,
        .wt_initial_max_streams_uni = 16,
        .wt_initial_max_streams_bidi = 8,
    };
    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);
    try std.testing.expectEqual(s.encodedLen(), n);
    const got = try Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 16), got.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 65536), got.max_field_section_size);
    try std.testing.expect(got.enable_connect_protocol);
    try std.testing.expect(got.h3_datagram);
    try std.testing.expect(got.wt_enabled);
    try std.testing.expectEqual(@as(?u64, 262144), got.wt_initial_max_data);
    try std.testing.expectEqual(@as(?u64, 16), got.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, 8), got.wt_initial_max_streams_bidi);
}

test "SETTINGS omits unset WT initial flow-control values" {
    const std = @import("std");
    // Defaults (null) must not appear on the wire, and a peer that never
    // sends them decodes back to null — no phantom zero limits.
    const s: Settings = .{ .wt_enabled = true };
    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);
    const got = try Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(?u64, null), got.wt_initial_max_data);
    try std.testing.expectEqual(@as(?u64, null), got.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, null), got.wt_initial_max_streams_bidi);
}

test "SETTINGS rejects a duplicate WT initial flow-control value" {
    const std = @import("std");
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try put(buf[pos..], protocol.SettingId.wt_initial_max_data, 100);
    pos += try put(buf[pos..], protocol.SettingId.wt_initial_max_data, 200);
    try std.testing.expectError(Error.DuplicateSetting, Settings.decode(buf[0..pos]));
}
