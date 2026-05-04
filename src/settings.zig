//! HTTP/3 SETTINGS frame payload codec.

const nullq = @import("nullq");
const protocol = @import("protocol.zig");

const varint = nullq.wire.varint;

pub const Error = varint.Error || error{
    DuplicateSetting,
    ReservedSetting,
    InvalidSettingValue,
};

pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: ?u64 = null,
    h3_datagram: bool = false,

    pub fn encodedLen(self: Settings) usize {
        var n: usize = 0;
        n += settingEncodedLen(protocol.SettingId.qpack_max_table_capacity, self.qpack_max_table_capacity);
        n += settingEncodedLen(protocol.SettingId.qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.max_field_section_size) |v| {
            n += settingEncodedLen(protocol.SettingId.max_field_section_size, v);
        }
        if (self.h3_datagram) {
            n += settingEncodedLen(protocol.SettingId.h3_datagram, 1);
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
        if (self.h3_datagram) {
            pos += try put(dst[pos..], protocol.SettingId.h3_datagram, 1);
        }
        return pos;
    }

    pub fn decode(src: []const u8) Error!Settings {
        var out: Settings = .{};
        var seen_qpack_max = false;
        var seen_qpack_blocked = false;
        var seen_max_field = false;
        var seen_h3_datagram = false;

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
                protocol.SettingId.h3_datagram => {
                    if (seen_h3_datagram) return Error.DuplicateSetting;
                    if (value > 1) return Error.InvalidSettingValue;
                    seen_h3_datagram = true;
                    out.h3_datagram = value == 1;
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
        .h3_datagram = true,
    };
    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);
    try std.testing.expectEqual(s.encodedLen(), n);
    const got = try Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 16), got.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 65536), got.max_field_section_size);
    try std.testing.expect(got.h3_datagram);
}
