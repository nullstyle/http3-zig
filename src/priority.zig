//! RFC 9218 priority parameters.
//!
//! This is intentionally small: it extracts the standard `u` urgency and
//! `i` incremental parameters from the Structured Fields dictionary form and
//! ignores extension parameters for now.

const std = @import("std");

pub const Error = error{
    InvalidParameter,
    InvalidUrgency,
    InvalidBoolean,
    BufferTooSmall,
};

pub const Priority = struct {
    urgency: u3 = 3,
    incremental: bool = false,

    pub fn parse(src: []const u8) Error!Priority {
        var out: Priority = .{};
        var it = std.mem.splitScalar(u8, src, ',');
        while (it.next()) |raw_member| {
            const member = std.mem.trim(u8, raw_member, " \t");
            if (member.len == 0) continue;

            const eq = std.mem.indexOfScalar(u8, member, '=');
            const key = if (eq) |i| std.mem.trim(u8, member[0..i], " \t") else member;
            const value = if (eq) |i| std.mem.trim(u8, member[i + 1 ..], " \t") else "";
            if (key.len == 0) return Error.InvalidParameter;

            if (std.mem.eql(u8, key, "u")) {
                if (value.len == 0) return Error.InvalidUrgency;
                const parsed = std.fmt.parseInt(u8, value, 10) catch return Error.InvalidUrgency;
                if (parsed > 7) return Error.InvalidUrgency;
                out.urgency = @intCast(parsed);
            } else if (std.mem.eql(u8, key, "i")) {
                out.incremental = try parseSfBoolean(value);
            } else {
                // Extension parameters are intentionally ignored by the core
                // scheduler scaffold; later phases can expose them losslessly.
            }
        }
        return out;
    }

    pub fn encode(self: Priority, dst: []u8) Error!usize {
        const out = if (self.incremental)
            std.fmt.bufPrint(dst, "u={}, i", .{@as(u8, self.urgency)}) catch return Error.BufferTooSmall
        else
            std.fmt.bufPrint(dst, "u={}", .{@as(u8, self.urgency)}) catch return Error.BufferTooSmall;
        return out.len;
    }
};

fn parseSfBoolean(value: []const u8) Error!bool {
    if (value.len == 0) return true;
    if (std.mem.eql(u8, value, "?1")) return true;
    if (std.mem.eql(u8, value, "?0")) return false;
    return Error.InvalidBoolean;
}

test "priority parse defaults and parameters" {
    var p = try Priority.parse("");
    try std.testing.expectEqual(@as(u3, 3), p.urgency);
    try std.testing.expect(!p.incremental);

    p = try Priority.parse("u=0, i");
    try std.testing.expectEqual(@as(u3, 0), p.urgency);
    try std.testing.expect(p.incremental);

    p = try Priority.parse("i=?0, u=7, foo=bar");
    try std.testing.expectEqual(@as(u3, 7), p.urgency);
    try std.testing.expect(!p.incremental);

    var buf: [16]u8 = undefined;
    const n = try p.encode(&buf);
    try std.testing.expectEqualStrings("u=7", buf[0..n]);
}
