//! RFC 9218 priority parameters.
//!
//! This is intentionally small: it extracts the standard `u` urgency and
//! `i` incremental parameters from the Structured Fields dictionary form and
//! ignores extension parameters for now.

const std = @import("std");

const qpack = @import("qpack/root.zig");

pub const Error = error{
    InvalidParameter,
    InvalidUrgency,
    InvalidBoolean,
    BufferTooSmall,
};

pub const field_name = "priority";

pub const Priority = struct {
    urgency: u3 = 3,
    incremental: bool = false,

    pub fn parse(src: []const u8) Error!Priority {
        var out: Priority = .{};
        try parseInto(&out, src);
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

pub fn fromFieldLines(fields: []const qpack.FieldLine) Error!?Priority {
    var out: Priority = .{};
    var found = false;
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, field_name)) {
            try parseInto(&out, field.value);
            found = true;
        }
    }
    return if (found) out else null;
}

pub fn fieldLine(value: []const u8) qpack.FieldLine {
    return .{ .name = field_name, .value = value };
}

fn parseInto(out: *Priority, src: []const u8) Error!void {
    var it = std.mem.splitScalar(u8, src, ',');
    while (it.next()) |raw_member| {
        const member = std.mem.trim(u8, raw_member, " \t");
        if (member.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, member, '=');
        const key = if (eq) |i| std.mem.trim(u8, member[0..i], " \t") else member;
        const value = if (eq) |i| std.mem.trim(u8, member[i + 1 ..], " \t") else "";
        if (key.len == 0) return Error.InvalidParameter;

        if (std.mem.eql(u8, key, "u")) {
            if (value.len != 1 or value[0] < '0' or value[0] > '7') return Error.InvalidUrgency;
            out.urgency = @intCast(value[0] - '0');
        } else if (std.mem.eql(u8, key, "i")) {
            out.incremental = try parseSfBoolean(value);
        } else {
            // Extension parameters are intentionally ignored by the core
            // scheduler scaffold; later phases can expose them losslessly.
        }
    }
}

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

    try std.testing.expectError(Error.InvalidUrgency, Priority.parse("u=07"));
}

test "priority extracts Priority field lines case-insensitively" {
    const fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "Priority", .value = "u=2" },
        .{ .name = "priority", .value = "i" },
    };
    const p = (try fromFieldLines(&fields)).?;
    try std.testing.expectEqual(@as(u3, 2), p.urgency);
    try std.testing.expect(p.incremental);

    const generated = fieldLine("u=4");
    try std.testing.expectEqualStrings("priority", generated.name);
    try std.testing.expectEqualStrings("u=4", generated.value);
}
