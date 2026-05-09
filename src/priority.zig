//! RFC 9218 priority parameters.
//!
//! This is intentionally small: it extracts the standard `u` urgency and
//! `i` incremental parameters from the Structured Fields dictionary form and
//! ignores extension parameters for now.
//!
//! Per RFC 9218 §4 ¶7, "Unknown priority parameters, priority parameters with
//! out-of-range values, or values of unexpected types MUST be ignored." The
//! parser therefore silently substitutes the parameter default (urgency=3,
//! incremental=false) when it encounters an out-of-range or wrong-typed value
//! for `u` or `i`. Structurally malformed Structured Fields dictionaries
//! (e.g. an empty member key) are a different layer and still error.

const std = @import("std");

const qpack = @import("qpack/root.zig");

pub const Error = error{
    InvalidParameter,
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
        // RFC 8941 §3.1.2 ABNF: `dict-member = member-name [ "=" member-value ]`.
        // No OWS is allowed around the `=`, inside the member-name, or
        // inside the member-value — surrounding OWS is stripped above
        // (RFC 8941 §4.2 step 2 / step 9). Anything left is structurally
        // malformed and must surface as `Error.InvalidParameter` so the
        // caller (RFC 9218 §8) can close with H3_GENERAL_PROTOCOL_ERROR
        // rather than fall through to the §4 ¶7 "ignore unknown / wrong
        // type" path that only applies to syntactically valid dictionaries.
        const key = if (eq) |i| member[0..i] else member;
        const value = if (eq) |i| member[i + 1 ..] else "";
        if (key.len == 0) return Error.InvalidParameter;
        // RFC 8941 §3.1.2 / §3.3.7: dictionary keys are restricted to
        // `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`.
        // Uppercase, internal whitespace, or any char outside that set
        // makes the dictionary structurally malformed.
        if (!isValidDictKey(key)) return Error.InvalidParameter;
        // Reject internal whitespace in the value (covers `u= 2`, `u=2 x`,
        // etc.). RFC 8941 §4.2 step 6/8 expects either OWS+`,` or end of
        // input immediately after the member-value, so any whitespace
        // surviving the outer trim is trailing garbage inside one member.
        if (containsWhitespace(value)) return Error.InvalidParameter;

        if (std.mem.eql(u8, key, "u")) {
            // RFC 9218 §4 ¶7: out-of-range or wrong-type urgency values MUST
            // be ignored — fall through to the default (urgency=3) by leaving
            // `out.urgency` at whatever it already was (the field default
            // when this parameter has not yet been seen, or the previously
            // accepted in-range value otherwise — both behaviours match
            // "as if the parameter were not present").
            if (parseUrgency(value)) |u| out.urgency = u;
        } else if (std.mem.eql(u8, key, "i")) {
            // RFC 9218 §4 ¶7: a wrong-type incremental value MUST be ignored.
            // The Structured Fields boolean type only admits the bare `i` /
            // `i=?1` / `i=?0` shapes; anything else is silently dropped.
            if (parseSfBoolean(value)) |b| out.incremental = b;
        } else {
            // Extension parameters are intentionally ignored by the core
            // scheduler scaffold; later phases can expose them losslessly.
        }
    }
}

fn isValidDictKey(key: []const u8) bool {
    // RFC 8941 §3.1.2 dict-key ABNF:
    //   key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
    //   lcalpha = %x61-7A
    if (key.len == 0) return false;
    if (!isLcalpha(key[0]) and key[0] != '*') return false;
    for (key[1..]) |c| {
        if (!isLcalpha(c) and !std.ascii.isDigit(c) and c != '_' and c != '-' and c != '.' and c != '*') {
            return false;
        }
    }
    return true;
}

fn isLcalpha(c: u8) bool {
    return c >= 'a' and c <= 'z';
}

fn containsWhitespace(s: []const u8) bool {
    for (s) |c| {
        if (c == ' ' or c == '\t') return true;
    }
    return false;
}

fn parseUrgency(value: []const u8) ?u3 {
    // §4.1 ¶1: urgency is an integer in 0..7. Anything else (multi-digit,
    // leading zero, non-digit, empty) is "out of range" or "unexpected type"
    // and §4 ¶7 says we MUST ignore it.
    if (value.len != 1) return null;
    if (value[0] < '0' or value[0] > '7') return null;
    return @intCast(value[0] - '0');
}

fn parseSfBoolean(value: []const u8) ?bool {
    if (value.len == 0) return true;
    if (std.mem.eql(u8, value, "?1")) return true;
    if (std.mem.eql(u8, value, "?0")) return false;
    return null;
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

    // RFC 9218 §4 ¶7: out-of-range / wrong-type urgency values are silently
    // ignored. "u=07" has an unexpected shape (multi-digit) so the parser
    // falls back to the default urgency (3).
    p = try Priority.parse("u=07");
    try std.testing.expectEqual(@as(u3, 3), p.urgency);
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
