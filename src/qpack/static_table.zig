//! QPACK static table (RFC 9204 Appendix A).

const std = @import("std");

pub const complete = true;

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

pub const entries = [_]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

pub fn get(index: usize) ?Entry {
    if (index >= entries.len) return null;
    return entries[index];
}

/// True when `mem` IS a static-table string (exact pointer + length
/// match against one of the comptime entries). Decoded field sections
/// BORROW static-resident name/value strings instead of duping them;
/// the free paths use this check to skip freeing borrowed slices. A
/// heap allocation can never coincide with comptime storage, so the
/// match is exact.
pub fn containsPtr(mem: []const u8) bool {
    for (entries) |entry| {
        if (entry.name.ptr == mem.ptr and entry.name.len == mem.len) return true;
        if (entry.value.ptr == mem.ptr and entry.value.len == mem.len) return true;
    }
    return false;
}

test "table has 99 entries and key RFC examples" {
    try std.testing.expectEqual(@as(usize, 99), entries.len);
    try std.testing.expectEqualStrings(":path", entries[1].name);
    try std.testing.expectEqualStrings("/", entries[1].value);
    try std.testing.expectEqual(@as(?usize, 17), find(":method", "GET"));
    try std.testing.expectEqual(@as(?usize, 23), find(":scheme", "https"));
}

// ---------------------------------------------------------------------------
// Comptime lookup index: buckets keyed by (name length, first byte).
// Encoders probe the table 2-3x per field (full match, then name-only);
// the bucket prefilter cuts the 99-entry scan to the 0-4 candidates
// that share a length and first byte.

const max_name_len = blk: {
    var m: usize = 0;
    for (entries) |entry| {
        if (entry.name.len > m) m = entry.name.len;
    }
    break :blk m;
};

const max_bucket_size = blk: {
    @setEvalBranchQuota(1_000_000);
    var counts: [max_name_len + 1][128]usize = @splat(@splat(0));
    for (entries) |entry| counts[entry.name.len][entry.name[0]] += 1;
    var m: usize = 0;
    for (&counts, 0..) |by_first, len| {
        for (by_first, 0..) |count, first| {
            if (len > 0 and first > 0 and count > m) m = count;
        }
    }
    break :blk m;
};

const lookup_storage: [max_name_len + 1][128][max_bucket_size]u16 = blk: {
    @setEvalBranchQuota(1_000_000);
    var storage: [max_name_len + 1][128][max_bucket_size]u16 = @splat(@splat(@splat(0)));
    var fill: [max_name_len + 1][128]usize = @splat(@splat(0));
    for (entries, 0..) |entry, i| {
        const l = entry.name.len;
        const f = entry.name[0];
        storage[l][f][fill[l][f]] = @intCast(i);
        fill[l][f] += 1;
    }
    break :blk storage;
};

const lookup_fills: [max_name_len + 1][128]usize = blk: {
    @setEvalBranchQuota(1_000_000);
    var fill: [max_name_len + 1][128]usize = @splat(@splat(0));
    for (entries) |entry| {
        fill[entry.name.len][entry.name[0]] += 1;
    }
    break :blk fill;
};

const lookup_index: [max_name_len + 1][128][]const u16 = blk: {
    @setEvalBranchQuota(1_000_000);
    var buckets: [max_name_len + 1][128][]const u16 = undefined;
    for (0..max_name_len + 1) |l| {
        for (0..128) |f| {
            buckets[l][f] = lookup_storage[l][f][0..lookup_fills[l][f]];
        }
    }
    break :blk buckets;
};

fn nameBucket(name: []const u8) ?[]const u16 {
    if (name.len == 0 or name.len > max_name_len) return null;
    const first = name[0];
    if (first >= 128) return null;
    return lookup_index[name.len][first];
}

pub fn find(name: []const u8, value: []const u8) ?usize {
    const bucket = nameBucket(name) orelse return null;
    for (bucket) |i| {
        const entry = entries[i];
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) return i;
    }
    return null;
}

pub fn findName(name: []const u8) ?usize {
    const bucket = nameBucket(name) orelse return null;
    for (bucket) |i| {
        if (std.mem.eql(u8, entries[i].name, name)) return i;
    }
    return null;
}

test "comptime bucket index preserves find/findName results" {
    // Every entry must be findable through the bucketed path.
    // findName keeps the original first-match semantics, so for
    // duplicated names (":path", "x-frame-options") the FIRST index
    // with that name is the correct answer.
    for (entries, 0..) |entry, i| {
        try std.testing.expectEqual(@as(?usize, i), find(entry.name, entry.value));
        if (findName(entry.name)) |first| {
            try std.testing.expectEqualStrings(entry.name, entries[first].name);
            try std.testing.expect(first <= i);
        } else return error.TestUnexpectedResult;
    }
    // Probes that can match nothing are cheap rejections.
    try std.testing.expectEqual(@as(?usize, null), find("nope", "x"));
    try std.testing.expectEqual(@as(?usize, null), findName(""));
    try std.testing.expectEqual(@as(?usize, null), findName("\xff-prefixed"));
    // Same name, different value still falls through to name-only.
    try std.testing.expectEqual(@as(?usize, null), find(":path", "/other"));
    try std.testing.expectEqual(@as(?usize, 1), findName(":path"));
}
