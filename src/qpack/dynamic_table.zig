//! QPACK dynamic table core.
//!
//! This module is transport-free. It owns the QPACK dynamic table state used by
//! encoder/decoder stream instruction handling and field-section references.

const std = @import("std");

const observability = @import("../observability.zig");
const protocol = @import("../protocol.zig");

pub const Error = std.mem.Allocator.Error || error{
    CapacityTooLarge,
    EntryTooLarge,
    InvalidDynamicIndex,
};

pub const overhead: usize = 32;

pub const Entry = struct {
    absolute_index: u64,
    name: []u8,
    value: []u8,
    sensitive: bool = false,

    pub fn size(self: *const Entry) usize {
        return entrySize(self.name, self.value);
    }
};

/// Optional trace surface attached to a `DynamicTable`. The session
/// installs its `observability.Hooks` and `protocol.Role` here so
/// dynamic-table mutations surface as `qpack_dynamic_insert` /
/// `qpack_dynamic_evict` trace events without coupling QPACK to the
/// session's transport state.
pub const TraceContext = struct {
    hooks: observability.Hooks = .{},
    role: protocol.Role = .client,
};

pub const DynamicTable = struct {
    allocator: std.mem.Allocator,
    max_capacity: usize,
    capacity: usize = 0,
    size: usize = 0,
    insert_count: u64 = 0,
    dropped_count: u64 = 0,
    entries: std.ArrayList(Entry) = .empty,
    /// Optional trace context. Defaults to a no-op hook so the table
    /// stays usable in transport-free settings (tests, fuzzing).
    trace: TraceContext = .{},

    pub fn init(allocator: std.mem.Allocator, max_capacity: usize) DynamicTable {
        return .{
            .allocator = allocator,
            .max_capacity = max_capacity,
        };
    }

    pub fn deinit(self: *DynamicTable) void {
        self.clear();
        self.entries.deinit(self.allocator);
    }

    pub fn clear(self: *DynamicTable) void {
        for (self.entries.items) |*entry| self.freeEntry(entry);
        self.entries.clearRetainingCapacity();
        self.size = 0;
        self.dropped_count = self.insert_count;
    }

    pub fn len(self: *const DynamicTable) usize {
        return self.entries.items.len;
    }

    pub fn setCapacity(self: *DynamicTable, capacity: usize) Error!void {
        if (capacity > self.max_capacity) return Error.CapacityTooLarge;
        self.capacity = capacity;
        try self.evictToCapacity(capacity);
    }

    pub fn canInsert(self: *const DynamicTable, name: []const u8, value: []const u8) bool {
        return entrySize(name, value) <= self.capacity;
    }

    /// Byte size (RFC 9204 §3.2.1) an entry with this name/value occupies in
    /// the dynamic table. Exposed so a caller can size a prospective insert
    /// before deciding whether performing it is safe (`insertOnlyEvicts`).
    pub fn entrySizeFor(name: []const u8, value: []const u8) usize {
        return entrySize(name, value);
    }

    /// True iff inserting an entry of `size_needed` bytes would evict ONLY
    /// entries the caller's `evictable` predicate approves. Simulates the same
    /// oldest-first eviction as `insert`/`insertOwned`, without mutating the
    /// table. This keeps the encoder honoring RFC 9204 §2.1.2 — never evict a
    /// dynamic-table entry still referenced by an unacknowledged field section
    /// — while leaving reference bookkeeping in the caller (`EncoderState`)
    /// rather than in this table.
    pub fn insertOnlyEvicts(
        self: *const DynamicTable,
        size_needed: usize,
        ctx: anytype,
        comptime evictable: fn (@TypeOf(ctx), u64) bool,
    ) bool {
        if (size_needed > self.capacity) return false; // cannot be inserted at all
        const target = self.capacity - size_needed;
        var remaining = self.size;
        var i: usize = 0;
        while (remaining > target) {
            if (i >= self.entries.items.len) break;
            const entry = &self.entries.items[i];
            if (!evictable(ctx, entry.absolute_index)) return false;
            remaining -= entry.size();
            i += 1;
        }
        return true;
    }

    pub fn insert(
        self: *DynamicTable,
        name: []const u8,
        value: []const u8,
        sensitive: bool,
    ) Error!u64 {
        const size_needed = entrySize(name, value);
        if (size_needed > self.capacity) return Error.EntryTooLarge;

        const copies = blk: {
            const name_copy = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(name_copy);
            const value_copy = try self.allocator.dupe(u8, value);
            break :blk .{ .name = name_copy, .value = value_copy };
        };
        return try self.insertOwned(copies.name, copies.value, sensitive);
    }

    pub fn duplicate(self: *DynamicTable, relative_index: u64) Error!u64 {
        const source = self.getEncoderRelative(relative_index) orelse return Error.InvalidDynamicIndex;
        const name = try self.allocator.dupe(u8, source.name);
        errdefer self.allocator.free(name);
        const value = try self.allocator.dupe(u8, source.value);
        errdefer self.allocator.free(value);
        return try self.insertOwned(name, value, source.sensitive);
    }

    pub fn getAbsolute(self: *const DynamicTable, absolute_index: u64) ?*const Entry {
        const offset = self.offsetForAbsolute(absolute_index) orelse return null;
        return &self.entries.items[offset];
    }

    pub fn getEncoderRelative(self: *const DynamicTable, relative_index: u64) ?*const Entry {
        const absolute_index = self.encoderRelativeToAbsolute(relative_index) orelse return null;
        return self.getAbsolute(absolute_index);
    }

    pub fn getRelative(self: *const DynamicTable, base: u64, relative_index: u64) ?*const Entry {
        const absolute_index = relativeToAbsolute(base, relative_index) orelse return null;
        return self.getAbsolute(absolute_index);
    }

    pub fn getPostBase(self: *const DynamicTable, base: u64, post_base_index: u64) ?*const Entry {
        const absolute_index = postBaseToAbsolute(base, post_base_index) orelse return null;
        return self.getAbsolute(absolute_index);
    }

    pub fn encoderRelativeToAbsolute(self: *const DynamicTable, relative_index: u64) ?u64 {
        if (relative_index >= self.len()) return null;
        return self.insert_count - 1 - relative_index;
    }

    pub fn absoluteToEncoderRelative(self: *const DynamicTable, absolute_index: u64) ?u64 {
        if (self.getAbsolute(absolute_index) == null) return null;
        return self.insert_count - 1 - absolute_index;
    }

    pub fn absoluteToRelative(self: *const DynamicTable, base: u64, absolute_index: u64) ?u64 {
        if (self.getAbsolute(absolute_index) == null) return null;
        if (absolute_index >= base) return null;
        return base - 1 - absolute_index;
    }

    pub fn absoluteToPostBase(self: *const DynamicTable, base: u64, absolute_index: u64) ?u64 {
        if (self.getAbsolute(absolute_index) == null) return null;
        if (absolute_index < base) return null;
        return absolute_index - base;
    }

    pub fn find(self: *const DynamicTable, name: []const u8, value: []const u8) ?u64 {
        var i = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.entries.items[i];
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return entry.absolute_index;
            }
        }
        return null;
    }

    pub fn findName(self: *const DynamicTable, name: []const u8) ?u64 {
        var i = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.entries.items[i];
            if (std.mem.eql(u8, entry.name, name)) return entry.absolute_index;
        }
        return null;
    }

    fn insertOwned(self: *DynamicTable, name: []u8, value: []u8, sensitive: bool) Error!u64 {
        errdefer {
            self.allocator.free(name);
            self.allocator.free(value);
        }

        const size_needed = entrySize(name, value);
        if (size_needed > self.capacity) return Error.EntryTooLarge;
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.evictToCapacity(self.capacity - size_needed);

        const absolute_index = self.insert_count;
        self.entries.appendAssumeCapacity(.{
            .absolute_index = absolute_index,
            .name = name,
            .value = value,
            .sensitive = sensitive,
        });
        self.insert_count += 1;
        self.size += size_needed;
        self.trace.hooks.emit(.{
            .name = .qpack_dynamic_insert,
            .role = self.trace.role,
            .bytes = size_needed,
            .count = self.entries.items.len,
            .value = absolute_index,
        });
        return absolute_index;
    }

    fn offsetForAbsolute(self: *const DynamicTable, absolute_index: u64) ?usize {
        if (absolute_index < self.dropped_count or absolute_index >= self.insert_count) return null;
        const offset = absolute_index - self.dropped_count;
        if (offset >= self.entries.items.len) return null;
        return @intCast(offset);
    }

    fn evictToCapacity(self: *DynamicTable, target_size: usize) Error!void {
        while (self.size > target_size) {
            if (self.entries.items.len == 0) return Error.EntryTooLarge;
            var entry = self.entries.orderedRemove(0);
            const entry_size = entry.size();
            const evicted_index = entry.absolute_index;
            self.size -= entry_size;
            self.dropped_count = evicted_index + 1;
            self.freeEntry(&entry);
            self.trace.hooks.emit(.{
                .name = .qpack_dynamic_evict,
                .role = self.trace.role,
                .bytes = entry_size,
                .count = self.entries.items.len,
                .value = evicted_index,
            });
        }
    }

    fn freeEntry(self: *DynamicTable, entry: *Entry) void {
        self.allocator.free(entry.name);
        self.allocator.free(entry.value);
    }
};

pub fn entrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + overhead;
}

pub fn requiredInsertCount(absolute_index: u64) u64 {
    return absolute_index + 1;
}

pub fn relativeToAbsolute(base: u64, relative_index: u64) ?u64 {
    if (base == 0 or relative_index >= base) return null;
    return base - 1 - relative_index;
}

pub fn postBaseToAbsolute(base: u64, post_base_index: u64) ?u64 {
    return std.math.add(u64, base, post_base_index) catch null;
}

test "dynamic table inserts and resolves encoder relative indices" {
    var table = DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);

    const first = try table.insert("a", "1", false);
    const second = try table.insert("b", "2", false);

    try std.testing.expectEqual(@as(u64, 0), first);
    try std.testing.expectEqual(@as(u64, 1), second);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(usize, 68), table.size);
    try std.testing.expectEqualStrings("b", table.getEncoderRelative(0).?.name);
    try std.testing.expectEqualStrings("a", table.getEncoderRelative(1).?.name);
    try std.testing.expectEqual(@as(?u64, 0), table.absoluteToEncoderRelative(1));
}

test "dynamic table evicts oldest entries to fit capacity" {
    var table = DynamicTable.init(std.testing.allocator, 96);
    defer table.deinit();
    try table.setCapacity(96);

    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(u64, 1), table.dropped_count);
    try std.testing.expect(table.getAbsolute(0) == null);
    try std.testing.expectEqualStrings("b", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("c", table.getAbsolute(2).?.name);

    try table.setCapacity(entrySize("c", "3"));
    try std.testing.expectEqual(@as(usize, 1), table.len());
    try std.testing.expectEqualStrings("c", table.getEncoderRelative(0).?.name);
}

test "dynamic table duplicates entries before eviction" {
    var table = DynamicTable.init(std.testing.allocator, 68);
    defer table.deinit();
    try table.setCapacity(68);

    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    const duplicate = try table.duplicate(1);

    try std.testing.expectEqual(@as(u64, 2), duplicate);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expect(table.getAbsolute(0) == null);
    try std.testing.expectEqualStrings("b", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("a", table.getAbsolute(2).?.name);
}

test "dynamic table resolves field-section relative and post-base indices" {
    var table = DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);

    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    try std.testing.expectEqual(@as(?u64, 1), relativeToAbsolute(2, 0));
    try std.testing.expectEqual(@as(?u64, 0), relativeToAbsolute(2, 1));
    try std.testing.expect(relativeToAbsolute(2, 2) == null);
    try std.testing.expectEqualStrings("b", table.getRelative(2, 0).?.name);
    try std.testing.expectEqualStrings("a", table.getRelative(2, 1).?.name);
    try std.testing.expectEqualStrings("c", table.getPostBase(2, 0).?.name);
    try std.testing.expectEqual(@as(?u64, 0), table.absoluteToPostBase(2, 2));
    try std.testing.expectEqual(@as(u64, 3), requiredInsertCount(2));
}

test "dynamic table rejects invalid capacity, entry, and index" {
    var table = DynamicTable.init(std.testing.allocator, 32);
    defer table.deinit();

    try std.testing.expectError(Error.CapacityTooLarge, table.setCapacity(33));
    try table.setCapacity(32);
    try std.testing.expectError(Error.EntryTooLarge, table.insert("x", "y", false));
    try std.testing.expectError(Error.InvalidDynamicIndex, table.duplicate(0));
}

test "dynamic table emits qpack_dynamic_insert and qpack_dynamic_evict trace events" {
    const TraceRecorder = struct {
        events: [8]observability.TraceEvent = undefined,
        count: usize = 0,

        fn callback(user_data: ?*anyopaque, event: observability.TraceEvent) void {
            const self: *@This() = @ptrCast(@alignCast(user_data.?));
            if (self.count < self.events.len) {
                self.events[self.count] = event;
                self.count += 1;
            }
        }
    };

    var recorder: TraceRecorder = .{};
    var table = DynamicTable.init(std.testing.allocator, 96);
    defer table.deinit();
    table.trace = .{
        .hooks = .{ .callback = TraceRecorder.callback, .user_data = &recorder },
        .role = .client,
    };
    try table.setCapacity(96);

    // Three inserts, third forces an eviction (96-byte capacity fits two
    // 34-byte entries, not three).
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    var inserts: usize = 0;
    var evicts: usize = 0;
    var evicted_index: ?u64 = null;
    for (recorder.events[0..recorder.count]) |event| {
        switch (event.name) {
            .qpack_dynamic_insert => {
                inserts += 1;
                try std.testing.expectEqual(protocol.Role.client, event.role);
                try std.testing.expectEqual(entrySize("a", "1"), event.bytes);
            },
            .qpack_dynamic_evict => {
                evicts += 1;
                evicted_index = event.value;
                try std.testing.expectEqual(entrySize("a", "1"), event.bytes);
            },
            else => {},
        }
    }

    try std.testing.expectEqual(@as(usize, 3), inserts);
    try std.testing.expectEqual(@as(usize, 1), evicts);
    try std.testing.expectEqual(@as(?u64, 0), evicted_index);

    // Metrics observe the same events.
    var metrics: observability.Metrics = .{};
    for (recorder.events[0..recorder.count]) |event| metrics.observe(event);
    try std.testing.expectEqual(@as(u64, 3), metrics.qpack_dynamic_inserts);
    try std.testing.expectEqual(@as(u64, 1), metrics.qpack_dynamic_evicts);
}
