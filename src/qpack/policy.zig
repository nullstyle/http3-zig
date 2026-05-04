//! QPACK indexing policy.
//!
//! The default policy is conservative: static references are allowed, dynamic
//! references require either an acknowledged entry or field-section tracking,
//! and dynamic insertions are opt-in. Sensitive fields never use the dynamic
//! table unless the caller explicitly opts out of that safety rail.

const std = @import("std");

const dynamic_table = @import("dynamic_table.zig");
const state = @import("state.zig");

pub const DynamicReferenceMode = enum {
    /// Never reference the dynamic table from field sections.
    none,
    /// Reference only entries acknowledged by the decoder.
    acknowledged,
    /// Reference entries when they are acknowledged or the field section will
    /// be tracked against SETTINGS_QPACK_BLOCKED_STREAMS.
    tracked,
    /// Reference any available dynamic table entry. The caller owns blocking
    /// risk management.
    any,
};

pub const DynamicInsertMode = enum {
    /// Never emit encoder-stream insertion instructions.
    never,
    /// Insert fields whose name can be referenced from an existing static or
    /// dynamic table entry.
    name_references,
    /// Insert all eligible fields that fit the dynamic table, using name
    /// references when possible and literal names otherwise.
    all,
};

pub const ReferenceContext = struct {
    encoder_state: ?*const state.EncoderState = null,
    will_track_field_section: bool = false,
};

pub const IndexingPolicy = struct {
    prefer_static: bool = true,
    dynamic_references: DynamicReferenceMode = .tracked,
    dynamic_inserts: DynamicInsertMode = .never,
    allow_sensitive_static_indexed: bool = false,
    allow_sensitive_dynamic_references: bool = false,
    allow_sensitive_dynamic_inserts: bool = false,
    min_insert_name_len: usize = 0,
    min_insert_value_len: usize = 0,

    pub const static_only: IndexingPolicy = .{
        .dynamic_references = .none,
        .dynamic_inserts = .never,
    };

    pub const nonblocking: IndexingPolicy = .{
        .dynamic_references = .acknowledged,
        .dynamic_inserts = .never,
    };

    pub const tracked_dynamic: IndexingPolicy = .{
        .dynamic_references = .tracked,
        .dynamic_inserts = .never,
    };

    pub const aggressive: IndexingPolicy = .{
        .dynamic_references = .any,
        .dynamic_inserts = .all,
    };

    pub fn allowsStaticIndexed(self: IndexingPolicy, sensitive: bool) bool {
        return !sensitive or self.allow_sensitive_static_indexed;
    }

    pub fn allowsDynamicReference(
        self: IndexingPolicy,
        sensitive: bool,
        absolute_index: u64,
        context: ReferenceContext,
    ) bool {
        if (sensitive and !self.allow_sensitive_dynamic_references) return false;
        if (absolute_index == std.math.maxInt(u64)) return false;

        return switch (self.dynamic_references) {
            .none => false,
            .acknowledged => if (context.encoder_state) |encoder|
                encoder.canReferenceWithoutBlocking(absolute_index)
            else
                false,
            .tracked => if (context.encoder_state) |encoder|
                encoder.canReferenceWithoutBlocking(absolute_index) or context.will_track_field_section
            else
                context.will_track_field_section,
            .any => true,
        };
    }

    pub fn allowsDynamicInsert(
        self: IndexingPolicy,
        table: *const dynamic_table.DynamicTable,
        sensitive: bool,
        name: []const u8,
        value: []const u8,
    ) bool {
        if (self.dynamic_inserts == .never) return false;
        if (sensitive and !self.allow_sensitive_dynamic_inserts) return false;
        if (name.len < self.min_insert_name_len or value.len < self.min_insert_value_len) return false;
        return table.canInsert(name, value);
    }
};

test "default policy requires tracked or acknowledged dynamic references" {
    const policy: IndexingPolicy = .{};
    try std.testing.expect(!policy.allowsDynamicReference(false, 0, .{}));
    try std.testing.expect(policy.allowsDynamicReference(false, 0, .{
        .will_track_field_section = true,
    }));

    var encoder = state.EncoderState.init(std.testing.allocator, 0);
    defer encoder.deinit();
    encoder.recordInsertCount(1);
    try encoder.receiveDecoderInstruction(.{ .insert_count_increment = 1 });
    try std.testing.expect(policy.allowsDynamicReference(false, 0, .{
        .encoder_state = &encoder,
    }));
}

test "policy refuses sensitive dynamic use unless explicitly enabled" {
    var table = dynamic_table.DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);

    const policy: IndexingPolicy = .{
        .dynamic_references = .any,
        .dynamic_inserts = .all,
    };
    try std.testing.expect(!policy.allowsDynamicReference(true, 0, .{}));
    try std.testing.expect(!policy.allowsDynamicInsert(&table, true, "authorization", "secret"));

    const explicit: IndexingPolicy = .{
        .dynamic_references = .any,
        .dynamic_inserts = .all,
        .allow_sensitive_dynamic_references = true,
        .allow_sensitive_dynamic_inserts = true,
    };
    try std.testing.expect(explicit.allowsDynamicReference(true, 0, .{}));
    try std.testing.expect(explicit.allowsDynamicInsert(&table, true, "authorization", "secret"));
}
