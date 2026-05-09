//! QPACK state synchronization helpers.
//!
//! This module tracks the transport-independent accounting around dynamic
//! references: Required Insert Count encoding, blocked streams, decoder
//! feedback, Known Received Count, and outstanding field-section references.

const std = @import("std");

const dynamic_table = @import("dynamic_table.zig");
const instructions = @import("instructions.zig");
const integer = @import("integer.zig");

pub const Error = instructions.Error || std.mem.Allocator.Error || error{
    InvalidRequiredInsertCount,
    RequiredInsertCountTooLarge,
    RequiredInsertCountNotReady,
    BlockedStreamLimitExceeded,
    UnexpectedSectionAcknowledgment,
    KnownReceivedCountTooHigh,
    InsertCountOverflow,
    ReferenceCountOverflow,
};

pub const FieldSectionPrefix = struct {
    required_insert_count: u64,
    base: u64,
};

pub const DecodedFieldSectionPrefix = struct {
    prefix: FieldSectionPrefix,
    bytes_read: usize,
};

pub const FieldSectionStatus = enum {
    ready,
    blocked,
};

const OutstandingSection = struct {
    stream_id: u64,
    required_insert_count: u64,
    references: []u64,
};

const EntryReference = struct {
    absolute_index: u64,
    count: u64,
};

const BlockedStream = struct {
    stream_id: u64,
    required_insert_count: u64,
};

pub fn maxEntries(max_table_capacity: u64) u64 {
    return max_table_capacity / dynamic_table.overhead;
}

pub fn requiredInsertCountForReferences(references: []const u64) Error!u64 {
    var required: u64 = 0;
    for (references) |absolute_index| {
        if (absolute_index == std.math.maxInt(u64)) return error.InsertCountOverflow;
        required = @max(required, absolute_index + 1);
    }
    return required;
}

pub fn encodeRequiredInsertCount(required_insert_count: u64, max_table_capacity: u64) Error!u64 {
    if (required_insert_count == 0) return 0;
    const full_range = try insertCountFullRange(max_table_capacity);
    return (required_insert_count % full_range) + 1;
}

pub fn decodeRequiredInsertCount(
    encoded_insert_count: u64,
    max_table_capacity: u64,
    total_number_of_inserts: u64,
) Error!u64 {
    if (encoded_insert_count == 0) return 0;

    const entries = maxEntries(max_table_capacity);
    const full_range = try insertCountFullRange(max_table_capacity);
    if (encoded_insert_count > full_range) return error.InvalidRequiredInsertCount;

    const max_value = std.math.add(u64, total_number_of_inserts, entries) catch {
        return error.InvalidRequiredInsertCount;
    };
    const max_wrapped = (max_value / full_range) * full_range;
    var required_insert_count = std.math.add(u64, max_wrapped, encoded_insert_count - 1) catch {
        return error.InvalidRequiredInsertCount;
    };

    if (required_insert_count > max_value) {
        if (required_insert_count <= full_range) return error.InvalidRequiredInsertCount;
        required_insert_count -= full_range;
    }
    if (required_insert_count == 0) return error.InvalidRequiredInsertCount;
    return required_insert_count;
}

pub fn fieldSectionPrefixEncodedLen(
    prefix: FieldSectionPrefix,
    max_table_capacity: u64,
) Error!usize {
    const encoded_insert_count = try encodeRequiredInsertCount(prefix.required_insert_count, max_table_capacity);
    const delta_base = try baseDelta(prefix);
    return integer.encodedLen(8, encoded_insert_count) + integer.encodedLen(7, delta_base);
}

pub fn encodeFieldSectionPrefix(
    dst: []u8,
    prefix: FieldSectionPrefix,
    max_table_capacity: u64,
) Error!usize {
    var pos: usize = 0;
    const encoded_insert_count = try encodeRequiredInsertCount(prefix.required_insert_count, max_table_capacity);
    pos += try integer.encode(dst[pos..], 8, 0, encoded_insert_count);

    const delta_base = try baseDelta(prefix);
    const sign: u8 = if (prefix.base < prefix.required_insert_count) 0x80 else 0;
    pos += try integer.encode(dst[pos..], 7, sign, delta_base);
    return pos;
}

pub fn decodeFieldSectionPrefix(
    src: []const u8,
    max_table_capacity: u64,
    total_number_of_inserts: u64,
) Error!DecodedFieldSectionPrefix {
    var pos: usize = 0;
    const encoded = try decodeFieldSectionInteger(src[pos..], 8);
    pos += encoded.bytes_read;
    const required_insert_count = try decodeRequiredInsertCount(
        encoded.value,
        max_table_capacity,
        total_number_of_inserts,
    );

    if (pos >= src.len) return error.InvalidRequiredInsertCount;
    const first = src[pos];
    const delta = try decodeFieldSectionInteger(src[pos..], 7);
    pos += delta.bytes_read;

    const base = if ((first & 0x80) == 0)
        std.math.add(u64, required_insert_count, delta.value) catch return error.InvalidRequiredInsertCount
    else blk: {
        if (required_insert_count <= delta.value) return error.InvalidRequiredInsertCount;
        break :blk required_insert_count - delta.value - 1;
    };

    return .{
        .prefix = .{
            .required_insert_count = required_insert_count,
            .base = base,
        },
        .bytes_read = pos,
    };
}

pub const EncoderState = struct {
    allocator: std.mem.Allocator,
    max_blocked_streams: u64,
    insert_count: u64 = 0,
    known_received_count: u64 = 0,
    sections: std.ArrayList(OutstandingSection) = .empty,
    references: std.ArrayList(EntryReference) = .empty,

    pub fn init(allocator: std.mem.Allocator, max_blocked_streams: u64) EncoderState {
        return .{
            .allocator = allocator,
            .max_blocked_streams = max_blocked_streams,
        };
    }

    pub fn deinit(self: *EncoderState) void {
        self.clear();
        self.sections.deinit(self.allocator);
        self.references.deinit(self.allocator);
    }

    pub fn clear(self: *EncoderState) void {
        for (self.sections.items) |section| self.allocator.free(section.references);
        self.sections.clearRetainingCapacity();
        self.references.clearRetainingCapacity();
        self.insert_count = 0;
        self.known_received_count = 0;
    }

    pub fn recordInsert(self: *EncoderState, absolute_index: u64) Error!void {
        if (absolute_index == std.math.maxInt(u64)) return error.InsertCountOverflow;
        self.insert_count = @max(self.insert_count, absolute_index + 1);
    }

    pub fn recordInsertCount(self: *EncoderState, insert_count: u64) void {
        self.insert_count = @max(self.insert_count, insert_count);
    }

    pub fn canReferenceWithoutBlocking(self: *const EncoderState, absolute_index: u64) bool {
        if (absolute_index == std.math.maxInt(u64)) return false;
        return absolute_index + 1 <= self.known_received_count;
    }

    pub fn isPotentiallyBlocked(self: *const EncoderState, required_insert_count: u64) bool {
        return required_insert_count > self.known_received_count;
    }

    pub fn blockedStreamCount(self: *const EncoderState) usize {
        var count: usize = 0;
        for (self.sections.items, 0..) |section, i| {
            if (!self.isPotentiallyBlocked(section.required_insert_count)) continue;
            var seen = false;
            for (self.sections.items[0..i]) |prior| {
                if (prior.stream_id == section.stream_id and
                    self.isPotentiallyBlocked(prior.required_insert_count))
                {
                    seen = true;
                    break;
                }
            }
            if (!seen) count += 1;
        }
        return count;
    }

    pub fn referenceCount(self: *const EncoderState, absolute_index: u64) u64 {
        for (self.references.items) |reference| {
            if (reference.absolute_index == absolute_index) return reference.count;
        }
        return 0;
    }

    pub fn isEvictable(self: *const EncoderState, absolute_index: u64) bool {
        if (absolute_index == std.math.maxInt(u64)) return false;
        return absolute_index + 1 <= self.known_received_count and self.referenceCount(absolute_index) == 0;
    }

    pub fn trackFieldSection(
        self: *EncoderState,
        stream_id: u64,
        references: []const u64,
    ) Error!u64 {
        const required_insert_count = try requiredInsertCountForReferences(references);
        if (required_insert_count == 0) return 0;
        if (required_insert_count > self.insert_count) return error.RequiredInsertCountTooLarge;

        if (self.isPotentiallyBlocked(required_insert_count) and
            !self.streamAlreadyPotentiallyBlocked(stream_id) and
            @as(u64, @intCast(self.blockedStreamCount())) >= self.max_blocked_streams)
        {
            return error.BlockedStreamLimitExceeded;
        }

        const owned_refs = try self.allocator.dupe(u64, references);
        errdefer self.allocator.free(owned_refs);
        try self.sections.ensureUnusedCapacity(self.allocator, 1);

        var added: usize = 0;
        errdefer {
            for (owned_refs[0..added]) |absolute_index| self.decrementReference(absolute_index);
        }
        for (owned_refs) |absolute_index| {
            try self.incrementReference(absolute_index);
            added += 1;
        }

        self.sections.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
            .references = owned_refs,
        });
        return required_insert_count;
    }

    pub fn receiveDecoderInstruction(
        self: *EncoderState,
        instruction: instructions.DecoderInstruction,
    ) Error!void {
        switch (instruction) {
            .section_ack => |stream_id| {
                const required_insert_count = try self.acknowledgeSection(stream_id);
                self.known_received_count = @max(self.known_received_count, required_insert_count);
            },
            .stream_cancel => |stream_id| self.cancelStream(stream_id),
            .insert_count_increment => |increment| {
                if (increment == 0) return error.InsertCountIncrementZero;
                const next = std.math.add(u64, self.known_received_count, increment) catch {
                    return error.KnownReceivedCountTooHigh;
                };
                if (next > self.insert_count) return error.KnownReceivedCountTooHigh;
                self.known_received_count = next;
            },
        }
    }

    pub fn acknowledgeSection(self: *EncoderState, stream_id: u64) Error!u64 {
        for (self.sections.items, 0..) |section, i| {
            if (section.stream_id == stream_id) return self.removeSectionAt(i);
        }
        return error.UnexpectedSectionAcknowledgment;
    }

    pub fn cancelStream(self: *EncoderState, stream_id: u64) void {
        var i: usize = 0;
        while (i < self.sections.items.len) {
            if (self.sections.items[i].stream_id == stream_id) {
                _ = self.removeSectionAt(i) catch unreachable;
            } else {
                i += 1;
            }
        }
    }

    fn streamAlreadyPotentiallyBlocked(self: *const EncoderState, stream_id: u64) bool {
        for (self.sections.items) |section| {
            if (section.stream_id == stream_id and self.isPotentiallyBlocked(section.required_insert_count)) {
                return true;
            }
        }
        return false;
    }

    fn incrementReference(self: *EncoderState, absolute_index: u64) Error!void {
        for (self.references.items) |*reference| {
            if (reference.absolute_index == absolute_index) {
                reference.count = std.math.add(u64, reference.count, 1) catch {
                    return error.ReferenceCountOverflow;
                };
                return;
            }
        }
        try self.references.append(self.allocator, .{
            .absolute_index = absolute_index,
            .count = 1,
        });
    }

    fn decrementReference(self: *EncoderState, absolute_index: u64) void {
        for (self.references.items, 0..) |*reference, i| {
            if (reference.absolute_index != absolute_index) continue;
            std.debug.assert(reference.count > 0);
            reference.count -= 1;
            if (reference.count == 0) _ = self.references.orderedRemove(i);
            return;
        }
        unreachable;
    }

    fn removeSectionAt(self: *EncoderState, index: usize) Error!u64 {
        const section = self.sections.orderedRemove(index);
        for (section.references) |absolute_index| self.decrementReference(absolute_index);
        const required_insert_count = section.required_insert_count;
        self.allocator.free(section.references);
        return required_insert_count;
    }
};

pub const DecoderState = struct {
    allocator: std.mem.Allocator,
    max_blocked_streams: u64,
    insert_count: u64 = 0,
    advertised_insert_count: u64 = 0,
    blocked: std.ArrayList(BlockedStream) = .empty,

    pub fn init(allocator: std.mem.Allocator, max_blocked_streams: u64) DecoderState {
        return .{
            .allocator = allocator,
            .max_blocked_streams = max_blocked_streams,
        };
    }

    pub fn deinit(self: *DecoderState) void {
        self.blocked.deinit(self.allocator);
    }

    pub fn recordInsert(self: *DecoderState, absolute_index: u64) Error!void {
        if (absolute_index == std.math.maxInt(u64)) return error.InsertCountOverflow;
        self.recordInsertCount(absolute_index + 1);
    }

    pub fn recordInsertCount(self: *DecoderState, insert_count: u64) void {
        self.insert_count = @max(self.insert_count, insert_count);
    }

    pub fn applyEncoderInstruction(
        self: *DecoderState,
        table: *dynamic_table.DynamicTable,
        instruction: instructions.EncoderInstruction,
    ) Error!?u64 {
        const inserted = try instructions.applyEncoderInstruction(table, instruction);
        if (inserted) |absolute_index| try self.recordInsert(absolute_index);
        return inserted;
    }

    pub fn beginFieldSection(
        self: *DecoderState,
        stream_id: u64,
        required_insert_count: u64,
    ) Error!FieldSectionStatus {
        if (required_insert_count <= self.insert_count) return .ready;

        if (self.findBlocked(stream_id)) |index| {
            self.blocked.items[index].required_insert_count = @max(
                self.blocked.items[index].required_insert_count,
                required_insert_count,
            );
            return .blocked;
        }

        if (@as(u64, @intCast(self.blocked.items.len)) >= self.max_blocked_streams) {
            return error.BlockedStreamLimitExceeded;
        }

        try self.blocked.append(self.allocator, .{
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
        });
        return .blocked;
    }

    pub fn fieldSectionStatus(self: *const DecoderState, required_insert_count: u64) FieldSectionStatus {
        return if (required_insert_count <= self.insert_count) .ready else .blocked;
    }

    pub fn blockedStreamCount(self: *const DecoderState) usize {
        return self.blocked.items.len;
    }

    pub fn isStreamBlocked(self: *const DecoderState, stream_id: u64) bool {
        return self.findBlocked(stream_id) != null;
    }

    pub fn completeFieldSection(
        self: *DecoderState,
        stream_id: u64,
        required_insert_count: u64,
    ) Error!?instructions.DecoderInstruction {
        if (required_insert_count > self.insert_count) return error.RequiredInsertCountNotReady;
        if (self.findBlocked(stream_id)) |index| {
            if (self.blocked.items[index].required_insert_count <= self.insert_count) {
                _ = self.blocked.orderedRemove(index);
            }
        }
        if (required_insert_count == 0) return null;

        self.advertised_insert_count = @max(self.advertised_insert_count, required_insert_count);
        return .{ .section_ack = stream_id };
    }

    pub fn cancelStream(self: *DecoderState, stream_id: u64) instructions.DecoderInstruction {
        if (self.findBlocked(stream_id)) |index| _ = self.blocked.orderedRemove(index);
        return .{ .stream_cancel = stream_id };
    }

    pub fn takeInsertCountIncrement(self: *DecoderState) ?instructions.DecoderInstruction {
        if (self.insert_count <= self.advertised_insert_count) return null;
        const increment = self.insert_count - self.advertised_insert_count;
        self.advertised_insert_count = self.insert_count;
        return .{ .insert_count_increment = increment };
    }

    fn findBlocked(self: *const DecoderState, stream_id: u64) ?usize {
        for (self.blocked.items, 0..) |blocked, i| {
            if (blocked.stream_id == stream_id) return i;
        }
        return null;
    }
};

fn insertCountFullRange(max_table_capacity: u64) Error!u64 {
    const entries = maxEntries(max_table_capacity);
    if (entries == 0) return error.InvalidRequiredInsertCount;
    return std.math.mul(u64, entries, 2) catch error.InvalidRequiredInsertCount;
}

fn baseDelta(prefix: FieldSectionPrefix) Error!u64 {
    if (prefix.base >= prefix.required_insert_count) {
        return prefix.base - prefix.required_insert_count;
    }
    if (prefix.required_insert_count == 0) return error.InvalidRequiredInsertCount;
    return prefix.required_insert_count - prefix.base - 1;
}

fn decodeFieldSectionInteger(src: []const u8, prefix_bits: u8) Error!integer.Decoded {
    return integer.decode(src, prefix_bits) catch |err| switch (err) {
        error.InsufficientBytes, error.ValueTooLarge, error.InvalidPrefix => error.InvalidRequiredInsertCount,
        error.BufferTooSmall => unreachable,
    };
}

test "required insert count and field section prefix follow RFC wrapping" {
    try std.testing.expectEqual(@as(u64, 3), maxEntries(100));
    try std.testing.expectEqual(@as(u64, 4), try encodeRequiredInsertCount(9, 100));
    try std.testing.expectEqual(@as(u64, 9), try decodeRequiredInsertCount(4, 100, 10));

    var buf: [16]u8 = undefined;
    const prefix = FieldSectionPrefix{ .required_insert_count = 9, .base = 6 };
    const n = try encodeFieldSectionPrefix(&buf, prefix, 100);
    try std.testing.expectEqual(try fieldSectionPrefixEncodedLen(prefix, 100), n);
    const decoded = try decodeFieldSectionPrefix(buf[0..n], 100, 10);
    try std.testing.expectEqual(prefix.required_insert_count, decoded.prefix.required_insert_count);
    try std.testing.expectEqual(prefix.base, decoded.prefix.base);
    try std.testing.expectEqual(n, decoded.bytes_read);

    const no_refs = FieldSectionPrefix{ .required_insert_count = 0, .base = 0 };
    const no_refs_n = try encodeFieldSectionPrefix(&buf, no_refs, 0);
    const decoded_no_refs = try decodeFieldSectionPrefix(buf[0..no_refs_n], 0, 0);
    try std.testing.expectEqual(@as(u64, 0), decoded_no_refs.prefix.required_insert_count);
    try std.testing.expectEqual(@as(u64, 0), decoded_no_refs.prefix.base);
}

test "Required Insert Count round-trips at the modular wrap boundary (RFC 9204 §4.5.1.1)" {
    // RFC 9204 §4.5.1.1 defines:
    //   EncReqInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
    //   when ReqInsertCount > 0; otherwise 0.
    //
    // The boundary case `ReqInsertCount == full_range` (a multiple of
    // 2 * MaxEntries) encodes to the same byte (1) as
    // `ReqInsertCount == 1`. The decoder disambiguates using
    // `total_number_of_inserts`. This test pins that round-trip at
    // the exact modular boundaries — the audit identified the wrap
    // point as a latent edge case whose behavior wasn't directly
    // covered.
    //
    // With max_table_capacity = 96 and dynamic_table.overhead = 32:
    //   MaxEntries = 96 / 32 = 3
    //   full_range = 6
    const max_table_capacity: u64 = 96;
    const full_range = try insertCountFullRange(max_table_capacity);
    try std.testing.expectEqual(@as(u64, 6), full_range);
    try std.testing.expectEqual(@as(u64, 3), maxEntries(max_table_capacity));

    // ReqInsertCount = full_range produces encoded value 1
    // (because full_range mod full_range = 0; +1 = 1).
    try std.testing.expectEqual(
        @as(u64, 1),
        try encodeRequiredInsertCount(full_range, max_table_capacity),
    );

    // Decoder disambiguates encoded=1 using `total_number_of_inserts`.
    // When total_number_of_inserts is in the same wrap window as the
    // value being communicated, the decoder MUST recover it exactly.
    try std.testing.expectEqual(
        @as(u64, full_range),
        try decodeRequiredInsertCount(1, max_table_capacity, full_range),
    );

    // ReqInsertCount = full_range + 1 wraps to encoded=2.
    try std.testing.expectEqual(
        @as(u64, 2),
        try encodeRequiredInsertCount(full_range + 1, max_table_capacity),
    );
    try std.testing.expectEqual(
        @as(u64, full_range + 1),
        try decodeRequiredInsertCount(2, max_table_capacity, full_range + 1),
    );

    // 2 * full_range (== 2 * 6 == 12) also encodes as 1.
    try std.testing.expectEqual(
        @as(u64, 1),
        try encodeRequiredInsertCount(full_range * 2, max_table_capacity),
    );
    try std.testing.expectEqual(
        @as(u64, full_range * 2),
        try decodeRequiredInsertCount(1, max_table_capacity, full_range * 2),
    );

    // Sweep the 0..2*full_range range to confirm round-trip at every
    // integer point (with a `total_number_of_inserts` that pins the
    // wrap window). This catches off-by-ones around the boundary
    // that the spot checks above might miss.
    var req: u64 = 0;
    while (req <= full_range * 2) : (req += 1) {
        const encoded = try encodeRequiredInsertCount(req, max_table_capacity);
        const recovered = try decodeRequiredInsertCount(encoded, max_table_capacity, req);
        try std.testing.expectEqual(req, recovered);
    }
}

test "encoder state tracks blocked streams, references, acknowledgments, and cancellations" {
    var encoder = EncoderState.init(std.testing.allocator, 1);
    defer encoder.deinit();
    try encoder.recordInsert(0);
    try encoder.recordInsert(1);

    try std.testing.expectEqual(@as(u64, 1), try encoder.trackFieldSection(0, &.{0}));
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());
    try std.testing.expectEqual(@as(u64, 1), encoder.referenceCount(0));
    try std.testing.expect(!encoder.isEvictable(0));

    try std.testing.expectError(error.BlockedStreamLimitExceeded, encoder.trackFieldSection(4, &.{1}));

    try encoder.receiveDecoderInstruction(.{ .insert_count_increment = 1 });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
    try std.testing.expect(!encoder.isEvictable(0));

    try encoder.receiveDecoderInstruction(.{ .section_ack = 0 });
    try std.testing.expectEqual(@as(u64, 0), encoder.referenceCount(0));
    try std.testing.expect(encoder.isEvictable(0));
    try std.testing.expectError(
        error.UnexpectedSectionAcknowledgment,
        encoder.receiveDecoderInstruction(.{ .section_ack = 0 }),
    );

    try std.testing.expectEqual(@as(u64, 2), try encoder.trackFieldSection(8, &.{1}));
    try encoder.receiveDecoderInstruction(.{ .stream_cancel = 8 });
    try std.testing.expectEqual(@as(u64, 0), encoder.referenceCount(1));
    try std.testing.expectError(
        error.KnownReceivedCountTooHigh,
        encoder.receiveDecoderInstruction(.{ .insert_count_increment = 9 }),
    );
}

test "section acknowledgments advance known received count from outstanding sections" {
    var encoder = EncoderState.init(std.testing.allocator, 16);
    defer encoder.deinit();
    encoder.recordInsertCount(3);

    _ = try encoder.trackFieldSection(4, &.{2});
    try std.testing.expectEqual(@as(u64, 0), encoder.known_received_count);
    try encoder.receiveDecoderInstruction(.{ .section_ack = 4 });
    try std.testing.expectEqual(@as(u64, 3), encoder.known_received_count);
    try std.testing.expect(encoder.isEvictable(2));
}

test "decoder state blocks, unblocks, acknowledges, and coalesces insert increments" {
    var decoder = DecoderState.init(std.testing.allocator, 1);
    defer decoder.deinit();

    try std.testing.expectEqual(FieldSectionStatus.ready, try decoder.beginFieldSection(0, 0));
    try std.testing.expectEqual(FieldSectionStatus.blocked, try decoder.beginFieldSection(4, 2));
    try std.testing.expect(decoder.isStreamBlocked(4));
    try std.testing.expectEqual(@as(usize, 1), decoder.blockedStreamCount());
    try std.testing.expectError(error.BlockedStreamLimitExceeded, decoder.beginFieldSection(8, 1));

    decoder.recordInsertCount(1);
    try std.testing.expectEqual(FieldSectionStatus.blocked, decoder.fieldSectionStatus(2));
    decoder.recordInsertCount(2);
    try std.testing.expectEqual(FieldSectionStatus.ready, decoder.fieldSectionStatus(2));

    const ack = (try decoder.completeFieldSection(4, 2)).?;
    try std.testing.expectEqual(@as(u64, 4), ack.section_ack);
    try std.testing.expectEqual(@as(u64, 2), decoder.advertised_insert_count);
    try std.testing.expect(decoder.takeInsertCountIncrement() == null);
    try std.testing.expectEqual(@as(usize, 0), decoder.blockedStreamCount());
}

test "decoder state applies encoder instructions and emits insert count increments" {
    var table = dynamic_table.DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    var decoder = DecoderState.init(std.testing.allocator, 4);
    defer decoder.deinit();

    try std.testing.expectEqual(@as(?u64, null), try decoder.applyEncoderInstruction(
        &table,
        .{ .set_capacity = 128 },
    ));
    const inserted = try decoder.applyEncoderInstruction(&table, .{ .insert_literal = .{
        .name = "x-test",
        .value = "one",
    } });
    try std.testing.expectEqual(@as(?u64, 0), inserted);
    try std.testing.expectEqual(@as(u64, 1), decoder.insert_count);

    const increment = decoder.takeInsertCountIncrement().?;
    try std.testing.expectEqual(@as(u64, 1), increment.insert_count_increment);
    try std.testing.expect(decoder.takeInsertCountIncrement() == null);
}
