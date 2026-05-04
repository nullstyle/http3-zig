//! QPACK primitives and a non-blocking field-section codec.

const std = @import("std");

pub const integer = @import("integer.zig");
pub const huffman = @import("huffman.zig");
pub const dynamic_table = @import("dynamic_table.zig");
pub const instructions = @import("instructions.zig");
pub const policy = @import("policy.zig");
pub const state = @import("state.zig");
pub const static_table = @import("static_table.zig");

pub const DynamicTable = dynamic_table.DynamicTable;
pub const DynamicEntry = dynamic_table.Entry;
pub const EncoderInstruction = instructions.EncoderInstruction;
pub const DecoderInstruction = instructions.DecoderInstruction;
pub const IndexingPolicy = policy.IndexingPolicy;
pub const QpackEncoderState = state.EncoderState;
pub const QpackDecoderState = state.DecoderState;
pub const FieldSectionPrefix = state.FieldSectionPrefix;

pub const Error = integer.Error || huffman.Error || dynamic_table.Error || instructions.Error || state.Error || error{
    BufferTooSmall,
    OutOfMemory,
    HuffmanUnsupported,
    DynamicTableUnsupported,
    UnsupportedRepresentation,
    MalformedFieldSection,
    InvalidStaticIndex,
};

pub const StringOptions = struct {
    huffman: bool = false,
};

pub const FieldSectionEncodeOptions = struct {
    huffman: bool = false,
};

pub const DynamicFieldSectionTracker = struct {
    encoder_state: *state.EncoderState,
    stream_id: u64,
};

pub const DynamicFieldSectionEncodeOptions = struct {
    huffman: bool = false,
    tracker: ?DynamicFieldSectionTracker = null,
    indexing: IndexingPolicy = .{},
};

pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    /// Maps to QPACK's N bit. Sensitive fields are never indexed.
    sensitive: bool = false,
};

const FieldRepresentation = union(enum) {
    static_indexed: usize,
    dynamic_indexed: u64,
    dynamic_post_base_indexed: u64,
    static_name: usize,
    dynamic_name: u64,
    dynamic_post_base_name: u64,
    literal,
};

const DynamicFieldSectionPlan = struct {
    base: u64,
    required_insert_count: u64,
    body_len: usize,

    pub fn totalLen(self: DynamicFieldSectionPlan, max_table_capacity: u64) Error!usize {
        return try state.fieldSectionPrefixEncodedLen(.{
            .required_insert_count = self.required_insert_count,
            .base = self.base,
        }, max_table_capacity) + self.body_len;
    }
};

pub fn literalFieldSectionEncodedLen(fields: []const FieldLine) usize {
    return literalFieldSectionEncodedLenWithOptions(fields, .{});
}

pub fn literalFieldSectionEncodedLenWithOptions(
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        const string_options: StringOptions = .{ .huffman = options.huffman };
        n += stringLiteralEncodedLen(3, field.name, string_options);
        n += stringLiteralEncodedLen(7, field.value, string_options);
    }
    return n;
}

/// Length for `encodeFieldSection`: static full matches become indexed
/// representations; static name matches become literal-with-name-reference;
/// everything else uses a literal-name representation.
pub fn fieldSectionEncodedLen(fields: []const FieldLine) usize {
    return fieldSectionEncodedLenWithOptions(fields, .{});
}

pub fn fieldSectionEncodedLenWithOptions(
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) usize {
    var n: usize = 2; // Required Insert Count = 0, Delta Base = 0.
    for (fields) |field| {
        if (!field.sensitive and static_table.find(field.name, field.value) != null) {
            const index = static_table.find(field.name, field.value).?;
            n += integer.encodedLen(6, index);
        } else if (static_table.findName(field.name)) |index| {
            n += integer.encodedLen(4, index);
            n += stringLiteralEncodedLen(7, field.value, .{ .huffman = options.huffman });
        } else {
            const string_options: StringOptions = .{ .huffman = options.huffman };
            n += stringLiteralEncodedLen(3, field.name, string_options);
            n += stringLiteralEncodedLen(7, field.value, string_options);
        }
    }
    return n;
}

/// Encode a non-blocking QPACK field section using literal-name
/// representations only. This is valid QPACK and is the safe baseline
/// until the dynamic table lands.
pub fn encodeLiteralFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    return encodeLiteralFieldSectionWithOptions(dst, fields, .{});
}

pub fn encodeLiteralFieldSectionWithOptions(
    dst: []u8,
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], 8, 0, 0); // Required Insert Count.
    pos += try integer.encode(dst[pos..], 7, 0, 0); // Sign bit 0, Delta Base 0.

    for (fields) |field| {
        const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
        const string_options: StringOptions = .{ .huffman = options.huffman };
        pos += try encodeStringLiteral(dst[pos..], field.name, 3, prefix, string_options);
        pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, string_options);
    }
    return pos;
}

/// Encode a non-blocking QPACK field section using the static table when
/// possible. It never references the dynamic table, so it cannot block on
/// QPACK encoder-stream delivery.
pub fn encodeFieldSection(dst: []u8, fields: []const FieldLine) Error!usize {
    return encodeFieldSectionWithOptions(dst, fields, .{});
}

pub fn encodeFieldSectionWithOptions(
    dst: []u8,
    fields: []const FieldLine,
    options: FieldSectionEncodeOptions,
) Error!usize {
    var pos: usize = 0;
    pos += try integer.encode(dst[pos..], 8, 0, 0); // Required Insert Count.
    pos += try integer.encode(dst[pos..], 7, 0, 0); // Sign bit 0, Delta Base 0.

    for (fields) |field| {
        if (!field.sensitive) {
            if (static_table.find(field.name, field.value)) |index| {
                pos += try integer.encode(dst[pos..], 6, 0xc0, @intCast(index));
                continue;
            }
        }

        if (static_table.findName(field.name)) |index| {
            const prefix: u8 = 0x50 | if (field.sensitive) @as(u8, 0x20) else 0;
            pos += try integer.encode(dst[pos..], 4, prefix, @intCast(index));
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, .{
                .huffman = options.huffman,
            });
        } else {
            const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
            const string_options: StringOptions = .{ .huffman = options.huffman };
            pos += try encodeStringLiteral(dst[pos..], field.name, 3, prefix, string_options);
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, string_options);
        }
    }
    return pos;
}

/// Length for `encodeDynamicFieldSection`: representation choices follow
/// `DynamicFieldSectionEncodeOptions.indexing`.
pub fn dynamicFieldSectionEncodedLen(
    table: *const DynamicTable,
    fields: []const FieldLine,
) Error!usize {
    return dynamicFieldSectionEncodedLenWithOptions(table, fields, .{});
}

pub fn dynamicFieldSectionEncodedLenWithOptions(
    table: *const DynamicTable,
    fields: []const FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) Error!usize {
    const plan = try planDynamicFieldSection(table, fields, options);
    return try plan.totalLen(@intCast(table.max_capacity));
}

/// Encode a QPACK field section that can reference the dynamic table according
/// to `options.indexing`. This is still transport-free: callers are
/// responsible for emitting any encoder stream instructions that populate
/// `table`.
pub fn encodeDynamicFieldSection(
    dst: []u8,
    table: *const DynamicTable,
    fields: []const FieldLine,
) Error!usize {
    return encodeDynamicFieldSectionWithOptions(dst, table, fields, .{});
}

pub fn encodeDynamicFieldSectionWithOptions(
    dst: []u8,
    table: *const DynamicTable,
    fields: []const FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) Error!usize {
    const max_table_capacity: u64 = @intCast(table.max_capacity);
    const plan = try planDynamicFieldSection(table, fields, options);
    const total_len = try plan.totalLen(max_table_capacity);
    if (dst.len < total_len) return Error.BufferTooSmall;

    if (options.tracker) |tracker| {
        tracker.encoder_state.recordInsertCount(table.insert_count);
        var references: std.ArrayList(u64) = .empty;
        defer references.deinit(tracker.encoder_state.allocator);
        try collectDynamicReferences(&references, tracker.encoder_state.allocator, table, fields, plan.base, options);
        _ = try tracker.encoder_state.trackFieldSection(tracker.stream_id, references.items);
    }

    var pos: usize = 0;
    pos += try state.encodeFieldSectionPrefix(dst[pos..], .{
        .required_insert_count = plan.required_insert_count,
        .base = plan.base,
    }, max_table_capacity);

    for (fields) |field| {
        const representation = chooseFieldRepresentation(table, plan.base, field, options);
        pos += try encodeFieldRepresentation(dst[pos..], table, plan.base, field, representation, options);
    }
    return pos;
}

/// Emit QPACK encoder-stream insertion instructions for `fields` according to
/// `options.indexing`, mutating `table` to mirror the emitted instructions.
/// The field section can then be encoded with `encodeDynamicFieldSection`.
pub fn encodeFieldSectionEncoderInstructions(
    dst: []u8,
    table: *DynamicTable,
    fields: []const FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) Error!usize {
    var pos: usize = 0;
    for (fields) |field| {
        const instruction = chooseInsertInstruction(table, field, options) orelse continue;
        const n = try instructions.encodeEncoderInstruction(dst[pos..], instruction);
        const inserted = try instructions.applyEncoderInstruction(table, instruction);
        if (inserted) |absolute_index| {
            if (options.tracker) |tracker| try tracker.encoder_state.recordInsert(absolute_index);
        }
        pos += n;
    }
    return pos;
}

/// Decode a field section that avoids the dynamic table. The returned field
/// list owns its name/value strings and must be released with
/// `freeFieldSection`.
pub fn decodeFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

/// Decode a field section that can reference `table`. If the Required Insert
/// Count is ahead of `table.insert_count`, the caller needs to wait for more
/// encoder-stream instructions and retry.
pub fn decodeDynamicFieldSection(
    allocator: std.mem.Allocator,
    table: *const DynamicTable,
    max_table_capacity: u64,
    src: []const u8,
) Error![]FieldLine {
    const decoded_prefix = try state.decodeFieldSectionPrefix(
        src,
        max_table_capacity,
        table.insert_count,
    );
    if (decoded_prefix.prefix.required_insert_count > table.insert_count) {
        return error.RequiredInsertCountNotReady;
    }
    return decodeDynamicFieldSectionBody(
        allocator,
        table,
        decoded_prefix.prefix,
        src[decoded_prefix.bytes_read..],
    );
}

/// Decode the static/literal profile produced by `encodeFieldSection`.
/// The returned field list owns its name/value strings and must be released
/// with `freeFieldSection`.
pub fn decodeLiteralFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    return decodeStaticOnlyFieldSection(allocator, src);
}

pub fn freeFieldSection(allocator: std.mem.Allocator, fields: []FieldLine) void {
    for (fields) |field| {
        allocator.free(@constCast(field.name));
        allocator.free(@constCast(field.value));
    }
    allocator.free(fields);
}

pub fn stringLiteralEncodedLen(prefix_bits: u8, value: []const u8, options: StringOptions) usize {
    const body_len = if (options.huffman) huffman.encodedLen(value) else value.len;
    return integer.encodedLen(prefix_bits, body_len) + body_len;
}

pub fn encodeStringLiteral(
    dst: []u8,
    value: []const u8,
    prefix_bits: u8,
    first_byte_prefix: u8,
    options: StringOptions,
) Error!usize {
    var pos: usize = 0;
    const encoded_len = if (options.huffman) huffman.encodedLen(value) else value.len;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const prefix = first_byte_prefix | if (options.huffman) huffman_mask else 0;
    pos += try integer.encode(dst[pos..], prefix_bits, prefix, @intCast(encoded_len));
    if (dst.len - pos < encoded_len) return Error.BufferTooSmall;
    if (options.huffman) {
        pos += try huffman.encode(dst[pos..], value);
    } else {
        @memcpy(dst[pos .. pos + value.len], value);
        pos += value.len;
    }
    return pos;
}

fn planDynamicFieldSection(
    table: *const DynamicTable,
    fields: []const FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) Error!DynamicFieldSectionPlan {
    const base = table.insert_count;
    var required_insert_count: u64 = 0;
    var body_len: usize = 0;

    for (fields) |field| {
        const representation = chooseFieldRepresentation(table, base, field, options);
        switch (representation) {
            .dynamic_indexed,
            .dynamic_post_base_indexed,
            .dynamic_name,
            .dynamic_post_base_name,
            => |absolute_index| {
                if (absolute_index == std.math.maxInt(u64)) return error.InsertCountOverflow;
                required_insert_count = @max(required_insert_count, absolute_index + 1);
            },
            .static_indexed, .static_name, .literal => {},
        }
        body_len += try fieldRepresentationEncodedLen(table, base, field, representation, options);
    }

    return .{
        .base = base,
        .required_insert_count = required_insert_count,
        .body_len = body_len,
    };
}

fn chooseFieldRepresentation(
    table: *const DynamicTable,
    base: u64,
    field: FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) FieldRepresentation {
    const reference_context = policy.ReferenceContext{
        .encoder_state = if (options.tracker) |tracker| tracker.encoder_state else null,
        .will_track_field_section = options.tracker != null,
    };

    if (options.indexing.prefer_static and options.indexing.allowsStaticIndexed(field.sensitive)) {
        if (static_table.find(field.name, field.value)) |index| return .{ .static_indexed = index };
    }

    if (table.find(field.name, field.value)) |absolute_index| {
        if (options.indexing.allowsDynamicReference(field.sensitive, absolute_index, reference_context)) {
            if (absolute_index < base) return .{ .dynamic_indexed = absolute_index };
            return .{ .dynamic_post_base_indexed = absolute_index };
        }
    }

    if (!options.indexing.prefer_static and options.indexing.allowsStaticIndexed(field.sensitive)) {
        if (static_table.find(field.name, field.value)) |index| return .{ .static_indexed = index };
    }

    if (options.indexing.prefer_static) {
        if (static_table.findName(field.name)) |index| return .{ .static_name = index };
    }

    if (table.findName(field.name)) |absolute_index| {
        if (options.indexing.allowsDynamicReference(field.sensitive, absolute_index, reference_context)) {
            if (absolute_index < base) return .{ .dynamic_name = absolute_index };
            return .{ .dynamic_post_base_name = absolute_index };
        }
    }

    if (!options.indexing.prefer_static) {
        if (static_table.findName(field.name)) |index| return .{ .static_name = index };
    }

    return .literal;
}

fn fieldRepresentationEncodedLen(
    table: *const DynamicTable,
    base: u64,
    field: FieldLine,
    representation: FieldRepresentation,
    options: DynamicFieldSectionEncodeOptions,
) Error!usize {
    return switch (representation) {
        .static_indexed => |index| integer.encodedLen(6, @intCast(index)),
        .dynamic_indexed => |absolute_index| integer.encodedLen(
            6,
            table.absoluteToRelative(base, absolute_index) orelse return error.InvalidDynamicIndex,
        ),
        .dynamic_post_base_indexed => |absolute_index| integer.encodedLen(
            4,
            table.absoluteToPostBase(base, absolute_index) orelse return error.InvalidDynamicIndex,
        ),
        .static_name => |index| integer.encodedLen(4, @intCast(index)) +
            stringLiteralEncodedLen(7, field.value, .{ .huffman = options.huffman }),
        .dynamic_name => |absolute_index| integer.encodedLen(
            4,
            table.absoluteToRelative(base, absolute_index) orelse return error.InvalidDynamicIndex,
        ) + stringLiteralEncodedLen(7, field.value, .{ .huffman = options.huffman }),
        .dynamic_post_base_name => |absolute_index| integer.encodedLen(
            3,
            table.absoluteToPostBase(base, absolute_index) orelse return error.InvalidDynamicIndex,
        ) + stringLiteralEncodedLen(7, field.value, .{ .huffman = options.huffman }),
        .literal => blk: {
            const string_options: StringOptions = .{ .huffman = options.huffman };
            break :blk stringLiteralEncodedLen(3, field.name, string_options) +
                stringLiteralEncodedLen(7, field.value, string_options);
        },
    };
}

fn encodeFieldRepresentation(
    dst: []u8,
    table: *const DynamicTable,
    base: u64,
    field: FieldLine,
    representation: FieldRepresentation,
    options: DynamicFieldSectionEncodeOptions,
) Error!usize {
    var pos: usize = 0;
    switch (representation) {
        .static_indexed => |index| {
            pos += try integer.encode(dst[pos..], 6, 0xc0, @intCast(index));
        },
        .dynamic_indexed => |absolute_index| {
            const relative = table.absoluteToRelative(base, absolute_index) orelse return error.InvalidDynamicIndex;
            pos += try integer.encode(dst[pos..], 6, 0x80, relative);
        },
        .dynamic_post_base_indexed => |absolute_index| {
            const post_base = table.absoluteToPostBase(base, absolute_index) orelse return error.InvalidDynamicIndex;
            pos += try integer.encode(dst[pos..], 4, 0x10, post_base);
        },
        .static_name => |index| {
            const prefix: u8 = 0x50 | if (field.sensitive) @as(u8, 0x20) else 0;
            pos += try integer.encode(dst[pos..], 4, prefix, @intCast(index));
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, .{
                .huffman = options.huffman,
            });
        },
        .dynamic_name => |absolute_index| {
            const relative = table.absoluteToRelative(base, absolute_index) orelse return error.InvalidDynamicIndex;
            const prefix: u8 = 0x40 | if (field.sensitive) @as(u8, 0x20) else 0;
            pos += try integer.encode(dst[pos..], 4, prefix, relative);
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, .{
                .huffman = options.huffman,
            });
        },
        .dynamic_post_base_name => |absolute_index| {
            const post_base = table.absoluteToPostBase(base, absolute_index) orelse return error.InvalidDynamicIndex;
            const prefix: u8 = if (field.sensitive) 0x08 else 0;
            pos += try integer.encode(dst[pos..], 3, prefix, post_base);
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, .{
                .huffman = options.huffman,
            });
        },
        .literal => {
            const prefix: u8 = 0x20 | if (field.sensitive) @as(u8, 0x10) else 0;
            const string_options: StringOptions = .{ .huffman = options.huffman };
            pos += try encodeStringLiteral(dst[pos..], field.name, 3, prefix, string_options);
            pos += try encodeStringLiteral(dst[pos..], field.value, 7, 0, string_options);
        },
    }
    return pos;
}

fn collectDynamicReferences(
    references: *std.ArrayList(u64),
    allocator: std.mem.Allocator,
    table: *const DynamicTable,
    fields: []const FieldLine,
    base: u64,
    options: DynamicFieldSectionEncodeOptions,
) Error!void {
    for (fields) |field| {
        const representation = chooseFieldRepresentation(table, base, field, options);
        switch (representation) {
            .dynamic_indexed,
            .dynamic_post_base_indexed,
            .dynamic_name,
            .dynamic_post_base_name,
            => |absolute_index| try references.append(allocator, absolute_index),
            .static_indexed, .static_name, .literal => {},
        }
    }
}

fn chooseInsertInstruction(
    table: *const DynamicTable,
    field: FieldLine,
    options: DynamicFieldSectionEncodeOptions,
) ?instructions.EncoderInstruction {
    if (!options.indexing.allowsDynamicInsert(table, field.sensitive, field.name, field.value)) return null;
    if (static_table.find(field.name, field.value) != null) return null;
    if (table.find(field.name, field.value) != null) return null;

    if (static_table.findName(field.name)) |index| {
        return .{ .insert_name_ref = .{
            .table = .static,
            .index = @intCast(index),
            .value = field.value,
            .value_huffman = options.huffman,
        } };
    }

    if (table.findName(field.name)) |absolute_index| {
        if (table.absoluteToEncoderRelative(absolute_index)) |relative_index| {
            return .{ .insert_name_ref = .{
                .table = .dynamic,
                .index = relative_index,
                .value = field.value,
                .value_huffman = options.huffman,
            } };
        }
    }

    if (options.indexing.dynamic_inserts != .all) return null;
    return .{ .insert_literal = .{
        .name = field.name,
        .value = field.value,
        .name_huffman = options.huffman,
        .value_huffman = options.huffman,
    } };
}

fn readStringAlloc(
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: *usize,
    prefix_bits: u8,
) Error![]u8 {
    if (pos.* >= src.len) return Error.MalformedFieldSection;
    const huffman_mask: u8 = @as(u8, 1) << @intCast(prefix_bits);
    const huffman_encoded = (src[pos.*] & huffman_mask) != 0;
    const len = try integer.decode(src[pos.*..], prefix_bits);
    pos.* += len.bytes_read;
    const len_usize: usize = @intCast(len.value);
    if (src.len - pos.* < len_usize) return Error.MalformedFieldSection;
    const encoded = src[pos.* .. pos.* + len_usize];
    pos.* += len_usize;
    if (huffman_encoded) return try huffman.decode(allocator, encoded);
    return try allocator.dupe(u8, encoded);
}

fn decodeStaticOnlyFieldSection(
    allocator: std.mem.Allocator,
    src: []const u8,
) Error![]FieldLine {
    var pos: usize = 0;
    const ric = try integer.decode(src[pos..], 8);
    pos += ric.bytes_read;
    if (ric.value != 0) return Error.DynamicTableUnsupported;

    if (pos >= src.len) return Error.MalformedFieldSection;
    const delta_first = src[pos];
    const delta = try integer.decode(src[pos..], 7);
    pos += delta.bytes_read;
    if ((delta_first & 0x80) != 0 or delta.value != 0) return Error.DynamicTableUnsupported;

    var fields: std.ArrayList(FieldLine) = .empty;
    errdefer {
        for (fields.items) |field| {
            allocator.free(@constCast(field.name));
            allocator.free(@constCast(field.value));
        }
        fields.deinit(allocator);
    }

    while (pos < src.len) {
        const first = src[pos];
        if ((first & 0x80) != 0) {
            if ((first & 0x40) == 0) return Error.DynamicTableUnsupported;
            const index = try integer.decode(src[pos..], 6);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            try appendCopiedField(&fields, allocator, entry.name, entry.value, false);
        } else if ((first & 0xc0) == 0x40) {
            if ((first & 0x10) == 0) return Error.DynamicTableUnsupported;
            const sensitive = (first & 0x20) != 0;
            const index = try integer.decode(src[pos..], 4);
            pos += index.bytes_read;
            const entry = static_table.get(@intCast(index.value)) orelse return Error.InvalidStaticIndex;
            try appendCopiedNameField(
                &fields,
                allocator,
                entry.name,
                try readStringAlloc(allocator, src, &pos, 7),
                sensitive,
            );
        } else if ((first & 0xe0) == 0x20) {
            const sensitive = (first & 0x10) != 0;
            try appendLiteralField(&fields, allocator, src, &pos, sensitive);
        } else {
            return Error.UnsupportedRepresentation;
        }
    }

    return try fields.toOwnedSlice(allocator);
}

fn decodeDynamicFieldSectionBody(
    allocator: std.mem.Allocator,
    table: *const DynamicTable,
    prefix: state.FieldSectionPrefix,
    src: []const u8,
) Error![]FieldLine {
    const ReferencedField = struct {
        name: []const u8,
        value: []const u8,
    };

    var pos: usize = 0;
    var fields: std.ArrayList(FieldLine) = .empty;
    errdefer {
        for (fields.items) |field| {
            allocator.free(@constCast(field.name));
            allocator.free(@constCast(field.value));
        }
        fields.deinit(allocator);
    }

    while (pos < src.len) {
        const first = src[pos];
        if ((first & 0x80) != 0) {
            const index = try integer.decode(src[pos..], 6);
            pos += index.bytes_read;
            const referenced: ReferencedField = if ((first & 0x40) != 0) static: {
                const static_index = std.math.cast(usize, index.value) orelse return error.InvalidStaticIndex;
                const entry = static_table.get(static_index) orelse return error.InvalidStaticIndex;
                break :static .{ .name = entry.name, .value = entry.value };
            } else dynamic: {
                const entry = table.getRelative(prefix.base, index.value) orelse return error.InvalidDynamicIndex;
                break :dynamic .{ .name = entry.name, .value = entry.value };
            };
            try appendCopiedField(&fields, allocator, referenced.name, referenced.value, false);
        } else if ((first & 0xc0) == 0x40) {
            const sensitive = (first & 0x20) != 0;
            const index = try integer.decode(src[pos..], 4);
            pos += index.bytes_read;
            const name = if ((first & 0x10) != 0) static: {
                const static_index = std.math.cast(usize, index.value) orelse return error.InvalidStaticIndex;
                break :static (static_table.get(static_index) orelse return error.InvalidStaticIndex).name;
            } else dynamic: {
                break :dynamic (table.getRelative(prefix.base, index.value) orelse return error.InvalidDynamicIndex).name;
            };
            try appendCopiedNameField(
                &fields,
                allocator,
                name,
                try readStringAlloc(allocator, src, &pos, 7),
                sensitive,
            );
        } else if ((first & 0xf0) == 0x10) {
            const index = try integer.decode(src[pos..], 4);
            pos += index.bytes_read;
            const entry = table.getPostBase(prefix.base, index.value) orelse return error.InvalidDynamicIndex;
            try appendCopiedField(&fields, allocator, entry.name, entry.value, false);
        } else if ((first & 0xf0) == 0) {
            const sensitive = (first & 0x08) != 0;
            const index = try integer.decode(src[pos..], 3);
            pos += index.bytes_read;
            const entry = table.getPostBase(prefix.base, index.value) orelse return error.InvalidDynamicIndex;
            try appendCopiedNameField(
                &fields,
                allocator,
                entry.name,
                try readStringAlloc(allocator, src, &pos, 7),
                sensitive,
            );
        } else if ((first & 0xe0) == 0x20) {
            const sensitive = (first & 0x10) != 0;
            try appendLiteralField(&fields, allocator, src, &pos, sensitive);
        } else {
            return Error.UnsupportedRepresentation;
        }
    }

    return try fields.toOwnedSlice(allocator);
}

fn appendCopiedField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name_src: []const u8,
    value_src: []const u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    const name = try allocator.dupe(u8, name_src);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, value_src);
    errdefer allocator.free(value);
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendCopiedNameField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name_src: []const u8,
    value: []u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    errdefer allocator.free(value);
    const name = try allocator.dupe(u8, name_src);
    errdefer allocator.free(name);
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendOwnedField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    name: []u8,
    value: []u8,
    sensitive: bool,
) std.mem.Allocator.Error!void {
    errdefer {
        allocator.free(name);
        allocator.free(value);
    }
    try fields.append(allocator, .{
        .name = name,
        .value = value,
        .sensitive = sensitive,
    });
}

fn appendLiteralField(
    fields: *std.ArrayList(FieldLine),
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: *usize,
    sensitive: bool,
) Error!void {
    const name = try readStringAlloc(allocator, src, pos, 3);
    const value = readStringAlloc(allocator, src, pos, 7) catch |err| {
        allocator.free(name);
        return err;
    };
    try appendOwnedField(fields, allocator, name, value, sensitive);
}

test "static table indexed fields and name references round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "authorization", .value = "bearer nope", .sensitive = true },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeFieldSection(&buf, &fields);
    try std.testing.expectEqual(fieldSectionEncodedLen(&fields), n);
    try std.testing.expect(buf[2] & 0xc0 == 0xc0);

    const decoded = try decodeFieldSection(std.testing.allocator, buf[0..n]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("/index.html", decoded[2].value);
    try std.testing.expect(decoded[3].sensitive);
}

test "literal field section round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeLiteralFieldSection(&buf, &fields);
    try std.testing.expectEqual(literalFieldSectionEncodedLen(&fields), n);

    const decoded = try decodeLiteralFieldSection(std.testing.allocator, buf[0..n]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "Huffman string literal field section round-trip" {
    const fields = [_]FieldLine{
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    };
    var huffman_buf: [256]u8 = undefined;
    var plain_buf: [256]u8 = undefined;
    const huffman_n = try encodeFieldSectionWithOptions(&huffman_buf, &fields, .{ .huffman = true });
    const plain_n = try encodeFieldSection(&plain_buf, &fields);
    try std.testing.expect(huffman_n < plain_n);

    const decoded = try decodeFieldSection(std.testing.allocator, huffman_buf[0..huffman_n]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("www.example.com", decoded[0].value);
    try std.testing.expectEqualStrings("no-cache", decoded[1].value);
}

test "dynamic field sections encode and decode indexed and name-reference fields" {
    var table = DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);
    _ = try table.insert("x-alt", "old", false);

    var encoder_state = state.EncoderState.init(std.testing.allocator, 1);
    defer encoder_state.deinit();

    const fields = [_]FieldLine{
        .{ .name = "x-test", .value = "one" },
        .{ .name = "x-alt", .value = "new" },
    };
    const options = DynamicFieldSectionEncodeOptions{
        .tracker = .{
            .encoder_state = &encoder_state,
            .stream_id = 12,
        },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, options);
    try std.testing.expectEqual(try dynamicFieldSectionEncodedLenWithOptions(&table, &fields, options), n);
    try std.testing.expectEqual(@as(u64, 2), encoder_state.insert_count);
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(0));
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(1));
    try std.testing.expectEqual(@as(usize, 1), encoder_state.blockedStreamCount());

    const decoded = try decodeDynamicFieldSection(std.testing.allocator, &table, table.max_capacity, buf[0..n]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("x-test", decoded[0].name);
    try std.testing.expectEqualStrings("one", decoded[0].value);
    try std.testing.expectEqualStrings("x-alt", decoded[1].name);
    try std.testing.expectEqualStrings("new", decoded[1].value);

    try encoder_state.receiveDecoderInstruction(.{ .section_ack = 12 });
    try std.testing.expectEqual(@as(u64, 0), encoder_state.referenceCount(0));
    try std.testing.expectEqual(@as(u64, 0), encoder_state.referenceCount(1));
}

test "default dynamic policy avoids untracked blocking references" {
    var table = DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-test", "one", false);

    const fields = [_]FieldLine{
        .{ .name = "x-test", .value = "one" },
    };
    var buf: [256]u8 = undefined;
    const n = try encodeDynamicFieldSection(&buf, &table, &fields);

    const decoded_prefix = try state.decodeFieldSectionPrefix(buf[0..n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 0), decoded_prefix.prefix.required_insert_count);
    try std.testing.expect(buf[decoded_prefix.bytes_read] & 0xe0 == 0x20);
}

test "indexing policy emits encoder instructions and references inserted fields" {
    var table = DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    var encoder_state = state.EncoderState.init(std.testing.allocator, 4);
    defer encoder_state.deinit();

    const fields = [_]FieldLine{
        .{ .name = "x-policy", .value = "one" },
        .{ .name = "authorization", .value = "secret", .sensitive = true },
    };
    const options = DynamicFieldSectionEncodeOptions{
        .tracker = .{
            .encoder_state = &encoder_state,
            .stream_id = 20,
        },
        .indexing = .{ .dynamic_inserts = .all },
    };

    var encoder_stream: [256]u8 = undefined;
    const instruction_n = try encodeFieldSectionEncoderInstructions(&encoder_stream, &table, &fields, options);
    try std.testing.expect(instruction_n > 0);
    try std.testing.expectEqual(@as(u64, 1), table.insert_count);
    try std.testing.expectEqualStrings("x-policy", table.getAbsolute(0).?.name);
    try std.testing.expect(table.find("authorization", "secret") == null);

    var field_section: [256]u8 = undefined;
    const field_n = try encodeDynamicFieldSectionWithOptions(&field_section, &table, &fields, options);
    const decoded_prefix = try state.decodeFieldSectionPrefix(field_section[0..field_n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), decoded_prefix.prefix.required_insert_count);
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(0));

    const decoded = try decodeDynamicFieldSection(
        std.testing.allocator,
        &table,
        table.max_capacity,
        field_section[0..field_n],
    );
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqualStrings("x-policy", decoded[0].name);
    try std.testing.expectEqualStrings("one", decoded[0].value);
    try std.testing.expectEqualStrings("authorization", decoded[1].name);
    try std.testing.expect(decoded[1].sensitive);
}

test "indexing policy can require acknowledged dynamic references" {
    var table = DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);
    _ = try table.insert("x-test", "one", false);

    var encoder_state = state.EncoderState.init(std.testing.allocator, 0);
    defer encoder_state.deinit();
    encoder_state.recordInsertCount(table.insert_count);

    const fields = [_]FieldLine{.{ .name = "x-test", .value = "one" }};
    const blocked_options = DynamicFieldSectionEncodeOptions{
        .tracker = .{
            .encoder_state = &encoder_state,
            .stream_id = 4,
        },
        .indexing = .{ .dynamic_references = .acknowledged },
    };
    var buf: [128]u8 = undefined;
    const literal_n = try encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, blocked_options);
    const literal_prefix = try state.decodeFieldSectionPrefix(buf[0..literal_n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 0), literal_prefix.prefix.required_insert_count);

    try encoder_state.receiveDecoderInstruction(.{ .insert_count_increment = 1 });
    const acked_n = try encodeDynamicFieldSectionWithOptions(&buf, &table, &fields, blocked_options);
    const acked_prefix = try state.decodeFieldSectionPrefix(buf[0..acked_n], table.max_capacity, table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), acked_prefix.prefix.required_insert_count);
}

test "dynamic field decoder supports post-base indexed and name-reference fields" {
    var table = DynamicTable.init(std.testing.allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("a", "1", false);
    _ = try table.insert("b", "2", false);
    _ = try table.insert("c", "3", false);

    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    pos += try state.encodeFieldSectionPrefix(buf[pos..], .{
        .required_insert_count = 3,
        .base = 1,
    }, table.max_capacity);
    pos += try integer.encode(buf[pos..], 4, 0x10, 1); // Post-base index 1 -> absolute index 2.
    pos += try integer.encode(buf[pos..], 3, 0x08, 0); // Sensitive post-base name index 0 -> absolute index 1.
    pos += try encodeStringLiteral(buf[pos..], "override", 7, 0, .{});

    const decoded = try decodeDynamicFieldSection(std.testing.allocator, &table, table.max_capacity, buf[0..pos]);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("c", decoded[0].name);
    try std.testing.expectEqualStrings("3", decoded[0].value);
    try std.testing.expectEqualStrings("b", decoded[1].name);
    try std.testing.expectEqualStrings("override", decoded[1].value);
    try std.testing.expect(decoded[1].sensitive);
}

test "dynamic field decoder reports sections waiting on encoder stream inserts" {
    var table = DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);

    var buf: [16]u8 = undefined;
    const n = try state.encodeFieldSectionPrefix(buf[0..], .{
        .required_insert_count = 1,
        .base = 1,
    }, table.max_capacity);
    try std.testing.expectError(
        error.RequiredInsertCountNotReady,
        decodeDynamicFieldSection(std.testing.allocator, &table, table.max_capacity, buf[0..n]),
    );
}

test "RFC 9204 Appendix B.1 literal field line with static name reference" {
    const fields = [_]FieldLine{
        .{ .name = ":path", .value = "/index.html" },
    };
    const expected = "\x00\x00\x51\x0b/index.html";

    var buf: [32]u8 = undefined;
    const n = try encodeFieldSection(&buf, &fields);
    try std.testing.expectEqualSlices(u8, expected, buf[0..n]);

    const decoded = try decodeFieldSection(std.testing.allocator, expected);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings(":path", decoded[0].name);
    try std.testing.expectEqualStrings("/index.html", decoded[0].value);
}

test "RFC 9204 Appendix B.2 dynamic table field section and acknowledgment" {
    const encoder_stream = "\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path";
    const field_section = "\x03\x81\x10\x11";

    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try instructions.encodeEncoderInstruction(buf[pos..], .{ .set_capacity = 220 });
    pos += try instructions.encodeEncoderInstruction(buf[pos..], .{ .insert_name_ref = .{
        .table = .static,
        .index = 0,
        .value = "www.example.com",
    } });
    pos += try instructions.encodeEncoderInstruction(buf[pos..], .{ .insert_name_ref = .{
        .table = .static,
        .index = 1,
        .value = "/sample/path",
    } });
    try std.testing.expectEqualSlices(u8, encoder_stream, buf[0..pos]);

    var table = DynamicTable.init(std.testing.allocator, 220);
    defer table.deinit();
    var decoder_state = state.DecoderState.init(std.testing.allocator, 4);
    defer decoder_state.deinit();
    try applyEncoderStreamFixture(&table, &decoder_state, encoder_stream);

    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(usize, 106), table.size);
    try std.testing.expectEqualStrings(":authority", table.getAbsolute(0).?.name);
    try std.testing.expectEqualStrings("www.example.com", table.getAbsolute(0).?.value);
    try std.testing.expectEqualStrings(":path", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("/sample/path", table.getAbsolute(1).?.value);

    const decoded = try decodeDynamicFieldSection(std.testing.allocator, &table, 220, field_section);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings(":authority", decoded[0].name);
    try std.testing.expectEqualStrings("www.example.com", decoded[0].value);
    try std.testing.expectEqualStrings(":path", decoded[1].name);
    try std.testing.expectEqualStrings("/sample/path", decoded[1].value);

    const ack_instruction = try decoder_state.completeFieldSection(4, 2);
    try std.testing.expectEqual(@as(u64, 4), ack_instruction.?.section_ack);
    var ack_buf: [8]u8 = undefined;
    const ack_n = try instructions.encodeDecoderInstruction(&ack_buf, ack_instruction.?);
    try std.testing.expectEqualSlices(u8, "\x84", ack_buf[0..ack_n]);
}

test "RFC 9204 Appendix B.3 speculative literal insert and insert count increment" {
    var table = DynamicTable.init(std.testing.allocator, 220);
    defer table.deinit();
    var decoder_state = state.DecoderState.init(std.testing.allocator, 4);
    defer decoder_state.deinit();
    try applyEncoderStreamFixture(
        &table,
        &decoder_state,
        "\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path",
    );
    _ = try decoder_state.completeFieldSection(4, 2);

    const encoder_stream = "\x4acustom-key\x0ccustom-value";
    var buf: [64]u8 = undefined;
    const n = try instructions.encodeEncoderInstruction(&buf, .{ .insert_literal = .{
        .name = "custom-key",
        .value = "custom-value",
    } });
    try std.testing.expectEqualSlices(u8, encoder_stream, buf[0..n]);
    try applyEncoderStreamFixture(&table, &decoder_state, encoder_stream);

    try std.testing.expectEqual(@as(usize, 3), table.len());
    try std.testing.expectEqual(@as(usize, 160), table.size);
    try std.testing.expectEqualStrings("custom-key", table.getAbsolute(2).?.name);
    try std.testing.expectEqualStrings("custom-value", table.getAbsolute(2).?.value);

    const increment = decoder_state.takeInsertCountIncrement().?;
    var increment_buf: [8]u8 = undefined;
    const increment_n = try instructions.encodeDecoderInstruction(&increment_buf, increment);
    try std.testing.expectEqualSlices(u8, "\x01", increment_buf[0..increment_n]);
}

test "RFC 9204 Appendix B.4 duplicate instruction and stream cancellation" {
    var table = DynamicTable.init(std.testing.allocator, 220);
    defer table.deinit();
    var decoder_state = state.DecoderState.init(std.testing.allocator, 4);
    defer decoder_state.deinit();
    try applyEncoderStreamFixture(
        &table,
        &decoder_state,
        "\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path\x4acustom-key\x0ccustom-value",
    );

    var encoder_state = state.EncoderState.init(std.testing.allocator, 4);
    defer encoder_state.deinit();
    encoder_state.recordInsertCount(3);
    try encoder_state.receiveDecoderInstruction(.{ .insert_count_increment = 3 });

    var duplicate_buf: [8]u8 = undefined;
    const duplicate_n = try instructions.encodeEncoderInstruction(&duplicate_buf, .{ .duplicate = 2 });
    try std.testing.expectEqualSlices(u8, "\x02", duplicate_buf[0..duplicate_n]);
    try applyEncoderStreamFixture(&table, &decoder_state, "\x02");
    try encoder_state.recordInsert(3);
    try std.testing.expectEqual(@as(usize, 217), table.size);
    try std.testing.expectEqualStrings(":authority", table.getAbsolute(3).?.name);
    try std.testing.expectEqualStrings("www.example.com", table.getAbsolute(3).?.value);

    const field_section = "\x05\x00\x80\xc1\x81";
    const decoded = try decodeDynamicFieldSection(std.testing.allocator, &table, 220, field_section);
    defer freeFieldSection(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqualStrings(":authority", decoded[0].name);
    try std.testing.expectEqualStrings("www.example.com", decoded[0].value);
    try std.testing.expectEqualStrings(":path", decoded[1].name);
    try std.testing.expectEqualStrings("/", decoded[1].value);
    try std.testing.expectEqualStrings("custom-key", decoded[2].name);
    try std.testing.expectEqualStrings("custom-value", decoded[2].value);

    try std.testing.expectEqual(@as(u64, 4), try encoder_state.trackFieldSection(8, &.{ 3, 2 }));
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(3));
    try std.testing.expectEqual(@as(u64, 1), encoder_state.referenceCount(2));
    try encoder_state.receiveDecoderInstruction(.{ .stream_cancel = 8 });
    try std.testing.expectEqual(@as(u64, 0), encoder_state.referenceCount(3));
    try std.testing.expectEqual(@as(u64, 0), encoder_state.referenceCount(2));

    const cancellation = decoder_state.cancelStream(8);
    var cancellation_buf: [8]u8 = undefined;
    const cancellation_n = try instructions.encodeDecoderInstruction(&cancellation_buf, cancellation);
    try std.testing.expectEqualSlices(u8, "\x48", cancellation_buf[0..cancellation_n]);
}

test "RFC 9204 Appendix B.5 dynamic insert and eviction" {
    var table = DynamicTable.init(std.testing.allocator, 220);
    defer table.deinit();
    var decoder_state = state.DecoderState.init(std.testing.allocator, 4);
    defer decoder_state.deinit();
    try applyEncoderStreamFixture(
        &table,
        &decoder_state,
        "\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path\x4acustom-key\x0ccustom-value\x02",
    );

    const encoder_stream = "\x81\x0dcustom-value2";
    var buf: [32]u8 = undefined;
    const n = try instructions.encodeEncoderInstruction(&buf, .{ .insert_name_ref = .{
        .table = .dynamic,
        .index = 1,
        .value = "custom-value2",
    } });
    try std.testing.expectEqualSlices(u8, encoder_stream, buf[0..n]);
    try applyEncoderStreamFixture(&table, &decoder_state, encoder_stream);

    try std.testing.expectEqual(@as(usize, 4), table.len());
    try std.testing.expectEqual(@as(u64, 1), table.dropped_count);
    try std.testing.expectEqual(@as(usize, 215), table.size);
    try std.testing.expect(table.getAbsolute(0) == null);
    try std.testing.expectEqualStrings(":path", table.getAbsolute(1).?.name);
    try std.testing.expectEqualStrings("custom-key", table.getAbsolute(4).?.name);
    try std.testing.expectEqualStrings("custom-value2", table.getAbsolute(4).?.value);
}

fn applyEncoderStreamFixture(
    table: *DynamicTable,
    decoder_state: *state.DecoderState,
    src: []const u8,
) Error!void {
    var pos: usize = 0;
    while (pos < src.len) {
        const decoded = try instructions.decodeEncoderInstruction(std.testing.allocator, src[pos..]);
        errdefer instructions.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
        _ = try decoder_state.applyEncoderInstruction(table, decoded.instruction);
        instructions.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
        pos += decoded.bytes_read;
    }
}
