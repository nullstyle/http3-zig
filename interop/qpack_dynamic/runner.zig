//! Dynamic QPACK fixture runner for exact-byte interop vectors.

const std = @import("std");
const null3 = @import("null3");
const fixtures = @import("fixtures.zig");

const qpack = null3.qpack;

test "dynamic QPACK encoder-stream fixtures reproduce exact bytes and table state" {
    for (fixtures.encoder_stream_vectors) |vector| {
        var table = qpack.DynamicTable.init(std.testing.allocator, vector.max_table_capacity);
        defer table.deinit();
        var decoder_state = qpack.QpackDecoderState.init(std.testing.allocator, 8);
        defer decoder_state.deinit();

        try applyEncoderStream(&table, &decoder_state, vector.setup_encoder_stream);
        if (vector.complete_before) |completion| {
            const feedback = (try decoder_state.completeFieldSection(
                completion.stream_id,
                completion.required_insert_count,
            )) orelse {
                std.debug.print("{s}: expected section acknowledgment\n", .{vector.name});
                return error.MissingDecoderFeedback;
            };
            try expectDecoderFeedback(feedback, completion.encoded_decoder_feedback);
        }

        var encoded: [256]u8 = undefined;
        const encoded_len = try encodeEncoderInstructions(&encoded, vector.instructions);
        try std.testing.expectEqualSlices(u8, vector.encoder_stream, encoded[0..encoded_len]);

        try applyEncoderStream(&table, &decoder_state, vector.encoder_stream);
        try expectTableSnapshot(&table, vector.table_after);

        if (vector.insert_count_increment) |expected| {
            const increment = decoder_state.takeInsertCountIncrement() orelse {
                std.debug.print("{s}: expected insert count increment\n", .{vector.name});
                return error.MissingDecoderFeedback;
            };
            try expectDecoderFeedback(increment, expected);
        }
    }
}

test "dynamic QPACK field-section fixtures decode and emit decoder feedback" {
    for (fixtures.field_section_vectors) |vector| {
        var table = qpack.DynamicTable.init(std.testing.allocator, @intCast(vector.max_table_capacity));
        defer table.deinit();
        var decoder_state = qpack.QpackDecoderState.init(std.testing.allocator, 8);
        defer decoder_state.deinit();

        try applyEncoderStream(&table, &decoder_state, vector.setup_encoder_stream);

        const prefix = try qpack.state.decodeFieldSectionPrefix(
            vector.field_section,
            vector.max_table_capacity,
            table.insert_count,
        );
        try std.testing.expectEqual(vector.required_insert_count, prefix.prefix.required_insert_count);
        try std.testing.expectEqual(vector.base, prefix.prefix.base);

        const decoded = try qpack.decodeDynamicFieldSection(
            std.testing.allocator,
            &table,
            vector.max_table_capacity,
            vector.field_section,
        );
        defer qpack.freeFieldSection(std.testing.allocator, decoded);
        try expectFields(decoded, vector.fields);

        if (vector.decoder_feedback) |feedback_vector| {
            const feedback = (try decoder_state.completeFieldSection(
                vector.stream_id,
                vector.required_insert_count,
            )) orelse {
                std.debug.print("{s}: expected decoder feedback\n", .{vector.name});
                return error.MissingDecoderFeedback;
            };
            try expectDecoderInstructionEqual(feedback_vector.instruction, feedback);
            try expectDecoderFeedback(feedback, feedback_vector.encoded);
        }

        if (vector.stream_cancel) |feedback_vector| {
            const feedback = decoder_state.cancelStream(vector.stream_id);
            try expectDecoderInstructionEqual(feedback_vector.instruction, feedback);
            try expectDecoderFeedback(feedback, feedback_vector.encoded);
        }
    }
}

fn encodeEncoderInstructions(
    dst: []u8,
    instructions: []const qpack.EncoderInstruction,
) qpack.Error!usize {
    var pos: usize = 0;
    for (instructions) |instruction| {
        pos += try qpack.instructions.encodeEncoderInstruction(dst[pos..], instruction);
    }
    return pos;
}

fn applyEncoderStream(
    table: *qpack.DynamicTable,
    decoder_state: *qpack.QpackDecoderState,
    src: []const u8,
) qpack.Error!void {
    var pos: usize = 0;
    while (pos < src.len) {
        const decoded = try qpack.instructions.decodeEncoderInstruction(std.testing.allocator, src[pos..]);
        errdefer qpack.instructions.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
        _ = try decoder_state.applyEncoderInstruction(table, decoded.instruction);
        qpack.instructions.freeDecodedEncoderInstruction(std.testing.allocator, decoded);
        pos += decoded.bytes_read;
    }
}

fn expectTableSnapshot(
    table: *const qpack.DynamicTable,
    snapshot: fixtures.TableSnapshot,
) !void {
    try std.testing.expectEqual(snapshot.capacity, table.capacity);
    try std.testing.expectEqual(snapshot.len, table.len());
    try std.testing.expectEqual(snapshot.size, table.size);
    try std.testing.expectEqual(snapshot.insert_count, table.insert_count);
    try std.testing.expectEqual(snapshot.dropped_count, table.dropped_count);

    for (snapshot.entries) |want| {
        const got = table.getAbsolute(want.absolute_index) orelse {
            std.debug.print("missing dynamic entry {d}\n", .{want.absolute_index});
            return error.MissingDynamicEntry;
        };
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
    for (snapshot.absent_absolute_indices) |absolute_index| {
        try std.testing.expect(table.getAbsolute(absolute_index) == null);
    }
}

fn expectFields(got: []const qpack.FieldLine, want: []const qpack.FieldLine) !void {
    try std.testing.expectEqual(want.len, got.len);
    for (want, got) |want_field, got_field| {
        try std.testing.expectEqualStrings(want_field.name, got_field.name);
        try std.testing.expectEqualStrings(want_field.value, got_field.value);
        try std.testing.expectEqual(want_field.sensitive, got_field.sensitive);
    }
}

fn expectDecoderFeedback(
    instruction: qpack.DecoderInstruction,
    expected: []const u8,
) !void {
    var buf: [16]u8 = undefined;
    const n = try qpack.instructions.encodeDecoderInstruction(&buf, instruction);
    try std.testing.expectEqualSlices(u8, expected, buf[0..n]);

    const decoded = try qpack.instructions.decodeDecoderInstruction(buf[0..n]);
    try std.testing.expectEqual(n, decoded.bytes_read);
    try expectDecoderInstructionEqual(instruction, decoded.instruction);
}

fn expectDecoderInstructionEqual(
    want: qpack.DecoderInstruction,
    got: qpack.DecoderInstruction,
) !void {
    switch (want) {
        .section_ack => |want_stream_id| switch (got) {
            .section_ack => |got_stream_id| try std.testing.expectEqual(want_stream_id, got_stream_id),
            else => return error.UnexpectedDecoderInstruction,
        },
        .stream_cancel => |want_stream_id| switch (got) {
            .stream_cancel => |got_stream_id| try std.testing.expectEqual(want_stream_id, got_stream_id),
            else => return error.UnexpectedDecoderInstruction,
        },
        .insert_count_increment => |want_increment| switch (got) {
            .insert_count_increment => |got_increment| try std.testing.expectEqual(want_increment, got_increment),
            else => return error.UnexpectedDecoderInstruction,
        },
    }
}
