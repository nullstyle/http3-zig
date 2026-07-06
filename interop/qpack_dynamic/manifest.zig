//! Implementation-neutral JSON manifest for the dynamic QPACK fixtures.
//!
//! `fixtures.zig` remains the source of truth. This module renders those
//! fixtures into a committed JSON file that external implementations can
//! consume without translating Zig initializers by hand.

const std = @import("std");
const http3_zig = @import("http3_zig");
const fixtures = @import("fixtures.zig");

const qpack = http3_zig.qpack;
const Writer = std.Io.Writer;

pub fn writeJson(out: *Writer) !void {
    try out.writeAll(
        \\{
        \\  "schema": "http3-zig.qpack-dynamic-fixtures.v1",
        \\  "format_version": 1,
        \\  "source": "RFC 9204 Appendix B exact bytes plus http3-zig negative coverage",
        \\  "encoder_streams": [
    );
    try writeEncoderStreamVectors(out);
    try out.writeAll(
        \\
        \\  ],
        \\  "field_sections": [
    );
    try writeFieldSectionVectors(out);
    try out.writeAll(
        \\
        \\  ],
        \\  "negative_encoder_streams": [
    );
    try writeNegativeEncoderStreamVectors(out);
    try out.writeAll(
        \\
        \\  ],
        \\  "negative_field_sections": [
    );
    try writeNegativeFieldSectionVectors(out);
    try out.writeAll(
        \\
        \\  ],
        \\  "negative_decoder_feedback": [
    );
    try writeNegativeDecoderFeedbackVectors(out);
    try out.writeAll(
        \\
        \\  ]
        \\}
        \\
    );
}

pub fn expectCommittedJson() !void {
    var buf: [64 * 1024]u8 = undefined;
    var writer: Writer = .fixed(&buf);
    try writeJson(&writer);
    try std.testing.expectEqualStrings(@embedFile("fixtures.json"), writer.buffered());
}

test "dynamic QPACK manifest matches committed JSON" {
    try expectCommittedJson();
}

fn writeEncoderStreamVectors(out: *Writer) !void {
    for (fixtures.encoder_stream_vectors, 0..) |vector, i| {
        try writeCommaNewline(out, i, 4);
        try out.writeAll("{\n");
        try writeStringField(out, 6, "name", vector.name, true);
        try writeIntField(out, 6, "max_table_capacity", vector.max_table_capacity, true);
        try writeHexField(out, 6, "setup_encoder_stream", vector.setup_encoder_stream, true);
        try out.writeAll("      \"complete_before\": ");
        if (vector.complete_before) |completion| {
            try out.writeAll("{");
            try out.print("\"stream_id\": {d}, ", .{completion.stream_id});
            try out.print("\"required_insert_count\": {d}, ", .{completion.required_insert_count});
            try out.writeAll("\"encoded_decoder_feedback\": ");
            try writeHexString(out, completion.encoded_decoder_feedback);
            try out.writeAll("},\n");
        } else {
            try out.writeAll("null,\n");
        }
        try out.writeAll("      \"instructions\": [");
        try writeEncoderInstructions(out, vector.instructions);
        try out.writeAll("\n      ],\n");
        try writeHexField(out, 6, "encoder_stream", vector.encoder_stream, true);
        try out.writeAll("      \"table_after\": ");
        try writeTableSnapshot(out, vector.table_after, 6);
        try out.writeAll(",\n");
        try out.writeAll("      \"insert_count_increment\": ");
        if (vector.insert_count_increment) |increment| {
            try writeHexString(out, increment);
        } else {
            try out.writeAll("null");
        }
        try out.writeAll("\n    }");
    }
}

fn writeFieldSectionVectors(out: *Writer) !void {
    for (fixtures.field_section_vectors, 0..) |vector, i| {
        try writeCommaNewline(out, i, 4);
        try out.writeAll("{\n");
        try writeStringField(out, 6, "name", vector.name, true);
        try writeIntField(out, 6, "max_table_capacity", vector.max_table_capacity, true);
        try writeHexField(out, 6, "setup_encoder_stream", vector.setup_encoder_stream, true);
        try writeIntField(out, 6, "stream_id", vector.stream_id, true);
        try writeIntField(out, 6, "required_insert_count", vector.required_insert_count, true);
        try writeIntField(out, 6, "base", vector.base, true);
        try writeHexField(out, 6, "field_section", vector.field_section, true);
        try out.writeAll("      \"fields\": [");
        try writeFields(out, vector.fields);
        try out.writeAll("\n      ],\n");
        try out.writeAll("      \"decoder_feedback\": ");
        if (vector.decoder_feedback) |feedback| {
            try writeDecoderFeedback(out, feedback);
        } else {
            try out.writeAll("null");
        }
        try out.writeAll(",\n");
        try out.writeAll("      \"stream_cancel\": ");
        if (vector.stream_cancel) |feedback| {
            try writeDecoderFeedback(out, feedback);
        } else {
            try out.writeAll("null");
        }
        try out.writeAll("\n    }");
    }
}

fn writeNegativeEncoderStreamVectors(out: *Writer) !void {
    for (fixtures.negative_encoder_stream_vectors, 0..) |vector, i| {
        try writeCommaNewline(out, i, 4);
        try out.writeAll("{\n");
        try writeStringField(out, 6, "name", vector.name, true);
        try writeIntField(out, 6, "max_table_capacity", vector.max_table_capacity, true);
        try writeHexField(out, 6, "setup_encoder_stream", vector.setup_encoder_stream, true);
        try writeHexField(out, 6, "encoder_stream", vector.encoder_stream, true);
        try writeStringField(out, 6, "expected_error", @errorName(vector.expected_error), true);
        try out.writeAll("      \"table_after_error\": ");
        try writeTableSnapshot(out, vector.table_after_error, 6);
        try out.writeAll("\n    }");
    }
}

fn writeNegativeFieldSectionVectors(out: *Writer) !void {
    for (fixtures.negative_field_section_vectors, 0..) |vector, i| {
        try writeCommaNewline(out, i, 4);
        try out.writeAll("{\n");
        try writeStringField(out, 6, "name", vector.name, true);
        try writeIntField(out, 6, "max_table_capacity", vector.max_table_capacity, true);
        try writeHexField(out, 6, "setup_encoder_stream", vector.setup_encoder_stream, true);
        try writeHexField(out, 6, "field_section", vector.field_section, true);
        try writeStringField(out, 6, "expected_error", @errorName(vector.expected_error), false);
        try out.writeAll("    }");
    }
}

fn writeNegativeDecoderFeedbackVectors(out: *Writer) !void {
    for (fixtures.negative_decoder_feedback_vectors, 0..) |vector, i| {
        try writeCommaNewline(out, i, 4);
        try out.writeAll("{\n");
        try writeStringField(out, 6, "name", vector.name, true);
        try writeHexField(out, 6, "encoded", vector.encoded, true);
        try writeStringField(out, 6, "expected_error", @errorName(vector.expected_error), false);
        try out.writeAll("    }");
    }
}

fn writeEncoderInstructions(out: *Writer, instructions: []const qpack.EncoderInstruction) !void {
    for (instructions, 0..) |instruction, i| {
        try writeCommaNewline(out, i, 8);
        try writeEncoderInstruction(out, instruction);
    }
}

fn writeEncoderInstruction(out: *Writer, instruction: qpack.EncoderInstruction) !void {
    try out.writeAll("{");
    switch (instruction) {
        .set_capacity => |capacity| {
            try out.print("\"type\": \"set_capacity\", \"capacity\": {d}", .{capacity});
        },
        .insert_name_ref => |ref| {
            try out.writeAll("\"type\": \"insert_name_ref\", \"table\": ");
            try writeJsonString(out, @tagName(ref.table));
            try out.print(", \"index\": {d}, \"value\": ", .{ref.index});
            try writeJsonString(out, ref.value);
        },
        .insert_literal => |literal| {
            try out.writeAll("\"type\": \"insert_literal\", \"name\": ");
            try writeJsonString(out, literal.name);
            try out.writeAll(", \"value\": ");
            try writeJsonString(out, literal.value);
        },
        .duplicate => |index| {
            try out.print("\"type\": \"duplicate\", \"index\": {d}", .{index});
        },
    }
    try out.writeAll("}");
}

fn writeFields(out: *Writer, fields: []const qpack.FieldLine) !void {
    for (fields, 0..) |field, i| {
        try writeCommaNewline(out, i, 8);
        try out.writeAll("{\"name\": ");
        try writeJsonString(out, field.name);
        try out.writeAll(", \"value\": ");
        try writeJsonString(out, field.value);
        try out.print(", \"sensitive\": {s}", .{if (field.sensitive) "true" else "false"});
        try out.writeAll("}");
    }
}

fn writeDecoderFeedback(out: *Writer, feedback: fixtures.DecoderFeedbackVector) !void {
    try out.writeAll("{\"instruction\": ");
    try writeDecoderInstruction(out, feedback.instruction);
    try out.writeAll(", \"encoded\": ");
    try writeHexString(out, feedback.encoded);
    try out.writeAll("}");
}

fn writeDecoderInstruction(out: *Writer, instruction: qpack.DecoderInstruction) !void {
    try out.writeAll("{");
    switch (instruction) {
        .section_ack => |stream_id| {
            try out.print("\"type\": \"section_ack\", \"stream_id\": {d}", .{stream_id});
        },
        .stream_cancel => |stream_id| {
            try out.print("\"type\": \"stream_cancel\", \"stream_id\": {d}", .{stream_id});
        },
        .insert_count_increment => |increment| {
            try out.print("\"type\": \"insert_count_increment\", \"increment\": {d}", .{increment});
        },
    }
    try out.writeAll("}");
}

fn writeTableSnapshot(out: *Writer, snapshot: fixtures.TableSnapshot, indent: usize) !void {
    try out.writeAll("{\n");
    try writeIntField(out, indent + 2, "capacity", snapshot.capacity, true);
    try writeIntField(out, indent + 2, "len", snapshot.len, true);
    try writeIntField(out, indent + 2, "size", snapshot.size, true);
    try writeIntField(out, indent + 2, "insert_count", snapshot.insert_count, true);
    try writeIntField(out, indent + 2, "dropped_count", snapshot.dropped_count, true);
    try writeIndent(out, indent + 2);
    try out.writeAll("\"entries\": ");
    if (snapshot.entries.len == 0) {
        try out.writeAll("[],\n");
    } else {
        try out.writeAll("[");
        for (snapshot.entries, 0..) |entry, i| {
            try writeCommaNewline(out, i, indent + 4);
            try out.writeAll("{\"absolute_index\": ");
            try out.print("{d}, \"name\": ", .{entry.absolute_index});
            try writeJsonString(out, entry.name);
            try out.writeAll(", \"value\": ");
            try writeJsonString(out, entry.value);
            try out.writeAll("}");
        }
        try out.writeAll("\n");
        try writeIndent(out, indent + 2);
        try out.writeAll("],\n");
    }
    try writeIndent(out, indent + 2);
    try out.writeAll("\"absent_absolute_indices\": [");
    for (snapshot.absent_absolute_indices, 0..) |absolute_index, i| {
        if (i != 0) try out.writeAll(", ");
        try out.print("{d}", .{absolute_index});
    }
    try out.writeAll("]\n");
    try writeIndent(out, indent);
    try out.writeAll("}");
}

fn writeStringField(out: *Writer, indent: usize, name: []const u8, value: []const u8, trailing_comma: bool) !void {
    try writeIndent(out, indent);
    try writeJsonString(out, name);
    try out.writeAll(": ");
    try writeJsonString(out, value);
    if (trailing_comma) try out.writeAll(",");
    try out.writeAll("\n");
}

fn writeHexField(out: *Writer, indent: usize, name: []const u8, value: []const u8, trailing_comma: bool) !void {
    try writeIndent(out, indent);
    try writeJsonString(out, name);
    try out.writeAll(": ");
    try writeHexString(out, value);
    if (trailing_comma) try out.writeAll(",");
    try out.writeAll("\n");
}

fn writeIntField(out: *Writer, indent: usize, name: []const u8, value: anytype, trailing_comma: bool) !void {
    try writeIndent(out, indent);
    try writeJsonString(out, name);
    try out.print(": {d}", .{value});
    if (trailing_comma) try out.writeAll(",");
    try out.writeAll("\n");
}

fn writeJsonString(out: *Writer, value: []const u8) !void {
    try out.writeByte('"');
    for (value) |byte| {
        if (byte < 0x20) {
            switch (byte) {
                '\n' => try out.writeAll("\\n"),
                '\r' => try out.writeAll("\\r"),
                '\t' => try out.writeAll("\\t"),
                else => try out.print("\\u{x:0>4}", .{byte}),
            }
        } else {
            switch (byte) {
                '"' => try out.writeAll("\\\""),
                '\\' => try out.writeAll("\\\\"),
                else => try out.writeByte(byte),
            }
        }
    }
    try out.writeByte('"');
}

fn writeHexString(out: *Writer, value: []const u8) !void {
    const hex = "0123456789abcdef";
    try out.writeByte('"');
    for (value) |byte| {
        const hi: usize = @intCast(byte >> 4);
        const lo: usize = @intCast(byte & 0x0f);
        try out.writeByte(hex[hi]);
        try out.writeByte(hex[lo]);
    }
    try out.writeByte('"');
}

fn writeCommaNewline(out: *Writer, index: usize, indent: usize) !void {
    if (index != 0) try out.writeAll(",");
    try out.writeAll("\n");
    try writeIndent(out, indent);
}

fn writeIndent(out: *Writer, indent: usize) !void {
    for (0..indent) |_| try out.writeByte(' ');
}
