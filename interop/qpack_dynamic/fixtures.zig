//! Dynamic-table QPACK fixture corpus.
//!
//! These vectors are transport-free and intentionally use exact bytes from
//! RFC 9204 Appendix B. The Zig runner exercises them directly; external
//! peers can mirror the same encoder stream, field section, and decoder
//! feedback bytes without depending on null3 internals.

const null3 = @import("null3");
const qpack = null3.qpack;

pub const TableEntry = struct {
    absolute_index: u64,
    name: []const u8,
    value: []const u8,
};

pub const TableSnapshot = struct {
    capacity: usize,
    len: usize,
    size: usize,
    insert_count: u64,
    dropped_count: u64,
    entries: []const TableEntry,
    absent_absolute_indices: []const u64 = &empty_absent_indices,
};

pub const SectionCompletion = struct {
    stream_id: u64,
    required_insert_count: u64,
    encoded_decoder_feedback: []const u8,
};

pub const DecoderFeedbackVector = struct {
    instruction: qpack.DecoderInstruction,
    encoded: []const u8,
};

pub const EncoderStreamVector = struct {
    name: []const u8,
    max_table_capacity: usize,
    setup_encoder_stream: []const u8 = "",
    complete_before: ?SectionCompletion = null,
    instructions: []const qpack.EncoderInstruction,
    encoder_stream: []const u8,
    table_after: TableSnapshot,
    insert_count_increment: ?[]const u8 = null,
};

pub const FieldSectionVector = struct {
    name: []const u8,
    max_table_capacity: u64,
    setup_encoder_stream: []const u8,
    stream_id: u64,
    required_insert_count: u64,
    base: u64,
    field_section: []const u8,
    fields: []const qpack.FieldLine,
    decoder_feedback: ?DecoderFeedbackVector = null,
    stream_cancel: ?DecoderFeedbackVector = null,
};

pub const b2_encoder_stream = "\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path";
pub const b3_encoder_stream = "\x4acustom-key\x0ccustom-value";
pub const b4_duplicate_stream = "\x02";
pub const b5_encoder_stream = "\x81\x0dcustom-value2";

pub const setup_b3 = b2_encoder_stream;
pub const setup_b4 = b2_encoder_stream ++ b3_encoder_stream;
pub const setup_b5 = b2_encoder_stream ++ b3_encoder_stream ++ b4_duplicate_stream;

const empty_absent_indices = [_]u64{};

const b2_instructions = [_]qpack.EncoderInstruction{
    .{ .set_capacity = 220 },
    .{ .insert_name_ref = .{
        .table = .static,
        .index = 0,
        .value = "www.example.com",
    } },
    .{ .insert_name_ref = .{
        .table = .static,
        .index = 1,
        .value = "/sample/path",
    } },
};

const b3_instructions = [_]qpack.EncoderInstruction{
    .{ .insert_literal = .{
        .name = "custom-key",
        .value = "custom-value",
    } },
};

const b4_instructions = [_]qpack.EncoderInstruction{
    .{ .duplicate = 2 },
};

const b5_instructions = [_]qpack.EncoderInstruction{
    .{ .insert_name_ref = .{
        .table = .dynamic,
        .index = 1,
        .value = "custom-value2",
    } },
};

const b2_entries = [_]TableEntry{
    .{ .absolute_index = 0, .name = ":authority", .value = "www.example.com" },
    .{ .absolute_index = 1, .name = ":path", .value = "/sample/path" },
};

const b3_entries = [_]TableEntry{
    .{ .absolute_index = 0, .name = ":authority", .value = "www.example.com" },
    .{ .absolute_index = 1, .name = ":path", .value = "/sample/path" },
    .{ .absolute_index = 2, .name = "custom-key", .value = "custom-value" },
};

const b4_entries = [_]TableEntry{
    .{ .absolute_index = 0, .name = ":authority", .value = "www.example.com" },
    .{ .absolute_index = 1, .name = ":path", .value = "/sample/path" },
    .{ .absolute_index = 2, .name = "custom-key", .value = "custom-value" },
    .{ .absolute_index = 3, .name = ":authority", .value = "www.example.com" },
};

const b5_entries = [_]TableEntry{
    .{ .absolute_index = 1, .name = ":path", .value = "/sample/path" },
    .{ .absolute_index = 2, .name = "custom-key", .value = "custom-value" },
    .{ .absolute_index = 3, .name = ":authority", .value = "www.example.com" },
    .{ .absolute_index = 4, .name = "custom-key", .value = "custom-value2" },
};

const b5_absent = [_]u64{0};

pub const encoder_stream_vectors = [_]EncoderStreamVector{
    .{
        .name = "rfc9204_appendix_b2_static_name_ref_insertions",
        .max_table_capacity = 220,
        .instructions = &b2_instructions,
        .encoder_stream = b2_encoder_stream,
        .table_after = .{
            .capacity = 220,
            .len = 2,
            .size = 106,
            .insert_count = 2,
            .dropped_count = 0,
            .entries = &b2_entries,
        },
    },
    .{
        .name = "rfc9204_appendix_b3_literal_insert",
        .max_table_capacity = 220,
        .setup_encoder_stream = setup_b3,
        .complete_before = .{
            .stream_id = 4,
            .required_insert_count = 2,
            .encoded_decoder_feedback = "\x84",
        },
        .instructions = &b3_instructions,
        .encoder_stream = b3_encoder_stream,
        .table_after = .{
            .capacity = 220,
            .len = 3,
            .size = 160,
            .insert_count = 3,
            .dropped_count = 0,
            .entries = &b3_entries,
        },
        .insert_count_increment = "\x01",
    },
    .{
        .name = "rfc9204_appendix_b4_duplicate",
        .max_table_capacity = 220,
        .setup_encoder_stream = setup_b4,
        .instructions = &b4_instructions,
        .encoder_stream = b4_duplicate_stream,
        .table_after = .{
            .capacity = 220,
            .len = 4,
            .size = 217,
            .insert_count = 4,
            .dropped_count = 0,
            .entries = &b4_entries,
        },
    },
    .{
        .name = "rfc9204_appendix_b5_dynamic_name_ref_eviction",
        .max_table_capacity = 220,
        .setup_encoder_stream = setup_b5,
        .instructions = &b5_instructions,
        .encoder_stream = b5_encoder_stream,
        .table_after = .{
            .capacity = 220,
            .len = 4,
            .size = 215,
            .insert_count = 5,
            .dropped_count = 1,
            .entries = &b5_entries,
            .absent_absolute_indices = &b5_absent,
        },
    },
};

const b2_fields = [_]qpack.FieldLine{
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = ":path", .value = "/sample/path" },
};

const b4_fields = [_]qpack.FieldLine{
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "custom-key", .value = "custom-value" },
};

pub const field_section_vectors = [_]FieldSectionVector{
    .{
        .name = "rfc9204_appendix_b2_dynamic_field_section_ack",
        .max_table_capacity = 220,
        .setup_encoder_stream = b2_encoder_stream,
        .stream_id = 4,
        .required_insert_count = 2,
        .base = 0,
        .field_section = "\x03\x81\x10\x11",
        .fields = &b2_fields,
        .decoder_feedback = .{
            .instruction = .{ .section_ack = 4 },
            .encoded = "\x84",
        },
    },
    .{
        .name = "rfc9204_appendix_b4_relative_and_static_refs_cancel",
        .max_table_capacity = 220,
        .setup_encoder_stream = setup_b5,
        .stream_id = 8,
        .required_insert_count = 4,
        .base = 4,
        .field_section = "\x05\x00\x80\xc1\x81",
        .fields = &b4_fields,
        .stream_cancel = .{
            .instruction = .{ .stream_cancel = 8 },
            .encoded = "\x48",
        },
    },
};
