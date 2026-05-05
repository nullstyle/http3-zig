const std = @import("std");
const null3 = @import("null3");

const max_iterator_items = 1024;

const qpack_decode_options: null3.QpackFieldSectionDecodeOptions = .{
    .max_field_lines = 64,
    .max_decoded_bytes = 16 * 1024,
};

pub const Target = enum {
    all,
    frame,
    settings,
    capsule,
    datagram,
    qpack_integer,
    qpack_huffman,
    qpack_field_static,
    qpack_field_literal,
    qpack_field_dynamic,
    qpack_encoder_instruction,
    qpack_decoder_instruction,
};

pub const concrete_targets = [_]Target{
    .frame,
    .settings,
    .capsule,
    .datagram,
    .qpack_integer,
    .qpack_huffman,
    .qpack_field_static,
    .qpack_field_literal,
    .qpack_field_dynamic,
    .qpack_encoder_instruction,
    .qpack_decoder_instruction,
};

const smoke_inputs = [_][]const u8{
    "",
    "\x00",
    "\x01",
    "\x00\x00",
    "\x00\x05hello",
    "\x01\x02\x00\x00",
    "\x04\x00",
    "\x00\x03abc",
    "\x3f\xe1\x1f",
    "\xff",
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "GET / HTTP/3\r\n\r\n",
};

pub fn smokeInputs() []const []const u8 {
    return &smoke_inputs;
}

pub fn targetName(target: Target) []const u8 {
    return switch (target) {
        .all => "all",
        .frame => "frame",
        .settings => "settings",
        .capsule => "capsule",
        .datagram => "datagram",
        .qpack_integer => "qpack-integer",
        .qpack_huffman => "qpack-huffman",
        .qpack_field_static => "qpack-field-static",
        .qpack_field_literal => "qpack-field-literal",
        .qpack_field_dynamic => "qpack-field-dynamic",
        .qpack_encoder_instruction => "qpack-encoder-instruction",
        .qpack_decoder_instruction => "qpack-decoder-instruction",
    };
}

pub fn targetFromName(name: []const u8) ?Target {
    if (std.mem.eql(u8, name, "all")) return .all;
    if (std.mem.eql(u8, name, "frame")) return .frame;
    if (std.mem.eql(u8, name, "settings")) return .settings;
    if (std.mem.eql(u8, name, "capsule")) return .capsule;
    if (std.mem.eql(u8, name, "datagram")) return .datagram;
    if (std.mem.eql(u8, name, "qpack-integer") or std.mem.eql(u8, name, "qpack_integer")) return .qpack_integer;
    if (std.mem.eql(u8, name, "qpack-huffman") or std.mem.eql(u8, name, "qpack_huffman")) return .qpack_huffman;
    if (std.mem.eql(u8, name, "qpack-field-static") or std.mem.eql(u8, name, "qpack_field_static")) return .qpack_field_static;
    if (std.mem.eql(u8, name, "qpack-field-literal") or std.mem.eql(u8, name, "qpack_field_literal")) return .qpack_field_literal;
    if (std.mem.eql(u8, name, "qpack-field-dynamic") or std.mem.eql(u8, name, "qpack_field_dynamic")) return .qpack_field_dynamic;
    if (std.mem.eql(u8, name, "qpack-encoder-instruction") or std.mem.eql(u8, name, "qpack_encoder_instruction")) return .qpack_encoder_instruction;
    if (std.mem.eql(u8, name, "qpack-decoder-instruction") or std.mem.eql(u8, name, "qpack_decoder_instruction")) return .qpack_decoder_instruction;
    return null;
}

pub fn runTarget(allocator: std.mem.Allocator, target: Target, input: []const u8) !void {
    switch (target) {
        .all => {
            inline for (concrete_targets) |concrete| {
                try runTarget(allocator, concrete, input);
            }
        },
        .frame => fuzzFrame(input),
        .settings => fuzzSettings(input),
        .capsule => fuzzCapsule(input),
        .datagram => fuzzDatagram(input),
        .qpack_integer => fuzzQpackInteger(input),
        .qpack_huffman => fuzzQpackHuffman(allocator, input),
        .qpack_field_static => fuzzQpackFieldStatic(allocator, input),
        .qpack_field_literal => fuzzQpackFieldLiteral(allocator, input),
        .qpack_field_dynamic => fuzzQpackFieldDynamic(allocator, input),
        .qpack_encoder_instruction => fuzzQpackEncoderInstruction(allocator, input),
        .qpack_decoder_instruction => fuzzQpackDecoderInstruction(input),
    }
}

fn fuzzFrame(input: []const u8) void {
    if (null3.frame.decode(input)) |_| {} else |_| {}

    var it = null3.frame.iter(input);
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = it.next() catch break;
        if (maybe == null) break;
    }
}

fn fuzzSettings(input: []const u8) void {
    if (null3.Settings.decode(input)) |_| {} else |_| {}
}

fn fuzzCapsule(input: []const u8) void {
    if (null3.capsule.decode(input)) |_| {} else |_| {}

    var it = null3.capsule.iter(input);
    var count: usize = 0;
    while (count < max_iterator_items) : (count += 1) {
        const maybe = it.next() catch break;
        if (maybe == null) break;
    }
}

fn fuzzDatagram(input: []const u8) void {
    if (null3.datagram.decode(input)) |decoded| {
        if (decoded.context()) |_| {} else |_| {}
    } else |_| {}

    if (null3.datagram.decodeContextPayload(input)) |_| {} else |_| {}
}

fn fuzzQpackInteger(input: []const u8) void {
    var prefix_bits: u8 = 1;
    while (prefix_bits <= 8) : (prefix_bits += 1) {
        if (null3.qpack.integer.decode(input, prefix_bits)) |_| {} else |_| {}
    }
}

fn fuzzQpackHuffman(allocator: std.mem.Allocator, input: []const u8) void {
    if (null3.qpack.huffman.decode(allocator, input)) |decoded| {
        allocator.free(decoded);
    } else |_| {}
}

fn fuzzQpackFieldStatic(allocator: std.mem.Allocator, input: []const u8) void {
    if (null3.qpack.decodeFieldSectionWithOptions(allocator, input, qpack_decode_options)) |fields| {
        null3.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackFieldLiteral(allocator: std.mem.Allocator, input: []const u8) void {
    if (null3.qpack.decodeLiteralFieldSectionWithOptions(allocator, input, qpack_decode_options)) |fields| {
        null3.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackFieldDynamic(allocator: std.mem.Allocator, input: []const u8) void {
    var table = null3.DynamicTable.init(allocator, 0);
    defer table.deinit();

    if (null3.qpack.decodeDynamicFieldSectionWithOptions(allocator, &table, 0, input, qpack_decode_options)) |fields| {
        null3.qpack.freeFieldSection(allocator, fields);
    } else |_| {}
}

fn fuzzQpackEncoderInstruction(allocator: std.mem.Allocator, input: []const u8) void {
    if (null3.qpack.instructions.decodeEncoderInstruction(allocator, input)) |decoded| {
        null3.qpack.instructions.freeDecodedEncoderInstruction(allocator, decoded);
    } else |_| {}
}

fn fuzzQpackDecoderInstruction(input: []const u8) void {
    if (null3.qpack.instructions.decodeDecoderInstruction(input)) |_| {} else |_| {}
}
