//! Fuzz corpus seeder.
//!
//! Generates `fuzz/corpus/<target>/<NN-name>` seed files using the
//! project's own codec encoders for well-formed cases plus
//! hand-crafted byte sequences for malformed / boundary cases.
//!
//! Re-run with `zig build seed-fuzz-corpus` whenever new seeds are
//! added or the codec wire format changes — the output directory is
//! version-controlled, and `run-fuzz-corpus` walks it at runtime
//! without rebuilding.
//!
//! The corpus is intentionally small enough to be tractable as a
//! non-gating CI step (~10 inputs per codec target). Coverage-guided
//! fuzzers (afl, libfuzzer) can supplement it later by writing into
//! the same directories.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const varint = quic_zig.wire.varint;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();
    const root_arg = args.next() orelse "fuzz/corpus";

    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(io, root_arg) catch {};
    try cwd.createDirPath(io, root_arg);

    const root = try cwd.openDir(io, root_arg, .{});

    // Buffer size large enough for any single seed. The biggest seeds
    // are HEADERS frames carrying ~1 KiB QPACK blocks.
    var buf: [4096]u8 = undefined;

    try seedFrame(allocator, io, root, &buf);
    try seedSettings(io, root, &buf);
    try seedCapsule(io, root, &buf);
    try seedDatagram(io, root, &buf);
    try seedQpackInteger(io, root, &buf);
    try seedQpackHuffman(io, root);
    try seedQpackFieldStatic(allocator, io, root, &buf);
    try seedQpackFieldLiteral(allocator, io, root, &buf);
    try seedQpackFieldDynamic(allocator, io, root, &buf);
    try seedQpackEncoderInstruction(allocator, io, root, &buf);
    try seedQpackDecoderInstruction(io, root, &buf);
    try seedWebSocketFrame(allocator, io, root, &buf);
    try seedWebSocketMessage(allocator, io, root, &buf);
    try seedMasque(io, root, &buf);
    try seedWebTransport(io, root, &buf);
    try seedWebTransportSession(io, root, &buf);

    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.print("seeded fuzz corpus into {s}\n", .{root_arg});
    try stdout.flush();
}

// ---------------------------------------------------------------- helpers

fn writeSeed(io: std.Io, root: std.Io.Dir, target: []const u8, name: []const u8, bytes: []const u8) !void {
    root.createDirPath(io, target) catch {};
    var subdir = try root.openDir(io, target, .{});
    defer subdir.close(io);
    var file = try subdir.createFile(io, name, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn settingsAll() http3_zig.Settings {
    return .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 16,
        .max_field_section_size = 65536,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };
}

// ---------------------------------------------------------------- frame

fn seedFrame(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    // 01-data-empty
    var n = try http3_zig.frame.encode(buf, .{ .data = "" });
    try writeSeed(io, root, "frame", "01-data-empty", buf[0..n]);

    // 02-data-small
    n = try http3_zig.frame.encode(buf, .{ .data = "hello" });
    try writeSeed(io, root, "frame", "02-data-small", buf[0..n]);

    // 03-headers-block — encoded as raw bytes (the field-section bytes
    // are opaque to the frame codec).
    n = try http3_zig.frame.encode(buf, .{ .headers = "\x00\x00" });
    try writeSeed(io, root, "frame", "03-headers-empty-prefix", buf[0..n]);

    // 04-settings-empty
    n = try http3_zig.frame.encode(buf, .{ .settings = .{} });
    try writeSeed(io, root, "frame", "04-settings-empty", buf[0..n]);

    // 05-settings-all
    n = try http3_zig.frame.encode(buf, .{ .settings = settingsAll() });
    try writeSeed(io, root, "frame", "05-settings-all", buf[0..n]);

    // 06-goaway-zero
    n = try http3_zig.frame.encode(buf, .{ .goaway = 0 });
    try writeSeed(io, root, "frame", "06-goaway-zero", buf[0..n]);

    // 07-max-push-id
    n = try http3_zig.frame.encode(buf, .{ .max_push_id = 1024 });
    try writeSeed(io, root, "frame", "07-max-push-id", buf[0..n]);

    // 08-cancel-push
    n = try http3_zig.frame.encode(buf, .{ .cancel_push = 7 });
    try writeSeed(io, root, "frame", "08-cancel-push", buf[0..n]);

    // 09-priority-update
    n = try http3_zig.frame.encode(buf, .{ .priority_update_request = .{
        .prioritized_element_id = 4,
        .priority_field_value = "u=3, i",
    } });
    try writeSeed(io, root, "frame", "09-priority-update-request", buf[0..n]);

    // 10-unknown-grease — a varint-encoded GREASE frame type 0x21,
    // with an empty payload.
    try writeSeed(io, root, "frame", "10-unknown-grease", &[_]u8{ 0x21, 0x00 });

    // 11-truncated-header — only the type varint, no length.
    try writeSeed(io, root, "frame", "11-truncated-header", &[_]u8{0x00});

    // 12-truncated-payload — type + length but missing payload bytes.
    try writeSeed(io, root, "frame", "12-truncated-payload", &[_]u8{ 0x00, 0x05, 'h' });

    // 13-reserved-http2 — frame type 0x02 (HTTP/2 PRIORITY).
    try writeSeed(io, root, "frame", "13-reserved-http2", &[_]u8{ 0x02, 0x00 });

    // 14-concatenated — DATA + HEADERS in one buffer.
    var pos: usize = 0;
    pos += try http3_zig.frame.encode(buf[pos..], .{ .data = "ab" });
    pos += try http3_zig.frame.encode(buf[pos..], .{ .headers = "\x00\x00" });
    try writeSeed(io, root, "frame", "14-concatenated", buf[0..pos]);
}

// ---------------------------------------------------------------- settings

fn seedSettings(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    // 01-empty
    var n = try (http3_zig.Settings{}).encode(buf);
    try writeSeed(io, root, "settings", "01-empty", buf[0..n]);

    // 02-all
    n = try settingsAll().encode(buf);
    try writeSeed(io, root, "settings", "02-all", buf[0..n]);

    // 03-h3-datagram-only
    n = try (http3_zig.Settings{ .h3_datagram = true }).encode(buf);
    try writeSeed(io, root, "settings", "03-h3-datagram-only", buf[0..n]);

    // 04-wt-enabled — draft-ietf-webtrans-http3-15 §9.2 boolean
    // SETTINGS_WT_ENABLED replaces draft-13's numeric WT_MAX_SESSIONS.
    n = try (http3_zig.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    }).encode(buf);
    try writeSeed(io, root, "settings", "04-wt-enabled", buf[0..n]);

    // 05-duplicate-setting — id 0x06 twice (max_field_section_size).
    try writeSeed(io, root, "settings", "05-duplicate", &[_]u8{ 0x06, 0x40, 0x10, 0x06, 0x40, 0x20 });

    // 06-reserved-http2 — id 0x02 (HTTP/2 SETTINGS_ENABLE_PUSH).
    try writeSeed(io, root, "settings", "06-reserved-http2", &[_]u8{ 0x02, 0x01 });

    // 07-grease-id — id 0x21 (GREASE), opaque value.
    try writeSeed(io, root, "settings", "07-grease", &[_]u8{ 0x21, 0x00 });

    // 08-truncated — id only, missing value.
    try writeSeed(io, root, "settings", "08-truncated", &[_]u8{0x06});
}

// ---------------------------------------------------------------- capsule

fn seedCapsule(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    // 01-datagram-empty
    var n = try http3_zig.capsule.encodeDatagram(buf, "");
    try writeSeed(io, root, "capsule", "01-datagram-empty", buf[0..n]);

    // 02-datagram-payload
    n = try http3_zig.capsule.encodeDatagram(buf, "payload");
    try writeSeed(io, root, "capsule", "02-datagram-payload", buf[0..n]);

    // 03-grease — capsule type 0x29 (1f*N + 21 for N=8) with opaque value.
    n = try http3_zig.capsule.encode(buf, 0x29 * 1 + 0x21, "grease");
    try writeSeed(io, root, "capsule", "03-grease", buf[0..n]);

    // 04-multi — DATAGRAM + GREASE concatenated.
    var pos: usize = 0;
    pos += try http3_zig.capsule.encodeDatagram(buf[pos..], "first");
    pos += try http3_zig.capsule.encode(buf[pos..], 0x40, "extension");
    try writeSeed(io, root, "capsule", "04-multi", buf[0..pos]);

    // 05-truncated-header
    try writeSeed(io, root, "capsule", "05-truncated-header", &[_]u8{0x00});

    // 06-length-mismatch — claims 5 bytes, only carries 2.
    try writeSeed(io, root, "capsule", "06-length-mismatch", &[_]u8{ 0x00, 0x05, 0x61, 0x62 });
}

// ---------------------------------------------------------------- datagram

fn seedDatagram(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    // 01-empty
    var n = try http3_zig.datagram.encode(buf, 0, "");
    try writeSeed(io, root, "datagram", "01-empty", buf[0..n]);

    // 02-payload
    n = try http3_zig.datagram.encode(buf, 4, "datagram");
    try writeSeed(io, root, "datagram", "02-payload", buf[0..n]);

    // 03-large-stream-id
    n = try http3_zig.datagram.encode(buf, 4096, "data");
    try writeSeed(io, root, "datagram", "03-large-stream-id", buf[0..n]);

    // 04-with-context — RFC 9297 context-aware payload (ctx=7).
    n = try http3_zig.datagram.encodeWithContext(buf, 8, 7, "ctx-payload");
    try writeSeed(io, root, "datagram", "04-with-context", buf[0..n]);

    // 05-empty-buf — completely empty input.
    try writeSeed(io, root, "datagram", "05-empty-buf", "");

    // 06-truncated-quarter-id — first byte of a 2-byte varint without
    // the second.
    try writeSeed(io, root, "datagram", "06-truncated-quarter-id", &[_]u8{0x40});
}

// ---------------------------------------------------------------- qpack-integer

fn seedQpackInteger(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = buf;
    // 01-zero
    try writeSeed(io, root, "qpack-integer", "01-zero", &[_]u8{0x00});
    // 02-small
    try writeSeed(io, root, "qpack-integer", "02-small", &[_]u8{0x05});
    // 03-prefix-mask-3 — value 7 in a 3-bit prefix means continuation.
    try writeSeed(io, root, "qpack-integer", "03-continuation", &[_]u8{ 0x07, 0x00 });
    // 04-multi-byte — RFC 7541 Appendix C.1 example: 1337 with 5-bit prefix.
    try writeSeed(io, root, "qpack-integer", "04-rfc-1337", &[_]u8{ 0x1f, 0x9a, 0x0a });
    // 05-truncated-continuation — first byte signals continuation but
    // the buffer ends.
    try writeSeed(io, root, "qpack-integer", "05-truncated", &[_]u8{0xff});
    // 06-overflow — many 0x80 continuation bytes followed by 0x7f.
    // Written out explicitly to avoid the `**` repeat operator's
    // strict whitespace rules.
    const overflow = [_]u8{
        0xff, // initial marker, requires continuation
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x7f, // terminator
    };
    try writeSeed(io, root, "qpack-integer", "06-overflow", &overflow);
}

// ---------------------------------------------------------------- qpack-huffman

fn seedQpackHuffman(io: std.Io, root: std.Io.Dir) !void {
    // 01-empty
    try writeSeed(io, root, "qpack-huffman", "01-empty", "");
    // 02-rfc-www — RFC 7541 Appendix C.4.1 "www.example.com" Huffman bytes.
    try writeSeed(io, root, "qpack-huffman", "02-www-example-com", &[_]u8{
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
        0xab, 0x90, 0xf4, 0xff,
    });
    // 03-rfc-no-cache — RFC 7541 Appendix C.4.2 "no-cache".
    try writeSeed(io, root, "qpack-huffman", "03-no-cache", &[_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf });
    // 04-truncated — single byte that needs continuation.
    try writeSeed(io, root, "qpack-huffman", "04-truncated", &[_]u8{0xff});
    // 05-padding-too-long — multiple bytes of trailing 1s.
    try writeSeed(io, root, "qpack-huffman", "05-padding-too-long", &[_]u8{ 0xff, 0xff, 0xff });
}

// ---------------------------------------------------------------- qpack field sections

fn seedQpackFieldStatic(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    // 01-empty-prefix — required-insert-count=0, base=0, no field lines.
    try writeSeed(io, root, "qpack-field-static", "01-empty", &[_]u8{ 0x00, 0x00 });

    // 02-indexed — :method GET (static index 17).
    const fields = [_]http3_zig.FieldLine{.{ .name = ":method", .value = "GET" }};
    var n = try http3_zig.qpack.encodeFieldSection(buf, &fields);
    try writeSeed(io, root, "qpack-field-static", "02-method-get", buf[0..n]);

    // 03-mixed-pseudo
    const mixed = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/api" },
    };
    n = try http3_zig.qpack.encodeFieldSection(buf, &mixed);
    try writeSeed(io, root, "qpack-field-static", "03-pseudo-headers", buf[0..n]);

    // 04-truncated — prefix only, no field lines body.
    try writeSeed(io, root, "qpack-field-static", "04-prefix-only", &[_]u8{0x00});

    // 05-malformed-index — references an out-of-range static entry.
    try writeSeed(io, root, "qpack-field-static", "05-bad-static-index", &[_]u8{ 0x00, 0x00, 0xff });
}

fn seedQpackFieldLiteral(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    // 01-literal-name-value — both name and value are literals (no static-table reuse).
    const fields = [_]http3_zig.FieldLine{.{ .name = "x-custom-header", .value = "hello world" }};
    var n = try http3_zig.qpack.encodeFieldSection(buf, &fields);
    try writeSeed(io, root, "qpack-field-literal", "01-custom-header", buf[0..n]);

    // 02-with-pseudo
    const fields2 = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "user-agent", .value = "fuzz/1.0" },
        .{ .name = "x-trace-id", .value = "abc-123" },
    };
    n = try http3_zig.qpack.encodeFieldSection(buf, &fields2);
    try writeSeed(io, root, "qpack-field-literal", "02-mixed", buf[0..n]);

    // 03-empty-value
    const fields3 = [_]http3_zig.FieldLine{.{ .name = "x-empty", .value = "" }};
    n = try http3_zig.qpack.encodeFieldSection(buf, &fields3);
    try writeSeed(io, root, "qpack-field-literal", "03-empty-value", buf[0..n]);

    // 04-bad-utf8 — name with high-bit byte that doesn't decode as ASCII.
    try writeSeed(io, root, "qpack-field-literal", "04-bad-bytes", &[_]u8{
        0x00, 0x00, // prefix
        0x27, 0x7f, 0xff, 0xff, // malformed literal header
    });
}

fn seedQpackFieldDynamic(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    _ = buf;
    // 01-empty-prefix
    try writeSeed(io, root, "qpack-field-dynamic", "01-empty", &[_]u8{ 0x00, 0x00 });
    // 02-required-insert-count
    try writeSeed(io, root, "qpack-field-dynamic", "02-ric-nonzero", &[_]u8{ 0x05, 0x00, 0x80 });
    // 03-grease-prefix-byte
    try writeSeed(io, root, "qpack-field-dynamic", "03-grease-byte", &[_]u8{ 0xff, 0x00 });
}

fn seedQpackEncoderInstruction(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    _ = buf;
    // 01-set-capacity-0
    try writeSeed(io, root, "qpack-encoder-instruction", "01-set-cap-0", &[_]u8{0x20});
    // 02-set-capacity-large
    try writeSeed(io, root, "qpack-encoder-instruction", "02-set-cap-large", &[_]u8{ 0x3f, 0xff, 0x40 });
    // 03-duplicate
    try writeSeed(io, root, "qpack-encoder-instruction", "03-duplicate", &[_]u8{0x00});
    // 04-insert-name-ref-static — high bit set, T=1.
    try writeSeed(io, root, "qpack-encoder-instruction", "04-insert-name-ref", &[_]u8{ 0xc0, 0x05, 'h', 'e', 'l', 'l', 'o' });
    // 05-truncated
    try writeSeed(io, root, "qpack-encoder-instruction", "05-truncated", &[_]u8{0xc0});
}

fn seedQpackDecoderInstruction(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = buf;
    // 01-section-ack
    try writeSeed(io, root, "qpack-decoder-instruction", "01-section-ack", &[_]u8{0x80});
    // 02-stream-cancel
    try writeSeed(io, root, "qpack-decoder-instruction", "02-stream-cancel", &[_]u8{0x40});
    // 03-insert-count-increment
    try writeSeed(io, root, "qpack-decoder-instruction", "03-insert-count-incr", &[_]u8{0x05});
    // 04-empty
    try writeSeed(io, root, "qpack-decoder-instruction", "04-empty", "");
}

// ---------------------------------------------------------------- websocket

fn seedWebSocketFrame(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    // 01-text-unmasked — server-to-client text frame "hi".
    var n = try http3_zig.websocket.frame.encode(
        buf,
        .{ .opcode = .text, .payload = "hi" },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-frame", "01-text-unmasked", buf[0..n]);

    // 02-binary-masked — client-to-server.
    n = try http3_zig.websocket.frame.encode(
        buf,
        .{ .opcode = .binary, .payload = &[_]u8{ 0xde, 0xad, 0xbe, 0xef } },
        .{ .mask = true, .masking_key = .{ 1, 2, 3, 4 } },
    );
    try writeSeed(io, root, "websocket-frame", "02-binary-masked", buf[0..n]);

    // 03-close-1000
    n = try http3_zig.websocket.frame.encodeClose(buf, 1000, "bye", .{});
    try writeSeed(io, root, "websocket-frame", "03-close-1000", buf[0..n]);

    // 04-ping
    n = try http3_zig.websocket.frame.encode(
        buf,
        .{ .opcode = .ping, .payload = "ping" },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-frame", "04-ping", buf[0..n]);

    // 05-extended-126 — 126-byte payload uses the 2-byte extended length.
    var big: [126]u8 = undefined;
    @memset(&big, 'a');
    n = try http3_zig.websocket.frame.encode(
        buf,
        .{ .opcode = .text, .payload = &big },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-frame", "05-extended-126", buf[0..n]);

    // 06-bad-rsv — RSV1 set with no extension negotiated.
    try writeSeed(io, root, "websocket-frame", "06-bad-rsv", &[_]u8{ 0xc1, 0x02, 'h', 'i' });

    // 07-non-minimal-126 — extended length 126 with value < 126.
    try writeSeed(io, root, "websocket-frame", "07-non-minimal-126", &[_]u8{ 0x81, 0x7e, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' });
}

fn seedWebSocketMessage(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = allocator;
    // 01-single-text
    const n = try http3_zig.websocket.frame.encode(
        buf,
        .{ .opcode = .text, .payload = "hello" },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-message", "01-single-text", buf[0..n]);

    // 02-fragmented — text "abc" + continuation "def" with FIN.
    var pos: usize = 0;
    pos += try http3_zig.websocket.frame.encode(
        buf[pos..],
        .{ .fin = false, .opcode = .text, .payload = "abc" },
        .{ .mask = false },
    );
    pos += try http3_zig.websocket.frame.encode(
        buf[pos..],
        .{ .fin = true, .opcode = .continuation, .payload = "def" },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-message", "02-fragmented", buf[0..pos]);

    // 03-text-with-ping-interleaved
    pos = 0;
    pos += try http3_zig.websocket.frame.encode(
        buf[pos..],
        .{ .fin = false, .opcode = .text, .payload = "hi" },
        .{ .mask = false },
    );
    pos += try http3_zig.websocket.frame.encode(
        buf[pos..],
        .{ .opcode = .ping, .payload = "p" },
        .{ .mask = false },
    );
    pos += try http3_zig.websocket.frame.encode(
        buf[pos..],
        .{ .fin = true, .opcode = .continuation, .payload = " there" },
        .{ .mask = false },
    );
    try writeSeed(io, root, "websocket-message", "03-interleaved-ping", buf[0..pos]);
}

// ---------------------------------------------------------------- masque

fn seedMasque(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    _ = buf;
    // 01-target-path-default
    try writeSeed(io, root, "masque", "01-target-path", "/.well-known/masque/udp/example.com/443/");
    // 02-ipv4
    try writeSeed(io, root, "masque", "02-ipv4", "/.well-known/masque/udp/192.0.2.1/443/");
    // 03-ipv6 — bracketed for path readability.
    try writeSeed(io, root, "masque", "03-ipv6", "/.well-known/masque/udp/[2001:db8::1]/443/");
    // 04-malformed-path — wrong prefix.
    try writeSeed(io, root, "masque", "04-bad-prefix", "/.foo/udp/host/123/");
    // 05-context-payload — context_id=0 + UDP payload.
    try writeSeed(io, root, "masque", "05-udp-payload", &[_]u8{ 0x00, 'h', 'i' });
    // 06-context-payload-extension — context_id=7 + extension payload.
    try writeSeed(io, root, "masque", "06-ext-payload", &[_]u8{ 0x07, 0x00, 0x01, 0x02 });
    // 07-truncated-context — context-id varint truncated.
    try writeSeed(io, root, "masque", "07-truncated", &[_]u8{0x40});
}

// ---------------------------------------------------------------- webtransport

fn seedWebTransport(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    // 01-uni-prefix-session-0
    var n = try http3_zig.webtransport.encodeUniStreamPrefix(buf, 0);
    try writeSeed(io, root, "webtransport", "01-uni-prefix-0", buf[0..n]);

    // 02-uni-prefix-session-large
    n = try http3_zig.webtransport.encodeUniStreamPrefix(buf, 65536);
    try writeSeed(io, root, "webtransport", "02-uni-prefix-large", buf[0..n]);

    // 03-bidi-prefix
    n = try http3_zig.webtransport.encodeBidiStreamPrefix(buf, 16);
    try writeSeed(io, root, "webtransport", "03-bidi-prefix", buf[0..n]);

    // 04-close-session
    n = try http3_zig.webtransport.encodeCloseSession(buf, 0xdeadbeef, "bye");
    try writeSeed(io, root, "webtransport", "04-close-session", buf[0..n]);

    // 05-close-session-empty-reason
    n = try http3_zig.webtransport.encodeCloseSession(buf, 0, "");
    try writeSeed(io, root, "webtransport", "05-close-empty-reason", buf[0..n]);

    // 06-drain-session
    n = try http3_zig.webtransport.encodeDrainSession(buf);
    try writeSeed(io, root, "webtransport", "06-drain-session", buf[0..n]);

    // 07-max-data
    n = try http3_zig.webtransport.encodeMaxData(buf, 1 << 20);
    try writeSeed(io, root, "webtransport", "07-max-data", buf[0..n]);

    // 08-data-blocked
    n = try http3_zig.webtransport.encodeDataBlocked(buf, 4096);
    try writeSeed(io, root, "webtransport", "08-data-blocked", buf[0..n]);

    // 09-max-streams-bidi
    n = try http3_zig.webtransport.encodeMaxStreamsBidi(buf, 8);
    try writeSeed(io, root, "webtransport", "09-max-streams-bidi", buf[0..n]);

    // 10-max-streams-uni
    n = try http3_zig.webtransport.encodeMaxStreamsUni(buf, 16);
    try writeSeed(io, root, "webtransport", "10-max-streams-uni", buf[0..n]);

    // 11-streams-blocked-bidi
    n = try http3_zig.webtransport.encodeStreamsBlockedBidi(buf, 2);
    try writeSeed(io, root, "webtransport", "11-streams-blocked-bidi", buf[0..n]);

    // 12-streams-blocked-uni
    n = try http3_zig.webtransport.encodeStreamsBlockedUni(buf, 4);
    try writeSeed(io, root, "webtransport", "12-streams-blocked-uni", buf[0..n]);

    // 13-truncated-prefix
    try writeSeed(io, root, "webtransport", "13-truncated-uni", &[_]u8{0x40});

    // 14-available-protocols
    try writeSeed(io, root, "webtransport", "14-available-protocols", "echo-v1,telemetry,echo-v2");

    // 15-malformed-close — too-small value (< 4 bytes).
    try writeSeed(io, root, "webtransport", "15-bad-close", &[_]u8{ 0x68, 0x43, 0x02, 0x00, 0x01 });
}

fn seedWebTransportSession(io: std.Io, root: std.Io.Dir, buf: []u8) !void {
    // The session-level fuzz target reuses every WT seed plus its own
    // stress cases. Keeping a smaller, distinct corpus here for the
    // "session-shaped" inputs that the existing transport-free target
    // doesn't naturally explore.

    // 01-uni-prefix-then-data
    var n = try http3_zig.webtransport.encodeUniStreamPrefix(buf, 4);
    @memcpy(buf[n .. n + 5], "hello");
    n += 5;
    try writeSeed(io, root, "webtransport-session", "01-uni-with-data", buf[0..n]);

    // 02-bidi-prefix-then-data
    n = try http3_zig.webtransport.encodeBidiStreamPrefix(buf, 0);
    @memcpy(buf[n .. n + 4], "ping");
    n += 4;
    try writeSeed(io, root, "webtransport-session", "02-bidi-with-data", buf[0..n]);

    // 03-stream-of-flow-control-capsules — concatenate every flow
    // control capsule so the session's classifyCapsule hot path
    // walks the whole set.
    var pos: usize = 0;
    pos += try http3_zig.webtransport.encodeMaxData(buf[pos..], 4096);
    pos += try http3_zig.webtransport.encodeDataBlocked(buf[pos..], 4096);
    pos += try http3_zig.webtransport.encodeMaxStreamsBidi(buf[pos..], 4);
    pos += try http3_zig.webtransport.encodeMaxStreamsUni(buf[pos..], 4);
    pos += try http3_zig.webtransport.encodeStreamsBlockedBidi(buf[pos..], 4);
    pos += try http3_zig.webtransport.encodeStreamsBlockedUni(buf[pos..], 4);
    try writeSeed(io, root, "webtransport-session", "03-flow-control-stream", buf[0..pos]);

    // 04-close-then-drain
    pos = 0;
    pos += try http3_zig.webtransport.encodeDrainSession(buf[pos..]);
    pos += try http3_zig.webtransport.encodeCloseSession(buf[pos..], 1, "drained");
    try writeSeed(io, root, "webtransport-session", "04-drain-then-close", buf[0..pos]);

    // 05-error-code-boundary — 0x52e4a40fa8db (the WT error-code
    // mapping base) as a u64 big-endian. Probes the
    // `http3ToAppError` fuzz path.
    try writeSeed(io, root, "webtransport-session", "05-error-base", &[_]u8{
        0x00, 0x00, 0x52, 0xe4, 0xa4, 0x0f, 0xa8, 0xdb,
    });

    // 06-error-code-stride — boundary slot at f(0)+30+1 (reserved).
    try writeSeed(io, root, "webtransport-session", "06-error-stride-boundary", &[_]u8{
        0x00, 0x00, 0x52, 0xe4, 0xa4, 0x0f, 0xa8, 0xfa,
    });

    // 07-empty
    try writeSeed(io, root, "webtransport-session", "07-empty", "");
}
