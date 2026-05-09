const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixt = @import("_fixtures.zig");

// Aliases — pulls in only the helpers this file's tests reference. It's
// fine to over-alias; unused aliases compile away.
const test_cert_pem = fixt.test_cert_pem;
const test_key_pem = fixt.test_key_pem;
const ClientCid = fixt.ClientCid;
const ServerCid = fixt.ServerCid;
const discardKeylog = fixt.discardKeylog;
const handshake = fixt.handshake;
const initConnectedQuic = fixt.initConnectedQuic;
const clearSessionEvents = fixt.clearSessionEvents;
const pumpH3 = fixt.pumpH3;
const pumpUntilH3Error = fixt.pumpUntilH3Error;
const writeFrame = fixt.writeFrame;
const writeQpackEncoderInstruction = fixt.writeQpackEncoderInstruction;
const writeStreamType = fixt.writeStreamType;
const writeVarint = fixt.writeVarint;
const openUniWithType = fixt.openUniWithType;
const writeHeadersFrame = fixt.writeHeadersFrame;
const writePushPromiseFrame = fixt.writePushPromiseFrame;
const expectLastCloseCode = fixt.expectLastCloseCode;
const fieldValue = fixt.fieldValue;
const H3Pair = fixt.H3Pair;
const expectPairH3Error = fixt.expectPairH3Error;
const exchangePairSettings = fixt.exchangePairSettings;
const openGetAndAwaitServerHeaders = fixt.openGetAndAwaitServerHeaders;
const sendRawH3Datagram = fixt.sendRawH3Datagram;

test "message encoder and decoder handles response body and trailers" {
    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]http3_zig.FieldLine{
        .{ .name = "server-timing", .value = "app;dur=1" },
    };

    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = http3_zig.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &fields);
    pos += try enc.encodeData(bytes[pos..], "ok");
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);

    var dec = http3_zig.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(http3_zig.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }

    try dec.observeBytes(std.testing.allocator, bytes[0..pos], &events);
    try dec.finish();
    try std.testing.expectEqual(@as(usize, 3), events.items.len);
    switch (events.items[0]) {
        .headers => |h| try std.testing.expectEqualStrings("200", h[0].value),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[1]) {
        .data => |body| try std.testing.expectEqualStrings("ok", body),
        else => return error.TestExpectedEqual,
    }
    switch (events.items[2]) {
        .trailers => |t| try std.testing.expectEqualStrings("app;dur=1", t[0].value),
        else => return error.TestExpectedEqual,
    }
}

test "message decoder rejects DATA before HEADERS" {
    var buf: [32]u8 = undefined;
    const n = try http3_zig.frame.encode(&buf, .{ .data = "nope" });
    const d = try http3_zig.frame.decode(buf[0..n]);
    var dec = http3_zig.MessageDecoder.init(.request, .{});
    try std.testing.expectError(
        http3_zig.message.Error.DataBeforeHeaders,
        dec.observe(std.testing.allocator, d.frame),
    );
}

test "message codec rejects oversized headers and DATA after trailers" {
    var oversized = http3_zig.MessageDecoder.init(.response, .{ .max_field_section_size = 1 });
    try std.testing.expectError(
        error.HeaderSectionTooLarge,
        oversized.observe(std.testing.allocator, .{ .headers = "too-large" }),
    );

    const headers = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    const trailers = [_]http3_zig.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    var bytes: [256]u8 = undefined;
    var pos: usize = 0;
    var enc = http3_zig.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &headers);
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);
    pos += try http3_zig.frame.encode(bytes[pos..], .{ .data = "late" });

    var dec = http3_zig.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(http3_zig.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.DataAfterTrailers,
        dec.observeBytes(std.testing.allocator, bytes[0..pos], &events),
    );
}

test "response decoder surfaces 1xx interim headers before final response (RFC 9110 §15.2)" {
    // A response that emits `100 Continue` followed by `200 OK` must
    // surface as `interim_headers: 100` then `headers: 200`, NOT as
    // `headers: 100` then `trailers: 200` (the pre-fix shape that
    // broke curl/nginx interop).
    const allocator = std.testing.allocator;

    const interim_fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "100" },
    };
    const final_fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };

    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = http3_zig.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &interim_fields);
    pos += try enc.encodeHeaders(bytes[pos..], &final_fields);
    pos += try http3_zig.frame.encode(bytes[pos..], .{ .data = "ok" });

    var dec = http3_zig.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(http3_zig.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }

    try dec.observeBytes(allocator, bytes[0..pos], &events);
    try dec.finish();

    try std.testing.expectEqual(@as(usize, 3), events.items.len);
    switch (events.items[0]) {
        .interim_headers => |fields| try std.testing.expectEqualStrings("100", fields[0].value),
        else => return error.ExpectedInterimHeaders,
    }
    switch (events.items[1]) {
        .headers => |fields| try std.testing.expectEqualStrings("200", fields[0].value),
        else => return error.ExpectedFinalHeaders,
    }
    switch (events.items[2]) {
        .data => |bytes_| try std.testing.expectEqualStrings("ok", bytes_),
        else => return error.ExpectedDataEvent,
    }
}

test "response decoder surfaces multiple 1xx interim responses before final" {
    // The spec allows multiple interim responses (e.g. `103 Early
    // Hints` followed by `100 Continue`). All surface as separate
    // `interim_headers` events; the non-1xx is the single `headers`.
    const allocator = std.testing.allocator;

    const early_hints = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "103" },
        .{ .name = "link", .value = "</style.css>; rel=preload" },
    };
    const continu = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "100" },
    };
    const final = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };

    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = http3_zig.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &early_hints);
    pos += try enc.encodeHeaders(bytes[pos..], &continu);
    pos += try enc.encodeHeaders(bytes[pos..], &final);

    var dec = http3_zig.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(http3_zig.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(allocator);
        events.deinit(allocator);
    }
    try dec.observeBytes(allocator, bytes[0..pos], &events);
    try dec.finish();

    try std.testing.expectEqual(@as(usize, 3), events.items.len);
    switch (events.items[0]) {
        .interim_headers => |fields| try std.testing.expectEqualStrings("103", fields[0].value),
        else => return error.ExpectedInterimHeaders,
    }
    switch (events.items[1]) {
        .interim_headers => |fields| try std.testing.expectEqualStrings("100", fields[0].value),
        else => return error.ExpectedInterimHeaders,
    }
    switch (events.items[2]) {
        .headers => |fields| try std.testing.expectEqualStrings("200", fields[0].value),
        else => return error.ExpectedFinalHeaders,
    }
}

