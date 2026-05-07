const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");
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
    const fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "server-timing", .value = "app;dur=1" },
    };

    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    var enc = null3.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &fields);
    pos += try enc.encodeData(bytes[pos..], "ok");
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);

    var dec = null3.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(null3.message.Event) = .empty;
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
    const n = try null3.frame.encode(&buf, .{ .data = "nope" });
    const d = try null3.frame.decode(buf[0..n]);
    var dec = null3.MessageDecoder.init(.request, .{});
    try std.testing.expectError(
        null3.message.Error.DataBeforeHeaders,
        dec.observe(std.testing.allocator, d.frame),
    );
}

test "message codec rejects oversized headers and DATA after trailers" {
    var oversized = null3.MessageDecoder.init(.response, .{ .max_field_section_size = 1 });
    try std.testing.expectError(
        error.HeaderSectionTooLarge,
        oversized.observe(std.testing.allocator, .{ .headers = "too-large" }),
    );

    const headers = [_]null3.FieldLine{
        .{ .name = ":status", .value = "200" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    var bytes: [256]u8 = undefined;
    var pos: usize = 0;
    var enc = null3.MessageEncoder.init(.response, .{});
    pos += try enc.encodeHeaders(bytes[pos..], &headers);
    pos += try enc.encodeTrailers(bytes[pos..], &trailers);
    pos += try null3.frame.encode(bytes[pos..], .{ .data = "late" });

    var dec = null3.MessageDecoder.init(.response, .{});
    var events: std.ArrayList(null3.message.Event) = .empty;
    defer {
        for (events.items) |event| event.deinit(std.testing.allocator);
        events.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.DataAfterTrailers,
        dec.observeBytes(std.testing.allocator, bytes[0..pos], &events),
    );
}

