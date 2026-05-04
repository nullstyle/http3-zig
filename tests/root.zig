const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

fn handshake(client: *nullq.Connection, server: *nullq.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

fn clearSessionEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(null3.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

fn pumpH3(
    client: *nullq.Connection,
    server: *nullq.Connection,
    client_h3: *null3.Session,
    server_h3: *null3.Session,
    client_events: *std.ArrayList(null3.session.Event),
    server_events: *std.ArrayList(null3.session.Event),
    now_us: *u64,
) !void {
    var pkt: [2048]u8 = undefined;

    try client.tick(now_us.*);
    try server.tick(now_us.*);

    if (try client.poll(&pkt, now_us.*)) |n| try server.handle(pkt[0..n], null, now_us.*);
    if (try server.poll(&pkt, now_us.*)) |n| try client.handle(pkt[0..n], null, now_us.*);

    try server_h3.drain(server_events);
    try client_h3.drain(client_events);

    now_us.* += 1_000;
}

test "HTTP/3 SETTINGS frame round-trip" {
    const s: null3.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 1 << 20,
        .h3_datagram = true,
    };
    var buf: [128]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{ .settings = s });
    const d = try null3.frame.decode(buf[0..n]);
    try std.testing.expectEqual(n, d.bytes_read);
    switch (d.frame) {
        .settings => |got| {
            try std.testing.expectEqual(@as(u64, 4096), got.qpack_max_table_capacity);
            try std.testing.expectEqual(@as(u64, 8), got.qpack_blocked_streams);
            try std.testing.expectEqual(@as(?u64, 1 << 20), got.max_field_section_size);
            try std.testing.expect(got.h3_datagram);
        },
        else => return error.TestExpectedEqual,
    }
}

test "literal QPACK field section validates as request headers" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "user-agent", .value = "null3-test" },
    };
    var block: [512]u8 = undefined;
    const n = try null3.qpack.encodeLiteralFieldSection(&block, &fields);
    const decoded = try null3.qpack.decodeLiteralFieldSection(std.testing.allocator, block[0..n]);
    defer std.testing.allocator.free(decoded);

    try null3.headers.validateRequest(decoded);
    try std.testing.expectEqual(fields.len, decoded.len);
    try std.testing.expectEqualStrings("example.com", decoded[3].value);
}

test "static QPACK field section uses indexed representation" {
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/search" },
    };
    var block: [128]u8 = undefined;
    var literal_block: [128]u8 = undefined;
    const n = try null3.qpack.encodeFieldSection(&block, &fields);
    const literal_n = try null3.qpack.encodeLiteralFieldSection(&literal_block, &fields);
    try std.testing.expect(n < literal_n);

    const decoded = try null3.qpack.decodeFieldSection(std.testing.allocator, block[0..n]);
    defer std.testing.allocator.free(decoded);
    try null3.headers.validateRequest(decoded);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("/search", decoded[2].value);
}

test "PRIORITY_UPDATE request frame round-trip" {
    var buf: [64]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=3, i",
        },
    });
    const d = try null3.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqualStrings("u=3, i", p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "priority parser and stream frame validator" {
    const p = try null3.Priority.parse("u=1, i");
    try std.testing.expectEqual(@as(u3, 1), p.urgency);
    try std.testing.expect(p.incremental);

    var validator = null3.stream.FrameValidator.init(.control);
    try validator.observe(null3.protocol.FrameType.settings);
    try validator.observe(null3.protocol.FrameType.priority_update_request);
    try std.testing.expectError(
        null3.stream.FrameValidationError.FrameUnexpected,
        validator.observe(null3.protocol.FrameType.headers),
    );
}

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

test "client and server facades classify session events" {
    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const response_fields = [_]null3.FieldLine{
        .{ .name = ":status", .value = "204" },
    };

    const request_headers: null3.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .request,
        .fields = @constCast(&request_fields),
    } };
    try std.testing.expect(null3.client.ResponseEvent.from(request_headers) == null);
    switch (null3.server.RequestEvent.from(request_headers).?) {
        .headers => |headers| {
            try std.testing.expectEqual(@as(u64, 0), headers.stream_id);
            try std.testing.expectEqualStrings("GET", headers.fields[0].value);
        },
        else => return error.TestExpectedEqual,
    }

    const response_headers: null3.session.Event = .{ .headers = .{
        .stream_id = 0,
        .kind = .response,
        .fields = @constCast(&response_fields),
    } };
    try std.testing.expect(null3.server.RequestEvent.from(response_headers) == null);
    switch (null3.client.ResponseEvent.from(response_headers).?) {
        .headers => |headers| try std.testing.expectEqualStrings("204", headers.fields[0].value),
        else => return error.TestExpectedEqual,
    }

    const request_data: null3.session.Event = .{ .data = .{
        .stream_id = 0,
        .kind = .request,
        .data = @constCast("body"),
    } };
    switch (null3.server.RequestEvent.from(request_data).?) {
        .data => |data| try std.testing.expectEqualStrings("body", data.bytes),
        else => return error.TestExpectedEqual,
    }

    const rejected: null3.session.Event = .{ .request_rejected = .{
        .stream_id = 4,
        .error_code = null3.protocol.ErrorCode.request_rejected,
    } };
    switch (null3.server.RequestEvent.from(rejected).?) {
        .rejected => |event| {
            try std.testing.expectEqual(@as(u64, 4), event.stream_id);
            try std.testing.expectEqual(null3.protocol.ErrorCode.request_rejected, event.error_code);
        },
        else => return error.TestExpectedEqual,
    }
}

test "request tracker owns server request lifecycle" {
    const allocator = std.testing.allocator;
    var tracker = null3.RequestTracker.init(allocator);
    defer tracker.deinit();

    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/tracked" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const trailers = [_]null3.FieldLine{
        .{ .name = "x-checksum", .value = "ok" },
    };

    _ = try tracker.observe(.{ .headers = .{
        .stream_id = 0,
        .fields = @constCast(&request_fields),
    } });
    _ = try tracker.observe(.{ .data = .{
        .stream_id = 0,
        .bytes = "hello",
    } });
    _ = try tracker.observe(.{ .trailers = .{
        .stream_id = 0,
        .fields = @constCast(&trailers),
    } });
    const state = (try tracker.observe(.{ .finished = .{ .stream_id = 0 } })).?;

    try std.testing.expectEqual(@as(u64, 0), state.stream_id);
    try std.testing.expectEqualStrings("/tracked", state.headerFields()[2].value);
    try std.testing.expectEqualStrings("hello", state.bodyBytes());
    try std.testing.expectEqualStrings("ok", state.trailerFields()[0].value);
    try std.testing.expect(state.complete);

    const removed = tracker.remove(0).?;
    defer {
        removed.deinit(allocator);
        allocator.destroy(removed);
    }
    try std.testing.expect(tracker.get(0) == null);
}

test "session exchanges HTTP/3 request and response over nullq streams" {
    const allocator = std.testing.allocator;

    var server_tls = try null3.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try null3.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(&client, &server);
    try std.testing.expectEqualStrings("h3", client.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("h3", server.inner.alpnSelected().?);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    var client_h3 = null3.Session.init(allocator, .client, &client, .{
        .settings = .{ .max_field_section_size = 1 << 20 },
        .max_field_section_size = 1 << 20,
    });
    defer client_h3.deinit();
    var server_h3 = null3.Session.init(allocator, .server, &server, .{
        .settings = .{ .max_field_section_size = 1 << 20 },
        .max_field_section_size = 1 << 20,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = null3.Client.init(&client_h3);
    var h3_server = null3.Server.init(&server_h3);
    var request_tracker = null3.RequestTracker.init(allocator);
    defer request_tracker.deinit();

    const request_headers = [_]null3.FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    const request = try h3_client.request(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/echo",
        .headers = &request_headers,
        .body = "ping",
    });
    const request_stream_id = request.stream_id;

    var client_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(null3.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var client_saw_settings = false;
    var server_saw_settings = false;
    var server_saw_request_headers = false;
    var server_saw_request_body = false;
    var server_saw_request_finish = false;
    var response_sent = false;
    var client_saw_response_headers = false;
    var client_saw_response_body = false;
    var client_saw_response_finish = false;
    var client_saw_goaway = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (!client_saw_response_finish or !client_saw_goaway) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    server_saw_settings = true;
                    try std.testing.expectEqual(@as(?u64, 1 << 20), settings.max_field_section_size);
                },
                else => {
                    const request_state = (try request_tracker.observe(request_event)) orelse continue;
                    try std.testing.expectEqual(request_stream_id, request_state.stream_id);
                    if (request_state.headers != null) {
                        server_saw_request_headers = true;
                        try std.testing.expectEqualStrings("POST", request_state.headerFields()[0].value);
                        try std.testing.expectEqualStrings("/echo", request_state.headerFields()[2].value);
                    }
                    if (request_state.bodyBytes().len > 0) {
                        server_saw_request_body = true;
                        try std.testing.expectEqualStrings("ping", request_state.bodyBytes());
                    }
                    if (request_state.complete) server_saw_request_finish = true;
                },
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (!response_sent and server_saw_request_headers and server_saw_request_body and server_saw_request_finish) {
            const response_fields = [_]null3.FieldLine{
                .{ .name = "content-type", .value = "text/plain" },
            };
            _ = try h3_server.respond(allocator, request_stream_id, .{
                .status = "200",
                .headers = &response_fields,
                .body = "pong",
            });
            try h3_server.goaway(request_stream_id + 4);
            response_sent = true;
        }

        for (client_events.items) |event| {
            const response_event = h3_client.classify(event) orelse continue;
            switch (response_event) {
                .settings => |settings| {
                    client_saw_settings = true;
                    try std.testing.expectEqual(@as(?u64, 1 << 20), settings.max_field_section_size);
                },
                .headers => |headers| {
                    client_saw_response_headers = true;
                    try std.testing.expectEqual(request_stream_id, headers.stream_id);
                    try std.testing.expectEqualStrings("200", headers.fields[0].value);
                },
                .data => |data| {
                    client_saw_response_body = true;
                    try std.testing.expectEqualStrings("pong", data.bytes);
                },
                .finished => |finished| {
                    try std.testing.expectEqual(request_stream_id, finished.stream_id);
                    client_saw_response_finish = true;
                },
                .goaway => |id| {
                    client_saw_goaway = true;
                    try std.testing.expectEqual(request_stream_id + 4, id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &client_events);
    }

    try std.testing.expect(client_saw_settings);
    try std.testing.expect(server_saw_settings);
    try std.testing.expect(server_saw_request_headers);
    try std.testing.expect(server_saw_request_body);
    try std.testing.expect(server_saw_request_finish);
    try std.testing.expect(response_sent);
    try std.testing.expect(client_saw_response_headers);
    try std.testing.expect(client_saw_response_body);
    try std.testing.expect(client_saw_response_finish);
    try std.testing.expect(client_saw_goaway);
    try std.testing.expectEqual(null3.session.ShutdownState.draining, client_h3.shutdownState());
    try std.testing.expectEqual(null3.session.ShutdownState.draining, server_h3.shutdownState());

    try std.testing.expectError(
        null3.session.Error.RequestBlockedByGoaway,
        h3_client.request(allocator, .{
            .method = "POST",
            .authority = "localhost",
            .path = "/echo",
            .headers = &request_headers,
        }),
    );

    const ignored_stream_id = request_stream_id + 4;
    _ = try client.openBidi(ignored_stream_id);
    var ignored_encoder = null3.MessageEncoder.init(.request, .{});
    const ignored_request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var ignored_bytes: [512]u8 = undefined;
    var ignored_len: usize = 0;
    ignored_len += try ignored_encoder.encodeHeaders(ignored_bytes[ignored_len..], &ignored_request_fields);
    ignored_len += try ignored_encoder.encodeData(ignored_bytes[ignored_len..], "late");
    _ = try client.streamWrite(ignored_stream_id, ignored_bytes[0..ignored_len]);
    try client.streamFinish(ignored_stream_id);

    var server_saw_rejection = false;
    iters = 0;
    while (!server_saw_rejection) : (iters += 1) {
        try std.testing.expect(iters < 20_000);
        try pumpH3(
            &client,
            &server,
            &client_h3,
            &server_h3,
            &client_events,
            &server_events,
            &now_us,
        );

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .rejected => |rejected| {
                    server_saw_rejection = true;
                    try std.testing.expectEqual(ignored_stream_id, rejected.stream_id);
                    try std.testing.expectEqual(null3.protocol.ErrorCode.request_rejected, rejected.error_code);
                },
                .headers => |headers| {
                    try std.testing.expect(headers.stream_id != ignored_stream_id);
                },
                else => {},
            }
        }
        clearSessionEvents(allocator, &server_events);
        clearSessionEvents(allocator, &client_events);
    }
}
