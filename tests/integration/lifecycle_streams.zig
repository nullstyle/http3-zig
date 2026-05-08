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

test "session exchanges HTTP/3 request and response over quic_zig streams" {
    const allocator = std.testing.allocator;

    var server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
    defer server_tls.deinit();
    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();

    var client = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: quic_zig.tls.TransportParams = .{
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

    const h3_settings: http3_zig.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 1 << 20,
    };
    var client_h3 = http3_zig.Session.init(allocator, .client, &client, .{
        .settings = h3_settings,
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 1 << 20,
    });
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server, .{
        .settings = h3_settings,
        .qpack_encoder_table_capacity = 256,
        .qpack_indexing = http3_zig.QpackIndexingPolicy.aggressive,
        .max_field_section_size = 1 << 20,
    });
    defer server_h3.deinit();

    try client_h3.start();
    try server_h3.start();
    var h3_client = http3_zig.Client.init(&client_h3);
    var h3_server = http3_zig.Server.init(&server_h3);
    var request_tracker = http3_zig.RequestTracker.init(allocator);
    defer request_tracker.deinit();
    var response_tracker = http3_zig.ResponseTracker.init(allocator);
    defer response_tracker.deinit();

    const request_headers = [_]http3_zig.FieldLine{
        .{ .name = "content-type", .value = "text/plain" },
    };
    var request_writer = try h3_client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/echo",
        .headers = &request_headers,
    });
    const request_stream_id = request_writer.stream_id;
    try request_writer.write("pi");
    try request_writer.write("ng");
    try request_writer.finish();

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearSessionEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
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
    var client_saw_dynamic_response_header = false;
    var client_saw_response_body = false;
    var client_saw_response_finish = false;
    var client_saw_goaway = false;
    var client_applied_dynamic_qpack = false;
    var server_saw_qpack_ack = false;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (!client_saw_response_finish or !client_saw_goaway or !server_saw_qpack_ack) : (iters += 1) {
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

        if (client_h3.qpack_decoder_table.insert_count > 0) {
            client_applied_dynamic_qpack = true;
        }
        if (server_h3.qpack_encoder_table.insert_count > 0 and
            server_h3.qpack_encoder_state.referenceCount(0) == 0 and
            server_h3.qpack_encoder_state.known_received_count > 0)
        {
            server_saw_qpack_ack = true;
        }

        for (server_events.items) |event| {
            const request_event = h3_server.classify(event) orelse continue;
            switch (request_event) {
                .settings => |settings| {
                    server_saw_settings = true;
                    try std.testing.expectEqual(@as(?u64, 1 << 20), settings.max_field_section_size);
                },
                else => {
                    const request_state = (try request_tracker.observe(request_event)) orelse continue;
                    const request_reader = request_state.reader();
                    try std.testing.expectEqual(request_stream_id, request_state.stream_id);
                    if (request_reader.headers().len > 0) {
                        server_saw_request_headers = true;
                        try std.testing.expectEqualStrings("POST", request_reader.method().?);
                        try std.testing.expectEqualStrings("/echo", request_reader.path().?);
                    }
                    if (request_reader.body().len > 0) {
                        const body = request_reader.body();
                        try std.testing.expect(body.len <= "ping".len);
                        try std.testing.expectEqualStrings("ping"[0..body.len], body);
                        if (std.mem.eql(u8, body, "ping")) server_saw_request_body = true;
                    }
                    if (request_reader.complete()) server_saw_request_finish = true;
                },
            }
        }
        clearSessionEvents(allocator, &server_events);

        if (!response_sent and server_saw_settings and server_saw_request_headers and server_saw_request_body and server_saw_request_finish) {
            const response_fields = [_]http3_zig.FieldLine{
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "x-dyn", .value = "one" },
            };
            var response_writer = try h3_server.startResponse(allocator, request_stream_id, .{
                .status = "200",
                .headers = &response_fields,
            });
            try response_writer.write("po");
            try response_writer.write("ng");
            try response_writer.finish();
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
                .goaway => |id| {
                    client_saw_goaway = true;
                    try std.testing.expectEqual(request_stream_id + 4, id);
                },
                else => {
                    const response_state = (try response_tracker.observe(response_event)) orelse continue;
                    const response_reader = response_state.reader();
                    try std.testing.expectEqual(request_stream_id, response_reader.streamId());
                    if (response_reader.headers().len > 0) {
                        client_saw_response_headers = true;
                        try std.testing.expectEqualStrings("200", response_reader.status().?);
                        for (response_reader.headers()) |field| {
                            if (std.mem.eql(u8, field.name, "x-dyn") and
                                std.mem.eql(u8, field.value, "one"))
                            {
                                client_saw_dynamic_response_header = true;
                            }
                        }
                    }
                    if (response_reader.body().len > 0) {
                        const body = response_reader.body();
                        try std.testing.expect(body.len <= "pong".len);
                        try std.testing.expectEqualStrings("pong"[0..body.len], body);
                        if (std.mem.eql(u8, body, "pong")) client_saw_response_body = true;
                    }
                    if (response_reader.complete()) client_saw_response_finish = true;
                },
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
    try std.testing.expect(client_saw_dynamic_response_header);
    try std.testing.expect(client_saw_response_body);
    try std.testing.expect(client_saw_response_finish);
    try std.testing.expect(client_saw_goaway);
    try std.testing.expect(client_applied_dynamic_qpack);
    try std.testing.expect(server_saw_qpack_ack);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, client_h3.shutdownState());
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, server_h3.shutdownState());

    try std.testing.expectError(
        http3_zig.session.Error.RequestBlockedByGoaway,
        h3_client.request(allocator, .{
            .method = "POST",
            .authority = "localhost",
            .path = "/echo",
            .headers = &request_headers,
        }),
    );

    const ignored_stream_id = request_stream_id + 4;
    _ = try client.openBidi(ignored_stream_id);
    var ignored_encoder = http3_zig.MessageEncoder.init(.request, .{});
    const ignored_request_fields = [_]http3_zig.FieldLine{
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
                    try std.testing.expectEqual(http3_zig.protocol.ErrorCode.request_rejected, rejected.error_code);
                    const info = rejected.errorInfo();
                    try std.testing.expectEqual(http3_zig.ErrorSource.local, info.source);
                    try std.testing.expectEqual(http3_zig.ErrorCategory.request, info.application.category);
                    try std.testing.expectEqual(http3_zig.ErrorScope.stream, info.application.default_scope);
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

