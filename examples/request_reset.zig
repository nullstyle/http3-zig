const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x52, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x00, 0x02 };
const ServerCid = [_]u8{ 0x52, 0x73, 0x74, 0x53, 0x72, 0x76, 0x00, 0x02 };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var cert_buf: [64 * 1024]u8 = undefined;
    var key_buf: [64 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    var client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
    defer client_tls.deinit();
    var server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
    defer server_tls.deinit();

    var client_quic = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client_quic.deinit();
    var server_quic = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server_quic.deinit();

    try connectQuic(&client_quic, &server_quic);

    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, .{});
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, .{});
    defer server_h3.deinit();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);

    var writer = try client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/reset-me",
    });
    const request_stream_id = writer.stream_id;
    try writer.write("partial body");

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (server_quic.stream(request_stream_id) == null) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;
        _ = try driver.step(&packet);
        http3_zig.clearEvents(allocator, &server_events);
        http3_zig.clearEvents(allocator, &client_events);
    }

    try writer.reset(http3_zig.protocol.ErrorCode.request_cancelled);

    steps = 0;
    while (true) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;
        _ = try driver.step(&packet);

        for (server_events.items) |event| {
            const request_event = server.classify(event) orelse continue;
            switch (request_event) {
                .reset => |reset| {
                    if (reset.stream_id != request_stream_id) continue;
                    if (reset.error_code != http3_zig.protocol.ErrorCode.request_cancelled) {
                        return error.UnexpectedResetCode;
                    }
                    if (reset.final_size == 0) return error.MissingFinalSize;

                    const info = reset.errorInfo();
                    if (info.source != .peer) return error.UnexpectedResetSource;
                    if (info.application.category != .request) return error.UnexpectedResetCategory;

                    std.debug.print(
                        "reset_stream={d}\nreset_code={s}\ncategory={s}\nfinal_size={d}\n",
                        .{
                            reset.stream_id,
                            info.application.name,
                            @tagName(info.application.category),
                            reset.final_size,
                        },
                    );
                    return;
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            }
        }
        http3_zig.clearEvents(allocator, &server_events);
        http3_zig.clearEvents(allocator, &client_events);
    }
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    if (!client.handshakeDone() or !server.handshakeDone()) return error.HandshakeTimedOut;

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);
}
