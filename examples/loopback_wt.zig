//! In-process WebTransport-over-HTTP/3 loopback example.
//!
//! Sister to `examples/loopback_get.zig`. Stands up a client and server
//! `http3_zig.Session` over a single-process `quic_zig.Connection` pair,
//! negotiates WebTransport via SETTINGS, opens an Extended CONNECT, and
//! exchanges a datagram in each direction plus a unidirectional WT
//! stream from the client. The client then sends
//! `CLOSE_WEBTRANSPORT_SESSION` and finishes the CONNECT stream.
//!
//! The point is to demonstrate the public API surface end-to-end so a
//! reader can follow the WebTransport flow without touching the test
//! fixtures (those are deliberately kept private to the test runner).

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

const datagram_to_server = "ping";
const datagram_to_client = "pong";
const uni_payload = "hello-from-client";
const close_code: u32 = 0xdeadbeef;
const close_reason = "shutdown";

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
    std.debug.print("step 1: QUIC handshake complete\n", .{});

    const wt_settings: http3_zig.Settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .wt_enabled = true,
    };
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, .{ .settings = wt_settings });
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, .{ .settings = wt_settings });
    defer server_h3.deinit();
    try client_h3.start();
    try server_h3.start();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);
    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    var client_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        client_h3.clearEvents(&client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        server_h3.clearEvents(&server_events);
        server_events.deinit(allocator);
    }

    // Step 2: drive both sides until SETTINGS have been exchanged so we
    // know both peers see the WebTransport-capable peer settings before
    // we open the CONNECT.
    var packet: [4096]u8 = undefined;
    var now_us: u64 = 1_000_000;
    {
        var iters: u32 = 0;
        while (client_h3.peer_settings == null or server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.SettingsExchangeTimedOut;
            try pump(&client_quic, &server_quic, &client_h3, &server_h3, &client_events, &server_events, &now_us, &packet);
            server_h3.clearEvents(&server_events);
            client_h3.clearEvents(&client_events);
        }
    }
    if (!http3_zig.webtransport.peerEnabled(client_h3.peer_settings.?)) return error.PeerDidNotEnableWebTransport;
    if (!http3_zig.webtransport.peerEnabled(server_h3.peer_settings.?)) return error.PeerDidNotEnableWebTransport;
    std.debug.print("step 2: SETTINGS exchanged, both peers WebTransport-capable\n", .{});

    // Step 3: client opens an Extended CONNECT for WebTransport.
    var client_wt = try client.startWebTransport(allocator, .{
        .authority = "localhost",
        .path = "/wt",
    });
    const session_id = client_wt.sessionId();
    std.debug.print("step 3: client opened WebTransport CONNECT (session_id={d})\n", .{session_id});

    var server_wt: ?http3_zig.WebTransportServerStream = null;
    var client_saw_response = false;
    var server_saw_datagram = false;
    var client_saw_datagram = false;
    var server_saw_uni_data: std.ArrayList(u8) = .empty;
    defer server_saw_uni_data.deinit(allocator);
    var server_saw_uni_finish = false;
    var server_saw_close = false;
    var client_uni_id: ?u64 = null;

    var iters: u32 = 0;
    while (!server_saw_close) : (iters += 1) {
        if (iters >= 20_000) return error.ExampleTimedOut;
        try pump(&client_quic, &server_quic, &client_h3, &server_h3, &client_events, &server_events, &now_us, &packet);

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (server_wt == null and request.headers().len > 0 and request.isWebTransport()) {
                        var accepted = try server.acceptWebTransport(allocator, request, .{});
                        std.debug.print("step 4: server accepted WebTransport CONNECT\n", .{});
                        try accepted.sendDatagram(datagram_to_client);
                        std.debug.print("step 5a: server sent datagram \"{s}\"\n", .{datagram_to_client});
                        server_wt = accepted;
                    }
                    // The CONNECT stream's body carries the
                    // CLOSE_WEBTRANSPORT_SESSION capsule once the
                    // client tears the session down.
                    if (server_wt != null and !server_saw_close and request.body().len > 0) {
                        var it = http3_zig.capsule.iter(request.body());
                        while (try it.next()) |decoded| {
                            const wt_event = try http3_zig.webtransport.classifyCapsule(decoded.capsule);
                            switch (wt_event) {
                                .close_session => |close| {
                                    std.debug.print(
                                        "step 7: server saw CLOSE_WEBTRANSPORT_SESSION (code=0x{x}, reason=\"{s}\")\n",
                                        .{ close.code, close.reason },
                                    );
                                    server_saw_close = true;
                                },
                                else => {},
                            }
                        }
                    }
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == session_id and !server_saw_datagram) {
                        std.debug.print(
                            "step 5b: server received datagram \"{s}\"\n",
                            .{datagram.payload},
                        );
                        server_saw_datagram = true;
                    }
                },
                else => {},
            }
            switch (event) {
                .webtransport_stream_opened => |opened| {
                    if (opened.session_id == session_id) {
                        std.debug.print(
                            "step 6a: server saw client open uni WT stream (id={d})\n",
                            .{opened.stream_id},
                        );
                    }
                },
                .webtransport_stream_data => |data| {
                    if (data.session_id == session_id) {
                        try server_saw_uni_data.appendSlice(allocator, data.data);
                    }
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == session_id) {
                        std.debug.print(
                            "step 6b: server received uni stream payload \"{s}\"\n",
                            .{server_saw_uni_data.items},
                        );
                        server_saw_uni_finish = true;
                    }
                },
                else => {},
            }
        }
        server_h3.clearEvents(&server_events);

        for (client_events.items) |event| {
            switch (try client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (!client_saw_response and response.headers().len > 0 and response.webTransportAccepted()) {
                        std.debug.print(
                            "step 4 (client side): WebTransport accepted (status={s})\n",
                            .{response.status() orelse ""},
                        );
                        client_saw_response = true;

                        // Push our datagram + uni stream now that the
                        // session is confirmed.
                        try client_wt.sendDatagram(datagram_to_server);
                        std.debug.print("step 5c: client sent datagram \"{s}\"\n", .{datagram_to_server});

                        const uni_id = try client_wt.openUniStream();
                        client_uni_id = uni_id;
                        try client_wt.writeStream(uni_id, uni_payload);
                        try client_wt.finishStream(uni_id);
                        std.debug.print(
                            "step 6c: client opened uni WT stream (id={d}) with \"{s}\"\n",
                            .{ uni_id, uni_payload },
                        );
                    }
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == session_id and !client_saw_datagram) {
                        std.debug.print(
                            "step 5d: client received datagram \"{s}\"\n",
                            .{datagram.payload},
                        );
                        client_saw_datagram = true;
                    }
                },
                else => {},
            }
        }
        client_h3.clearEvents(&client_events);

        // Once the round-trip side traffic has landed, send CLOSE.
        if (server_saw_datagram and client_saw_datagram and server_saw_uni_finish and !server_saw_close) {
            // Issue close once. The pump below will deliver it to the
            // server, which will then exit the while loop.
            if (client_uni_id != null) {
                client_uni_id = null;
                try client_wt.close(close_code, close_reason);
                std.debug.print(
                    "step 7 (client side): sent CLOSE_WEBTRANSPORT_SESSION (code=0x{x}, reason=\"{s}\")\n",
                    .{ close_code, close_reason },
                );
            }
        }
    }

    if (!client_saw_response) return error.ClientMissedResponse;
    if (!server_saw_datagram) return error.ServerMissedDatagram;
    if (!client_saw_datagram) return error.ClientMissedDatagram;
    if (!server_saw_uni_finish) return error.ServerMissedUniFinish;
    if (!std.mem.eql(u8, server_saw_uni_data.items, uni_payload)) return error.UniPayloadMismatch;
    if (server_wt == null) return error.ServerMissingHandle;

    std.debug.print("WebTransport loopback example completed successfully\n", .{});
}

fn pump(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    client_h3: *http3_zig.Session,
    server_h3: *http3_zig.Session,
    client_events: *std.ArrayList(http3_zig.Event),
    server_events: *std.ArrayList(http3_zig.Event),
    now_us: *u64,
    packet: []u8,
) !void {
    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(client, client_h3, client_events),
        http3_zig.TransportEndpoint.withSession(server, server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 1,
        },
    );
    _ = try driver.step(packet);
    now_us.* = driver.now_us;
}

fn connectQuic(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    try client.bind();
    try server.bind();
    client.peer = server;
    server.peer = client;

    // WebTransport requires QUIC datagram frames; keep the cap healthy
    // so the loopback can carry our test payloads (RFC 9221).
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
