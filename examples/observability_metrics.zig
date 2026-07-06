const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x4f, 0x62, 0x73, 0x43, 0x6c, 0x69, 0x00, 0x01 };
const ServerCid = [_]u8{ 0x4f, 0x62, 0x73, 0x53, 0x72, 0x76, 0x00, 0x01 };

const TraceRecorder = struct {
    events: [64]http3_zig.TraceEvent = undefined,
    count: usize = 0,

    fn callback(user_data: ?*anyopaque, event: http3_zig.TraceEvent) void {
        const self: *TraceRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count < self.events.len) {
            self.events[self.count] = event;
            self.count += 1;
        }
    }

    fn countNamed(self: *const TraceRecorder, name: http3_zig.TraceEventName) usize {
        var total: usize = 0;
        for (self.events[0..self.count]) |event| {
            if (event.name == name) total += 1;
        }
        return total;
    }
};

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

    const session_config = http3_zig.SessionConfig.production(.{});
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, session_config);
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, session_config);
    defer server_h3.deinit();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);
    var client_traces: TraceRecorder = .{};
    var server_traces: TraceRecorder = .{};
    client.setObservabilityHooks(.{
        .callback = TraceRecorder.callback,
        .user_data = &client_traces,
    });
    server.setObservabilityHooks(.{
        .callback = TraceRecorder.callback,
        .user_data = &server_traces,
    });

    var client_runner = http3_zig.ClientRunner.init(allocator);
    defer client_runner.deinit();
    var server_runner = http3_zig.ServerRunner.init(allocator);
    defer server_runner.deinit();

    const request = try client.request(allocator, .{
        .authority = "localhost",
        .path = "/observability",
    });

    var client_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.session.Event) = .empty;
    defer {
        clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }
    var completed_responses: std.ArrayList(*http3_zig.ResponseState) = .empty;
    defer completed_responses.deinit(allocator);

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var response_sent = false;
    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (completed_responses.items.len == 0) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        _ = try driver.step(&packet);

        for (server_events.items) |event| {
            switch (try server_runner.observe(event)) {
                .request_complete => |incoming| {
                    if (!response_sent and incoming.stream_id == request.stream_id) {
                        const reader = incoming.reader();
                        if (!std.mem.eql(u8, reader.path() orelse "", "/observability")) {
                            return error.UnexpectedPath;
                        }
                        _ = try server.respond(allocator, incoming.stream_id, .{
                            .status = "200",
                            .body = "observed\n",
                        });
                        response_sent = true;
                    }
                },
                .connection_closed => return error.ServerConnectionClosed,
                else => {},
            }
        }
        clearEvents(allocator, &server_events);

        _ = try client_runner.observeBatch(client_events.items, &completed_responses);
        clearEvents(allocator, &client_events);
    }

    const response = completed_responses.items[0].reader();
    if (!std.mem.eql(u8, response.status() orelse "", "200")) return error.UnexpectedStatus;
    if (!std.mem.eql(u8, response.body(), "observed\n")) return error.UnexpectedBody;

    const client_metrics = client.metrics();
    const server_metrics = server.metrics();
    if (client_metrics.headers_sent == 0) return error.MissingClientHeadersSentMetric;
    if (client_metrics.headers_received == 0) return error.MissingClientHeadersReceivedMetric;
    if (client_metrics.data_bytes_received != "observed\n".len) return error.UnexpectedClientDataMetric;
    if (server_metrics.headers_received == 0) return error.MissingServerHeadersReceivedMetric;
    if (server_metrics.headers_sent == 0) return error.MissingServerHeadersSentMetric;
    if (server_metrics.data_bytes_sent != "observed\n".len) return error.UnexpectedServerDataMetric;

    const client_headers_received = client_traces.countNamed(.headers_received);
    const client_data_received = client_traces.countNamed(.data_received);
    const server_headers_received = server_traces.countNamed(.headers_received);
    if (client_headers_received == 0) return error.MissingClientHeadersTrace;
    if (client_data_received == 0) return error.MissingClientDataTrace;
    if (server_headers_received == 0) return error.MissingServerHeadersTrace;

    std.debug.print(
        "status={s}\nclient_data_bytes_received={d}\nserver_data_bytes_sent={d}\nclient_traces={d}\nserver_traces={d}\n",
        .{
            response.status() orelse "",
            client_metrics.data_bytes_received,
            server_metrics.data_bytes_sent,
            client_traces.count,
            server_traces.count,
        },
    );
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

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
