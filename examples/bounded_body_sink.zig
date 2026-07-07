const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x42, 0x6f, 0x64, 0x79, 0x43, 0x6c, 0x69, 0x00 };
const ServerCid = [_]u8{ 0x42, 0x6f, 0x64, 0x79, 0x53, 0x72, 0x76, 0x00 };

const response_chunks = [_][]const u8{
    "alpha\n",
    "bravo\n",
    "charlie\n",
    "delta\n",
    "echo\n",
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

    const session_config = http3_zig.SessionConfig.production(.{
        .max_data_frame_payload = 8,
        .max_event_payload_size = 1024,
        .max_event_payload_bytes_per_drain = 256,
        .max_events_per_drain = 32,
    });
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, session_config);
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, session_config);
    defer server_h3.deinit();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);

    const request = try client.request(allocator, .{
        .authority = "localhost",
        .path = "/stream",
    });

    var client_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &client_events);
        client_events.deinit(allocator);
    }
    var server_events: std.ArrayList(http3_zig.Event) = .empty;
    defer {
        http3_zig.clearEvents(allocator, &server_events);
        server_events.deinit(allocator);
    }

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var response = StreamingResponse{};
    var sink = BodySink{ .limit = 128 };
    var status = Status{};

    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (!sink.finished) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        _ = try driver.step(&packet);

        try observeServerEvents(server_events.items, &server, allocator, request.stream_id, &response);
        http3_zig.clearEvents(allocator, &server_events);

        try response.pump();

        try observeClientEvents(client_events.items, request.stream_id, &status, &sink);
        http3_zig.clearEvents(allocator, &client_events);
    }

    if (!status.ok()) return error.UnexpectedStatus;

    std.debug.print(
        "status={s}\nchunks={d}\nbytes={d}\npreview={s}",
        .{ status.slice(), sink.chunks, sink.received, sink.previewSlice() },
    );
}

const StreamingResponse = struct {
    writer: ?http3_zig.server.ResponseWriter = null,
    next_chunk: usize = 0,
    finished: bool = false,

    fn start(
        self: *StreamingResponse,
        server: *http3_zig.Server,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) !void {
        if (self.writer != null) return;
        self.writer = try server.startResponse(allocator, stream_id, .{
            .status = "200",
            .headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
    }

    fn pump(self: *StreamingResponse) !void {
        if (self.writer) |*writer| {
            while (self.next_chunk < response_chunks.len) {
                const chunk = response_chunks[self.next_chunk];
                if (!try writer.canWrite(chunk.len)) return;
                try writer.write(chunk);
                self.next_chunk += 1;
            }
            if (!self.finished) {
                try writer.finish();
                self.finished = true;
            }
        }
    }
};

const BodySink = struct {
    limit: usize,
    received: usize = 0,
    chunks: usize = 0,
    finished: bool = false,
    preview: [64]u8 = undefined,
    preview_len: usize = 0,

    fn write(self: *BodySink, bytes: []const u8) !void {
        if (bytes.len > self.limit - self.received) return error.BodyBudgetExceeded;
        self.received += bytes.len;
        self.chunks += 1;

        const space = self.preview.len - self.preview_len;
        const take = @min(space, bytes.len);
        @memcpy(self.preview[self.preview_len..][0..take], bytes[0..take]);
        self.preview_len += take;
    }

    fn finish(self: *BodySink) void {
        self.finished = true;
    }

    fn previewSlice(self: *const BodySink) []const u8 {
        return self.preview[0..self.preview_len];
    }
};

const Status = struct {
    bytes: [3]u8 = undefined,
    len: usize = 0,

    fn set(self: *Status, value: []const u8) !void {
        if (value.len > self.bytes.len) return error.StatusTooLong;
        @memcpy(self.bytes[0..value.len], value);
        self.len = value.len;
    }

    fn ok(self: *const Status) bool {
        return std.mem.eql(u8, self.slice(), "200");
    }

    fn slice(self: *const Status) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn observeServerEvents(
    events: []const http3_zig.Event,
    server: *http3_zig.Server,
    allocator: std.mem.Allocator,
    request_stream_id: u64,
    response: *StreamingResponse,
) !void {
    for (events) |event| {
        const request_event = http3_zig.RequestEvent.from(event) orelse continue;
        switch (request_event) {
            .headers => |headers| {
                if (headers.stream_id != request_stream_id) continue;
                const path = fieldValue(headers.fields, ":path") orelse return error.MissingPath;
                if (!std.mem.eql(u8, path, "/stream")) return error.UnexpectedPath;
                try response.start(server, allocator, headers.stream_id);
            },
            .data => |data| if (data.stream_id == request_stream_id and data.bytes.len != 0) {
                return error.UnexpectedRequestBody;
            },
            .reset => |reset| if (reset.stream_id == request_stream_id) return error.RequestReset,
            .connection_closed => return error.ConnectionClosed,
            else => {},
        }
    }
}

fn observeClientEvents(
    events: []const http3_zig.Event,
    request_stream_id: u64,
    status: *Status,
    sink: *BodySink,
) !void {
    for (events) |event| {
        const response_event = http3_zig.ResponseEvent.from(event) orelse continue;
        switch (response_event) {
            .headers => |headers| {
                if (headers.stream_id != request_stream_id) continue;
                try status.set(fieldValue(headers.fields, ":status") orelse return error.MissingStatus);
            },
            .data => |data| {
                if (data.stream_id == request_stream_id) try sink.write(data.bytes);
            },
            .finished => |finished| {
                if (finished.stream_id == request_stream_id) sink.finish();
            },
            .reset => |reset| if (reset.stream_id == request_stream_id) return error.ResponseReset,
            .connection_closed => return error.ConnectionClosed,
            else => {},
        }
    }
}

fn fieldValue(fields: []const http3_zig.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
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
