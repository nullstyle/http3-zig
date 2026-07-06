const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x55, 0x70, 0x6c, 0x64, 0x43, 0x6c, 0x69, 0x00 };
const ServerCid = [_]u8{ 0x55, 0x70, 0x6c, 0x64, 0x53, 0x72, 0x76, 0x00 };

const upload_chunks = [_][]const u8{
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
        .max_stream_send_buffered = 32,
        .max_event_payload_size = 1024,
        .max_event_payload_bytes_per_drain = 1024,
        .max_events_per_drain = 32,
    });
    var client_h3 = http3_zig.Session.init(allocator, .client, &client_quic, session_config);
    defer client_h3.deinit();
    var server_h3 = http3_zig.Session.init(allocator, .server, &server_quic, session_config);
    defer server_h3.deinit();

    var client = http3_zig.Client.init(&client_h3);
    var server = http3_zig.Server.init(&server_h3);

    const request_writer = try client.startRequest(allocator, .{
        .method = "POST",
        .authority = "localhost",
        .path = "/upload",
        .headers = &.{
            .{ .name = "content-type", .value = "text/plain" },
        },
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

    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&client_quic, &client_h3, &client_events),
        http3_zig.TransportEndpoint.withSession(&server_quic, &server_h3, &server_events),
        .{},
    );

    var upload = StreamingUpload{ .writer = request_writer };
    var received = UploadSink{ .limit = 128 };
    var response = ResponseSink{ .limit = 64 };

    var packet: [4096]u8 = undefined;
    var steps: u32 = 0;
    while (!response.finished) : (steps += 1) {
        if (steps >= 20_000) return error.ExampleTimedOut;

        try upload.pump();
        _ = try driver.step(&packet);

        try observeServerEvents(server_events.items, &server, allocator, upload.streamId(), &received);
        clearEvents(allocator, &server_events);

        try observeClientEvents(client_events.items, upload.streamId(), &response);
        clearEvents(allocator, &client_events);
    }

    if (!upload.finished) return error.UploadDidNotFinish;
    if (!received.finished) return error.ServerDidNotFinishRequest;
    if (!response.status.ok()) return error.UnexpectedStatus;

    std.debug.print(
        "upload_chunks={d}\nupload_bytes={d}\nstatus={s}\nresponse={s}",
        .{ received.chunks, received.received, response.status.slice(), response.previewSlice() },
    );
}

const StreamingUpload = struct {
    writer: http3_zig.client.RequestWriter,
    next_chunk: usize = 0,
    finished: bool = false,

    fn streamId(self: *const StreamingUpload) u64 {
        return self.writer.stream_id;
    }

    fn pump(self: *StreamingUpload) !void {
        while (self.next_chunk < upload_chunks.len) {
            const chunk = upload_chunks[self.next_chunk];
            if (!try self.writer.canWrite(chunk.len)) return;
            try self.writer.write(chunk);
            self.next_chunk += 1;
        }
        if (!self.finished) {
            try self.writer.finish();
            self.finished = true;
        }
    }
};

const UploadSink = struct {
    limit: usize,
    received: usize = 0,
    chunks: usize = 0,
    finished: bool = false,
    responded: bool = false,

    fn write(self: *UploadSink, bytes: []const u8) !void {
        if (bytes.len > self.limit - self.received) return error.UploadBudgetExceeded;
        self.received += bytes.len;
        self.chunks += 1;
    }

    fn finish(self: *UploadSink) void {
        self.finished = true;
    }
};

const ResponseSink = struct {
    limit: usize,
    status: Status = .{},
    preview: [64]u8 = undefined,
    preview_len: usize = 0,
    finished: bool = false,

    fn write(self: *ResponseSink, bytes: []const u8) !void {
        if (bytes.len > self.limit - self.preview_len) return error.ResponseBudgetExceeded;
        @memcpy(self.preview[self.preview_len..][0..bytes.len], bytes);
        self.preview_len += bytes.len;
    }

    fn finish(self: *ResponseSink) void {
        self.finished = true;
    }

    fn previewSlice(self: *const ResponseSink) []const u8 {
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
    events: []const http3_zig.session.Event,
    server: *http3_zig.Server,
    allocator: std.mem.Allocator,
    request_stream_id: u64,
    sink: *UploadSink,
) !void {
    for (events) |event| {
        const request_event = http3_zig.server.RequestEvent.from(event) orelse continue;
        switch (request_event) {
            .headers => |headers| {
                if (headers.stream_id != request_stream_id) continue;
                const method = fieldValue(headers.fields, ":method") orelse return error.MissingMethod;
                const path = fieldValue(headers.fields, ":path") orelse return error.MissingPath;
                if (!std.mem.eql(u8, method, "POST")) return error.UnexpectedMethod;
                if (!std.mem.eql(u8, path, "/upload")) return error.UnexpectedPath;
            },
            .data => |data| {
                if (data.stream_id == request_stream_id) try sink.write(data.bytes);
            },
            .finished => |finished| {
                if (finished.stream_id != request_stream_id) continue;
                sink.finish();
                if (!sink.responded) {
                    _ = try server.respond(allocator, finished.stream_id, .{
                        .status = "200",
                        .headers = &.{
                            .{ .name = "content-type", .value = "text/plain" },
                        },
                        .body = "upload accepted\n",
                    });
                    sink.responded = true;
                }
            },
            .reset => |reset| if (reset.stream_id == request_stream_id) return error.RequestReset,
            .connection_closed => return error.ConnectionClosed,
            else => {},
        }
    }
}

fn observeClientEvents(
    events: []const http3_zig.session.Event,
    request_stream_id: u64,
    response: *ResponseSink,
) !void {
    for (events) |event| {
        const response_event = http3_zig.client.ResponseEvent.from(event) orelse continue;
        switch (response_event) {
            .headers => |headers| {
                if (headers.stream_id != request_stream_id) continue;
                try response.status.set(fieldValue(headers.fields, ":status") orelse return error.MissingStatus);
            },
            .data => |data| {
                if (data.stream_id == request_stream_id) try response.write(data.bytes);
            },
            .finished => |finished| {
                if (finished.stream_id == request_stream_id) response.finish();
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

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
