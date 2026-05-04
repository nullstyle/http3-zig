//! HTTP/3 client-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");

pub const TlsOptions = struct {
    verify: boringssl.tls.VerifyMode = .system,
    early_data_enabled: bool = false,
};

pub fn initTlsContext(options: TlsOptions) boringssl.tls.Error!boringssl.tls.Context {
    return boringssl.tls.Context.initClient(.{
        .verify = options.verify,
        .min_version = @intCast(boringssl.raw.TLS1_3_VERSION),
        .alpn = &protocol.alpn_protocols,
        .early_data_enabled = options.early_data_enabled,
    });
}

pub const Headers = struct {
    stream_id: u64,
    fields: []qpack.FieldLine,
};

pub const Data = struct {
    stream_id: u64,
    bytes: []const u8,
};

pub const StreamFinished = struct {
    stream_id: u64,
};

pub const StreamReset = struct {
    stream_id: u64,
    error_code: u64,
    final_size: u64,
};

pub const UnknownFrame = session_mod.UnknownFrameEvent;

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    headers: []const qpack.FieldLine = &.{},
    body: ?[]const u8 = null,
    trailers: []const qpack.FieldLine = &.{},
    end_stream: bool = true,
};

pub const RequestHeadOptions = struct {
    method: []const u8 = "GET",
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    path: []const u8 = "/",
    headers: []const qpack.FieldLine = &.{},
};

pub const Request = struct {
    stream_id: u64,
};

pub const RequestWriter = struct {
    client: *Client,
    stream_id: u64,

    pub fn write(self: *RequestWriter, data: []const u8) session_mod.Error!void {
        if (data.len > 0) try self.client.sendData(self.stream_id, data);
    }

    pub fn trailers(self: *RequestWriter, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.client.sendTrailers(self.stream_id, fields);
    }

    pub fn finish(self: *RequestWriter) session_mod.Error!void {
        try self.client.finish(self.stream_id);
    }

    pub fn cancel(self: *RequestWriter) session_mod.Error!void {
        try self.client.cancel(self.stream_id);
    }
};

/// Client-facing view over `session.Event`.
///
/// Slices borrow from the source event. Callers should finish consuming the
/// returned value before deinitializing or clearing the underlying event list.
pub const ResponseEvent = union(enum) {
    settings: settings_mod.Settings,
    headers: Headers,
    data: Data,
    trailers: Headers,
    push_promise: session_mod.PushPromiseEvent,
    finished: StreamFinished,
    reset: StreamReset,
    goaway: u64,
    ignored_unknown_frame: UnknownFrame,

    pub fn from(event: session_mod.Event) ?ResponseEvent {
        return switch (event) {
            .peer_settings => |settings| .{ .settings = settings },
            .headers => |headers| if (headers.kind == .response) .{
                .headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else null,
            .data => |data| if (data.kind == .response) .{
                .data = .{ .stream_id = data.stream_id, .bytes = data.data },
            } else null,
            .trailers => |trailers| if (trailers.kind == .response) .{
                .trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else null,
            .push_promise => |promise| .{ .push_promise = promise },
            .stream_finished => |finished| if (finished.kind != null and finished.kind.? == .response) .{
                .finished = .{ .stream_id = finished.stream_id },
            } else null,
            .stream_reset => |reset| if (reset.kind != null and reset.kind.? == .response) .{
                .reset = .{
                    .stream_id = reset.stream_id,
                    .error_code = reset.error_code,
                    .final_size = reset.final_size,
                },
            } else null,
            .goaway => |id| .{ .goaway = id },
            .ignored_unknown_frame => |unknown| .{ .ignored_unknown_frame = unknown },
            .request_rejected => null,
        };
    }
};

pub const Client = struct {
    session: *session_mod.Session,

    pub fn init(session: *session_mod.Session) Client {
        return .{ .session = session };
    }

    pub fn open(self: *Client, fields: []const qpack.FieldLine) session_mod.Error!u64 {
        return try self.session.openRequest(fields);
    }

    pub fn sendData(self: *Client, stream_id: u64, data: []const u8) session_mod.Error!void {
        try self.session.sendRequestData(stream_id, data);
    }

    pub fn sendTrailers(self: *Client, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendRequestTrailers(stream_id, fields);
    }

    pub fn finish(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    pub fn cancel(self: *Client, stream_id: u64) session_mod.Error!void {
        try self.session.cancelRequest(stream_id);
    }

    pub fn request(
        self: *Client,
        allocator: std.mem.Allocator,
        options: RequestOptions,
    ) session_mod.Error!Request {
        var writer = try self.startRequest(allocator, .{
            .method = options.method,
            .scheme = options.scheme,
            .authority = options.authority,
            .path = options.path,
            .headers = options.headers,
        });

        if (options.body) |body| {
            try writer.write(body);
        }
        if (options.trailers.len > 0) try writer.trailers(options.trailers);
        if (options.end_stream) try writer.finish();

        return .{ .stream_id = writer.stream_id };
    }

    pub fn startRequest(
        self: *Client,
        allocator: std.mem.Allocator,
        options: RequestHeadOptions,
    ) session_mod.Error!RequestWriter {
        const fields = try buildRequestFields(allocator, options);
        defer allocator.free(fields);
        return .{
            .client = self,
            .stream_id = try self.open(fields),
        };
    }

    pub fn classify(self: *const Client, event: session_mod.Event) ?ResponseEvent {
        _ = self;
        return ResponseEvent.from(event);
    }
};

fn buildRequestFields(
    allocator: std.mem.Allocator,
    options: RequestHeadOptions,
) session_mod.Error![]qpack.FieldLine {
    const fields = try allocator.alloc(qpack.FieldLine, 4 + options.headers.len);
    fields[0] = .{ .name = ":method", .value = options.method };
    fields[1] = .{ .name = ":scheme", .value = options.scheme };
    fields[2] = .{ .name = ":path", .value = options.path };
    fields[3] = .{ .name = ":authority", .value = options.authority };
    for (options.headers, 0..) |header, i| fields[4 + i] = header;
    return fields;
}
