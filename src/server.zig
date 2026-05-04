//! HTTP/3 server-side helpers.

const std = @import("std");
const boringssl = @import("boringssl");
const errors_mod = @import("errors.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");

pub const TlsOptions = struct {
    verify: boringssl.tls.VerifyMode = .none,
    early_data_enabled: bool = false,
};

pub fn initTlsContext(
    options: TlsOptions,
    cert_chain_pem: []const u8,
    private_key_pem: []const u8,
) boringssl.tls.Error!boringssl.tls.Context {
    var ctx = try boringssl.tls.Context.initServer(.{
        .verify = options.verify,
        .min_version = @intCast(boringssl.raw.TLS1_3_VERSION),
        .alpn = &protocol.alpn_protocols,
        .early_data_enabled = options.early_data_enabled,
    });
    errdefer ctx.deinit();
    try ctx.loadCertChainAndKey(cert_chain_pem, private_key_pem);
    return ctx;
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

    pub fn errorInfo(self: StreamReset) errors_mod.StreamError {
        return errors_mod.peerStreamError(self.stream_id, self.error_code, self.final_size);
    }
};

pub const RequestRejected = session_mod.RequestRejectedEvent;
pub const UnknownFrame = session_mod.UnknownFrameEvent;

pub const ResponseOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    body: ?[]const u8 = null,
    trailers: []const qpack.FieldLine = &.{},
    end_stream: bool = true,
};

pub const ResponseHeadOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
};

pub const Response = struct {
    stream_id: u64,
};

pub const ResponseWriter = struct {
    server: *Server,
    stream_id: u64,

    pub fn write(self: *ResponseWriter, data: []const u8) session_mod.Error!void {
        if (data.len > 0) try self.server.sendData(self.stream_id, data);
    }

    pub fn trailers(self: *ResponseWriter, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.server.sendTrailers(self.stream_id, fields);
    }

    pub fn finish(self: *ResponseWriter) session_mod.Error!void {
        try self.server.finish(self.stream_id);
    }
};

pub const RequestReader = struct {
    request: *const RequestState,

    pub fn streamId(self: RequestReader) u64 {
        return self.request.stream_id;
    }

    pub fn headers(self: RequestReader) []const qpack.FieldLine {
        return self.request.headerFields();
    }

    pub fn trailers(self: RequestReader) []const qpack.FieldLine {
        return self.request.trailerFields();
    }

    pub fn body(self: RequestReader) []const u8 {
        return self.request.bodyBytes();
    }

    pub fn method(self: RequestReader) ?[]const u8 {
        return self.request.method();
    }

    pub fn scheme(self: RequestReader) ?[]const u8 {
        return self.request.scheme();
    }

    pub fn authority(self: RequestReader) ?[]const u8 {
        return self.request.authority();
    }

    pub fn path(self: RequestReader) ?[]const u8 {
        return self.request.path();
    }

    pub fn complete(self: RequestReader) bool {
        return self.request.complete;
    }

    pub fn reset(self: RequestReader) ?StreamReset {
        return self.request.reset;
    }

    pub fn rejected(self: RequestReader) ?RequestRejected {
        return self.request.rejected;
    }
};

/// Server-facing view over `session.Event`.
///
/// Slices borrow from the source event. Callers should finish consuming the
/// returned value before deinitializing or clearing the underlying event list.
pub const RequestEvent = union(enum) {
    settings: settings_mod.Settings,
    headers: Headers,
    data: Data,
    trailers: Headers,
    finished: StreamFinished,
    reset: StreamReset,
    rejected: RequestRejected,
    goaway: u64,
    ignored_unknown_frame: UnknownFrame,

    pub fn from(event: session_mod.Event) ?RequestEvent {
        return switch (event) {
            .peer_settings => |settings| .{ .settings = settings },
            .headers => |headers| if (headers.kind == .request) .{
                .headers = .{ .stream_id = headers.stream_id, .fields = headers.fields },
            } else null,
            .data => |data| if (data.kind == .request) .{
                .data = .{ .stream_id = data.stream_id, .bytes = data.data },
            } else null,
            .trailers => |trailers| if (trailers.kind == .request) .{
                .trailers = .{ .stream_id = trailers.stream_id, .fields = trailers.fields },
            } else null,
            .stream_finished => |finished| if (finished.kind != null and finished.kind.? == .request) .{
                .finished = .{ .stream_id = finished.stream_id },
            } else null,
            .stream_reset => |reset| if (reset.kind != null and reset.kind.? == .request) .{
                .reset = .{
                    .stream_id = reset.stream_id,
                    .error_code = reset.error_code,
                    .final_size = reset.final_size,
                },
            } else null,
            .request_rejected => |rejected| .{ .rejected = rejected },
            .goaway => |id| .{ .goaway = id },
            .ignored_unknown_frame => |unknown| .{ .ignored_unknown_frame = unknown },
            .push_promise => null,
        };
    }
};

pub const Server = struct {
    session: *session_mod.Session,

    pub fn init(session: *session_mod.Session) Server {
        return .{ .session = session };
    }

    pub fn sendHeaders(self: *Server, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendResponseHeaders(stream_id, fields);
    }

    pub fn sendData(self: *Server, stream_id: u64, data: []const u8) session_mod.Error!void {
        try self.session.sendResponseData(stream_id, data);
    }

    pub fn sendTrailers(self: *Server, stream_id: u64, fields: []const qpack.FieldLine) session_mod.Error!void {
        try self.session.sendResponseTrailers(stream_id, fields);
    }

    pub fn finish(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.session.finishStream(stream_id);
    }

    pub fn reject(self: *Server, stream_id: u64) session_mod.Error!void {
        try self.session.rejectRequest(stream_id);
    }

    pub fn goaway(self: *Server, id: u64) session_mod.Error!void {
        try self.session.sendGoaway(id);
    }

    pub fn respond(
        self: *Server,
        allocator: std.mem.Allocator,
        stream_id: u64,
        options: ResponseOptions,
    ) session_mod.Error!Response {
        var writer = try self.startResponse(allocator, stream_id, .{
            .status = options.status,
            .headers = options.headers,
        });

        if (options.body) |body| {
            try writer.write(body);
        }
        if (options.trailers.len > 0) try writer.trailers(options.trailers);
        if (options.end_stream) try writer.finish();

        return .{ .stream_id = stream_id };
    }

    pub fn startResponse(
        self: *Server,
        allocator: std.mem.Allocator,
        stream_id: u64,
        options: ResponseHeadOptions,
    ) session_mod.Error!ResponseWriter {
        const fields = try buildResponseFields(allocator, options);
        defer allocator.free(fields);
        try self.sendHeaders(stream_id, fields);
        return .{
            .server = self,
            .stream_id = stream_id,
        };
    }

    pub fn classify(self: *const Server, event: session_mod.Event) ?RequestEvent {
        _ = self;
        return RequestEvent.from(event);
    }
};

pub const RequestState = struct {
    stream_id: u64,
    headers: ?[]qpack.FieldLine = null,
    body: std.ArrayList(u8) = .empty,
    trailers: ?[]qpack.FieldLine = null,
    complete: bool = false,
    reset: ?StreamReset = null,
    rejected: ?RequestRejected = null,

    pub fn deinit(self: *RequestState, allocator: std.mem.Allocator) void {
        if (self.headers) |fields| freeFields(allocator, fields);
        if (self.trailers) |fields| freeFields(allocator, fields);
        self.body.deinit(allocator);
    }

    pub fn reader(self: *const RequestState) RequestReader {
        return .{ .request = self };
    }

    pub fn headerFields(self: *const RequestState) []const qpack.FieldLine {
        return self.headers orelse &.{};
    }

    pub fn trailerFields(self: *const RequestState) []const qpack.FieldLine {
        return self.trailers orelse &.{};
    }

    pub fn bodyBytes(self: *const RequestState) []const u8 {
        return self.body.items;
    }

    pub fn method(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":method");
    }

    pub fn scheme(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":scheme");
    }

    pub fn authority(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":authority");
    }

    pub fn path(self: *const RequestState) ?[]const u8 {
        return fieldValue(self.headerFields(), ":path");
    }

    fn setHeaders(
        self: *RequestState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.headers) |old| freeFields(allocator, old);
        self.headers = copy;
    }

    fn setTrailers(
        self: *RequestState,
        allocator: std.mem.Allocator,
        fields: []const qpack.FieldLine,
    ) std.mem.Allocator.Error!void {
        const copy = try cloneFields(allocator, fields);
        if (self.trailers) |old| freeFields(allocator, old);
        self.trailers = copy;
    }
};

pub const RequestTracker = struct {
    allocator: std.mem.Allocator,
    requests: std.AutoHashMapUnmanaged(u64, *RequestState) = .empty,

    pub fn init(allocator: std.mem.Allocator) RequestTracker {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RequestTracker) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            const request = entry.value_ptr.*;
            request.deinit(self.allocator);
            self.allocator.destroy(request);
        }
        self.requests.deinit(self.allocator);
    }

    pub fn get(self: *const RequestTracker, stream_id: u64) ?*RequestState {
        return self.requests.get(stream_id);
    }

    pub fn remove(self: *RequestTracker, stream_id: u64) ?*RequestState {
        const entry = self.requests.fetchRemove(stream_id) orelse return null;
        return entry.value;
    }

    pub fn observe(
        self: *RequestTracker,
        event: RequestEvent,
    ) std.mem.Allocator.Error!?*RequestState {
        switch (event) {
            .headers => |headers| {
                const request = try self.ensure(headers.stream_id);
                try request.setHeaders(self.allocator, headers.fields);
                return request;
            },
            .data => |data| {
                const request = try self.ensure(data.stream_id);
                try request.body.appendSlice(self.allocator, data.bytes);
                return request;
            },
            .trailers => |trailers| {
                const request = try self.ensure(trailers.stream_id);
                try request.setTrailers(self.allocator, trailers.fields);
                return request;
            },
            .finished => |finished| {
                const request = try self.ensure(finished.stream_id);
                request.complete = true;
                return request;
            },
            .reset => |reset| {
                const request = try self.ensure(reset.stream_id);
                request.reset = reset;
                request.complete = true;
                return request;
            },
            .rejected => |rejected| {
                const request = try self.ensure(rejected.stream_id);
                request.rejected = rejected;
                request.complete = true;
                return request;
            },
            .settings, .goaway, .ignored_unknown_frame => return null,
        }
    }

    fn ensure(self: *RequestTracker, stream_id: u64) std.mem.Allocator.Error!*RequestState {
        if (self.requests.get(stream_id)) |request| return request;

        const request = try self.allocator.create(RequestState);
        errdefer self.allocator.destroy(request);
        request.* = .{ .stream_id = stream_id };
        try self.requests.put(self.allocator, stream_id, request);
        return request;
    }
};

fn buildResponseFields(
    allocator: std.mem.Allocator,
    options: ResponseHeadOptions,
) session_mod.Error![]qpack.FieldLine {
    const fields = try allocator.alloc(qpack.FieldLine, 1 + options.headers.len);
    fields[0] = .{ .name = ":status", .value = options.status };
    for (options.headers, 0..) |header, i| fields[1 + i] = header;
    return fields;
}

fn cloneFields(
    allocator: std.mem.Allocator,
    fields: []const qpack.FieldLine,
) std.mem.Allocator.Error![]qpack.FieldLine {
    const out = try allocator.alloc(qpack.FieldLine, fields.len);
    var initialized: usize = 0;
    errdefer {
        freeFields(allocator, out[0..initialized]);
        allocator.free(out);
    }

    for (fields) |field| {
        const name = try allocator.dupe(u8, field.name);
        const value = allocator.dupe(u8, field.value) catch |err| {
            allocator.free(name);
            return err;
        };
        out[initialized] = .{
            .name = name,
            .value = value,
            .sensitive = field.sensitive,
        };
        initialized += 1;
    }

    return out;
}

fn freeFields(allocator: std.mem.Allocator, fields: []qpack.FieldLine) void {
    for (fields) |field| {
        allocator.free(@constCast(field.name));
        allocator.free(@constCast(field.value));
    }
    allocator.free(fields);
}

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
