//! HTTP/3 server-side helpers.

const boringssl = @import("boringssl");
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
};

pub const RequestRejected = session_mod.RequestRejectedEvent;
pub const UnknownFrame = session_mod.UnknownFrameEvent;

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

    pub fn classify(self: *const Server, event: session_mod.Event) ?RequestEvent {
        _ = self;
        return RequestEvent.from(event);
    }
};
