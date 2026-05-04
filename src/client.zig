//! HTTP/3 client-side helpers.

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

    pub fn classify(self: *const Client, event: session_mod.Event) ?ResponseEvent {
        _ = self;
        return ResponseEvent.from(event);
    }
};
