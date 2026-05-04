//! Higher-level event runners over the client/server facades.
//!
//! Runners compose `session.Event` classification with the owned lifecycle
//! trackers. They do not decide application policy; callers still choose how to
//! respond, cancel, close, and clear the underlying event batch.

const std = @import("std");
const client_mod = @import("client.zig");
const server_mod = @import("server.zig");
const session_mod = @import("session.zig");
const settings_mod = @import("settings.zig");

pub const BatchStats = struct {
    observed: usize = 0,
    ignored: usize = 0,
    settings: usize = 0,
    datagrams: usize = 0,
    datagram_acks: usize = 0,
    datagram_losses: usize = 0,
    flow_blocked: usize = 0,
    goaways: usize = 0,
    connection_closes: usize = 0,
    ignored_unknown_frames: usize = 0,
    state_updates: usize = 0,
    completions: usize = 0,
};

pub const ClientObservation = union(enum) {
    ignored,
    settings: settings_mod.Settings,
    response_updated: *client_mod.ResponseState,
    response_complete: *client_mod.ResponseState,
    datagram: client_mod.Datagram,
    datagram_acked: client_mod.DatagramSend,
    datagram_lost: client_mod.DatagramSend,
    flow_blocked: client_mod.FlowBlocked,
    goaway: u64,
    connection_closed: client_mod.ConnectionClosed,
    ignored_unknown_frame: client_mod.UnknownFrame,
};

pub const ServerObservation = union(enum) {
    ignored,
    settings: settings_mod.Settings,
    request_updated: *server_mod.RequestState,
    request_complete: *server_mod.RequestState,
    datagram: server_mod.Datagram,
    datagram_acked: server_mod.DatagramSend,
    datagram_lost: server_mod.DatagramSend,
    flow_blocked: server_mod.FlowBlocked,
    goaway: u64,
    connection_closed: server_mod.ConnectionClosed,
    ignored_unknown_frame: server_mod.UnknownFrame,
};

pub const ClientRunner = struct {
    tracker: client_mod.ResponseTracker,
    peer_settings: ?settings_mod.Settings = null,
    last_goaway: ?u64 = null,
    connection_closed_seen: bool = false,

    pub fn init(allocator: std.mem.Allocator) ClientRunner {
        return .{ .tracker = client_mod.ResponseTracker.init(allocator) };
    }

    pub fn deinit(self: *ClientRunner) void {
        self.tracker.deinit();
    }

    pub fn getResponse(self: *const ClientRunner, stream_id: u64) ?*client_mod.ResponseState {
        return self.tracker.get(stream_id);
    }

    pub fn observe(
        self: *ClientRunner,
        event: session_mod.Event,
    ) std.mem.Allocator.Error!ClientObservation {
        const response_event = client_mod.ResponseEvent.from(event) orelse return .ignored;
        return self.observeResponseEvent(response_event);
    }

    pub fn observeResponseEvent(
        self: *ClientRunner,
        event: client_mod.ResponseEvent,
    ) std.mem.Allocator.Error!ClientObservation {
        switch (event) {
            .settings => |settings| {
                self.peer_settings = settings;
                return .{ .settings = settings };
            },
            .datagram => |datagram| return .{ .datagram = datagram },
            .datagram_acked => |acked| return .{ .datagram_acked = acked },
            .datagram_lost => |lost| return .{ .datagram_lost = lost },
            .flow_blocked => |blocked| return .{ .flow_blocked = blocked },
            .goaway => |id| {
                self.last_goaway = id;
                return .{ .goaway = id };
            },
            .connection_closed => |closed| {
                self.connection_closed_seen = true;
                return .{ .connection_closed = closed };
            },
            .ignored_unknown_frame => |unknown| return .{ .ignored_unknown_frame = unknown },
            .headers, .data, .trailers, .push_promise => {
                const response = (try self.tracker.observe(event)) orelse return .ignored;
                return .{ .response_updated = response };
            },
            .finished, .reset => {
                const response = (try self.tracker.observe(event)) orelse return .ignored;
                return .{ .response_complete = response };
            },
        }
    }

    pub fn observeBatch(
        self: *ClientRunner,
        events: []const session_mod.Event,
        completed: ?*std.ArrayList(*client_mod.ResponseState),
    ) std.mem.Allocator.Error!BatchStats {
        var stats: BatchStats = .{};
        for (events) |event| {
            try noteClientObservation(try self.observe(event), self.tracker.allocator, &stats, completed);
        }
        return stats;
    }
};

pub const ServerRunner = struct {
    tracker: server_mod.RequestTracker,
    peer_settings: ?settings_mod.Settings = null,
    last_goaway: ?u64 = null,
    connection_closed_seen: bool = false,

    pub fn init(allocator: std.mem.Allocator) ServerRunner {
        return .{ .tracker = server_mod.RequestTracker.init(allocator) };
    }

    pub fn deinit(self: *ServerRunner) void {
        self.tracker.deinit();
    }

    pub fn getRequest(self: *const ServerRunner, stream_id: u64) ?*server_mod.RequestState {
        return self.tracker.get(stream_id);
    }

    pub fn observe(
        self: *ServerRunner,
        event: session_mod.Event,
    ) std.mem.Allocator.Error!ServerObservation {
        const request_event = server_mod.RequestEvent.from(event) orelse return .ignored;
        return self.observeRequestEvent(request_event);
    }

    pub fn observeRequestEvent(
        self: *ServerRunner,
        event: server_mod.RequestEvent,
    ) std.mem.Allocator.Error!ServerObservation {
        switch (event) {
            .settings => |settings| {
                self.peer_settings = settings;
                return .{ .settings = settings };
            },
            .datagram => |datagram| return .{ .datagram = datagram },
            .datagram_acked => |acked| return .{ .datagram_acked = acked },
            .datagram_lost => |lost| return .{ .datagram_lost = lost },
            .flow_blocked => |blocked| return .{ .flow_blocked = blocked },
            .goaway => |id| {
                self.last_goaway = id;
                return .{ .goaway = id };
            },
            .connection_closed => |closed| {
                self.connection_closed_seen = true;
                return .{ .connection_closed = closed };
            },
            .ignored_unknown_frame => |unknown| return .{ .ignored_unknown_frame = unknown },
            .headers, .data, .trailers => {
                const request_state = (try self.tracker.observe(event)) orelse return .ignored;
                return .{ .request_updated = request_state };
            },
            .finished, .reset, .rejected => {
                const request_state = (try self.tracker.observe(event)) orelse return .ignored;
                return .{ .request_complete = request_state };
            },
        }
    }

    pub fn observeBatch(
        self: *ServerRunner,
        events: []const session_mod.Event,
        completed: ?*std.ArrayList(*server_mod.RequestState),
    ) std.mem.Allocator.Error!BatchStats {
        var stats: BatchStats = .{};
        for (events) |event| {
            try noteServerObservation(try self.observe(event), self.tracker.allocator, &stats, completed);
        }
        return stats;
    }
};

fn noteClientObservation(
    observation: ClientObservation,
    allocator: std.mem.Allocator,
    stats: *BatchStats,
    completed: ?*std.ArrayList(*client_mod.ResponseState),
) std.mem.Allocator.Error!void {
    stats.observed += 1;
    switch (observation) {
        .ignored => stats.ignored += 1,
        .settings => stats.settings += 1,
        .response_updated => stats.state_updates += 1,
        .response_complete => |response| {
            stats.completions += 1;
            if (completed) |out| try out.append(allocator, response);
        },
        .datagram => stats.datagrams += 1,
        .datagram_acked => stats.datagram_acks += 1,
        .datagram_lost => stats.datagram_losses += 1,
        .flow_blocked => stats.flow_blocked += 1,
        .goaway => stats.goaways += 1,
        .connection_closed => stats.connection_closes += 1,
        .ignored_unknown_frame => stats.ignored_unknown_frames += 1,
    }
}

fn noteServerObservation(
    observation: ServerObservation,
    allocator: std.mem.Allocator,
    stats: *BatchStats,
    completed: ?*std.ArrayList(*server_mod.RequestState),
) std.mem.Allocator.Error!void {
    stats.observed += 1;
    switch (observation) {
        .ignored => stats.ignored += 1,
        .settings => stats.settings += 1,
        .request_updated => stats.state_updates += 1,
        .request_complete => |request| {
            stats.completions += 1;
            if (completed) |out| try out.append(allocator, request);
        },
        .datagram => stats.datagrams += 1,
        .datagram_acked => stats.datagram_acks += 1,
        .datagram_lost => stats.datagram_losses += 1,
        .flow_blocked => stats.flow_blocked += 1,
        .goaway => stats.goaways += 1,
        .connection_closed => stats.connection_closes += 1,
        .ignored_unknown_frame => stats.ignored_unknown_frames += 1,
    }
}
