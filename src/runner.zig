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
    /// Count of `ClientObservation.interim_headers` events seen
    /// in the batch (RFC 9110 §15.2 1xx responses preceding the
    /// final response).
    interim_headers: usize = 0,
    push_state_updates: usize = 0,
    push_completions: usize = 0,
    datagrams: usize = 0,
    datagram_acks: usize = 0,
    datagram_losses: usize = 0,
    flow_blocked: usize = 0,
    connection_id_replenishments: usize = 0,
    cancel_pushes: usize = 0,
    priority_updates: usize = 0,
    goaways: usize = 0,
    connection_closes: usize = 0,
    ignored_unknown_frames: usize = 0,
    state_updates: usize = 0,
    completions: usize = 0,
    webtransport_streams_opened: usize = 0,
    webtransport_stream_data: usize = 0,
    webtransport_streams_finished: usize = 0,
    webtransport_streams_reset: usize = 0,
    webtransport_flow_violations: usize = 0,

    pub fn madeProgress(self: BatchStats) bool {
        return self.observed != 0 or
            self.ignored != 0 or
            self.settings != 0 or
            self.interim_headers != 0 or
            self.push_state_updates != 0 or
            self.push_completions != 0 or
            self.datagrams != 0 or
            self.datagram_acks != 0 or
            self.datagram_losses != 0 or
            self.flow_blocked != 0 or
            self.connection_id_replenishments != 0 or
            self.cancel_pushes != 0 or
            self.priority_updates != 0 or
            self.goaways != 0 or
            self.connection_closes != 0 or
            self.ignored_unknown_frames != 0 or
            self.state_updates != 0 or
            self.completions != 0 or
            self.webtransport_streams_opened != 0 or
            self.webtransport_stream_data != 0 or
            self.webtransport_streams_finished != 0 or
            self.webtransport_streams_reset != 0 or
            self.webtransport_flow_violations != 0;
    }

    pub fn accumulate(self: *BatchStats, other: BatchStats) void {
        self.observed += other.observed;
        self.ignored += other.ignored;
        self.settings += other.settings;
        self.interim_headers += other.interim_headers;
        self.push_state_updates += other.push_state_updates;
        self.push_completions += other.push_completions;
        self.datagrams += other.datagrams;
        self.datagram_acks += other.datagram_acks;
        self.datagram_losses += other.datagram_losses;
        self.flow_blocked += other.flow_blocked;
        self.connection_id_replenishments += other.connection_id_replenishments;
        self.cancel_pushes += other.cancel_pushes;
        self.priority_updates += other.priority_updates;
        self.goaways += other.goaways;
        self.connection_closes += other.connection_closes;
        self.ignored_unknown_frames += other.ignored_unknown_frames;
        self.state_updates += other.state_updates;
        self.completions += other.completions;
        self.webtransport_streams_opened += other.webtransport_streams_opened;
        self.webtransport_stream_data += other.webtransport_stream_data;
        self.webtransport_streams_finished += other.webtransport_streams_finished;
        self.webtransport_streams_reset += other.webtransport_streams_reset;
        self.webtransport_flow_violations += other.webtransport_flow_violations;
    }
};

pub const ClientObservation = union(enum) {
    ignored,
    settings: settings_mod.Settings,
    /// 1xx informational response (RFC 9110 §15.2). Surfaced before
    /// the final `response_updated` / `response_complete`. The
    /// fields slice borrows from the source event — copy if you
    /// need to outlive the next drain.
    interim_headers: client_mod.Headers,
    response_updated: *client_mod.ResponseState,
    response_complete: *client_mod.ResponseState,
    pushed_response_updated: *client_mod.PushedResponseState,
    pushed_response_complete: *client_mod.PushedResponseState,
    datagram: client_mod.Datagram,
    datagram_acked: client_mod.DatagramSend,
    datagram_lost: client_mod.DatagramSend,
    flow_blocked: client_mod.FlowBlocked,
    connection_ids_needed: client_mod.ConnectionIdsNeeded,
    cancel_push: session_mod.CancelPushEvent,
    goaway: u64,
    connection_closed: client_mod.ConnectionClosed,
    ignored_unknown_frame: client_mod.UnknownFrame,
    webtransport_stream_opened: session_mod.WebTransportStreamOpenedEvent,
    webtransport_stream_data: session_mod.WebTransportStreamDataEvent,
    webtransport_stream_finished: session_mod.WebTransportStreamFinishedEvent,
    webtransport_stream_reset: session_mod.WebTransportStreamResetEvent,
    webtransport_flow_violated: session_mod.WebTransportFlowViolationEvent,
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
    connection_ids_needed: server_mod.ConnectionIdsNeeded,
    cancel_push: session_mod.CancelPushEvent,
    priority_update: session_mod.PriorityUpdateEvent,
    goaway: u64,
    connection_closed: server_mod.ConnectionClosed,
    ignored_unknown_frame: server_mod.UnknownFrame,
    webtransport_stream_opened: session_mod.WebTransportStreamOpenedEvent,
    webtransport_stream_data: session_mod.WebTransportStreamDataEvent,
    webtransport_stream_finished: session_mod.WebTransportStreamFinishedEvent,
    webtransport_stream_reset: session_mod.WebTransportStreamResetEvent,
    webtransport_flow_violated: session_mod.WebTransportFlowViolationEvent,
};

test "BatchStats reports progress and accumulates runner counters" {
    try std.testing.expect(!(BatchStats{}).madeProgress());

    var total = BatchStats{
        .observed = 1,
        .ignored = 2,
        .settings = 3,
        .interim_headers = 4,
        .push_state_updates = 5,
        .push_completions = 6,
        .datagrams = 7,
        .datagram_acks = 8,
        .datagram_losses = 9,
        .flow_blocked = 10,
        .connection_id_replenishments = 11,
        .cancel_pushes = 12,
        .priority_updates = 13,
        .goaways = 14,
        .connection_closes = 15,
        .ignored_unknown_frames = 16,
        .state_updates = 17,
        .completions = 18,
        .webtransport_streams_opened = 19,
        .webtransport_stream_data = 20,
        .webtransport_streams_finished = 21,
        .webtransport_streams_reset = 22,
        .webtransport_flow_violations = 23,
    };

    try std.testing.expect(total.madeProgress());

    total.accumulate(.{
        .observed = 10,
        .ignored = 20,
        .settings = 30,
        .interim_headers = 40,
        .push_state_updates = 50,
        .push_completions = 60,
        .datagrams = 70,
        .datagram_acks = 80,
        .datagram_losses = 90,
        .flow_blocked = 100,
        .connection_id_replenishments = 110,
        .cancel_pushes = 120,
        .priority_updates = 130,
        .goaways = 140,
        .connection_closes = 150,
        .ignored_unknown_frames = 160,
        .state_updates = 170,
        .completions = 180,
        .webtransport_streams_opened = 190,
        .webtransport_stream_data = 200,
        .webtransport_streams_finished = 210,
        .webtransport_streams_reset = 220,
        .webtransport_flow_violations = 230,
    });

    try std.testing.expectEqual(@as(usize, 11), total.observed);
    try std.testing.expectEqual(@as(usize, 22), total.ignored);
    try std.testing.expectEqual(@as(usize, 33), total.settings);
    try std.testing.expectEqual(@as(usize, 44), total.interim_headers);
    try std.testing.expectEqual(@as(usize, 55), total.push_state_updates);
    try std.testing.expectEqual(@as(usize, 66), total.push_completions);
    try std.testing.expectEqual(@as(usize, 77), total.datagrams);
    try std.testing.expectEqual(@as(usize, 88), total.datagram_acks);
    try std.testing.expectEqual(@as(usize, 99), total.datagram_losses);
    try std.testing.expectEqual(@as(usize, 110), total.flow_blocked);
    try std.testing.expectEqual(@as(usize, 121), total.connection_id_replenishments);
    try std.testing.expectEqual(@as(usize, 132), total.cancel_pushes);
    try std.testing.expectEqual(@as(usize, 143), total.priority_updates);
    try std.testing.expectEqual(@as(usize, 154), total.goaways);
    try std.testing.expectEqual(@as(usize, 165), total.connection_closes);
    try std.testing.expectEqual(@as(usize, 176), total.ignored_unknown_frames);
    try std.testing.expectEqual(@as(usize, 187), total.state_updates);
    try std.testing.expectEqual(@as(usize, 198), total.completions);
    try std.testing.expectEqual(@as(usize, 209), total.webtransport_streams_opened);
    try std.testing.expectEqual(@as(usize, 220), total.webtransport_stream_data);
    try std.testing.expectEqual(@as(usize, 231), total.webtransport_streams_finished);
    try std.testing.expectEqual(@as(usize, 242), total.webtransport_streams_reset);
    try std.testing.expectEqual(@as(usize, 253), total.webtransport_flow_violations);
}

pub const ClientRunnerConfig = struct {
    response_tracker: client_mod.ResponseTrackerConfig = .{},
    pushed_response_tracker: client_mod.PushedResponseTrackerConfig = .{},
};

pub const ServerRunnerConfig = struct {
    request_tracker: server_mod.RequestTrackerConfig = .{},
};

pub const ClientRunner = struct {
    tracker: client_mod.ResponseTracker,
    push_tracker: client_mod.PushedResponseTracker,
    peer_settings: ?settings_mod.Settings = null,
    last_goaway: ?u64 = null,
    connection_closed_seen: bool = false,

    pub fn init(allocator: std.mem.Allocator) ClientRunner {
        return .{
            .tracker = client_mod.ResponseTracker.init(allocator),
            .push_tracker = client_mod.PushedResponseTracker.init(allocator),
        };
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: ClientRunnerConfig) ClientRunner {
        return .{
            .tracker = client_mod.ResponseTracker.initWithConfig(allocator, config.response_tracker),
            .push_tracker = client_mod.PushedResponseTracker.initWithConfig(allocator, config.pushed_response_tracker),
        };
    }

    pub fn deinit(self: *ClientRunner) void {
        self.tracker.deinit();
        self.push_tracker.deinit();
    }

    pub fn getResponse(self: *const ClientRunner, stream_id: u64) ?*client_mod.ResponseState {
        return self.tracker.get(stream_id);
    }

    pub fn getPushedResponse(self: *const ClientRunner, push_id: u64) ?*client_mod.PushedResponseState {
        return self.push_tracker.get(push_id);
    }

    pub fn getPushedResponseByStream(self: *const ClientRunner, stream_id: u64) ?*client_mod.PushedResponseState {
        return self.push_tracker.getByStream(stream_id);
    }

    pub fn observe(
        self: *ClientRunner,
        event: session_mod.Event,
    ) client_mod.ResponseTrackerError!ClientObservation {
        const response_event = client_mod.ResponseEvent.from(event) orelse return .ignored;
        return self.observeResponseEvent(response_event);
    }

    pub fn observeResponseEvent(
        self: *ClientRunner,
        event: client_mod.ResponseEvent,
    ) client_mod.ResponseTrackerError!ClientObservation {
        switch (event) {
            .settings => |settings| {
                self.peer_settings = settings;
                return .{ .settings = settings };
            },
            .datagram => |datagram| return .{ .datagram = datagram },
            .datagram_acked => |acked| return .{ .datagram_acked = acked },
            .datagram_lost => |lost| return .{ .datagram_lost = lost },
            .flow_blocked => |blocked| return .{ .flow_blocked = blocked },
            .connection_ids_needed => |needed| return .{ .connection_ids_needed = needed },
            .cancel_push => |cancel| {
                _ = try self.push_tracker.observe(event);
                return .{ .cancel_push = cancel };
            },
            .goaway => |id| {
                self.last_goaway = id;
                return .{ .goaway = id };
            },
            .connection_closed => |closed| {
                self.connection_closed_seen = true;
                return .{ .connection_closed = closed };
            },
            .ignored_unknown_frame => |unknown| return .{ .ignored_unknown_frame = unknown },
            .interim_headers => |interim| return .{ .interim_headers = interim },
            .headers, .data, .trailers, .push_promise => {
                const response = (try self.tracker.observe(event)) orelse return .ignored;
                _ = try self.push_tracker.observe(event);
                return .{ .response_updated = response };
            },
            .finished, .reset => {
                const response = (try self.tracker.observe(event)) orelse return .ignored;
                return .{ .response_complete = response };
            },
            .push_stream,
            .push_headers,
            .push_data,
            .push_trailers,
            => {
                const pushed = (try self.push_tracker.observe(event)) orelse return .ignored;
                return .{ .pushed_response_updated = pushed };
            },
            .push_finished,
            .push_reset,
            => {
                const pushed = (try self.push_tracker.observe(event)) orelse return .ignored;
                return .{ .pushed_response_complete = pushed };
            },
            .webtransport_stream_opened => |opened| return .{ .webtransport_stream_opened = opened },
            .webtransport_stream_data => |data| return .{ .webtransport_stream_data = data },
            .webtransport_stream_finished => |finished| return .{ .webtransport_stream_finished = finished },
            .webtransport_stream_reset => |reset| return .{ .webtransport_stream_reset = reset },
            .webtransport_flow_violated => |v| return .{ .webtransport_flow_violated = v },
        }
    }

    pub fn observeBatch(
        self: *ClientRunner,
        events: []const session_mod.Event,
        completed: ?*std.ArrayList(*client_mod.ResponseState),
    ) client_mod.ResponseTrackerError!BatchStats {
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

    pub fn initWithConfig(allocator: std.mem.Allocator, config: ServerRunnerConfig) ServerRunner {
        return .{ .tracker = server_mod.RequestTracker.initWithConfig(allocator, config.request_tracker) };
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
    ) server_mod.RequestTrackerError!ServerObservation {
        const request_event = server_mod.RequestEvent.from(event) orelse return .ignored;
        return self.observeRequestEvent(request_event);
    }

    pub fn observeRequestEvent(
        self: *ServerRunner,
        event: server_mod.RequestEvent,
    ) server_mod.RequestTrackerError!ServerObservation {
        switch (event) {
            .settings => |settings| {
                self.peer_settings = settings;
                return .{ .settings = settings };
            },
            .datagram => |datagram| return .{ .datagram = datagram },
            .datagram_acked => |acked| return .{ .datagram_acked = acked },
            .datagram_lost => |lost| return .{ .datagram_lost = lost },
            .flow_blocked => |blocked| return .{ .flow_blocked = blocked },
            .connection_ids_needed => |needed| return .{ .connection_ids_needed = needed },
            .cancel_push => |cancel| return .{ .cancel_push = cancel },
            .priority_update => |update| return .{ .priority_update = update },
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
            .webtransport_stream_opened => |opened| return .{ .webtransport_stream_opened = opened },
            .webtransport_stream_data => |data| return .{ .webtransport_stream_data = data },
            .webtransport_stream_finished => |finished| return .{ .webtransport_stream_finished = finished },
            .webtransport_stream_reset => |reset| return .{ .webtransport_stream_reset = reset },
            .webtransport_flow_violated => |v| return .{ .webtransport_flow_violated = v },
        }
    }

    pub fn observeBatch(
        self: *ServerRunner,
        events: []const session_mod.Event,
        completed: ?*std.ArrayList(*server_mod.RequestState),
    ) server_mod.RequestTrackerError!BatchStats {
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
        .interim_headers => stats.interim_headers += 1,
        .response_updated => stats.state_updates += 1,
        .response_complete => |response| {
            stats.completions += 1;
            if (completed) |out| try out.append(allocator, response);
        },
        .pushed_response_updated => stats.push_state_updates += 1,
        .pushed_response_complete => stats.push_completions += 1,
        .datagram => stats.datagrams += 1,
        .datagram_acked => stats.datagram_acks += 1,
        .datagram_lost => stats.datagram_losses += 1,
        .flow_blocked => stats.flow_blocked += 1,
        .connection_ids_needed => stats.connection_id_replenishments += 1,
        .cancel_push => stats.cancel_pushes += 1,
        .goaway => stats.goaways += 1,
        .connection_closed => stats.connection_closes += 1,
        .ignored_unknown_frame => stats.ignored_unknown_frames += 1,
        .webtransport_stream_opened => stats.webtransport_streams_opened += 1,
        .webtransport_stream_data => stats.webtransport_stream_data += 1,
        .webtransport_stream_finished => stats.webtransport_streams_finished += 1,
        .webtransport_stream_reset => stats.webtransport_streams_reset += 1,
        .webtransport_flow_violated => stats.webtransport_flow_violations += 1,
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
        .connection_ids_needed => stats.connection_id_replenishments += 1,
        .cancel_push => stats.cancel_pushes += 1,
        .priority_update => stats.priority_updates += 1,
        .goaway => stats.goaways += 1,
        .connection_closed => stats.connection_closes += 1,
        .ignored_unknown_frame => stats.ignored_unknown_frames += 1,
        .webtransport_stream_opened => stats.webtransport_streams_opened += 1,
        .webtransport_stream_data => stats.webtransport_stream_data += 1,
        .webtransport_stream_finished => stats.webtransport_streams_finished += 1,
        .webtransport_stream_reset => stats.webtransport_streams_reset += 1,
        .webtransport_flow_violated => stats.webtransport_flow_violations += 1,
    }
}
