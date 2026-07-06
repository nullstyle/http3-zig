const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixt = @import("_fixtures.zig");

const clearSessionEvents = fixt.clearSessionEvents;
const exchangePairSettings = fixt.exchangePairSettings;
const H3Pair = fixt.H3Pair;
const pumpH3 = fixt.pumpH3;

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

const ForwardingHarness = struct {
    allocator: std.mem.Allocator,

    downstream: H3Pair,
    upstream: H3Pair,
    downstream_started: bool,
    upstream_started: bool,

    downstream_client: http3_zig.Client,
    proxy_in_server: http3_zig.Server,
    proxy_out_client: http3_zig.Client,
    upstream_server: http3_zig.Server,

    downstream_client_wt: http3_zig.WebTransportClientStream,
    proxy_in_wt: http3_zig.WebTransportServerStream,
    proxy_out_wt: http3_zig.WebTransportClientStream,
    upstream_server_wt: http3_zig.WebTransportServerStream,

    downstream_client_runner: http3_zig.ClientRunner,
    downstream_proxy_runner: http3_zig.ServerRunner,
    upstream_proxy_runner: http3_zig.ClientRunner,
    upstream_server_runner: http3_zig.ServerRunner,

    downstream_client_events: std.ArrayList(http3_zig.session.Event),
    downstream_proxy_events: std.ArrayList(http3_zig.session.Event),
    upstream_proxy_events: std.ArrayList(http3_zig.session.Event),
    upstream_server_events: std.ArrayList(http3_zig.session.Event),

    downstream_now_us: u64,
    upstream_now_us: u64,
    downstream_response_cursor: usize,
    upstream_request_cursor: usize,

    pub fn init(self: *ForwardingHarness, allocator: std.mem.Allocator) !void {
        self.* = .{
            .allocator = allocator,
            .downstream = undefined,
            .upstream = undefined,
            .downstream_started = false,
            .upstream_started = false,
            .downstream_client = undefined,
            .proxy_in_server = undefined,
            .proxy_out_client = undefined,
            .upstream_server = undefined,
            .downstream_client_wt = undefined,
            .proxy_in_wt = undefined,
            .proxy_out_wt = undefined,
            .upstream_server_wt = undefined,
            .downstream_client_runner = http3_zig.ClientRunner.init(allocator),
            .downstream_proxy_runner = http3_zig.ServerRunner.init(allocator),
            .upstream_proxy_runner = http3_zig.ClientRunner.init(allocator),
            .upstream_server_runner = http3_zig.ServerRunner.init(allocator),
            .downstream_client_events = .empty,
            .downstream_proxy_events = .empty,
            .upstream_proxy_events = .empty,
            .upstream_server_events = .empty,
            .downstream_now_us = 1_000_000,
            .upstream_now_us = 2_000_000,
            .downstream_response_cursor = 0,
            .upstream_request_cursor = 0,
        };
        errdefer self.deinit();

        try self.downstream.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
        self.downstream_started = true;
        try self.upstream.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
        self.upstream_started = true;

        try exchangePairSettings(allocator, &self.downstream);
        try exchangePairSettings(allocator, &self.upstream);

        self.downstream_client = http3_zig.Client.init(&self.downstream.client_h3);
        self.proxy_in_server = http3_zig.Server.init(&self.downstream.server_h3);
        self.proxy_out_client = http3_zig.Client.init(&self.upstream.client_h3);
        self.upstream_server = http3_zig.Server.init(&self.upstream.server_h3);

        self.downstream_client_wt = try self.downstream_client.startWebTransport(allocator, .{
            .authority = "proxy.local",
            .path = "/wt",
        });
        try self.acceptDownstream();

        self.proxy_out_wt = try self.proxy_out_client.startWebTransport(allocator, .{
            .authority = "upstream.local",
            .path = "/wt",
        });
        try self.acceptUpstream();
    }

    pub fn deinit(self: *ForwardingHarness) void {
        clearSessionEvents(self.allocator, &self.downstream_client_events);
        clearSessionEvents(self.allocator, &self.downstream_proxy_events);
        clearSessionEvents(self.allocator, &self.upstream_proxy_events);
        clearSessionEvents(self.allocator, &self.upstream_server_events);
        self.downstream_client_events.deinit(self.allocator);
        self.downstream_proxy_events.deinit(self.allocator);
        self.upstream_proxy_events.deinit(self.allocator);
        self.upstream_server_events.deinit(self.allocator);

        self.downstream_client_runner.deinit();
        self.downstream_proxy_runner.deinit();
        self.upstream_proxy_runner.deinit();
        self.upstream_server_runner.deinit();

        if (self.upstream_started) self.upstream.deinit();
        if (self.downstream_started) self.downstream.deinit();
    }

    fn pumpDownstream(self: *ForwardingHarness) !void {
        try pumpH3(
            &self.downstream.client,
            &self.downstream.server,
            &self.downstream.client_h3,
            &self.downstream.server_h3,
            &self.downstream_client_events,
            &self.downstream_proxy_events,
            &self.downstream_now_us,
        );
    }

    fn pumpUpstream(self: *ForwardingHarness) !void {
        try pumpH3(
            &self.upstream.client,
            &self.upstream.server,
            &self.upstream.client_h3,
            &self.upstream.server_h3,
            &self.upstream_proxy_events,
            &self.upstream_server_events,
            &self.upstream_now_us,
        );
    }

    fn clearDownstreamEvents(self: *ForwardingHarness) void {
        clearSessionEvents(self.allocator, &self.downstream_client_events);
        clearSessionEvents(self.allocator, &self.downstream_proxy_events);
    }

    fn clearUpstreamEvents(self: *ForwardingHarness) void {
        clearSessionEvents(self.allocator, &self.upstream_proxy_events);
        clearSessionEvents(self.allocator, &self.upstream_server_events);
    }

    fn acceptDownstream(self: *ForwardingHarness) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpDownstream();
            for (self.downstream_proxy_events.items) |event| {
                switch (try self.downstream_proxy_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (request.headers().len > 0 and request.isWebTransport()) {
                            self.proxy_in_wt = try self.proxy_in_server.acceptWebTransport(self.allocator, request, .{});
                            self.clearDownstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearDownstreamEvents();
        }
        return error.ExpectedDownstreamWebTransport;
    }

    fn acceptUpstream(self: *ForwardingHarness) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpUpstream();
            for (self.upstream_server_events.items) |event| {
                switch (try self.upstream_server_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (request.headers().len > 0 and request.isWebTransport()) {
                            self.upstream_server_wt = try self.upstream_server.acceptWebTransport(self.allocator, request, .{});
                            self.clearUpstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearUpstreamEvents();
        }
        return error.ExpectedUpstreamWebTransport;
    }

    fn nextUpstreamServerCapsule(self: *ForwardingHarness) !http3_zig.Capsule {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpUpstream();
            for (self.upstream_server_events.items) |event| {
                switch (try self.upstream_server_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (request.streamId() != self.upstream_server_wt.sessionId()) continue;
                        const body = request.body();
                        if (self.upstream_request_cursor >= body.len) continue;
                        const decoded = try http3_zig.capsule.decode(body[self.upstream_request_cursor..]);
                        self.upstream_request_cursor += decoded.bytes_read;
                        try self.upstream_server_wt.observeCapsule(decoded.capsule);
                        self.clearUpstreamEvents();
                        return decoded.capsule;
                    },
                    else => {},
                }
            }
            self.clearUpstreamEvents();
        }
        return error.ExpectedUpstreamCapsule;
    }

    fn nextDownstreamClientCapsule(self: *ForwardingHarness) !http3_zig.Capsule {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpDownstream();
            for (self.downstream_client_events.items) |event| {
                switch (try self.downstream_client_runner.observe(event)) {
                    .response_updated, .response_complete => |response_state| {
                        const response = response_state.reader();
                        if (response.streamId() != self.downstream_client_wt.sessionId()) continue;
                        const body = response.body();
                        if (self.downstream_response_cursor >= body.len) continue;
                        const decoded = try http3_zig.capsule.decode(body[self.downstream_response_cursor..]);
                        self.downstream_response_cursor += decoded.bytes_read;
                        try self.downstream_client_wt.observeCapsule(decoded.capsule);
                        self.clearDownstreamEvents();
                        return decoded.capsule;
                    },
                    else => {},
                }
            }
            self.clearDownstreamEvents();
        }
        return error.ExpectedDownstreamCapsule;
    }
};

fn varintCapsule(capsule_type: u64, value: u64, storage: *[8]u8) !http3_zig.Capsule {
    const n = try quic_zig.wire.varint.encode(storage[0..], value);
    return .{ .capsule_type = capsule_type, .value = storage[0..n] };
}

fn expectCapsuleEqual(expected: http3_zig.Capsule, actual: http3_zig.Capsule) !void {
    try std.testing.expectEqual(expected.capsule_type, actual.capsule_type);
    try std.testing.expectEqualStrings(expected.value, actual.value);
}

test "WebTransport forwarding helpers carry WT_MAX_DATA across two H3 pairs" {
    const allocator = std.testing.allocator;
    const h = try allocator.create(ForwardingHarness);
    defer allocator.destroy(h);
    try h.init(allocator);
    defer h.deinit();

    var downstream_value: [8]u8 = undefined;
    const downstream_max: u64 = 64 * 1024;
    const downstream_capsule = try varintCapsule(
        http3_zig.webtransport.CapsuleType.max_data,
        downstream_max,
        &downstream_value,
    );
    try h.proxy_in_wt.forwardCapsuleTo(downstream_capsule, &h.proxy_out_wt);

    try std.testing.expectEqual(
        @as(?u64, downstream_max),
        (h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow).peer_max_data,
    );
    const upstream_seen = try h.nextUpstreamServerCapsule();
    try expectCapsuleEqual(downstream_capsule, upstream_seen);
    try std.testing.expectEqual(
        @as(?u64, downstream_max),
        (h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow).peer_max_data,
    );

    var upstream_value: [8]u8 = undefined;
    const upstream_max: u64 = 128 * 1024;
    const upstream_capsule = try varintCapsule(
        http3_zig.webtransport.CapsuleType.max_data,
        upstream_max,
        &upstream_value,
    );
    try h.proxy_out_wt.forwardCapsuleTo(upstream_capsule, &h.proxy_in_wt);

    try std.testing.expectEqual(
        @as(?u64, upstream_max),
        (h.proxy_out_wt.flowState() orelse return error.MissingProxyOutFlow).peer_max_data,
    );
    const downstream_seen = try h.nextDownstreamClientCapsule();
    try expectCapsuleEqual(upstream_capsule, downstream_seen);
    try std.testing.expectEqual(
        @as(?u64, upstream_max),
        (h.downstream_client_wt.flowState() orelse return error.MissingDownstreamFlow).peer_max_data,
    );
}

test "WebTransport forwarding observes BLOCKED capsules without mutating limits" {
    const allocator = std.testing.allocator;
    const h = try allocator.create(ForwardingHarness);
    defer allocator.destroy(h);
    try h.init(allocator);
    defer h.deinit();

    const before = h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow;

    var data_blocked_value: [8]u8 = undefined;
    const data_blocked = try varintCapsule(
        http3_zig.webtransport.CapsuleType.data_blocked,
        4096,
        &data_blocked_value,
    );
    try h.proxy_in_wt.forwardCapsuleTo(data_blocked, &h.proxy_out_wt);

    var streams_bidi_value: [8]u8 = undefined;
    const streams_bidi = try varintCapsule(
        http3_zig.webtransport.CapsuleType.streams_blocked_bidi,
        2,
        &streams_bidi_value,
    );
    try h.proxy_in_wt.forwardCapsuleTo(streams_bidi, &h.proxy_out_wt);

    var streams_uni_value: [8]u8 = undefined;
    const streams_uni = try varintCapsule(
        http3_zig.webtransport.CapsuleType.streams_blocked_uni,
        3,
        &streams_uni_value,
    );
    try h.proxy_in_wt.forwardCapsuleTo(streams_uni, &h.proxy_out_wt);

    const after = h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow;
    try std.testing.expectEqual(before.peer_max_data, after.peer_max_data);
    try std.testing.expectEqual(before.peer_max_streams_bidi, after.peer_max_streams_bidi);
    try std.testing.expectEqual(before.peer_max_streams_uni, after.peer_max_streams_uni);

    const metrics = h.downstream.server_h3.metrics();
    try std.testing.expectEqual(@as(u64, 1), metrics.webtransport_peer_data_blocked);
    try std.testing.expectEqual(@as(u64, 2), metrics.webtransport_peer_streams_blocked);
}

test "WebTransport forwarding preserves DRAIN unknown and CLOSE capsule lifecycle" {
    const allocator = std.testing.allocator;
    const h = try allocator.create(ForwardingHarness);
    defer allocator.destroy(h);
    try h.init(allocator);
    defer h.deinit();

    const drain: http3_zig.Capsule = .{
        .capsule_type = http3_zig.webtransport.CapsuleType.drain_session,
        .value = "",
    };
    try h.proxy_in_wt.forwardCapsuleTo(drain, &h.proxy_out_wt);
    try std.testing.expect((h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow).received_drain);
    try std.testing.expectError(error.WebTransportSessionDraining, h.proxy_in_wt.openUniStream());

    const upstream_drain = try h.nextUpstreamServerCapsule();
    try expectCapsuleEqual(drain, upstream_drain);
    try std.testing.expect((h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow).received_drain);
    try std.testing.expectError(error.WebTransportSessionDraining, h.upstream_server_wt.openUniStream());

    const before_unknown = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;
    const unknown: http3_zig.Capsule = .{ .capsule_type = 0x41, .value = "opaque-forward" };
    try h.proxy_in_wt.forwardCapsuleTo(unknown, &h.proxy_out_wt);
    const upstream_unknown = try h.nextUpstreamServerCapsule();
    try expectCapsuleEqual(unknown, upstream_unknown);
    const after_unknown = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;
    try std.testing.expectEqual(before_unknown.peer_max_data, after_unknown.peer_max_data);
    try std.testing.expectEqual(before_unknown.received_drain, after_unknown.received_drain);

    var close_buf: [64]u8 = undefined;
    const close_n = try http3_zig.webtransport.encodeCloseSession(&close_buf, 7, "bye");
    const close_decoded = try http3_zig.capsule.decode(close_buf[0..close_n]);
    try h.proxy_in_wt.forwardCapsuleTo(close_decoded.capsule, &h.proxy_out_wt);

    const upstream_close = try h.nextUpstreamServerCapsule();
    try expectCapsuleEqual(close_decoded.capsule, upstream_close);
    try std.testing.expect(h.proxy_in_wt.flowState() != null);
    try std.testing.expect(h.proxy_out_wt.flowState() != null);
    try std.testing.expect(h.upstream_server_wt.flowState() != null);
}
