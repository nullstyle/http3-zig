//! Two-hop WebTransport intermediary coverage. A proxy terminates a
//! downstream WT session (server role) and originates an upstream WT
//! session (client role); session-scoped capsule traffic crosses the
//! hop via `forwardSessionEventTo` — the proxy watches the typed
//! `webtransport_*` events on one leg and re-emits them onto the other,
//! byte-equivalent on the wire. Native ingestion supplies the events;
//! there is no raw-body capsule iteration anywhere in the datapath.

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic = @import("quic");
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

    downstream_proxy_runner: http3_zig.ServerRunner,
    upstream_server_runner: http3_zig.ServerRunner,

    downstream_client_events: std.ArrayList(http3_zig.session.Event),
    downstream_proxy_events: std.ArrayList(http3_zig.session.Event),
    upstream_proxy_events: std.ArrayList(http3_zig.session.Event),
    upstream_server_events: std.ArrayList(http3_zig.session.Event),

    downstream_now_us: u64,
    upstream_now_us: u64,

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
            .downstream_proxy_runner = http3_zig.ServerRunner.init(allocator),
            .upstream_server_runner = http3_zig.ServerRunner.init(allocator),
            .downstream_client_events = .empty,
            .downstream_proxy_events = .empty,
            .upstream_proxy_events = .empty,
            .upstream_server_events = .empty,
            .downstream_now_us = 1_000_000,
            .upstream_now_us = 2_000_000,
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

        self.downstream_proxy_runner.deinit();
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

    const EventTag = std.meta.Tag(http3_zig.session.Event);

    /// Proxy datapath, downstream → upstream: pumps the downstream pair
    /// until the proxy's downstream leg surfaces at least one `tag`
    /// event, forwards every one in that batch onto the upstream leg,
    /// and returns how many were forwarded. Every forward must be
    /// accepted (the events belong to the proxy's own session).
    fn forwardDownstream(self: *ForwardingHarness, comptime tag: EventTag) !usize {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpDownstream();
            var forwarded: usize = 0;
            for (self.downstream_proxy_events.items) |event| {
                if (event != tag) continue;
                try std.testing.expect(try self.proxy_in_wt.forwardSessionEventTo(event, &self.proxy_out_wt));
                forwarded += 1;
            }
            self.clearDownstreamEvents();
            if (forwarded > 0) return forwarded;
        }
        return error.ExpectedDownstreamWtEvent;
    }

    /// Proxy datapath, upstream → downstream: mirror of
    /// `forwardDownstream` for events observed on the proxy's upstream
    /// (client) leg.
    fn forwardUpstream(self: *ForwardingHarness, comptime tag: EventTag) !usize {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpUpstream();
            var forwarded: usize = 0;
            for (self.upstream_proxy_events.items) |event| {
                if (event != tag) continue;
                try std.testing.expect(try self.proxy_out_wt.forwardSessionEventTo(event, &self.proxy_in_wt));
                forwarded += 1;
            }
            self.clearUpstreamEvents();
            if (forwarded > 0) return forwarded;
        }
        return error.ExpectedUpstreamWtEvent;
    }
};

fn varintValue(value: u64, storage: *[8]u8) ![]const u8 {
    const n = try quic.wire.varint.encode(storage[0..], value);
    return storage[0..n];
}

test "WebTransport forwarding carries WT_MAX_DATA credit across two H3 pairs" {
    const allocator = std.testing.allocator;
    const h = try allocator.create(ForwardingHarness);
    defer allocator.destroy(h);
    try h.init(allocator);
    defer h.deinit();

    // Hop 1: downstream client raises the proxy's send budget; the
    // proxy observes the typed credit event on its downstream leg and
    // re-grants it upstream.
    const downstream_max: u64 = 64 * 1024;
    try h.downstream_client_wt.sendMaxData(downstream_max);
    _ = try h.forwardDownstream(.webtransport_credit_granted);

    // The proxy's own downstream flow state folded the credit natively.
    try std.testing.expectEqual(
        @as(?u64, downstream_max),
        (h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow).peer_max_data,
    );

    // The upstream server sees the forwarded credit as its own typed
    // event and folds it into peer_max_data.
    {
        var seen = false;
        var iters: u32 = 0;
        while (!seen) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpUpstream();
            for (h.upstream_server_events.items) |event| {
                if (event != .webtransport_credit_granted) continue;
                const credit = event.webtransport_credit_granted;
                try std.testing.expectEqual(h.upstream_server_wt.sessionId(), credit.session_id);
                try std.testing.expect(credit.kind == .data);
                try std.testing.expectEqual(downstream_max, credit.limit);
                seen = true;
            }
            h.clearUpstreamEvents();
        }
    }
    try std.testing.expectEqual(
        @as(?u64, downstream_max),
        (h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow).peer_max_data,
    );

    // Hop 2 (reverse): the upstream server grants credit; the proxy
    // relays it downstream to the client.
    const upstream_max: u64 = 128 * 1024;
    try h.upstream_server_wt.sendMaxData(upstream_max);
    _ = try h.forwardUpstream(.webtransport_credit_granted);

    try std.testing.expectEqual(
        @as(?u64, upstream_max),
        (h.proxy_out_wt.flowState() orelse return error.MissingProxyOutFlow).peer_max_data,
    );

    {
        var seen = false;
        var iters: u32 = 0;
        while (!seen) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpDownstream();
            for (h.downstream_client_events.items) |event| {
                if (event != .webtransport_credit_granted) continue;
                const credit = event.webtransport_credit_granted;
                try std.testing.expectEqual(h.downstream_client_wt.sessionId(), credit.session_id);
                try std.testing.expect(credit.kind == .data);
                try std.testing.expectEqual(upstream_max, credit.limit);
                seen = true;
            }
            h.clearDownstreamEvents();
        }
    }
    try std.testing.expectEqual(
        @as(?u64, upstream_max),
        (h.downstream_client_wt.flowState() orelse return error.MissingDownstreamFlow).peer_max_data,
    );
}

test "WebTransport forwarding relays BLOCKED events without mutating limits" {
    const allocator = std.testing.allocator;
    const h = try allocator.create(ForwardingHarness);
    defer allocator.destroy(h);
    try h.init(allocator);
    defer h.deinit();

    const proxy_before = h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow;
    const upstream_before = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;

    // The downstream client reports being blocked on all three limit
    // kinds. BLOCKED capsules normally auto-emit from gated sends; the
    // raw `writer.capsule` escape injects them directly here.
    var storage: [3][8]u8 = undefined;
    try h.downstream_client_wt.underlyingWriter().capsule(
        http3_zig.webtransport.CapsuleType.data_blocked,
        try varintValue(4096, &storage[0]),
    );
    try h.downstream_client_wt.underlyingWriter().capsule(
        http3_zig.webtransport.CapsuleType.streams_blocked_bidi,
        try varintValue(2, &storage[1]),
    );
    try h.downstream_client_wt.underlyingWriter().capsule(
        http3_zig.webtransport.CapsuleType.streams_blocked_uni,
        try varintValue(3, &storage[2]),
    );

    // The proxy relays each typed blocked event upstream. The three
    // capsules coalesce on the wire, so keep forwarding until all
    // three have crossed the hop.
    var relayed: usize = 0;
    while (relayed < 3) {
        relayed += try h.forwardDownstream(.webtransport_peer_blocked);
    }
    try std.testing.expectEqual(@as(usize, 3), relayed);

    // The upstream server observes all three blocked events with the
    // offered limits intact.
    {
        var seen_data = false;
        var seen_bidi = false;
        var seen_uni = false;
        var iters: u32 = 0;
        while (!(seen_data and seen_bidi and seen_uni)) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpUpstream();
            for (h.upstream_server_events.items) |event| {
                if (event != .webtransport_peer_blocked) continue;
                const blocked = event.webtransport_peer_blocked;
                try std.testing.expectEqual(h.upstream_server_wt.sessionId(), blocked.session_id);
                switch (blocked.kind) {
                    .data => {
                        try std.testing.expectEqual(@as(u64, 4096), blocked.offered_limit);
                        seen_data = true;
                    },
                    .streams_bidi => {
                        try std.testing.expectEqual(@as(u64, 2), blocked.offered_limit);
                        seen_bidi = true;
                    },
                    .streams_uni => {
                        try std.testing.expectEqual(@as(u64, 3), blocked.offered_limit);
                        seen_uni = true;
                    },
                }
            }
            h.clearUpstreamEvents();
        }
    }

    // BLOCKED is a pure signal: no limit on either leg moved.
    const proxy_after = h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow;
    try std.testing.expectEqual(proxy_before.peer_max_data, proxy_after.peer_max_data);
    try std.testing.expectEqual(proxy_before.peer_max_streams_bidi, proxy_after.peer_max_streams_bidi);
    try std.testing.expectEqual(proxy_before.peer_max_streams_uni, proxy_after.peer_max_streams_uni);
    const upstream_after = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;
    try std.testing.expectEqual(upstream_before.peer_max_data, upstream_after.peer_max_data);
    try std.testing.expectEqual(upstream_before.peer_max_streams_bidi, upstream_after.peer_max_streams_bidi);
    try std.testing.expectEqual(upstream_before.peer_max_streams_uni, upstream_after.peer_max_streams_uni);

    // The proxy's session traced the peer-blocked signals as metrics.
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

    // DRAIN: downstream client asks the proxy to wind down; the proxy
    // relays the draining event upstream.
    try h.downstream_client_wt.sendDrain();
    _ = try h.forwardDownstream(.webtransport_session_draining);
    try std.testing.expect((h.proxy_in_wt.flowState() orelse return error.MissingProxyInFlow).received_drain);
    try std.testing.expectError(error.WebTransportSessionDraining, h.proxy_in_wt.openUniStream());

    {
        var seen = false;
        var iters: u32 = 0;
        while (!seen) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpUpstream();
            for (h.upstream_server_events.items) |event| {
                if (event != .webtransport_session_draining) continue;
                try std.testing.expectEqual(
                    h.upstream_server_wt.sessionId(),
                    event.webtransport_session_draining.session_id,
                );
                seen = true;
            }
            h.clearUpstreamEvents();
        }
    }
    try std.testing.expect((h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow).received_drain);
    try std.testing.expectError(error.WebTransportSessionDraining, h.upstream_server_wt.openUniStream());

    // Unknown capsule: forwards byte-exact (RFC 9297 §3.2) and leaves
    // flow state untouched on both legs.
    const before_unknown = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;
    const unknown_type: u64 = 0x41;
    const unknown_value = "opaque-forward";
    try h.downstream_client_wt.underlyingWriter().capsule(unknown_type, unknown_value);
    _ = try h.forwardDownstream(.webtransport_unknown_capsule);
    {
        var seen = false;
        var iters: u32 = 0;
        while (!seen) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpUpstream();
            for (h.upstream_server_events.items) |event| {
                if (event != .webtransport_unknown_capsule) continue;
                const unknown = event.webtransport_unknown_capsule;
                try std.testing.expectEqual(h.upstream_server_wt.sessionId(), unknown.session_id);
                try std.testing.expectEqual(unknown_type, unknown.capsule_type);
                try std.testing.expectEqualStrings(unknown_value, unknown.value);
                seen = true;
            }
            h.clearUpstreamEvents();
        }
    }
    const after_unknown = h.upstream_server_wt.flowState() orelse return error.MissingUpstreamFlow;
    try std.testing.expectEqual(before_unknown.peer_max_data, after_unknown.peer_max_data);
    try std.testing.expectEqual(before_unknown.received_drain, after_unknown.received_drain);

    // CLOSE: ends the proxy's downstream session on arrival (native
    // ingestion), forwards as a CLOSE on the upstream leg (ending the
    // proxy's upstream session locally via `close`), and ends the
    // upstream server's session when it lands.
    try h.downstream_client_wt.close(7, "bye");
    _ = try h.forwardDownstream(.webtransport_session_closed);
    try std.testing.expect(h.proxy_in_wt.flowState() == null);
    try std.testing.expect(h.proxy_out_wt.flowState() == null);

    {
        var seen = false;
        var iters: u32 = 0;
        while (!seen) : (iters += 1) {
            try std.testing.expect(iters < 20_000);
            try h.pumpUpstream();
            for (h.upstream_server_events.items) |event| {
                if (event != .webtransport_session_closed) continue;
                const closed = event.webtransport_session_closed;
                try std.testing.expectEqual(h.upstream_server_wt.sessionId(), closed.session_id);
                try std.testing.expect(closed.how == .close_capsule);
                try std.testing.expectEqual(@as(?u32, 7), closed.code);
                try std.testing.expectEqualStrings("bye", closed.reason);
                seen = true;
            }
            h.clearUpstreamEvents();
        }
    }
    try std.testing.expect(h.upstream_server_wt.flowState() == null);
}
