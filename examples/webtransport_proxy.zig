//! In-process WebTransport proxy datapath example.
//!
//! This is deliberately an application example, not a new http3-zig proxy
//! abstraction. It wires two independent HTTP/3+QUIC pairs:
//!
//!   downstream client <-> proxy inbound server
//!   proxy outbound client <-> upstream server
//!
//! The proxy accepts a downstream WebTransport CONNECT, opens its own
//! upstream WebTransport CONNECT, then forwards the pieces applications own:
//! control capsules, datagrams, WebTransport substream data, FIN, reset, and
//! CONNECT lifecycle. The library supplies the endpoint handles and event
//! stream; stream-id maps, socket policy, retry policy, and close policy stay
//! in application code.

const std = @import("std");
const boringssl = @import("boringssl");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

const wt_settings: http3_zig.Settings = .{
    .enable_connect_protocol = true,
    .h3_datagram = true,
    .wt_enabled = true,
};

const downstream_datagram = "downstream-datagram";
const upstream_datagram = "upstream-datagram";
const downstream_stream_payload = "stream-from-downstream";
const upstream_stream_payload = "stream-from-upstream";
const downstream_max_data: u64 = 96 * 1024;
const close_code: u32 = 0x5150_0001;
const close_reason = "proxy-demo-complete";

const H3Pair = struct {
    client_tls: boringssl.tls.Context,
    server_tls: boringssl.tls.Context,
    client: quic_zig.Connection,
    server: quic_zig.Connection,
    client_h3: http3_zig.Session,
    server_h3: http3_zig.Session,

    pub fn initStarted(
        self: *H3Pair,
        allocator: std.mem.Allocator,
        cert_pem: []const u8,
        key_pem: []const u8,
    ) !void {
        self.client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
        errdefer self.client_tls.deinit();

        self.server_tls = try http3_zig.server.initTlsContext(.{}, cert_pem, key_pem);
        errdefer self.server_tls.deinit();

        self.client = try quic_zig.Connection.initClient(allocator, self.client_tls, "localhost");
        errdefer self.client.deinit();

        self.server = try quic_zig.Connection.initServer(allocator, self.server_tls);
        errdefer self.server.deinit();

        try connectQuic(&self.client, &self.server);

        self.client_h3 = http3_zig.Session.init(allocator, .client, &self.client, .{ .settings = wt_settings });
        errdefer self.client_h3.deinit();

        self.server_h3 = http3_zig.Session.init(allocator, .server, &self.server, .{ .settings = wt_settings });
        errdefer self.server_h3.deinit();

        try self.client_h3.start();
        try self.server_h3.start();
    }

    pub fn deinit(self: *H3Pair) void {
        self.server_h3.deinit();
        self.client_h3.deinit();
        self.server.deinit();
        self.client.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
    }
};

const ProxyDemo = struct {
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

    down_to_up_streams: std.AutoHashMap(u64, u64),
    up_to_down_streams: std.AutoHashMap(u64, u64),

    downstream_now_us: u64,
    upstream_now_us: u64,

    downstream_request_cursor: usize,
    downstream_response_cursor: usize,
    upstream_request_cursor: usize,
    upstream_response_cursor: usize,

    upstream_saw_max_data: bool,
    upstream_saw_downstream_datagram: bool,
    upstream_saw_downstream_stream_finish: bool,
    upstream_saw_close: bool,
    upstream_saw_proxy_fin: bool,
    upstream_replied: bool,
    downstream_saw_upstream_datagram: bool,
    downstream_saw_upstream_stream_finish: bool,
    downstream_saw_drain: bool,
    downstream_client_closed: bool,
    proxy_finished_upstream_connect: bool,

    upstream_stream_bytes: std.ArrayList(u8),
    downstream_stream_bytes: std.ArrayList(u8),

    pub fn init(
        self: *ProxyDemo,
        allocator: std.mem.Allocator,
        cert_pem: []const u8,
        key_pem: []const u8,
    ) !void {
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
            .down_to_up_streams = std.AutoHashMap(u64, u64).init(allocator),
            .up_to_down_streams = std.AutoHashMap(u64, u64).init(allocator),
            .downstream_now_us = 1_000_000,
            .upstream_now_us = 2_000_000,
            .downstream_request_cursor = 0,
            .downstream_response_cursor = 0,
            .upstream_request_cursor = 0,
            .upstream_response_cursor = 0,
            .upstream_saw_max_data = false,
            .upstream_saw_downstream_datagram = false,
            .upstream_saw_downstream_stream_finish = false,
            .upstream_saw_close = false,
            .upstream_saw_proxy_fin = false,
            .upstream_replied = false,
            .downstream_saw_upstream_datagram = false,
            .downstream_saw_upstream_stream_finish = false,
            .downstream_saw_drain = false,
            .downstream_client_closed = false,
            .proxy_finished_upstream_connect = false,
            .upstream_stream_bytes = .empty,
            .downstream_stream_bytes = .empty,
        };
        errdefer self.deinit();

        try self.downstream.initStarted(allocator, cert_pem, key_pem);
        self.downstream_started = true;
        try self.upstream.initStarted(allocator, cert_pem, key_pem);
        self.upstream_started = true;

        try self.exchangeDownstreamSettings();
        try self.exchangeUpstreamSettings();

        self.downstream_client = http3_zig.Client.init(&self.downstream.client_h3);
        self.proxy_in_server = http3_zig.Server.init(&self.downstream.server_h3);
        self.proxy_out_client = http3_zig.Client.init(&self.upstream.client_h3);
        self.upstream_server = http3_zig.Server.init(&self.upstream.server_h3);

        self.downstream_client_wt = try self.downstream_client.startWebTransport(allocator, .{
            .authority = "proxy.local",
            .path = "/wt",
        });
        try self.acceptDownstream();
        try self.waitDownstreamAccepted();

        self.proxy_out_wt = try self.proxy_out_client.startWebTransport(allocator, .{
            .authority = "upstream.local",
            .path = "/wt",
        });
        try self.acceptUpstream();
        try self.waitUpstreamAccepted();
    }

    pub fn deinit(self: *ProxyDemo) void {
        self.upstream_stream_bytes.deinit(self.allocator);
        self.downstream_stream_bytes.deinit(self.allocator);
        self.up_to_down_streams.deinit();
        self.down_to_up_streams.deinit();

        clearEvents(self.allocator, &self.downstream_client_events);
        clearEvents(self.allocator, &self.downstream_proxy_events);
        clearEvents(self.allocator, &self.upstream_proxy_events);
        clearEvents(self.allocator, &self.upstream_server_events);
        self.downstream_client_events.deinit(self.allocator);
        self.downstream_proxy_events.deinit(self.allocator);
        self.upstream_proxy_events.deinit(self.allocator);
        self.upstream_server_events.deinit(self.allocator);

        self.upstream_server_runner.deinit();
        self.upstream_proxy_runner.deinit();
        self.downstream_proxy_runner.deinit();
        self.downstream_client_runner.deinit();

        if (self.upstream_started) self.upstream.deinit();
        if (self.downstream_started) self.downstream.deinit();
    }

    pub fn run(self: *ProxyDemo) !void {
        try self.downstream_client_wt.sendMaxData(downstream_max_data);
        try self.downstream_client_wt.sendDatagram(downstream_datagram);
        const down_stream = try self.downstream_client_wt.openUniStream();
        try self.downstream_client_wt.writeStream(down_stream, downstream_stream_payload);
        try self.downstream_client_wt.finishStream(down_stream);
        std.debug.print(
            "downstream client: sent WT_MAX_DATA, datagram, and uni stream {d}\n",
            .{down_stream},
        );

        var iters: u32 = 0;
        while (!self.upstream_saw_close or !self.upstream_saw_proxy_fin) : (iters += 1) {
            if (iters >= 40_000) return error.ProxyDemoTimedOut;
            try self.step();
        }

        if (!std.mem.eql(u8, self.upstream_stream_bytes.items, downstream_stream_payload)) {
            return error.UpstreamPayloadMismatch;
        }
        if (!std.mem.eql(u8, self.downstream_stream_bytes.items, upstream_stream_payload)) {
            return error.DownstreamPayloadMismatch;
        }

        std.debug.print("WebTransport proxy datapath example completed successfully\n", .{});
    }

    fn step(self: *ProxyDemo) !void {
        try self.pumpDownstream();
        try self.processDownstreamProxyEvents();
        try self.processDownstreamClientEvents();

        try self.pumpUpstream();
        try self.processUpstreamServerEvents();
        try self.processUpstreamProxyEvents();

        try self.maybeSendUpstreamReply();
        try self.maybeCloseDownstream();
    }

    fn pumpDownstream(self: *ProxyDemo) !void {
        try pumpPair(
            &self.downstream,
            &self.downstream_client_events,
            &self.downstream_proxy_events,
            &self.downstream_now_us,
        );
    }

    fn pumpUpstream(self: *ProxyDemo) !void {
        try pumpPair(
            &self.upstream,
            &self.upstream_proxy_events,
            &self.upstream_server_events,
            &self.upstream_now_us,
        );
    }

    fn exchangeDownstreamSettings(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (self.downstream.client_h3.peer_settings == null or self.downstream.server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.DownstreamSettingsTimedOut;
            try self.pumpDownstream();
            self.clearDownstreamEvents();
        }
    }

    fn exchangeUpstreamSettings(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (self.upstream.client_h3.peer_settings == null or self.upstream.server_h3.peer_settings == null) : (iters += 1) {
            if (iters >= 20_000) return error.UpstreamSettingsTimedOut;
            try self.pumpUpstream();
            self.clearUpstreamEvents();
        }
    }

    fn acceptDownstream(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpDownstream();
            for (self.downstream_proxy_events.items) |event| {
                switch (try self.downstream_proxy_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (request.headers().len > 0 and request.isWebTransport()) {
                            self.proxy_in_wt = try self.proxy_in_server.acceptWebTransport(self.allocator, request, .{});
                            std.debug.print("proxy: accepted downstream CONNECT\n", .{});
                            self.clearDownstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearDownstreamEvents();
        }
        return error.ExpectedDownstreamConnect;
    }

    fn acceptUpstream(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpUpstream();
            for (self.upstream_server_events.items) |event| {
                switch (try self.upstream_server_runner.observe(event)) {
                    .request_updated, .request_complete => |request_state| {
                        const request = request_state.reader();
                        if (request.headers().len > 0 and request.isWebTransport()) {
                            self.upstream_server_wt = try self.upstream_server.acceptWebTransport(self.allocator, request, .{});
                            std.debug.print("upstream server: accepted proxy CONNECT\n", .{});
                            self.clearUpstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearUpstreamEvents();
        }
        return error.ExpectedUpstreamConnect;
    }

    fn waitDownstreamAccepted(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpDownstream();
            for (self.downstream_client_events.items) |event| {
                switch (try self.downstream_client_runner.observe(event)) {
                    .response_updated, .response_complete => |response_state| {
                        const response = response_state.reader();
                        if (response.streamId() == self.downstream_client_wt.sessionId() and
                            response.headers().len > 0 and response.webTransportAccepted())
                        {
                            std.debug.print("downstream client: CONNECT accepted by proxy\n", .{});
                            self.clearDownstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearDownstreamEvents();
        }
        return error.DownstreamAcceptTimedOut;
    }

    fn waitUpstreamAccepted(self: *ProxyDemo) !void {
        var iters: u32 = 0;
        while (iters < 20_000) : (iters += 1) {
            try self.pumpUpstream();
            for (self.upstream_proxy_events.items) |event| {
                switch (try self.upstream_proxy_runner.observe(event)) {
                    .response_updated, .response_complete => |response_state| {
                        const response = response_state.reader();
                        if (response.streamId() == self.proxy_out_wt.sessionId() and
                            response.headers().len > 0 and response.webTransportAccepted())
                        {
                            std.debug.print("proxy: upstream CONNECT accepted\n", .{});
                            self.clearUpstreamEvents();
                            return;
                        }
                    },
                    else => {},
                }
            }
            self.clearUpstreamEvents();
        }
        return error.UpstreamAcceptTimedOut;
    }

    fn processDownstreamProxyEvents(self: *ProxyDemo) !void {
        defer self.clearDownstreamProxyEvents();
        for (self.downstream_proxy_events.items) |event| {
            switch (try self.downstream_proxy_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (request.streamId() != self.proxy_in_wt.sessionId()) continue;
                    try self.forwardRequestCapsules(
                        request.body(),
                        &self.downstream_request_cursor,
                        &self.proxy_in_wt,
                        &self.proxy_out_wt,
                        "proxy: downstream capsule -> upstream",
                    );
                    if (request.complete() and !self.proxy_finished_upstream_connect) {
                        try self.proxy_out_wt.finish();
                        self.proxy_finished_upstream_connect = true;
                        std.debug.print("proxy: explicitly forwarded CONNECT FIN upstream\n", .{});
                    }
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == self.proxy_in_wt.sessionId()) {
                        try self.proxy_out_wt.sendDatagram(datagram.payload);
                        std.debug.print("proxy: downstream datagram -> upstream\n", .{});
                    }
                },
                else => {},
            }

            switch (event) {
                .webtransport_stream_opened => |opened| {
                    if (opened.session_id == self.proxy_in_wt.sessionId()) {
                        const outbound = try openMatchingStream(&self.proxy_out_wt, opened.kind);
                        try self.down_to_up_streams.put(opened.stream_id, outbound);
                        std.debug.print(
                            "proxy: opened upstream WT stream {d} for downstream stream {d}\n",
                            .{ outbound, opened.stream_id },
                        );
                    }
                },
                .webtransport_stream_data => |data| {
                    if (data.session_id == self.proxy_in_wt.sessionId()) {
                        const outbound = self.down_to_up_streams.get(data.stream_id) orelse return error.MissingDownstreamStreamMap;
                        try self.proxy_out_wt.writeStream(outbound, data.data);
                        std.debug.print("proxy: copied downstream stream bytes upstream\n", .{});
                    }
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == self.proxy_in_wt.sessionId()) {
                        const outbound = self.down_to_up_streams.get(finished.stream_id) orelse return error.MissingDownstreamStreamMap;
                        try self.proxy_out_wt.finishStream(outbound);
                        std.debug.print("proxy: forwarded downstream stream FIN upstream\n", .{});
                    }
                },
                .webtransport_stream_reset => |reset| {
                    if (reset.session_id == self.proxy_in_wt.sessionId()) {
                        const outbound = self.down_to_up_streams.get(reset.stream_id) orelse return error.MissingDownstreamStreamMap;
                        try self.proxy_out_wt.resetStreamWithCode(outbound, reset.error_code);
                        std.debug.print("proxy: forwarded downstream stream reset upstream\n", .{});
                    }
                },
                else => {},
            }
        }
    }

    fn processUpstreamProxyEvents(self: *ProxyDemo) !void {
        defer self.clearUpstreamProxyEvents();
        for (self.upstream_proxy_events.items) |event| {
            switch (try self.upstream_proxy_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.streamId() != self.proxy_out_wt.sessionId()) continue;
                    try self.forwardResponseCapsules(
                        response.body(),
                        &self.upstream_response_cursor,
                        &self.proxy_out_wt,
                        &self.proxy_in_wt,
                        "proxy: upstream capsule -> downstream",
                    );
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == self.proxy_out_wt.sessionId()) {
                        try self.proxy_in_wt.sendDatagram(datagram.payload);
                        std.debug.print("proxy: upstream datagram -> downstream\n", .{});
                    }
                },
                else => {},
            }

            switch (event) {
                .webtransport_stream_opened => |opened| {
                    if (opened.session_id == self.proxy_out_wt.sessionId()) {
                        const outbound = try openMatchingStream(&self.proxy_in_wt, opened.kind);
                        try self.up_to_down_streams.put(opened.stream_id, outbound);
                        std.debug.print(
                            "proxy: opened downstream WT stream {d} for upstream stream {d}\n",
                            .{ outbound, opened.stream_id },
                        );
                    }
                },
                .webtransport_stream_data => |data| {
                    if (data.session_id == self.proxy_out_wt.sessionId()) {
                        const outbound = self.up_to_down_streams.get(data.stream_id) orelse return error.MissingUpstreamStreamMap;
                        try self.proxy_in_wt.writeStream(outbound, data.data);
                        std.debug.print("proxy: copied upstream stream bytes downstream\n", .{});
                    }
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == self.proxy_out_wt.sessionId()) {
                        const outbound = self.up_to_down_streams.get(finished.stream_id) orelse return error.MissingUpstreamStreamMap;
                        try self.proxy_in_wt.finishStream(outbound);
                        std.debug.print("proxy: forwarded upstream stream FIN downstream\n", .{});
                    }
                },
                .webtransport_stream_reset => |reset| {
                    if (reset.session_id == self.proxy_out_wt.sessionId()) {
                        const outbound = self.up_to_down_streams.get(reset.stream_id) orelse return error.MissingUpstreamStreamMap;
                        try self.proxy_in_wt.resetStreamWithCode(outbound, reset.error_code);
                        std.debug.print("proxy: forwarded upstream stream reset downstream\n", .{});
                    }
                },
                else => {},
            }
        }
    }

    fn processUpstreamServerEvents(self: *ProxyDemo) !void {
        defer self.clearUpstreamServerEvents();
        for (self.upstream_server_events.items) |event| {
            switch (try self.upstream_server_runner.observe(event)) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (request.streamId() != self.upstream_server_wt.sessionId()) continue;
                    try self.observeEndpointRequestCapsules(
                        request.body(),
                        &self.upstream_request_cursor,
                        &self.upstream_server_wt,
                    );
                    if (request.complete()) {
                        self.upstream_saw_proxy_fin = true;
                    }
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == self.upstream_server_wt.sessionId()) {
                        if (!std.mem.eql(u8, datagram.payload, downstream_datagram)) {
                            return error.UpstreamDatagramMismatch;
                        }
                        self.upstream_saw_downstream_datagram = true;
                        std.debug.print("upstream server: received forwarded downstream datagram\n", .{});
                    }
                },
                else => {},
            }

            switch (event) {
                .webtransport_stream_data => |data| {
                    if (data.session_id == self.upstream_server_wt.sessionId()) {
                        try self.upstream_stream_bytes.appendSlice(self.allocator, data.data);
                    }
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == self.upstream_server_wt.sessionId()) {
                        self.upstream_saw_downstream_stream_finish = true;
                        std.debug.print("upstream server: received forwarded downstream stream FIN\n", .{});
                    }
                },
                else => {},
            }
        }
    }

    fn processDownstreamClientEvents(self: *ProxyDemo) !void {
        defer self.clearDownstreamClientEvents();
        for (self.downstream_client_events.items) |event| {
            switch (try self.downstream_client_runner.observe(event)) {
                .response_updated, .response_complete => |response_state| {
                    const response = response_state.reader();
                    if (response.streamId() != self.downstream_client_wt.sessionId()) continue;
                    try self.observeEndpointResponseCapsules(
                        response.body(),
                        &self.downstream_response_cursor,
                        &self.downstream_client_wt,
                    );
                },
                .datagram => |datagram| {
                    if (datagram.stream_id == self.downstream_client_wt.sessionId()) {
                        if (!std.mem.eql(u8, datagram.payload, upstream_datagram)) {
                            return error.DownstreamDatagramMismatch;
                        }
                        self.downstream_saw_upstream_datagram = true;
                        std.debug.print("downstream client: received forwarded upstream datagram\n", .{});
                    }
                },
                else => {},
            }

            switch (event) {
                .webtransport_stream_data => |data| {
                    if (data.session_id == self.downstream_client_wt.sessionId()) {
                        try self.downstream_stream_bytes.appendSlice(self.allocator, data.data);
                    }
                },
                .webtransport_stream_finished => |finished| {
                    if (finished.session_id == self.downstream_client_wt.sessionId()) {
                        self.downstream_saw_upstream_stream_finish = true;
                        std.debug.print("downstream client: received forwarded upstream stream FIN\n", .{});
                    }
                },
                else => {},
            }
        }
    }

    fn maybeSendUpstreamReply(self: *ProxyDemo) !void {
        if (self.upstream_replied) return;
        if (!self.upstream_saw_max_data or
            !self.upstream_saw_downstream_datagram or
            !self.upstream_saw_downstream_stream_finish)
        {
            return;
        }
        if (!std.mem.eql(u8, self.upstream_stream_bytes.items, downstream_stream_payload)) {
            return error.UpstreamPayloadMismatch;
        }

        try self.upstream_server_wt.sendDrain();
        try self.upstream_server_wt.sendDatagram(upstream_datagram);
        const up_stream = try self.upstream_server_wt.openUniStream();
        try self.upstream_server_wt.writeStream(up_stream, upstream_stream_payload);
        try self.upstream_server_wt.finishStream(up_stream);
        self.upstream_replied = true;
        std.debug.print(
            "upstream server: sent DRAIN, datagram, and uni stream {d}\n",
            .{up_stream},
        );
    }

    fn maybeCloseDownstream(self: *ProxyDemo) !void {
        if (self.downstream_client_closed) return;
        if (!self.downstream_saw_drain or
            !self.downstream_saw_upstream_datagram or
            !self.downstream_saw_upstream_stream_finish)
        {
            return;
        }
        if (!std.mem.eql(u8, self.downstream_stream_bytes.items, upstream_stream_payload)) {
            return error.DownstreamPayloadMismatch;
        }

        try self.downstream_client_wt.close(close_code, close_reason);
        self.downstream_client_closed = true;
        std.debug.print("downstream client: sent CLOSE_WEBTRANSPORT_SESSION + FIN\n", .{});
    }

    fn forwardRequestCapsules(
        self: *ProxyDemo,
        body: []const u8,
        cursor: *usize,
        inbound: anytype,
        outbound: anytype,
        label: []const u8,
    ) !void {
        while (cursor.* < body.len) {
            const decoded = try http3_zig.capsule.decode(body[cursor.*..]);
            cursor.* += decoded.bytes_read;
            const wt_event = try http3_zig.webtransport.classifyCapsule(decoded.capsule);
            if (wt_event.isClose()) {
                std.debug.print("{s}: CLOSE\n", .{label});
            } else {
                std.debug.print("{s}: type=0x{x}\n", .{ label, decoded.capsule.capsule_type });
            }
            try inbound.forwardCapsuleTo(decoded.capsule, outbound);
            _ = self;
        }
    }

    fn forwardResponseCapsules(
        self: *ProxyDemo,
        body: []const u8,
        cursor: *usize,
        inbound: anytype,
        outbound: anytype,
        label: []const u8,
    ) !void {
        while (cursor.* < body.len) {
            const decoded = try http3_zig.capsule.decode(body[cursor.*..]);
            cursor.* += decoded.bytes_read;
            const wt_event = try http3_zig.webtransport.classifyCapsule(decoded.capsule);
            if (wt_event.isDrain()) {
                std.debug.print("{s}: DRAIN\n", .{label});
            } else {
                std.debug.print("{s}: type=0x{x}\n", .{ label, decoded.capsule.capsule_type });
            }
            try inbound.forwardCapsuleTo(decoded.capsule, outbound);
            _ = self;
        }
    }

    fn observeEndpointRequestCapsules(
        self: *ProxyDemo,
        body: []const u8,
        cursor: *usize,
        wt: *http3_zig.WebTransportServerStream,
    ) !void {
        while (cursor.* < body.len) {
            const decoded = try http3_zig.capsule.decode(body[cursor.*..]);
            cursor.* += decoded.bytes_read;
            try wt.observeCapsule(decoded.capsule);
            switch (try http3_zig.webtransport.classifyCapsule(decoded.capsule)) {
                .max_data => |value| {
                    if (value != downstream_max_data) return error.UpstreamMaxDataMismatch;
                    self.upstream_saw_max_data = true;
                    std.debug.print("upstream server: observed forwarded WT_MAX_DATA\n", .{});
                },
                .close_session => |close| {
                    if (close.code != close_code or !std.mem.eql(u8, close.reason, close_reason)) {
                        return error.UpstreamCloseMismatch;
                    }
                    self.upstream_saw_close = true;
                    std.debug.print("upstream server: observed forwarded CLOSE\n", .{});
                },
                else => {},
            }
        }
    }

    fn observeEndpointResponseCapsules(
        self: *ProxyDemo,
        body: []const u8,
        cursor: *usize,
        wt: *http3_zig.WebTransportClientStream,
    ) !void {
        while (cursor.* < body.len) {
            const decoded = try http3_zig.capsule.decode(body[cursor.*..]);
            cursor.* += decoded.bytes_read;
            try wt.observeCapsule(decoded.capsule);
            switch (try http3_zig.webtransport.classifyCapsule(decoded.capsule)) {
                .drain_session => {
                    self.downstream_saw_drain = true;
                    std.debug.print("downstream client: observed forwarded DRAIN\n", .{});
                },
                else => {},
            }
        }
    }

    fn clearDownstreamEvents(self: *ProxyDemo) void {
        self.clearDownstreamClientEvents();
        self.clearDownstreamProxyEvents();
    }

    fn clearUpstreamEvents(self: *ProxyDemo) void {
        self.clearUpstreamProxyEvents();
        self.clearUpstreamServerEvents();
    }

    fn clearDownstreamClientEvents(self: *ProxyDemo) void {
        clearEvents(self.allocator, &self.downstream_client_events);
    }

    fn clearDownstreamProxyEvents(self: *ProxyDemo) void {
        clearEvents(self.allocator, &self.downstream_proxy_events);
    }

    fn clearUpstreamProxyEvents(self: *ProxyDemo) void {
        clearEvents(self.allocator, &self.upstream_proxy_events);
    }

    fn clearUpstreamServerEvents(self: *ProxyDemo) void {
        clearEvents(self.allocator, &self.upstream_server_events);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var cert_buf: [64 * 1024]u8 = undefined;
    var key_buf: [64 * 1024]u8 = undefined;
    const cert_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_cert.pem", &cert_buf);
    const key_pem = try std.Io.Dir.cwd().readFile(io, "tests/data/test_key.pem", &key_buf);

    const demo = try allocator.create(ProxyDemo);
    defer allocator.destroy(demo);
    try demo.init(allocator, cert_pem, key_pem);
    defer demo.deinit();

    try demo.run();
}

fn openMatchingStream(
    wt: anytype,
    kind: http3_zig.webtransport.StreamKind,
) http3_zig.session.Error!u64 {
    return switch (kind) {
        .uni => try wt.openUniStream(),
        .bidi => try wt.openBidiStream(),
    };
}

fn pumpPair(
    pair: *H3Pair,
    client_events: *std.ArrayList(http3_zig.session.Event),
    server_events: *std.ArrayList(http3_zig.session.Event),
    now_us: *u64,
) !void {
    var packet: [4096]u8 = undefined;
    var driver = http3_zig.TransportLoopback.init(
        http3_zig.TransportEndpoint.withSession(&pair.client, &pair.client_h3, client_events),
        http3_zig.TransportEndpoint.withSession(&pair.server, &pair.server_h3, server_events),
        .{
            .now_us = now_us.*,
            .max_datagrams_per_direction = 4,
        },
    );
    _ = try driver.step(&packet);
    now_us.* = driver.now_us;
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
        .max_datagram_frame_size = 1200,
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
    _ = server.markPathValidated(server.activePathId());
}

fn clearEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}
