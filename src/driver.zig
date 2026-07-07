//! Small transport-driving helpers for examples, tests, and interop peers.
//!
//! The helpers intentionally do not own sockets or clocks. Embedders still
//! decide how packets are received, where outgoing datagrams are sent, and how
//! time advances; this module just keeps the repeated quic_zig/http3_zig step order in
//! one place.

const std = @import("std");
const quic_zig = @import("quic_zig");
const session_mod = @import("session.zig");

pub const default_step_us: u64 = 1_000;

pub const Error = session_mod.Error;

pub const StepStats = struct {
    handled_datagrams: usize = 0,
    sent_datagrams: usize = 0,
    client_to_server_datagrams: usize = 0,
    server_to_client_datagrams: usize = 0,
    client_events: usize = 0,
    server_events: usize = 0,
    session_events: usize = 0,

    pub fn madeProgress(self: StepStats) bool {
        return self.handled_datagrams != 0 or
            self.sent_datagrams != 0 or
            self.client_to_server_datagrams != 0 or
            self.server_to_client_datagrams != 0 or
            self.client_events != 0 or
            self.server_events != 0 or
            self.session_events != 0;
    }

    pub fn accumulate(self: *StepStats, other: StepStats) void {
        self.handled_datagrams += other.handled_datagrams;
        self.sent_datagrams += other.sent_datagrams;
        self.client_to_server_datagrams += other.client_to_server_datagrams;
        self.server_to_client_datagrams += other.server_to_client_datagrams;
        self.client_events += other.client_events;
        self.server_events += other.server_events;
        self.session_events += other.session_events;
    }
};

pub const Endpoint = struct {
    quic: *quic_zig.Connection,
    session: ?*session_mod.Session = null,
    events: ?*std.ArrayList(session_mod.Event) = null,
    auto_start_session: bool = true,

    pub fn init(quic: *quic_zig.Connection) Endpoint {
        return .{ .quic = quic };
    }

    pub fn withSession(
        quic: *quic_zig.Connection,
        session: *session_mod.Session,
        events: *std.ArrayList(session_mod.Event),
    ) Endpoint {
        return .{
            .quic = quic,
            .session = session,
            .events = events,
        };
    }

    pub fn handle(
        self: *Endpoint,
        datagram: []u8,
        from: ?quic_zig.Address,
        now_us: u64,
    ) Error!void {
        try self.quic.handle(datagram, from, now_us);
    }

    pub fn poll(self: *Endpoint, packet_buffer: []u8, now_us: u64) Error!?usize {
        return self.quic.poll(packet_buffer, now_us);
    }

    pub fn tick(self: *Endpoint, now_us: u64) Error!void {
        try self.quic.tick(now_us);
    }

    pub fn drainSession(self: *Endpoint) Error!usize {
        const h3 = self.session orelse return 0;
        if (self.auto_start_session) try h3.start();
        const out = self.events orelse return 0;
        const before = out.items.len;
        try h3.drain(out);
        return out.items.len - before;
    }

    pub fn flush(self: *Endpoint, packet_buffer: []u8, now_us: u64, sink: anytype) !usize {
        var sent: usize = 0;
        while (try self.poll(packet_buffer, now_us)) |n| {
            try sink.send(packet_buffer[0..n]);
            sent += 1;
        }
        return sent;
    }

    pub fn relayTo(
        self: *Endpoint,
        peer: *Endpoint,
        packet_buffer: []u8,
        now_us: u64,
        max_datagrams: usize,
    ) Error!usize {
        var sent: usize = 0;
        while (sent < max_datagrams) {
            const n = (try self.poll(packet_buffer, now_us)) orelse break;
            try peer.handle(packet_buffer[0..n], null, now_us);
            sent += 1;
        }
        return sent;
    }
};

test "StepStats reports whether a transport step made progress" {
    try std.testing.expect(!(StepStats{}).madeProgress());
    try std.testing.expect((StepStats{ .handled_datagrams = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .sent_datagrams = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .client_to_server_datagrams = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .server_to_client_datagrams = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .client_events = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .server_events = 1 }).madeProgress());
    try std.testing.expect((StepStats{ .session_events = 1 }).madeProgress());
}

test "StepStats accumulates transport loop counters" {
    var total = StepStats{
        .handled_datagrams = 1,
        .sent_datagrams = 2,
        .client_to_server_datagrams = 3,
        .server_to_client_datagrams = 4,
        .client_events = 5,
        .server_events = 6,
        .session_events = 7,
    };
    total.accumulate(.{
        .handled_datagrams = 10,
        .sent_datagrams = 20,
        .client_to_server_datagrams = 30,
        .server_to_client_datagrams = 40,
        .client_events = 50,
        .server_events = 60,
        .session_events = 70,
    });

    try std.testing.expectEqual(@as(usize, 11), total.handled_datagrams);
    try std.testing.expectEqual(@as(usize, 22), total.sent_datagrams);
    try std.testing.expectEqual(@as(usize, 33), total.client_to_server_datagrams);
    try std.testing.expectEqual(@as(usize, 44), total.server_to_client_datagrams);
    try std.testing.expectEqual(@as(usize, 55), total.client_events);
    try std.testing.expectEqual(@as(usize, 66), total.server_events);
    try std.testing.expectEqual(@as(usize, 77), total.session_events);
}

pub const LoopbackOptions = struct {
    now_us: u64 = 1_000_000,
    step_us: u64 = default_step_us,
    max_datagrams_per_direction: usize = 16,
};

pub const Loopback = struct {
    client: Endpoint,
    server: Endpoint,
    now_us: u64,
    step_us: u64,
    max_datagrams_per_direction: usize,

    pub fn init(client: Endpoint, server: Endpoint, options: LoopbackOptions) Loopback {
        return .{
            .client = client,
            .server = server,
            .now_us = options.now_us,
            .step_us = options.step_us,
            .max_datagrams_per_direction = options.max_datagrams_per_direction,
        };
    }

    pub fn step(self: *Loopback, packet_buffer: []u8) Error!StepStats {
        var stats: StepStats = .{};

        try self.client.tick(self.now_us);
        try self.server.tick(self.now_us);

        stats.client_to_server_datagrams = try self.client.relayTo(
            &self.server,
            packet_buffer,
            self.now_us,
            self.max_datagrams_per_direction,
        );
        stats.server_to_client_datagrams = try self.server.relayTo(
            &self.client,
            packet_buffer,
            self.now_us,
            self.max_datagrams_per_direction,
        );
        stats.sent_datagrams = stats.client_to_server_datagrams + stats.server_to_client_datagrams;
        stats.handled_datagrams = stats.sent_datagrams;

        stats.server_events = try self.server.drainSession();
        stats.client_events = try self.client.drainSession();
        stats.session_events = stats.server_events + stats.client_events;

        self.now_us += self.step_us;
        return stats;
    }
};
