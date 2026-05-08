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
        from: ?quic_zig.conn.path.Address,
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

        stats.server_events = try self.server.drainSession();
        stats.client_events = try self.client.drainSession();
        stats.session_events = stats.server_events + stats.client_events;

        self.now_us += self.step_us;
        return stats;
    }
};
