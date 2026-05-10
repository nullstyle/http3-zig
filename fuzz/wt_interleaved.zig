//! WebTransport interleaved-operations fuzz harness.
//!
//! Property-based fuzz target that interprets a corpus byte buffer as a
//! small bytecode driving a real H3Pair through random sequences of
//! WebTransport operations. Where the existing `webtransport-session`
//! target only exercises single-frame parsing, this harness drives
//! whole sessions: open + send + drain + close + reset, interleaved
//! across multiple sessions and streams, alternating between the
//! client and server initiator.
//!
//! Each opcode mod-16 maps cleanly to one of the operations below; any
//! parameters are drawn from subsequent corpus bytes (length-prefixed
//! payloads truncate at the buffer's end).
//!
//! Bytecode (high nibble of byte 1 = opcode mod 16, low nibble = side bit
//! + reserved):
//!
//!   0x00 OPEN_SESSION         path implicit; opens a CONNECT request
//!   0x01 OPEN_UNI_STREAM      [session_idx]
//!   0x02 OPEN_BIDI_STREAM     [session_idx]
//!   0x03 SEND_BYTES           [stream_idx, len, bytes...]
//!   0x04 SEND_DATAGRAM        [session_idx, len, bytes...]
//!   0x05 SEND_MAX_DATA        [session_idx, 4-byte big-endian value]
//!   0x06 SEND_DRAIN           [session_idx]
//!   0x07 SEND_CLOSE           [session_idx, 1-byte code, 1-byte reason_len, reason_bytes...]
//!   0x08 FINISH_SESSION       [session_idx]   (FIN of CONNECT)
//!   0x09 RESET_STREAM         [stream_idx, 1-byte error_code]
//!   0x0a FINISH_STREAM        [stream_idx]
//!   0x0b PUMP                 (one drain step both directions)
//!   0x0c SEND_MAX_STREAMS_BIDI [session_idx, 1-byte value]
//!   0x0d SEND_MAX_STREAMS_UNI  [session_idx, 1-byte value]
//!   0x0e ACCEPT_PENDING        (server-side: accept pending CONNECT)
//!   0x0f NOOP
//!
//! Side bit: low bit of the opcode byte (after masking) chooses
//! client-initiator vs server-initiator for the operations that have
//! both flavors (open, send, drain, close, finish, reset).
//!
//! After the input is exhausted the harness drains to quiescence and
//! checks invariants:
//!   - No panic (Zig's fuzz mode catches these).
//!   - No memory leak (DebugAllocator detects on deinit).
//!   - No spurious connection close (lastCloseError null unless an op
//!     deliberately triggered one).
//!   - All deliberately closed sessions ultimately reach .none state on
//!     both peers.

const std = @import("std");
const boringssl = @import("boringssl");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");

const max_sessions = 4;
const max_streams_per_session = 8;
const max_input_bytes = 64 * 1024;
// Cap the total wall-clock pumps the harness will do per input. A
// pathological input could trigger a billion pumps — bound it.
const max_pump_iters: u32 = 4_000;
// Cap on opcode dispatches per input.
const max_ops: u32 = 1_000;

// In-tree test cert, embedded so the harness has zero external deps.
// Copied from `tests/data/` because @embedFile cannot escape the
// fuzz module's package root.
const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };

/// Public entry point used by both the runner main and the corpus
/// walker. Drives `bytes` through the harness, returning normally on
/// any cleanly-handled outcome (including expected protocol errors)
/// and propagating only invariant violations.
pub fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
    // Heap-allocate the harness because H3Pair holds connections that
    // peer-link to each other via interior pointers. Returning the
    // struct by value would invalidate those pointers.
    const harness = try allocator.create(Harness);
    defer allocator.destroy(harness);
    try Harness.init(harness, allocator);
    defer harness.deinit();

    try harness.exchangeSettings();

    // Open one session up front so most opcodes have something to act
    // on even with a tiny input. The harness can OPEN more, up to
    // max_sessions, when it sees opcode 0x00.
    harness.openClientSession() catch |err| switch (err) {
        // The bootstrap path can fail on stream-id exhaustion or peer
        // refusal in pathological QUIC-state edge cases; those aren't
        // bugs in the fuzz target itself.
        error.PeerSettingsNotReceived,
        error.PeerDidNotEnableWebTransport,
        => return,
        else => return err,
    };

    var ip: usize = 0;
    var ops_run: u32 = 0;
    while (ip < bytes.len and ops_run < max_ops) : (ops_run += 1) {
        const opcode_byte = bytes[ip];
        ip += 1;
        const op = opcode_byte & 0x0f;
        const side: Side = if ((opcode_byte & 0x10) != 0) .server else .client;
        const cursor = Cursor{ .bytes = bytes, .pos = ip };
        // Any error from dispatchOp that isn't a memory-allocation
        // failure is treated as a "this op didn't apply" — the fuzz
        // harness cares about panics, leaks, and unexpected close
        // events, not refusing-to-do-bad-things.
        if (harness.dispatchOp(op, side, cursor)) |new_ip| {
            ip = new_ip;
        } else |err| {
            if (err == error.OutOfMemory) return err;
            // Skip past the opcode byte we consumed; the param bytes
            // for this opcode are unread. We could try to model their
            // length but the simpler "advance by 1" keeps the harness
            // making progress on adversarial inputs.
        }
    }

    // Drain to quiescence so any deferred close / drain capsules
    // fully propagate before the invariant check.
    try harness.drainToQuiescence();

    // Invariants. Both peers have or have-not seen a connection-level
    // close depending on whether any opcode deliberately triggered one.
    // The harness tracks the deliberate-close flag.
    if (!harness.deliberate_close) {
        if (harness.pair.client_h3.lastCloseError() != null) return error.UnexpectedClientClose;
        if (harness.pair.server_h3.lastCloseError() != null) return error.UnexpectedServerClose;
    }

    // Every session that the harness ever issued a CLOSE or FINISH on
    // should ultimately end up in `.none` on both sides.
    for (harness.client_sessions.items, 0..) |maybe_session, idx| {
        if (maybe_session == null) continue;
        if (idx >= max_sessions) continue;
        if (harness.session_explicitly_ended[idx]) {
            const sid = maybe_session.?.handle.sessionId();
            const cs = harness.pair.client_h3.webTransportSessionState(sid);
            const ss = harness.pair.server_h3.webTransportSessionState(sid);
            if (cs != .none) return error.ClientSessionStillActive;
            if (ss != .none) return error.ServerSessionStillActive;
        }
    }
}

const Side = enum { client, server };

/// Cursor over the input buffer with truncation-safe reads. A short
/// buffer just yields zeros for fixed-width fields and an empty slice
/// for length-prefixed ones, which keeps the harness driving even with
/// adversarial inputs.
const Cursor = struct {
    bytes: []const u8,
    pos: usize,

    fn remaining(self: Cursor) usize {
        return self.bytes.len -| self.pos;
    }

    fn readU8(self: *Cursor) u8 {
        if (self.pos >= self.bytes.len) return 0;
        defer self.pos += 1;
        return self.bytes[self.pos];
    }

    fn readU32Be(self: *Cursor) u32 {
        if (self.pos + 4 > self.bytes.len) {
            self.pos = self.bytes.len;
            return 0;
        }
        defer self.pos += 4;
        return std.mem.readInt(u32, self.bytes[self.pos..][0..4], .big);
    }

    fn readSlice(self: *Cursor, max_len: usize) []const u8 {
        const declared = self.readU8();
        const want = @min(@as(usize, declared), max_len);
        const have = @min(want, self.remaining());
        defer self.pos += have;
        return self.bytes[self.pos..][0..have];
    }
};

const ClientStream = struct {
    handle: http3_zig.WebTransportClientStream,
    side: Side, // initiator
    /// True after we've already issued a CLOSE/FIN on the session.
    closed: bool = false,
};

const ServerStream = struct {
    handle: http3_zig.WebTransportServerStream,
    side: Side,
    closed: bool = false,
};

/// Per-stream record: which side opened it, the QUIC stream id, and a
/// flag for whether we've already finished/reset locally so a follow-up
/// op can still go through QUIC's API even if the stream has nothing
/// left to do.
const StreamRecord = struct {
    quic_id: u64,
    session_idx: usize,
    side: Side,
    finished: bool = false,
    reset: bool = false,
};

const Harness = struct {
    allocator: std.mem.Allocator,
    pair: H3Pair,

    h3_client: http3_zig.Client,
    h3_server: http3_zig.Server,

    // Sessions are indexed [0..max_sessions). Each slot may have a
    // client-side and a server-side handle once the CONNECT has been
    // accepted.
    client_sessions: std.ArrayList(?ClientStream),
    server_sessions: std.ArrayList(?ServerStream),

    // List of streams the harness is tracking. Stream idx in the
    // bytecode is `idx mod streams.items.len`.
    streams: std.ArrayList(StreamRecord),

    // Per-session bookkeeping for the invariant check.
    session_explicitly_ended: [max_sessions]bool,

    /// True once any opcode has deliberately torn the connection /
    /// session down with a close-style operation. Suppresses the
    /// "unexpected close" invariant.
    deliberate_close: bool = false,

    client_runner: http3_zig.ClientRunner,
    server_runner: http3_zig.ServerRunner,
    client_events: std.ArrayList(http3_zig.session.Event),
    server_events: std.ArrayList(http3_zig.session.Event),
    now_us: u64 = 1_000_000,

    fn init(self: *Harness, allocator: std.mem.Allocator) !void {
        const wt_settings: http3_zig.Settings = .{
            .enable_connect_protocol = true,
            .h3_datagram = true,
            .wt_enabled = true,
        };
        try self.pair.initStarted(allocator, .{ .settings = wt_settings }, .{ .settings = wt_settings });
        errdefer self.pair.deinit();

        self.allocator = allocator;
        self.h3_client = http3_zig.Client.init(&self.pair.client_h3);
        self.h3_server = http3_zig.Server.init(&self.pair.server_h3);
        self.client_sessions = .empty;
        self.server_sessions = .empty;
        self.streams = .empty;
        self.session_explicitly_ended = @splat(false);
        self.deliberate_close = false;
        self.client_runner = http3_zig.ClientRunner.init(allocator);
        self.server_runner = http3_zig.ServerRunner.init(allocator);
        self.client_events = .empty;
        self.server_events = .empty;
        self.now_us = 1_000_000;
    }

    fn deinit(self: *Harness) void {
        clearSessionEvents(self.allocator, &self.client_events);
        self.client_events.deinit(self.allocator);
        clearSessionEvents(self.allocator, &self.server_events);
        self.server_events.deinit(self.allocator);
        self.client_runner.deinit();
        self.server_runner.deinit();
        self.streams.deinit(self.allocator);
        self.client_sessions.deinit(self.allocator);
        self.server_sessions.deinit(self.allocator);
        self.pair.deinit();
    }

    fn exchangeSettings(self: *Harness) !void {
        var iters: u32 = 0;
        while (self.pair.client_h3.peer_settings == null or self.pair.server_h3.peer_settings == null) : (iters += 1) {
            if (iters > 1000) return error.SettingsExchangeTimeout;
            try self.pump();
            clearSessionEvents(self.allocator, &self.client_events);
            clearSessionEvents(self.allocator, &self.server_events);
        }
    }

    fn pump(self: *Harness) !void {
        var pkt: [2048]u8 = undefined;
        var driver = http3_zig.TransportLoopback.init(
            http3_zig.TransportEndpoint.withSession(&self.pair.client, &self.pair.client_h3, &self.client_events),
            http3_zig.TransportEndpoint.withSession(&self.pair.server, &self.pair.server_h3, &self.server_events),
            .{
                .now_us = self.now_us,
                .max_datagrams_per_direction = 1,
            },
        );
        _ = try driver.step(&pkt);
        self.now_us = driver.now_us;
    }

    /// Drains both sides until no more progress is made, then runs a
    /// fixed-budget tail to absorb deferred capsules (close, drain).
    fn drainToQuiescence(self: *Harness) !void {
        // Always run the server-side accept loop first so any CONNECTs
        // that landed during the input pass have a server-side handle
        // before we start tearing down.
        try self.acceptAllPendingServerSessions();

        var iters: u32 = 0;
        while (iters < max_pump_iters) : (iters += 1) {
            try self.pump();
            try self.acceptAllPendingServerSessions();
            clearSessionEvents(self.allocator, &self.client_events);
            clearSessionEvents(self.allocator, &self.server_events);

            // Cheap quiescence check: nothing new in either event queue
            // after a full pump implies the session machinery has no
            // work to do. Pump twice more to absorb any final capsules
            // and break.
            if (self.client_events.items.len == 0 and self.server_events.items.len == 0 and iters > 4) break;
        }
    }

    fn pumpOnce(self: *Harness) !void {
        try self.pump();
        try self.acceptAllPendingServerSessions();
        // Process events to drive the runners (so any state machinery
        // that depends on classified events makes progress) but discard
        // the application-level outputs — the fuzz harness doesn't
        // assert on event content.
        for (self.server_events.items) |event| {
            _ = self.server_runner.observe(event) catch {};
        }
        for (self.client_events.items) |event| {
            _ = self.client_runner.observe(event) catch {};
        }
        clearSessionEvents(self.allocator, &self.client_events);
        clearSessionEvents(self.allocator, &self.server_events);
    }

    fn acceptAllPendingServerSessions(self: *Harness) !void {
        // Walk server events looking for inbound CONNECT requests we
        // haven't accepted yet. Pair them with the next free server
        // session slot.
        for (self.server_events.items) |event| {
            const cls = self.server_runner.observe(event) catch continue;
            switch (cls) {
                .request_updated, .request_complete => |request_state| {
                    const request = request_state.reader();
                    if (request.headers().len == 0 or !request.isWebTransport()) continue;
                    // Already accepted?
                    var already = false;
                    for (self.server_sessions.items) |maybe| {
                        if (maybe) |s| {
                            if (s.handle.sessionId() == request.streamId()) {
                                already = true;
                                break;
                            }
                        }
                    }
                    if (already) continue;
                    if (self.server_sessions.items.len >= max_sessions) continue;
                    // The server side may already have exceeded the
                    // session cap; just drop the request.
                    const accepted = self.h3_server.acceptWebTransport(self.allocator, request, .{}) catch continue;
                    try self.server_sessions.append(self.allocator, .{ .handle = accepted, .side = .client });
                },
                else => {},
            }
        }
    }

    fn openClientSession(self: *Harness) !void {
        if (self.client_sessions.items.len >= max_sessions) return;
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/wt-{d}", .{self.client_sessions.items.len}) catch "/wt";
        const handle = try self.h3_client.startWebTransport(self.allocator, .{
            .authority = "localhost",
            .path = path,
        });
        try self.client_sessions.append(self.allocator, .{ .handle = handle, .side = .client });
    }

    fn dispatchOp(self: *Harness, op: u8, side: Side, c: Cursor) !usize {
        var cur = c;
        switch (op) {
            0x00 => try self.opOpenSession(side),
            0x01 => try self.opOpenUni(&cur, side),
            0x02 => try self.opOpenBidi(&cur, side),
            0x03 => try self.opSendBytes(&cur, side),
            0x04 => try self.opSendDatagram(&cur, side),
            0x05 => try self.opSendMaxData(&cur, side),
            0x06 => try self.opSendDrain(&cur, side),
            0x07 => try self.opSendClose(&cur, side),
            0x08 => try self.opFinishSession(&cur, side),
            0x09 => try self.opResetStream(&cur, side),
            0x0a => try self.opFinishStream(&cur, side),
            0x0b => try self.pumpOnce(),
            0x0c => try self.opSendMaxStreamsBidi(&cur, side),
            0x0d => try self.opSendMaxStreamsUni(&cur, side),
            0x0e => try self.acceptAllPendingServerSessions(),
            else => {}, // 0x0f and unmapped: noop
        }
        return cur.pos;
    }

    fn opOpenSession(self: *Harness, side: Side) !void {
        // Sessions are always client-initiated in WebTransport (the
        // CONNECT request comes from the client). The side bit on
        // 0x00 is reserved for future asymmetric uses; ignore it.
        _ = side;
        try self.openClientSession();
        // Pump a few times so the SETTINGS+CONNECT round-trip can land
        // before any subsequent op references the new session.
        var i: u8 = 0;
        while (i < 8) : (i += 1) try self.pumpOnce();
    }

    fn opOpenUni(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const stream_id = switch (side) {
            .client => blk: {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                break :blk try s.handle.openUniStream();
            },
            .server => blk: {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                break :blk try s.handle.openUniStream();
            },
        };
        if (self.streams.items.len < max_sessions * max_streams_per_session) {
            try self.streams.append(self.allocator, .{
                .quic_id = stream_id,
                .session_idx = session_idx,
                .side = side,
            });
        }
    }

    fn opOpenBidi(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const stream_id = switch (side) {
            .client => blk: {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                break :blk try s.handle.openBidiStream();
            },
            .server => blk: {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                break :blk try s.handle.openBidiStream();
            },
        };
        if (self.streams.items.len < max_sessions * max_streams_per_session) {
            try self.streams.append(self.allocator, .{
                .quic_id = stream_id,
                .session_idx = session_idx,
                .side = side,
            });
        }
    }

    fn opSendBytes(self: *Harness, c: *Cursor, side: Side) !void {
        if (self.streams.items.len == 0) return error.NoStreamAvailable;
        const stream_idx = c.readU8() % @as(u8, @intCast(@min(self.streams.items.len, 256)));
        const rec = &self.streams.items[stream_idx];
        if (rec.finished or rec.reset) return; // best-effort
        const payload = c.readSlice(255);
        if (payload.len == 0) return;

        if (rec.side == .client) {
            const s = self.clientSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            // Side bit ignored: writes go through the side that opened
            // the stream (the only side that can write to it on uni).
            _ = side;
            try s.handle.writeStream(rec.quic_id, payload);
        } else {
            const s = self.serverSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            _ = side;
            try s.handle.writeStream(rec.quic_id, payload);
        }
    }

    fn opSendDatagram(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const payload = c.readSlice(255);
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendDatagram(payload);
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendDatagram(payload);
            },
        }
    }

    fn opSendMaxData(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const value = c.readU32Be();
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxData(value);
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxData(value);
            },
        }
    }

    fn opSendDrain(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendDrain();
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendDrain();
            },
        }
        // Drain is informative; no explicit-end flag.
    }

    fn opSendClose(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const code: u32 = @as(u32, c.readU8());
        const reason = c.readSlice(255);
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                if (s.closed) return;
                s.closed = true;
                try s.handle.close(code, reason);
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                if (s.closed) return;
                s.closed = true;
                try s.handle.close(code, reason);
            },
        }
        if (session_idx < max_sessions) self.session_explicitly_ended[session_idx] = true;
        self.deliberate_close = true;
    }

    fn opFinishSession(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                if (s.closed) return;
                s.closed = true;
                try s.handle.finish();
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                if (s.closed) return;
                s.closed = true;
                try s.handle.finish();
            },
        }
        if (session_idx < max_sessions) self.session_explicitly_ended[session_idx] = true;
        self.deliberate_close = true;
    }

    fn opResetStream(self: *Harness, c: *Cursor, side: Side) !void {
        if (self.streams.items.len == 0) return error.NoStreamAvailable;
        const stream_idx = c.readU8() % @as(u8, @intCast(@min(self.streams.items.len, 256)));
        const rec = &self.streams.items[stream_idx];
        const code: u32 = @as(u32, c.readU8());
        if (rec.reset or rec.finished) return;
        rec.reset = true;
        _ = side; // reset goes through whichever side opened the stream
        if (rec.side == .client) {
            const s = self.clientSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            try s.handle.resetStream(rec.quic_id, code);
        } else {
            const s = self.serverSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            try s.handle.resetStream(rec.quic_id, code);
        }
    }

    fn opFinishStream(self: *Harness, c: *Cursor, side: Side) !void {
        if (self.streams.items.len == 0) return error.NoStreamAvailable;
        const stream_idx = c.readU8() % @as(u8, @intCast(@min(self.streams.items.len, 256)));
        const rec = &self.streams.items[stream_idx];
        if (rec.finished or rec.reset) return;
        rec.finished = true;
        _ = side;
        if (rec.side == .client) {
            const s = self.clientSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            try s.handle.finishStream(rec.quic_id);
        } else {
            const s = self.serverSessionAt(rec.session_idx) orelse return error.NoSessionAvailable;
            try s.handle.finishStream(rec.quic_id);
        }
    }

    fn opSendMaxStreamsBidi(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const value: u64 = @as(u64, c.readU8());
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxStreamsBidi(value);
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxStreamsBidi(value);
            },
        }
    }

    fn opSendMaxStreamsUni(self: *Harness, c: *Cursor, side: Side) !void {
        const sid_idx = c.readU8();
        const session_idx = try self.pickSession(sid_idx, side);
        const value: u64 = @as(u64, c.readU8());
        switch (side) {
            .client => {
                const s = self.clientSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxStreamsUni(value);
            },
            .server => {
                const s = self.serverSessionAt(session_idx) orelse return error.NoSessionAvailable;
                try s.handle.sendMaxStreamsUni(value);
            },
        }
    }

    /// Folds an arbitrary byte index into one of the active session
    /// slots for the requested side. Returns `IndexOutOfBounds` (caller
    /// silently swallows) if no session of that side exists yet.
    fn pickSession(self: *Harness, raw: u8, side: Side) !usize {
        const len = switch (side) {
            .client => self.client_sessions.items.len,
            .server => self.server_sessions.items.len,
        };
        if (len == 0) return error.IndexOutOfBounds;
        const start: usize = @as(usize, raw) % len;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            const idx = (start + i) % len;
            const occupied = switch (side) {
                .client => self.client_sessions.items[idx] != null,
                .server => self.server_sessions.items[idx] != null,
            };
            if (occupied) return idx;
        }
        return error.IndexOutOfBounds;
    }

    fn clientSessionAt(self: *Harness, idx: usize) ?*ClientStream {
        if (idx >= self.client_sessions.items.len) return null;
        if (self.client_sessions.items[idx]) |*s| return s;
        return null;
    }

    fn serverSessionAt(self: *Harness, idx: usize) ?*ServerStream {
        if (idx >= self.server_sessions.items.len) return null;
        if (self.server_sessions.items[idx]) |*s| return s;
        return null;
    }
};

fn clearSessionEvents(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(http3_zig.session.Event),
) void {
    for (events.items) |event| event.deinit(allocator);
    events.clearRetainingCapacity();
}

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
        client_config: http3_zig.session.Config,
        server_config: http3_zig.session.Config,
    ) !void {
        self.client_tls = try http3_zig.client.initTlsContext(.{ .verify = .none });
        errdefer self.client_tls.deinit();

        self.server_tls = try http3_zig.server.initTlsContext(.{}, test_cert_pem, test_key_pem);
        errdefer self.server_tls.deinit();

        try initConnectedQuic(allocator, self.client_tls, self.server_tls, &self.client, &self.server);
        errdefer {
            self.server.deinit();
            self.client.deinit();
        }

        self.client_h3 = http3_zig.Session.init(allocator, .client, &self.client, client_config);
        errdefer self.client_h3.deinit();

        self.server_h3 = http3_zig.Session.init(allocator, .server, &self.server, server_config);
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

fn initConnectedQuic(
    allocator: std.mem.Allocator,
    client_tls: anytype,
    server_tls: anytype,
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
) !void {
    client.* = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    errdefer client.deinit();
    server.* = try quic_zig.Connection.initServer(allocator, server_tls);
    errdefer server.deinit();

    client.reveal_close_reason_on_wire = true;
    server.reveal_close_reason_on_wire = true;

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

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    _ = server.markPathValidated(server.activePathId());
}
