//! Observability surfaces for embedders.
//!
//! http3_zig does not write logs itself. Applications can install callbacks,
//! snapshot counters, and translate trace events into qlog JSON, metrics, or
//! local diagnostics.

const std = @import("std");
const boringssl = @import("boringssl");
const quic_zig = @import("quic_zig");

const protocol = @import("protocol.zig");

pub const KeylogCallback = boringssl.tls.KeylogCallback;
pub const QuicQlogCallback = quic_zig.QlogCallback;
pub const QuicQlogEvent = quic_zig.QlogEvent;
pub const QuicQlogEventName = quic_zig.QlogEventName;

pub const TraceEventName = enum {
    control_stream_opened,
    qpack_streams_opened,
    settings_sent,
    settings_received,
    request_opened,
    push_stream_received,
    cancel_push_sent,
    cancel_push_received,
    priority_update_sent,
    priority_update_received,
    headers_sent,
    headers_received,
    trailers_sent,
    trailers_received,
    data_sent,
    data_received,
    datagram_sent,
    datagram_received,
    datagram_acked,
    datagram_lost,
    capsule_sent,
    goaway_sent,
    goaway_received,
    stream_finished,
    stream_reset_sent,
    stream_reset_received,
    request_rejected,
    connection_close_sent,
    connection_closed,
    ignored_unknown_frame,
    qpack_encoder_bytes_sent,
    qpack_encoder_instruction_received,
    qpack_decoder_instruction_sent,
    qpack_decoder_instruction_received,
    flow_blocked,
    connection_ids_needed,
    webtransport_stream_opened,
    webtransport_stream_data_received,
    webtransport_stream_finished,
    webtransport_stream_reset_received,
    /// Peer sent `WT_DATA_BLOCKED` (draft-ietf-webtrans-http3-15
    /// §5.6.5). The application should consider raising
    /// `local_max_data` via `Session.sendWebTransportMaxData`.
    webtransport_peer_data_blocked,
    /// Peer sent `WT_STREAMS_BLOCKED_BIDI` or `_UNI`
    /// (§5.6.3). Application may want to raise the matching
    /// `local_max_streams_*` via `Session.sendWebTransportMaxStreams`.
    webtransport_peer_streams_blocked,
    /// Peer sent `DRAIN_WEBTRANSPORT_SESSION` (§5.5).
    webtransport_session_drain_received,
};

pub const TraceEvent = struct {
    name: TraceEventName,
    role: protocol.Role,
    stream_id: ?u64 = null,
    frame_type: ?u64 = null,
    bytes: usize = 0,
    count: usize = 0,
    value: ?u64 = null,
    error_code: ?u64 = null,
    early_data: bool = false,
};

pub const TraceCallback = *const fn (user_data: ?*anyopaque, event: TraceEvent) void;

pub const Hooks = struct {
    callback: ?TraceCallback = null,
    user_data: ?*anyopaque = null,

    pub fn emit(self: Hooks, event: TraceEvent) void {
        if (self.callback) |callback| callback(self.user_data, event);
    }
};

pub const Metrics = struct {
    control_streams_opened: u64 = 0,
    qpack_stream_pairs_opened: u64 = 0,
    settings_sent: u64 = 0,
    settings_received: u64 = 0,
    requests_opened: u64 = 0,
    push_streams_received: u64 = 0,
    cancel_pushes_sent: u64 = 0,
    cancel_pushes_received: u64 = 0,
    priority_updates_sent: u64 = 0,
    priority_updates_received: u64 = 0,

    frames_sent: u64 = 0,
    frames_received: u64 = 0,
    headers_sent: u64 = 0,
    headers_received: u64 = 0,
    trailers_sent: u64 = 0,
    trailers_received: u64 = 0,
    data_frames_sent: u64 = 0,
    data_frames_received: u64 = 0,
    data_bytes_sent: u64 = 0,
    data_bytes_received: u64 = 0,

    datagrams_sent: u64 = 0,
    datagrams_received: u64 = 0,
    datagrams_acked: u64 = 0,
    datagrams_lost: u64 = 0,
    /// Inbound DATAGRAMs whose embedded stream id doesn't reference a
    /// known session stream. Per RFC 9297 §5, these are silently
    /// dropped rather than surfaced as `datagram` events.
    datagrams_dropped_orphan: u64 = 0,
    datagram_bytes_sent: u64 = 0,
    datagram_bytes_received: u64 = 0,

    capsules_sent: u64 = 0,
    capsule_value_bytes_sent: u64 = 0,

    goaways_sent: u64 = 0,
    goaways_received: u64 = 0,
    stream_fin_received: u64 = 0,
    stream_resets_sent: u64 = 0,
    stream_resets_received: u64 = 0,
    requests_rejected: u64 = 0,
    connection_closes_sent: u64 = 0,
    connection_closes_received: u64 = 0,
    ignored_unknown_frames: u64 = 0,

    qpack_encoder_bytes_sent: u64 = 0,
    qpack_encoder_instructions_received: u64 = 0,
    qpack_decoder_instructions_sent: u64 = 0,
    qpack_decoder_instructions_received: u64 = 0,

    flow_blocked_events: u64 = 0,
    connection_ids_needed_events: u64 = 0,

    webtransport_streams_opened: u64 = 0,
    webtransport_stream_data_received: u64 = 0,
    webtransport_stream_data_bytes_received: u64 = 0,
    webtransport_streams_finished: u64 = 0,
    webtransport_stream_resets_received: u64 = 0,
    /// Inbound `WT_DATA_BLOCKED` capsules.
    webtransport_peer_data_blocked: u64 = 0,
    /// Inbound `WT_STREAMS_BLOCKED_BIDI` + `WT_STREAMS_BLOCKED_UNI`
    /// capsules (combined).
    webtransport_peer_streams_blocked: u64 = 0,
    /// Inbound `DRAIN_WEBTRANSPORT_SESSION` capsules.
    webtransport_session_drain_received: u64 = 0,

    pub fn observe(self: *Metrics, event: TraceEvent) void {
        switch (event.name) {
            .control_stream_opened => increment(&self.control_streams_opened),
            .qpack_streams_opened => increment(&self.qpack_stream_pairs_opened),
            .settings_sent => {
                increment(&self.settings_sent);
                increment(&self.frames_sent);
            },
            .settings_received => {
                increment(&self.settings_received);
                increment(&self.frames_received);
            },
            .request_opened => increment(&self.requests_opened),
            .push_stream_received => increment(&self.push_streams_received),
            .cancel_push_sent => {
                increment(&self.cancel_pushes_sent);
                increment(&self.frames_sent);
            },
            .cancel_push_received => {
                increment(&self.cancel_pushes_received);
                increment(&self.frames_received);
            },
            .priority_update_sent => {
                increment(&self.priority_updates_sent);
                increment(&self.frames_sent);
            },
            .priority_update_received => {
                increment(&self.priority_updates_received);
                increment(&self.frames_received);
            },
            .headers_sent => {
                increment(&self.headers_sent);
                increment(&self.frames_sent);
            },
            .headers_received => {
                increment(&self.headers_received);
                increment(&self.frames_received);
            },
            .trailers_sent => {
                increment(&self.trailers_sent);
                increment(&self.frames_sent);
            },
            .trailers_received => {
                increment(&self.trailers_received);
                increment(&self.frames_received);
            },
            .data_sent => {
                increment(&self.data_frames_sent);
                increment(&self.frames_sent);
                addBytes(&self.data_bytes_sent, event.bytes);
            },
            .data_received => {
                increment(&self.data_frames_received);
                increment(&self.frames_received);
                addBytes(&self.data_bytes_received, event.bytes);
            },
            .datagram_sent => {
                increment(&self.datagrams_sent);
                addBytes(&self.datagram_bytes_sent, event.bytes);
            },
            .datagram_received => {
                increment(&self.datagrams_received);
                addBytes(&self.datagram_bytes_received, event.bytes);
            },
            .datagram_acked => increment(&self.datagrams_acked),
            .datagram_lost => increment(&self.datagrams_lost),
            .capsule_sent => {
                increment(&self.capsules_sent);
                addBytes(&self.capsule_value_bytes_sent, event.bytes);
            },
            .goaway_sent => {
                increment(&self.goaways_sent);
                increment(&self.frames_sent);
            },
            .goaway_received => {
                increment(&self.goaways_received);
                increment(&self.frames_received);
            },
            .stream_finished => increment(&self.stream_fin_received),
            .stream_reset_sent => increment(&self.stream_resets_sent),
            .stream_reset_received => increment(&self.stream_resets_received),
            .request_rejected => increment(&self.requests_rejected),
            .connection_close_sent => increment(&self.connection_closes_sent),
            .connection_closed => increment(&self.connection_closes_received),
            .ignored_unknown_frame => increment(&self.ignored_unknown_frames),
            .qpack_encoder_bytes_sent => addBytes(&self.qpack_encoder_bytes_sent, event.bytes),
            .qpack_encoder_instruction_received => increment(&self.qpack_encoder_instructions_received),
            .qpack_decoder_instruction_sent => increment(&self.qpack_decoder_instructions_sent),
            .qpack_decoder_instruction_received => increment(&self.qpack_decoder_instructions_received),
            .flow_blocked => increment(&self.flow_blocked_events),
            .connection_ids_needed => increment(&self.connection_ids_needed_events),
            .webtransport_stream_opened => increment(&self.webtransport_streams_opened),
            .webtransport_stream_data_received => {
                increment(&self.webtransport_stream_data_received);
                addBytes(&self.webtransport_stream_data_bytes_received, event.bytes);
            },
            .webtransport_stream_finished => increment(&self.webtransport_streams_finished),
            .webtransport_stream_reset_received => increment(&self.webtransport_stream_resets_received),
            .webtransport_peer_data_blocked => increment(&self.webtransport_peer_data_blocked),
            .webtransport_peer_streams_blocked => increment(&self.webtransport_peer_streams_blocked),
            .webtransport_session_drain_received => increment(&self.webtransport_session_drain_received),
        }
    }
};

fn increment(counter: *u64) void {
    addCounter(counter, 1);
}

fn addBytes(counter: *u64, value: usize) void {
    addCounter(counter, intCastCounter(value));
}

fn addCounter(counter: *u64, value: u64) void {
    const max = std.math.maxInt(u64);
    if (counter.* > max - value) {
        counter.* = max;
    } else {
        counter.* += value;
    }
}

fn intCastCounter(value: usize) u64 {
    return std.math.cast(u64, value) orelse std.math.maxInt(u64);
}

test "metrics observes trace events" {
    var metrics: Metrics = .{};
    metrics.observe(.{ .name = .headers_received, .role = .server, .stream_id = 0, .count = 3 });
    metrics.observe(.{ .name = .data_received, .role = .server, .stream_id = 0, .bytes = 12 });
    metrics.observe(.{ .name = .datagram_sent, .role = .server, .stream_id = 0, .bytes = 7 });

    try std.testing.expectEqual(@as(u64, 2), metrics.frames_received);
    try std.testing.expectEqual(@as(u64, 1), metrics.headers_received);
    try std.testing.expectEqual(@as(u64, 12), metrics.data_bytes_received);
    try std.testing.expectEqual(@as(u64, 1), metrics.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 7), metrics.datagram_bytes_sent);

    metrics.data_bytes_received = std.math.maxInt(u64) - 1;
    metrics.observe(.{ .name = .data_received, .role = .server, .stream_id = 0, .bytes = 8 });
    try std.testing.expectEqual(std.math.maxInt(u64), metrics.data_bytes_received);
}
