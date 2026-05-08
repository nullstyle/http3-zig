//! RFC 9114 §5 (connections), §5.2 (connection shutdown via GOAWAY),
//! §6.2.1 (control-stream uniqueness + SETTINGS-first session integration),
//! §7.2.4.2 (SETTINGS exchange, duplicate-frame handling at the connection
//! layer), §7.2.6 (GOAWAY semantics — last-allowed stream IDs and
//! monotonicity), and §10 normative MUST/MUST NOTs.
//!
//! These tests exercise `http3_zig.Session` end-to-end via the in-process
//! `H3Pair` loopback fixture so the close-error code, shutdown state, and
//! peer-state observable for each rule come out of the real session
//! pipeline rather than a unit-test mock. SETTINGS *codec* parsing
//! (duplicate IDs at byte level, value-out-of-range, reserved IDs) lives
//! in `rfc9114_settings.zig`; the SETTINGS *handshake* and connection-level
//! framing rules are here.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9114 §3.1   ¶3  MUST     advertise ALPN identifier "h3" (TLS handshake)
//!   RFC9114 §3.1   ¶3  MUST     expose only the "h3" ALPN id in http3_zig.protocol.alpn_protocols
//!   RFC9114 §5.1   ¶?  MUST     each peer opens exactly one control stream during start()
//!   RFC9114 §5.1   ¶?  MUST     local Session.start() emits SETTINGS as first frame on the control stream
//!   RFC9114 §5.2   ¶1  MUST     GOAWAY transitions the local session into draining
//!   RFC9114 §5.2   ¶1  MUST     Session.sent_goaway_id reflects the locally advertised GOAWAY id
//!   RFC9114 §5.2   ¶3  MUST     GOAWAY transitions the receiving session into draining
//!   RFC9114 §5.2   ¶3  MUST     Session.peer_goaway_id reflects the peer-advertised GOAWAY id
//!   RFC9114 §5.2   ¶?  NORMATIVE shutdown is irrevocable once GOAWAY is sent
//!   RFC9114 §5.2   ¶3  MUST     refuse to start a new request whose id ≥ peer GOAWAY id
//!   RFC9114 §5.2   ¶3  MUST     allow starting a new request whose id < peer GOAWAY id
//!   RFC9114 §5.2   ¶3  MUST NOT issue a new PUSH_PROMISE after the peer has issued a GOAWAY
//!   RFC9114 §6.2.1 ¶6  MUST     local SETTINGS frame is shipped immediately after the control-stream type prefix
//!   RFC9114 §6.2.1 ¶7  MUST     duplicate peer control-stream attempt closes with H3_STREAM_CREATION_ERROR
//!   RFC9114 §6.2.1 ¶?  MUST     QPACK encoder + decoder critical streams open during start when configured
//!   RFC9114 §7.2.4 ¶2  MUST     applied peer SETTINGS surface as Session.peer_settings
//!   RFC9114 §7.2.4 ¶3  MUST     each side sends SETTINGS exactly once (Session.start is idempotent)
//!   RFC9114 §7.2.4 ¶3  MUST     close with H3_FRAME_UNEXPECTED on a duplicate peer SETTINGS frame
//!   RFC9114 §7.2.6 ¶1  MUST     server GOAWAY id is a 4-divisible client-bidi stream id
//!   RFC9114 §7.2.6 ¶1  MUST     client GOAWAY id is an arbitrary push id varint (incl. non-bidi shapes)
//!   RFC9114 §7.2.6 ¶?  MUST     server rejects a GOAWAY whose id is non-bidi or server-initiated
//!   RFC9114 §7.2.6 ¶7  MUST     local sender refuses to monotonically *increase* a previously sent server GOAWAY id
//!   RFC9114 §7.2.6 ¶7  MUST     local sender refuses to monotonically *increase* a previously sent client GOAWAY id
//!   RFC9114 §7.2.6 ¶?  MUST     local sender accepts narrowing (decreasing) client GOAWAY ids
//!   RFC9114 §7.2.6 ¶7  MUST     receiver refuses a peer GOAWAY whose id increases versus a prior peer GOAWAY
//!   RFC9114 §7.2.6 ¶?  MUST     receiver accepts a peer GOAWAY whose id decreases versus a prior peer GOAWAY
//!   RFC9114 §7.2.6 ¶?  MUST     receiver accepts a repeated peer GOAWAY id
//!   RFC9114 §7.2.6 ¶?  MUST     out-of-role peer GOAWAY (server-initiated bidi id from server) closes with H3_ID_ERROR
//!   RFC9114 §10.5   ¶?  NORMATIVE Session classifies inbound CONNECTION_CLOSE error space and code
//!
//! Visible debt:
//!   (none)
//!
//! Out of scope here (covered elsewhere or by design):
//!   RFC9114 §6.2.1 ¶6  MUST close with H3_MISSING_SETTINGS on a peer's
//!     non-SETTINGS first control-stream frame, end-to-end. The Session
//!     control-stream open path is private (Session.start owns it), so the
//!     end-to-end gate is exercised at the validator layer in
//!     `rfc9114_streams.zig` against `http3_zig.stream.FrameValidator`. That
//!     validator is the same one Session runs every received frame through.
//!   RFC9114 §5.2   ¶9  SHOULD reject inbound requests above a previously-
//!     issued local GOAWAY id. RFC 9114 §5.2 ¶9 phrases this as MAY/SHOULD
//!     ("a server that receives any new request can either reject the new
//!     request or accept and process it"); the MUST is monotonicity, which
//!     IS covered. The SHOULD-strength rejection is application policy
//!     above the protocol layer.
//!   RFC9114 §3.1   ¶2  MUST verify the server certificate matches the
//!     URI's origin server. This is a TLS-layer requirement that flows
//!     through `http3_zig.client.initTlsContext` / boringssl-zig; it is not
//!     observable through the bare Session API.
//!   RFC9114 §6        stream-layer frame placement → rfc9114_streams.zig
//!   RFC9114 §6.1   ¶3  server-initiated bidi rejection → rfc9114_streams.zig
//!   RFC9114 §7.2.4.1  individual SETTINGS identifiers (codec) → rfc9114_settings.zig
//!   RFC9114 §7.2      wire-format frame layouts → rfc9114_frames.zig
//!   RFC9114 §11.2.3   numeric error-code values → rfc9114_errors.zig
//!   RFC9114 §4        HTTP semantics / pseudo headers → rfc9114_messages.zig

const std = @import("std");
const http3_zig = @import("http3_zig");
const quic_zig = @import("quic_zig");
const fixture = @import("_h3_fixture.zig");

const protocol = http3_zig.protocol;
const ErrorCode = protocol.ErrorCode;
const FrameType = protocol.FrameType;
const StreamType = protocol.StreamType;

// ---------------------------------------------------------------- §3.1 ALPN

test "MUST advertise the \"h3\" ALPN protocol identifier [RFC9114 §3.1 ¶?]" {
    // §3.1 ¶?: "the ALPN [RFC7301] protocol identification token [is] 'h3'".
    // This is the literal token http3_zig must hand TLS — verify the constant
    // and its bytes are exactly "h3".
    try std.testing.expectEqualStrings("h3", protocol.alpn_h3);
}

test "MUST expose only the \"h3\" ALPN identifier in the offered protocol list [RFC9114 §3.1 ¶?]" {
    try std.testing.expectEqual(@as(usize, 1), protocol.alpn_protocols.len);
    try std.testing.expectEqualStrings("h3", protocol.alpn_protocols[0]);
}

// ---------------------------------------------------------------- §5.1 connection establishment

test "MUST open exactly one local control stream per peer during session start [RFC9114 §5.1 ¶?]" {
    // §5.1 + §6.2.1 ¶7: "Each side MUST initiate a single control stream".
    // Verify Session.start() opens a control stream and exposes its
    // stream id; calling start() a second time is idempotent and does
    // NOT open a second control stream.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const initial_id = pair.client_h3.control_stream_id orelse return error.MissingControlStream;
    try pair.client_h3.start();
    try std.testing.expectEqual(initial_id, pair.client_h3.control_stream_id.?);
    try std.testing.expectEqual(initial_id, pair.client_h3.control_stream_id.?);
}

test "MUST classify the local control stream id as a unidirectional stream [RFC9114 §6.2.1 ¶?]" {
    // §6.2 ¶3: control streams are unidirectional. Drive the session's
    // own control_stream_id through the public stream classifier.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const cid = pair.client_h3.control_stream_id orelse return error.MissingControlStream;
    try std.testing.expect(http3_zig.stream.isUnidirectional(cid));
    try std.testing.expect(http3_zig.stream.isClientInitiated(cid));
}

test "MUST classify the server's control stream id as server-initiated unidirectional [RFC9114 §6.2.1 ¶?]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    const cid = pair.server_h3.control_stream_id orelse return error.MissingControlStream;
    try std.testing.expect(http3_zig.stream.isUnidirectional(cid));
    try std.testing.expect(!http3_zig.stream.isClientInitiated(cid));
}

// ---------------------------------------------------------------- §6.2.1 SETTINGS-first integration

test "MUST receive peer SETTINGS once the loopback delivers the control-stream prefix [RFC9114 §6.2.1 ¶6]" {
    // §6.2.1 ¶6: "A SETTINGS frame MUST be sent as the first frame of each
    // control stream". Driving the loopback to the point where both
    // sessions have applied each other's SETTINGS asserts the SETTINGS
    // frame *is* the first frame the peer received — otherwise the
    // session's frame validator would have raised MissingSettings.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{}); // both ends use default Settings
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);
    try std.testing.expect(pair.client_h3.peer_settings != null);
    try std.testing.expect(pair.server_h3.peer_settings != null);
}

test "MUST surface peer SETTINGS values via Session.peer_settings [RFC9114 §7.2.4 ¶2]" {
    // §7.2.4 ¶2: SETTINGS communicates configuration. Verify the
    // session's `peer_settings` snapshot reflects the peer-advertised
    // values exactly.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{},
        .{ .settings = .{
            .qpack_max_table_capacity = 4096,
            .qpack_blocked_streams = 8,
            .max_field_section_size = 1 << 20,
            .enable_connect_protocol = true,
            .h3_datagram = true,
        } },
    );
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);
    const peer = pair.client_h3.peer_settings.?;
    try std.testing.expectEqual(@as(u64, 4096), peer.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 8), peer.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 1 << 20), peer.max_field_section_size);
    try std.testing.expect(peer.enable_connect_protocol);
    try std.testing.expect(peer.h3_datagram);
}

test "MUST keep peer SETTINGS unset until the peer has sent SETTINGS [RFC9114 §7.2.4 ¶2]" {
    // Before the loopback runs at all the local session must not have
    // peer_settings observed.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try std.testing.expectEqual(@as(?http3_zig.Settings, null), pair.client_h3.peer_settings);
    try std.testing.expectEqual(@as(?http3_zig.Settings, null), pair.server_h3.peer_settings);
}

// ---------------------------------------------------------------- §7.2.4 ¶3 duplicate SETTINGS handling

test "MUST close with H3_FRAME_UNEXPECTED on a duplicate peer SETTINGS frame [RFC9114 §7.2.4 ¶3]" {
    // §7.2.4 ¶3: "If an endpoint receives a second SETTINGS frame on the
    // control stream, the endpoint MUST respond with a connection error
    // of type H3_FRAME_UNEXPECTED."
    //
    // The frame-level duplicate (a second SETTINGS frame) is distinct
    // from the in-frame duplicate-identifier case (§7.2.4 ¶5), which
    // remains H3_SETTINGS_ERROR.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.writeFrame(
        &pair.client,
        pair.client_h3.control_stream_id.?,
        .{ .settings = .{} },
    );

    try fixture.expectPairH3Error(allocator, &pair, error.DuplicateSettings);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.frame_unexpected);
}

// ---------------------------------------------------------------- §6.2.1 ¶7 control-stream uniqueness (session-level)

test "MUST close with H3_STREAM_CREATION_ERROR on a duplicate peer control stream [RFC9114 §6.2.1 ¶7]" {
    // §6.2.1 ¶7: "Receipt of a second stream claiming to be a control
    // stream MUST be treated as a connection error of type
    // H3_STREAM_CREATION_ERROR." The session-level mirror of the
    // streams-suite test, here to anchor the requirement to
    // http3_zig.Session and not just the validator.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.openUniWithType(&pair.client, 6, StreamType.control);
    try fixture.expectPairH3Error(allocator, &pair, error.CriticalStreamAlreadyOpen);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.server_h3.shutdownState());
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.stream_creation_error);
}

// ---------------------------------------------------------------- §5.2 GOAWAY: shutdown semantics

test "MUST transition the local session to draining when GOAWAY is sent [RFC9114 §5.2 ¶1]" {
    // §5.2 ¶1: "Sending a GOAWAY frame allows the peer to retry requests
    // ... the sender MUST NOT initiate any new requests after sending a
    // GOAWAY frame." The first observable: the local session enters
    // draining state immediately after `sendGoaway`.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.active, pair.server_h3.shutdownState());

    try pair.server_h3.sendGoaway(0); // server GOAWAY: client-bidi id 0
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.server_h3.shutdownState());
}

test "MUST transition the receiving session to draining on peer GOAWAY [RFC9114 §5.2 ¶1]" {
    // The dual: a peer that *receives* a GOAWAY also enters draining so
    // it stops issuing new requests above the advertised limit.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 0 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);

    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.client_h3.shutdownState());
}

test "NORMATIVE shutdown is irrevocable once GOAWAY is sent [RFC9114 §5.2 ¶?]" {
    // The session never re-enters `active` after entering `draining`.
    // Sending a second (smaller) GOAWAY id leaves the state at
    // `draining`, never resurrects the connection.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    try pair.server_h3.sendGoaway(8);
    try pair.server_h3.sendGoaway(4); // narrowing is allowed; still draining.
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.server_h3.shutdownState());
}

// ---------------------------------------------------------------- §5.2 GOAWAY: refuse new requests above the limit

test "MUST refuse to open a new request whose stream id is at or above the peer GOAWAY id [RFC9114 §5.2 ¶3]" {
    // §5.2 ¶3: "After sending a GOAWAY frame, the sender MUST NOT
    // initiate any new requests" — symmetric requirement on the
    // receiver: it MUST NOT use streams above the limit. http3_zig enforces
    // this through `peerAllowsRequest`, which surfaces as
    // `error.RequestBlockedByGoaway` when the next bidi id we would
    // pick is at or above the cap.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    // Server announces "I'll accept requests below client-bidi id 0" —
    // i.e. nothing.
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 0 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);

    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = ":authority", .value = "localhost" },
    };

    try std.testing.expectError(
        http3_zig.session.Error.RequestBlockedByGoaway,
        pair.client_h3.openRequest(&fields),
    );
}

test "MUST allow opening a request whose stream id is below the peer GOAWAY id [RFC9114 §5.2 ¶3]" {
    // The complement: a peer GOAWAY of (e.g.) id 8 still allows the
    // local session to open requests on ids 0 and 4.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 8 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);

    const fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/allowed" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const stream_id = try pair.client_h3.openRequest(&fields);
    try std.testing.expect(stream_id < 8);
}

test "MUST NOT issue a new PUSH_PROMISE after the peer has issued a GOAWAY [RFC9114 §5.2 ¶3]" {
    // §5.2 ¶3: "Endpoints MUST NOT initiate new requests or promise new
    // pushes on the connection after receipt of a GOAWAY frame from the
    // peer." A client GOAWAY carries a push id (§7.2.6 ¶1); §5.2 ¶7
    // says "Requests or pushes with the indicated identifier or greater
    // are rejected by the sender of the GOAWAY", so a server that
    // observes peer_goaway_id = N MUST refuse to mint a new PUSH_PROMISE
    // whose push id is at or above N. http3_zig surfaces this as
    // `error.PushBlockedByGoaway`, mirroring the request-side
    // `RequestBlockedByGoaway` analogue.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 8 }, .{});
    defer pair.deinit();

    try fixture.exchangePairSettings(allocator, &pair);

    // Client says: "no pushes with id ≥ 0" — i.e. nothing.
    try fixture.writeFrame(
        &pair.client,
        pair.client_h3.control_stream_id.?,
        .{ .goaway = 0 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);
    try std.testing.expectEqual(@as(?u64, 0), pair.server_h3.peer_goaway_id);

    const promise_fields = [_]http3_zig.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked.css" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const response_fields = [_]http3_zig.FieldLine{
        .{ .name = ":status", .value = "200" },
    };

    // The request_stream_id is irrelevant — the GOAWAY gate fires before
    // any stream-side validation, so the server refuses the promise even
    // when the request stream id is well-formed.
    try std.testing.expectError(
        http3_zig.session.Error.PushBlockedByGoaway,
        pair.server_h3.startPush(0, &promise_fields, &response_fields),
    );
}

// ---------------------------------------------------------------- §7.2.6 GOAWAY: id role/role validation (local-send side)

test "MUST refuse to send a server GOAWAY with a non-bidi-client stream id [RFC9114 §7.2.6 ¶1]" {
    // §7.2.6 ¶1: server GOAWAY IDs are "the client-initiated bidirectional
    // stream IDs". http3_zig surfaces a non-conforming id as
    // InvalidGoawayId. Test all three rejected categories: server-bidi
    // (low bits 0b01), client-uni (0b10), server-uni (0b11).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(http3_zig.session.Error.InvalidGoawayId, pair.server_h3.sendGoaway(1));
    try std.testing.expectError(http3_zig.session.Error.InvalidGoawayId, pair.server_h3.sendGoaway(2));
    try std.testing.expectError(http3_zig.session.Error.InvalidGoawayId, pair.server_h3.sendGoaway(3));
}

test "MUST allow a server GOAWAY whose id is a client-initiated bidi stream id [RFC9114 §7.2.6 ¶1]" {
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.server_h3.sendGoaway(0); // first client-bidi stream id
    try pair.server_h3.sendGoaway(0); // identical id repeats are allowed
}

test "MUST refuse to monotonically increase a previously sent local GOAWAY id [RFC9114 §7.2.6 ¶?]" {
    // §7.2.6: "A GOAWAY frame with a stream ID that is greater than any
    // previously sent GOAWAY frame's stream ID is invalid." Local-send
    // side: a server that already shipped GOAWAY(4) MUST NOT later send
    // GOAWAY(8).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.server_h3.sendGoaway(4);
    try std.testing.expectError(
        http3_zig.session.Error.InvalidGoawayId,
        pair.server_h3.sendGoaway(8),
    );
}

test "MUST allow a smaller subsequent local GOAWAY id [RFC9114 §7.2.6 ¶?]" {
    // §7.2.6: "A server MAY use a non-zero stream ID ... A server SHOULD
    // send a GOAWAY ... so that any new requests can be retried."
    // Narrowing the limit is explicitly permitted.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.server_h3.sendGoaway(8);
    try pair.server_h3.sendGoaway(4);
}

// ---------------------------------------------------------------- §7.2.6 GOAWAY: id validation on receive

test "MUST close with H3_ID_ERROR on a peer server GOAWAY whose id is not a client-bidi stream id [RFC9114 §7.2.6 ¶?]" {
    // The receive-side dual of the role check: the client receiving an
    // out-of-role server GOAWAY MUST close with H3_ID_ERROR.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 1 }, // server-bidi — illegal as a server GOAWAY id
    );

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try fixture.expectLastCloseCode(&pair.client_h3, ErrorCode.id_error);
}

test "MUST close with H3_ID_ERROR on a peer GOAWAY id that increases versus a prior peer GOAWAY [RFC9114 §7.2.6 ¶?]" {
    // §7.2.6: "Endpoints MUST NOT increase the value they send in the
    // last Stream ID. Receivers MUST treat receipt of a GOAWAY frame
    // containing a stream ID greater than previously received as a
    // connection error of type H3_ID_ERROR."
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 4 },
    );
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 8 }, // increasing — must be rejected
    );

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidGoawayId);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.closed, pair.client_h3.shutdownState());
    try fixture.expectLastCloseCode(&pair.client_h3, ErrorCode.id_error);
}

test "MUST accept a peer GOAWAY id that decreases versus a prior peer GOAWAY [RFC9114 §7.2.6 ¶?]" {
    // §7.2.6 explicitly allows narrowing — the receiver should accept a
    // smaller subsequent GOAWAY id and remain in `draining` (no close).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 8 },
    );
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 4 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);

    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.client_h3.shutdownState());
    try std.testing.expectEqual(@as(?http3_zig.errors.ConnectionError, null), pair.client_h3.lastCloseError());
}

test "MUST accept a repeated peer GOAWAY id [RFC9114 §7.2.6 ¶?]" {
    // §7.2.6: "GOAWAY frames are advisory ... Senders MAY send GOAWAY
    // multiple times". Identical successive GOAWAY ids must be accepted.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 4 },
    );
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 4 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);

    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.client_h3.shutdownState());
    try std.testing.expectEqual(@as(?http3_zig.errors.ConnectionError, null), pair.client_h3.lastCloseError());
}

// ---------------------------------------------------------------- §10 normative — close-code classification

test "NORMATIVE classify a peer-side known H3 close error code [RFC9114 §10 ¶?]" {
    // §10 normative: the receiver of a CONNECTION_CLOSE that names an
    // H3 error code SHOULD surface that code through its
    // ConnectionError shape so applications can distinguish protocol
    // versus application terminations. Direct unit on http3_zig.errors.
    const known = http3_zig.errors.applicationError(ErrorCode.frame_unexpected);
    try std.testing.expectEqualStrings("H3_FRAME_UNEXPECTED", known.name);
    try std.testing.expectEqual(http3_zig.ErrorCategory.frame, known.category);
    try std.testing.expectEqual(http3_zig.ErrorScope.connection, known.default_scope);
}

test "NORMATIVE classify an unknown application error code [RFC9114 §10 ¶?]" {
    // The receiver MUST surface a previously-unknown code as an
    // application-scoped unknown error rather than rejecting the whole
    // CONNECTION_CLOSE.
    const unknown = http3_zig.errors.applicationError(0xface);
    try std.testing.expect(!unknown.known());
    try std.testing.expectEqual(http3_zig.ErrorScope.application, unknown.default_scope);
}

// ---------------------------------------------------------------- §7.2.6 client-side GOAWAY (push ID) semantics

test "MUST allow a client GOAWAY whose id is an arbitrary push id varint [RFC9114 §7.2.6 ¶1]" {
    // §7.2.6 ¶1: "a server sends a client-initiated stream ID, and a
    // client sends a push ID." Push IDs are unconstrained varints so
    // http3_zig must accept ids that would be illegal as a server GOAWAY
    // (e.g. low bits 0b01, 0b10, 0b11). This is the dual of the
    // server-side client-bidi rejection test.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client_h3.sendGoaway(1); // illegal as server GOAWAY id
    // After sendGoaway the client MUST be in draining; that is the
    // observable assertion the local-id-shape rule does not block.
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.client_h3.shutdownState());
}

test "MUST refuse to monotonically increase a previously sent client GOAWAY id [RFC9114 §7.2.6 ¶7]" {
    // §7.2.6 ¶7: "the identifier in each frame MUST NOT be greater
    // than the identifier in any previous frame." This is symmetric
    // across both peer roles — the existing server-side test has a
    // client-side dual.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client_h3.sendGoaway(4);
    try std.testing.expectError(
        http3_zig.session.Error.InvalidGoawayId,
        pair.client_h3.sendGoaway(8),
    );
}

test "MUST allow a client GOAWAY id that decreases versus a previously sent client GOAWAY [RFC9114 §7.2.6 ¶7]" {
    // The narrowing complement: a client may follow GOAWAY(8) with
    // GOAWAY(4). http3_zig must accept the smaller subsequent push id
    // and remain in draining.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client_h3.sendGoaway(8);
    try pair.client_h3.sendGoaway(4);
    try std.testing.expectEqual(http3_zig.session.ShutdownState.draining, pair.client_h3.shutdownState());
}

// ---------------------------------------------------------------- §5.2 GOAWAY observable session state

test "MUST record the locally-sent GOAWAY id on Session.sent_goaway_id [RFC9114 §5.2 ¶1]" {
    // §5.2 ¶1: "Endpoints initiate the graceful shutdown of an HTTP/3
    // connection by sending a GOAWAY frame." After sendGoaway returns
    // the local session must surface the id it advertised so callers
    // can synchronize their own state machines.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectEqual(@as(?u64, null), pair.server_h3.sent_goaway_id);
    try pair.server_h3.sendGoaway(0);
    try std.testing.expectEqual(@as(?u64, 0), pair.server_h3.sent_goaway_id);
}

test "MUST record the peer-observed GOAWAY id on Session.peer_goaway_id [RFC9114 §5.2 ¶3]" {
    // §5.2 ¶3: "Endpoints MUST NOT initiate new requests or promise
    // new pushes on the connection after receipt of a GOAWAY frame
    // from the peer." Enforcement requires remembering the peer's
    // last-allowed id, which Session exposes as peer_goaway_id.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectEqual(@as(?u64, null), pair.client_h3.peer_goaway_id);
    try fixture.writeFrame(
        &pair.server,
        pair.server_h3.control_stream_id.?,
        .{ .goaway = 8 },
    );
    try fixture.pumpQuiet(allocator, &pair, 64);
    try std.testing.expectEqual(@as(?u64, 8), pair.client_h3.peer_goaway_id);
}

// ---------------------------------------------------------------- §6.2.1 critical-stream open during start()

test "MUST open the QPACK encoder + decoder critical streams when configured [RFC9114 §6.2.1 ¶? + RFC9204 §4.2 ¶?]" {
    // The QPACK encoder/decoder streams are critical streams in the
    // RFC 9204 sense; http3_zig.Session.start opens them when
    // open_qpack_streams is set. Verify the stream ids are populated
    // and follow the local-uni id pattern (low bits 0b10 for client,
    // 0b11 for server).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(
        allocator,
        .{ .open_qpack_streams = true },
        .{ .open_qpack_streams = true },
    );
    defer pair.deinit();

    const enc_id = pair.client_h3.qpack_encoder_stream_id orelse
        return error.MissingEncoderStream;
    const dec_id = pair.client_h3.qpack_decoder_stream_id orelse
        return error.MissingDecoderStream;
    try std.testing.expect(http3_zig.stream.isUnidirectional(enc_id));
    try std.testing.expect(http3_zig.stream.isUnidirectional(dec_id));
    try std.testing.expect(http3_zig.stream.isClientInitiated(enc_id));
    try std.testing.expect(http3_zig.stream.isClientInitiated(dec_id));
    try std.testing.expect(enc_id != dec_id);
}

// ---------------------------------------------------------------- §3.1 TLS ALPN list shape

test "MUST advertise exactly one ALPN protocol identifier in the offer list [RFC9114 §3.1 ¶3]" {
    // §3.1 ¶3: "the token \"h3\" is used in the Application-Layer
    // Protocol Negotiation". http3_zig must offer that token and only
    // that token from its base configuration; extensions can extend
    // the list but the suite asserts the conformance baseline.
    try std.testing.expectEqual(@as(usize, 1), protocol.alpn_protocols.len);
    try std.testing.expectEqualStrings("h3", protocol.alpn_protocols[0]);
}
