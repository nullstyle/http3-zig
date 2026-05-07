//! RFC 9218 — Extensible Prioritization Scheme for HTTP.
//!
//! RFC 9218 specifies how HTTP endpoints communicate priority signals
//! through:
//!
//!   * a Priority HTTP field (§4) carrying a Structured Fields dictionary
//!     with `u` (urgency, 0..7, default 3) and `i` (incremental, boolean,
//!     default false) parameters;
//!   * a PRIORITY_UPDATE HTTP/3 frame (§7) — type 0xF0700 for request
//!     streams and 0xF0701 for push streams — sent on the control stream
//!     to revise a previously signalled priority.
//!
//! This suite locks down null3's three normative surfaces for those rules:
//!
//!   * `null3.priority.Priority.parse` / `.encode` — the Structured Fields
//!     dictionary parser, default values, and unknown-parameter ignore
//!     behaviour (§4, §4.1, §4.2, §8 ¶unknown-parameter).
//!   * `null3.priority.fromFieldLines` — extraction from a QPACK
//!     field-section value list, case-insensitive (§4 ¶1; HTTP fields are
//!     case-insensitive per RFC 9110 §5.1).
//!   * `null3.session.Session.sendPriorityUpdateForRequest`
//!     / `.sendPriorityUpdateForPush` and the receive path
//!     (`PriorityUpdateEvent`) — semantic validation of target
//!     prioritized-element IDs (§7.1, §8) and the round-trip through a
//!     real HTTP/3 control-stream frame.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9218 §4   ¶3      MUST     Priority field name is "priority" (case-insensitive)
//!   RFC9218 §4.1 ¶1      MUST     urgency is an integer in 0..7
//!   RFC9218 §4.1 ¶1      NORMATIVE default urgency is 3 when the parameter is absent
//!   RFC9218 §4.2 ¶1      NORMATIVE incremental defaults to false (?0) when absent
//!   RFC9218 §4.2 ¶1      MUST     incremental is a Structured Fields boolean
//!   RFC9218 §4   ¶?      MUST     parse a Priority field with no parameters as the defaults
//!   RFC9218 §4   ¶?      MUST     parse "u=N" with N in 0..7
//!   RFC9218 §4   ¶7      MUST     silently ignore an out-of-range urgency value (urgency falls back to default)
//!   RFC9218 §4   ¶7      MUST     silently ignore a wrong-type urgency value (urgency falls back to default)
//!   RFC9218 §4   ¶7      MUST     silently ignore a wrong-type incremental value (incremental falls back to default)
//!   RFC9218 §4   ¶?      MUST     accept "i" as bare-true SF boolean
//!   RFC9218 §4   ¶?      MUST     accept "i=?1" / "i=?0" as SF boolean
//!   RFC9218 §8   ¶?      MUST     ignore unknown parameters in the Priority dictionary
//!   RFC9218 §4   ¶?      MUST     parse parameters in any order
//!   RFC9218 §4   ¶?      MUST     tolerate optional whitespace between members
//!   RFC9218 §4   ¶3      MUST     fromFieldLines is case-insensitive on the "priority" name
//!   RFC9218 §4   ¶3      NORMATIVE last Priority field wins when duplicated
//!   RFC9218 §4   ¶3      NORMATIVE fromFieldLines returns null when no Priority field is present
//!   RFC9218 §4   ¶?      MUST     encode emits "u=N" for urgency N
//!   RFC9218 §4   ¶?      MUST     encode emits "i" sentinel for incremental=true
//!   RFC9218 §4   ¶?      MUST NOT emit "i" when incremental=false
//!   RFC9218 §4   ¶?      MUST     encoded value re-parses to the same Priority
//!   RFC9218 §4   ¶?      MUST NOT overrun the encode buffer
//!   RFC9218 §11  ¶?      MUST     PRIORITY_UPDATE frame type IDs are 0xF0700 / 0xF0701
//!   RFC9218 §7.2 ¶?      MUST     PRIORITY_UPDATE Request frame round-trips Prioritized Element ID + Priority value
//!   RFC9218 §7.2 ¶?      MUST     PRIORITY_UPDATE Push frame round-trips Prioritized Element ID + Priority value
//!   RFC9218 §7.2 ¶?      NORMATIVE empty Priority field value is allowed (server applies defaults)
//!   RFC9218 §7.1 ¶?      MUST     client may send PRIORITY_UPDATE for a request stream
//!   RFC9218 §7.1 ¶?      MUST NOT send PRIORITY_UPDATE for a non-request stream id (server-initiated, uni)
//!   RFC9218 §7.1 ¶?      MUST NOT send PRIORITY_UPDATE for a push id when push not enabled
//!   RFC9218 §7.1 ¶?      MUST NOT a server send PRIORITY_UPDATE
//!   RFC9218 §8   ¶target server MUST close with H3_ID_ERROR on PRIORITY_UPDATE for an invalid request stream id
//!   RFC9218 §8   ¶?      server MUST close with H3_ID_ERROR on PRIORITY_UPDATE-Push when push is not enabled
//!   RFC9218 §8   ¶?      server MUST close with H3_GENERAL_PROTOCOL_ERROR on a structurally malformed Priority value
//!   RFC9218 §4   ¶7      MUST     silently ignore an out-of-range urgency in a PRIORITY_UPDATE Priority Field Value
//!   RFC9218 §8   ¶?      client MUST close with H3_FRAME_UNEXPECTED on receiving PRIORITY_UPDATE
//!   RFC9218 §7   ¶?      MUST     received PRIORITY_UPDATE is reflected in priorityForRequest
//!   RFC9218 §5   ¶?      NORMATIVE PRIORITY_UPDATE value overrides the request-header value
//!   RFC9218 §4   ¶5      NORMATIVE priorityForRequest returns null when no Priority signal has been seen
//!   RFC9218 §7   ¶4      NORMATIVE PRIORITY_UPDATE received before the stream opens is buffered
//!   RFC9218 §7   ¶3      NORMATIVE empty PRIORITY_UPDATE Priority Field Value applies parameter defaults
//!
//! Out of scope here (covered elsewhere or by design):
//!   RFC9218 §7.2 wire layout (frame-type ID, Prioritized Element ID
//!                varint, Priority Field Value byte run) → handled by the
//!                generic frame codec in rfc9114_frames.zig and the IANA
//!                IDs in rfc9114_protocol.zig.
//!   RFC9218 §7.2 placement — control stream only, frame_unexpected on
//!                request/push stream — exercised in rfc9114_streams.zig
//!                via the FrameValidator suite.
//!   RFC9218 §6   PRIORITY_UPDATE frame ack/observability — internal to
//!                null3's tracing layer, not an interop requirement.
//!   RFC9218 §9   Scheduling policy — RFC explicitly leaves the policy
//!                to the implementation; nothing to lock down here.
//!   RFC9218 §12  "Priority signals MUST NOT leak application data" —
//!                generally not testable: the priority signal is
//!                application data by definition, and the rule is a
//!                cross-cutting design constraint rather than an
//!                observable behavior at any single API surface.

const std = @import("std");
const null3 = @import("null3");
const nullq = @import("nullq");
const fixture = @import("_h3_fixture.zig");

const priority = null3.priority;
const Priority = null3.Priority;
const protocol = null3.protocol;
const ErrorCode = protocol.ErrorCode;

// ---------------------------------------------------------------- §4 — Priority field name

test "MUST register the Priority HTTP field name as \"priority\" [RFC9218 §4 ¶3]" {
    // §4 ¶3: "The 'Priority' HTTP header field is used by clients ..."
    // RFC 9110 §5.1 makes HTTP field names case-insensitive; RFC 9114
    // §4.2 narrows that further to "lowercase on the wire". null3
    // exposes the canonical lowercase token.
    try std.testing.expectEqualStrings("priority", priority.field_name);
}

// ---------------------------------------------------------------- §4.1 — urgency `u`

test "NORMATIVE Priority defaults urgency to 3 when the field is empty [RFC9218 §4.1 ¶1]" {
    // §4.1 ¶1: "If the urgency parameter is not present, the default
    // value is 3." Verify this through the parser by feeding an empty
    // string (= field absent / no parameters).
    const p = try Priority.parse("");
    try std.testing.expectEqual(@as(u3, 3), p.urgency);
}

test "NORMATIVE Priority defaults incremental to false when the field is empty [RFC9218 §4.2 ¶1]" {
    // §4.2 ¶1: "If the incremental parameter is not present, the default
    // value is false."
    const p = try Priority.parse("");
    try std.testing.expect(!p.incremental);
}

test "MUST accept urgency 0 (highest priority) [RFC9218 §4.1 ¶1]" {
    // §4.1 ¶1: range is "0..7"; lower values are higher priority.
    const p = try Priority.parse("u=0");
    try std.testing.expectEqual(@as(u3, 0), p.urgency);
}

test "MUST accept urgency 7 (lowest priority) [RFC9218 §4.1 ¶1]" {
    const p = try Priority.parse("u=7");
    try std.testing.expectEqual(@as(u3, 7), p.urgency);
}

test "MUST accept every urgency in the 0..7 range [RFC9218 §4.1 ¶1]" {
    // Iterate the entire allowed integer range — the parser must
    // accept every value from 0 through 7 inclusive.
    var u: u8 = 0;
    while (u <= 7) : (u += 1) {
        var buf: [4]u8 = undefined;
        const value = try std.fmt.bufPrint(&buf, "u={}", .{u});
        const p = try Priority.parse(value);
        try std.testing.expectEqual(@as(u3, @intCast(u)), p.urgency);
    }
}

test "MUST silently ignore an out-of-range urgency value [RFC9218 §4 ¶7]" {
    // §4 ¶7: "Unknown priority parameters, priority parameters with
    // out-of-range values, or values of unexpected types MUST be
    // ignored." The receiver therefore treats `u=8`, `u=9`, etc. as if
    // the parameter were not present and falls back to the default
    // urgency (3) per §4.1 ¶1. The parse call itself MUST succeed.
    const out_of_range = [_][]const u8{ "u=8", "u=9", "u=99" };
    for (out_of_range) |raw| {
        const p = try Priority.parse(raw);
        try std.testing.expectEqual(@as(u3, 3), p.urgency);
    }
}

test "MUST silently ignore a wrong-type urgency value [RFC9218 §4 ¶7]" {
    // §4 ¶7 also covers "values of unexpected types" — anything that is
    // not a Structured Fields integer in 0..7 (a leading zero like "07"
    // is multi-digit; "abc" / "-1" / "" are not single-digit integers).
    // null3 silently drops the bad value and applies the default.
    const wrong_type = [_][]const u8{ "u=07", "u=abc", "u=-1", "u=" };
    for (wrong_type) |raw| {
        const p = try Priority.parse(raw);
        try std.testing.expectEqual(@as(u3, 3), p.urgency);
    }
}

test "MUST keep a previously-accepted urgency when a later out-of-range urgency is ignored [RFC9218 §4 ¶7]" {
    // §4 ¶7 ignore rules behave "as if the parameter were not
    // present", so a bad later value must not clobber an earlier valid
    // one within the same dictionary. ("Last valid wins" follows from
    // dictionary semantics; the bad value is invisible.)
    const p = try Priority.parse("u=5, u=8");
    try std.testing.expectEqual(@as(u3, 5), p.urgency);
}

// ---------------------------------------------------------------- §4.2 — incremental `i`

test "MUST accept bare \"i\" as incremental=true (SF boolean shorthand) [RFC9218 §4.2 ¶1]" {
    // §4.2 ¶1 + RFC 8941 §3.3.6: a parameter without a value defaults
    // to the boolean `?1` (true). null3 implements that shorthand.
    const p = try Priority.parse("i");
    try std.testing.expect(p.incremental);
}

test "MUST accept \"i=?1\" as incremental=true [RFC9218 §4.2 ¶1]" {
    // §4.2 ¶1 + RFC 8941 §4.1.9: SF booleans are written `?1` / `?0`.
    const p = try Priority.parse("i=?1");
    try std.testing.expect(p.incremental);
}

test "MUST accept \"i=?0\" as incremental=false [RFC9218 §4.2 ¶1]" {
    const p = try Priority.parse("i=?0");
    try std.testing.expect(!p.incremental);
}

test "MUST silently ignore a wrong-type incremental value [RFC9218 §4 ¶7]" {
    // §4 ¶7: a value of unexpected type for `i` MUST be ignored.
    // "i=true" and "i=1" are not Structured Fields booleans (only `?1`
    // / `?0` / bare `i` are), so the parser drops them and the field
    // falls back to the default incremental=false per §4.2 ¶1.
    const wrong_type = [_][]const u8{ "i=true", "i=1", "i=?2", "i=yes" };
    for (wrong_type) |raw| {
        const p = try Priority.parse(raw);
        try std.testing.expect(!p.incremental);
    }
}

test "MUST keep a previously-accepted incremental when a later wrong-type incremental is ignored [RFC9218 §4 ¶7]" {
    // Twin of the urgency ignore-then-keep test: `i=?1` sets the
    // incremental flag, the second member `i=true` is wrong-type and
    // MUST be silently dropped, leaving incremental=true.
    const p = try Priority.parse("i=?1, i=true");
    try std.testing.expect(p.incremental);
}

// ---------------------------------------------------------------- §4 — dictionary parsing & ignore-unknown

test "MUST parse both \"u\" and \"i\" together [RFC9218 §4 ¶1]" {
    const p = try Priority.parse("u=2, i");
    try std.testing.expectEqual(@as(u3, 2), p.urgency);
    try std.testing.expect(p.incremental);
}

test "MUST parse parameters in arbitrary order [RFC9218 §4 ¶1]" {
    // Structured Fields dictionaries are unordered; "i, u=4" must
    // equal "u=4, i" semantically.
    const p = try Priority.parse("i, u=4");
    try std.testing.expectEqual(@as(u3, 4), p.urgency);
    try std.testing.expect(p.incremental);
}

test "MUST tolerate optional whitespace between dictionary members [RFC9218 §4 ¶1]" {
    // RFC 8941 §4.2 allows zero or more SP/TAB after the comma. Verify
    // both leading and trailing whitespace are stripped.
    const p = try Priority.parse("  u=5 ,\ti=?0  ");
    try std.testing.expectEqual(@as(u3, 5), p.urgency);
    try std.testing.expect(!p.incremental);
}

test "MUST ignore unknown parameters when parsing the Priority field [RFC9218 §8 ¶unknown-param]" {
    // §8 ¶? "Receivers MUST ignore unknown parameters." A future
    // extension defining a new parameter must not break existing
    // parsers — null3 extracts only `u` and `i` and silently drops the
    // rest.
    const p = try Priority.parse("u=1, future-param=42, i, x-vendor=foo");
    try std.testing.expectEqual(@as(u3, 1), p.urgency);
    try std.testing.expect(p.incremental);
}

test "MUST ignore an unknown parameter that has no value [RFC9218 §8 ¶unknown-param]" {
    const p = try Priority.parse("flag, u=2");
    try std.testing.expectEqual(@as(u3, 2), p.urgency);
    try std.testing.expect(!p.incremental);
}

test "MUST tolerate empty members produced by leading/trailing/consecutive commas [RFC9218 §4 ¶1]" {
    // RFC 8941 §4.2.1 says empty members "MUST be ignored". null3 skips
    // members of length 0 — this protects the parser from peers that
    // emit ",,u=2".
    const p = try Priority.parse(",,u=2,");
    try std.testing.expectEqual(@as(u3, 2), p.urgency);
}

test "MUST NOT accept a member whose key is empty (\"=value\") [RFC9218 §4 ¶1]" {
    // RFC 8941 §4.2.1 requires every member to have a key. null3
    // surfaces an empty key as `Error.InvalidParameter`.
    try std.testing.expectError(priority.Error.InvalidParameter, Priority.parse("=42"));
}

// ---------------------------------------------------------------- §4 — fromFieldLines

test "MUST extract Priority from QPACK field lines case-insensitively [RFC9218 §4 ¶3]" {
    // RFC 9110 §5.1 + RFC 9114 §4.2: HTTP field names are
    // case-insensitive. null3 must recognise both "priority" and
    // "Priority" as the same field so a HEADERS section sent with
    // mixed case is honoured.
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "Priority", .value = "u=2, i" },
    };
    const p = (try priority.fromFieldLines(&fields)).?;
    try std.testing.expectEqual(@as(u3, 2), p.urgency);
    try std.testing.expect(p.incremental);
}

test "NORMATIVE fromFieldLines returns null when no Priority field is present [RFC9218 §4 ¶3]" {
    // The caller can distinguish "no signal" (apply server defaults)
    // from "explicit defaults" by null vs Priority.{}: null3
    // returns null when the field is absent.
    const fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expect((try priority.fromFieldLines(&fields)) == null);
}

test "NORMATIVE fromFieldLines folds duplicate Priority headers (last wins) [RFC9218 §4 ¶3]" {
    // RFC 9110 §5.2 allows multiple field lines for the same field.
    // null3 parses each into the same accumulator so the final state
    // reflects the last occurrence — the caller can pre-fold if it
    // needs alternate semantics.
    const fields = [_]null3.FieldLine{
        .{ .name = "priority", .value = "u=0" },
        .{ .name = "priority", .value = "u=4, i" },
    };
    const p = (try priority.fromFieldLines(&fields)).?;
    try std.testing.expectEqual(@as(u3, 4), p.urgency);
    try std.testing.expect(p.incremental);
}

test "NORMATIVE fieldLine helper produces a \"priority\" field line [RFC9218 §4 ¶3]" {
    // The helper exists so that QPACK encoding paths can emit a
    // canonical "priority" field line without spelling the name out at
    // every call site. Verify the produced name is exactly the
    // registered token.
    const line = priority.fieldLine("u=4");
    try std.testing.expectEqualStrings("priority", line.name);
    try std.testing.expectEqualStrings("u=4", line.value);
}

// ---------------------------------------------------------------- §4 — encode

test "MUST encode urgency as \"u=N\" [RFC9218 §4.1 ¶1]" {
    // The encoder produces a Structured Fields dictionary; for an
    // integer parameter the form is "key=value" with no spaces, per
    // RFC 8941 §4.1.
    const p: Priority = .{ .urgency = 5, .incremental = false };
    var buf: [16]u8 = undefined;
    const n = try p.encode(&buf);
    try std.testing.expectEqualStrings("u=5", buf[0..n]);
}

test "MUST emit the bare \"i\" sentinel when incremental=true [RFC9218 §4.2 ¶1]" {
    // RFC 8941 §4.1.7 allows boolean parameters to be written without a
    // value (interpreted as `?1`). null3 prefers the shorter form for
    // wire economy.
    const p: Priority = .{ .urgency = 1, .incremental = true };
    var buf: [16]u8 = undefined;
    const n = try p.encode(&buf);
    try std.testing.expectEqualStrings("u=1, i", buf[0..n]);
}

test "MUST NOT emit \"i\" when incremental=false [RFC9218 §4.2 ¶1]" {
    // Defaults must not appear on the wire (RFC 8941 §3.1.2): if
    // incremental is the default `false`, the encoded value must not
    // contain "i" at all.
    const p: Priority = .{ .urgency = 3, .incremental = false };
    var buf: [16]u8 = undefined;
    const n = try p.encode(&buf);
    try std.testing.expectEqualStrings("u=3", buf[0..n]);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "i") == null);
}

test "MUST round-trip every (urgency, incremental) pair through encode/parse [RFC9218 §4]" {
    // The generative round-trip: encode every distinct Priority and
    // parse it back. Failure here is a codec asymmetry bug, not a
    // spec ambiguity.
    var u: u8 = 0;
    while (u <= 7) : (u += 1) {
        for ([_]bool{ false, true }) |incremental| {
            const original: Priority = .{
                .urgency = @intCast(u),
                .incremental = incremental,
            };
            var buf: [16]u8 = undefined;
            const n = try original.encode(&buf);
            const decoded = try Priority.parse(buf[0..n]);
            try std.testing.expectEqual(original.urgency, decoded.urgency);
            try std.testing.expectEqual(original.incremental, decoded.incremental);
        }
    }
}

test "MUST NOT overrun the encode buffer [RFC9218 §4]" {
    // The encoder must surface BufferTooSmall instead of writing past
    // the destination. The longest "u=N, i" form is 6 bytes; a 3-byte
    // buffer guarantees overflow.
    const p: Priority = .{ .urgency = 4, .incremental = true };
    var tiny: [3]u8 = undefined;
    try std.testing.expectError(priority.Error.BufferTooSmall, p.encode(&tiny));
}

// ---------------------------------------------------------------- §11 — IANA-assigned frame type IDs

test "MUST register PRIORITY_UPDATE frame type IDs as 0xF0700 / 0xF0701 [RFC9218 §11 ¶?]" {
    // IANA "HTTP/3 Frame Types" registry (RFC 9218 §11; §7.2 ¶1):
    // 0xF0700 → PRIORITY_UPDATE Request, 0xF0701 → PRIORITY_UPDATE Push.
    // null3 mirrors these in `protocol.FrameType.priority_update_*`
    // and the codec dispatches on these values; pin them so an
    // accidental constant edit is caught at conformance time.
    try std.testing.expectEqual(@as(u64, 0xF0700), protocol.FrameType.priority_update_request);
    try std.testing.expectEqual(@as(u64, 0xF0701), protocol.FrameType.priority_update_push);
}

// ---------------------------------------------------------------- §7.2 — PRIORITY_UPDATE wire round-trip (semantic view)

test "MUST round-trip PRIORITY_UPDATE Request frame (Prioritized Element ID + Priority Field Value) [RFC9218 §7.2 ¶?]" {
    // §7.2: the PRIORITY_UPDATE Request frame payload is "Prioritized
    // Element ID (varint) + Priority Field Value (opaque bytes)". The
    // generic frame codec is exercised in rfc9114_frames.zig; here we
    // verify the Priority-specific pair encodes and decodes losslessly
    // so callers of `null3.frame.encode` get back what they put in.
    var buf: [64]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 16,
            .priority_field_value = "u=2, i",
        },
    });
    const d = try null3.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 16), p.prioritized_element_id);
            try std.testing.expectEqualStrings("u=2, i", p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "MUST round-trip PRIORITY_UPDATE Push frame (Prioritized Element ID + Priority Field Value) [RFC9218 §7.2 ¶?]" {
    // Twin of the request-stream variant — the only difference on the
    // wire is the frame-type tag (0xF0701 vs 0xF0700). The semantic
    // payload shape is identical.
    var buf: [64]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{
        .priority_update_push = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=0",
        },
    });
    const d = try null3.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_push => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqualStrings("u=0", p.priority_field_value);
        },
        else => return error.TestExpectedEqual,
    }
}

test "NORMATIVE PRIORITY_UPDATE may carry an empty Priority Field Value [RFC9218 §7.2 ¶?]" {
    // RFC 9218 does not require the Priority Field Value to be
    // non-empty: a sender that wants to "reset to defaults" can emit
    // an empty value. The codec must not refuse it.
    var buf: [16]u8 = undefined;
    const n = try null3.frame.encode(&buf, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "",
        },
    });
    const d = try null3.frame.decode(buf[0..n]);
    switch (d.frame) {
        .priority_update_request => |p| {
            try std.testing.expectEqual(@as(u64, 0), p.prioritized_element_id);
            try std.testing.expectEqual(@as(usize, 0), p.priority_field_value.len);
        },
        else => return error.TestExpectedEqual,
    }
}

// ---------------------------------------------------------------- §7.1 / §8 — sender-side target validation

test "MUST NOT permit a server to send PRIORITY_UPDATE [RFC9218 §7.1 ¶?]" {
    // §7.1 ¶? "The PRIORITY_UPDATE frame MUST be sent by a client".
    // null3 enforces this in `Session.sendPriorityUpdateForRequest`
    // by returning `InvalidRole` for any non-client caller.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.InvalidRole,
        pair.server_h3.sendPriorityUpdateForRequest(0, .{ .urgency = 1 }),
    );
}

test "MUST NOT send PRIORITY_UPDATE for a server-initiated bidirectional stream id [RFC9218 §7.1 ¶?]" {
    // §7.1 ¶? "The Prioritized Element ID ... MUST be a client-
    // initiated bidirectional stream ..." Stream ID 1 is
    // server-initiated bidi (lowest 2 bits = 0b01). null3 surfaces
    // this as `InvalidPriorityTarget` before any frame is written.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.InvalidPriorityTarget,
        pair.client_h3.sendPriorityUpdateForRequest(1, .{ .urgency = 1 }),
    );
}

test "MUST NOT send PRIORITY_UPDATE for a unidirectional stream id [RFC9218 §7.1 ¶?]" {
    // §7.1 ¶? Unidirectional streams cannot carry HTTP requests, so
    // they cannot be the target of PRIORITY_UPDATE. Stream ID 2 is
    // client-initiated uni.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.InvalidPriorityTarget,
        pair.client_h3.sendPriorityUpdateForRequest(2, .{ .urgency = 1 }),
    );
}

test "MUST NOT send PRIORITY_UPDATE-Push when push is not enabled [RFC9218 §7.1 ¶?]" {
    // §7.1: pushed responses can only be prioritized when the client
    // has enabled push by sending MAX_PUSH_ID. Without that, even an
    // otherwise-valid push id has no meaning.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.PushNotEnabled,
        pair.client_h3.sendPriorityUpdateForPush(0, .{ .urgency = 0 }),
    );
}

test "MUST NOT send PRIORITY_UPDATE-Push for an unannounced push id [RFC9218 §7.1 ¶?]" {
    // §7.1: the push id MUST refer to a server push the client has
    // already accepted (received PUSH_PROMISE for). null3 surfaces an
    // unknown push id as `InvalidPriorityTarget`.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{ .max_push_id = 4 }, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expectError(
        error.InvalidPriorityTarget,
        pair.client_h3.sendPriorityUpdateForPush(0, .{ .urgency = 0 }),
    );
}

test "MUST allow a client to send PRIORITY_UPDATE for a client-initiated bidi stream [RFC9218 §7.1 ¶?]" {
    // The positive case — a fresh client-initiated bidi id (stream 0,
    // lowest 2 bits = 0b00) accepted by `validatePriorityRequestStreamId`.
    // We only check that the call succeeds; the over-the-wire
    // observation is the receive-side test below.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try pair.client_h3.sendPriorityUpdateForRequest(0, .{ .urgency = 5, .incremental = true });
}

// ---------------------------------------------------------------- §8 — receiver-side validation

test "MUST close with H3_ID_ERROR on PRIORITY_UPDATE for an invalid request stream id [RFC9218 §8 ¶?]" {
    // §8 ¶? "If a server receives a PRIORITY_UPDATE frame with a
    // Prioritized Element ID that does not refer to a request the
    // server could have received, the server MUST treat it as a
    // connection error of type H3_ID_ERROR." Stream id 2 is
    // client-initiated unidirectional — it can never carry a request.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    // Inject a malicious frame onto the client's control stream; the
    // server's session must close with id_error.
    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 2,
            .priority_field_value = "u=1",
        },
    });

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidPriorityTarget);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.id_error);
}

test "MUST close with H3_ID_ERROR on PRIORITY_UPDATE for a server-initiated stream id [RFC9218 §8 ¶?]" {
    // Stream id 1 is server-initiated bidi — also an invalid target.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 1,
            .priority_field_value = "u=1",
        },
    });

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidPriorityTarget);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.id_error);
}

test "MUST close with H3_GENERAL_PROTOCOL_ERROR on PRIORITY_UPDATE with structurally malformed Priority value [RFC9218 §8 ¶?]" {
    // §8 ¶? A Priority field value that fails to parse as a Structured
    // Fields dictionary cannot be applied; null3 surfaces the parse
    // error and closes the connection. ("=42" has an empty member key,
    // which RFC 8941 §4.2.1 forbids — distinct from §4 ¶7's "ignore
    // out-of-range" rule, which only covers individual parameter
    // values.) null3 maps `Error.InvalidParameter` to
    // H3_GENERAL_PROTOCOL_ERROR via `errors_mod.codeForError`.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "=42",
        },
    });

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidParameter);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.general_protocol_error);
}

test "MUST silently ignore an out-of-range urgency in a PRIORITY_UPDATE Priority Field Value [RFC9218 §4 ¶7]" {
    // §4 ¶7 "MUST be ignored" applies on the wire as well as in
    // Priority headers. A peer sending PRIORITY_UPDATE with `u=9`
    // (out-of-range urgency) must not cause a connection close —
    // instead the urgency falls back to its default of 3 and the
    // priority is stored. Verify this through the public observable:
    // `priorityForRequest` reflects urgency=3 after the frame.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const request_stream_id: u64 = 0;
    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = request_stream_id,
            .priority_field_value = "u=9",
        },
    });
    try fixture.pumpQuiet(allocator, &pair, 64);

    const stored = pair.server_h3.priorityForRequest(request_stream_id) orelse return error.MissingPriority;
    try std.testing.expectEqual(@as(u3, 3), stored.urgency);
    try std.testing.expect(!stored.incremental);
}

test "MUST close with H3_FRAME_UNEXPECTED when a client receives PRIORITY_UPDATE [RFC9218 §7.1 ¶?]" {
    // §7.1 ¶? "PRIORITY_UPDATE ... MUST be sent by a client". A server
    // that emits one is in violation; the client receiver must close
    // with H3_FRAME_UNEXPECTED.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(&pair.server, pair.server_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=1",
        },
    });

    try fixture.expectPairH3Error(allocator, &pair, error.FrameUnexpected);
    try fixture.expectLastCloseCode(&pair.client_h3, ErrorCode.frame_unexpected);
}

test "MUST close with H3_ID_ERROR on PRIORITY_UPDATE-Push when push is not enabled [RFC9218 §8 ¶?]" {
    // §8 ¶? Server-side companion of `validatePriorityPushId`: if a
    // client sends a PRIORITY_UPDATE Push frame for a push id that
    // exceeds the server-known MAX_PUSH_ID (or no MAX_PUSH_ID has been
    // received), the server MUST close with H3_ID_ERROR. We craft the
    // frame directly because the client API would refuse to emit it.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_push = .{
            .prioritized_element_id = 0,
            .priority_field_value = "u=2",
        },
    });

    try fixture.expectPairH3Error(allocator, &pair, error.InvalidPriorityTarget);
    try fixture.expectLastCloseCode(&pair.server_h3, ErrorCode.id_error);
}

// ---------------------------------------------------------------- §5 / §7 — applied priority

test "MUST reflect a received PRIORITY_UPDATE in priorityForRequest [RFC9218 §7 ¶?]" {
    // The interop end-to-end check: a client's PRIORITY_UPDATE must
    // be parsed, validated, stored, and become observable through
    // `Session.priorityForRequest`. We use the loopback driver to
    // run a real handshake + control-stream frame exchange.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    // Open a request stream so the prioritized id (0) is one the
    // server could have received. Push a HEADERS frame so the server
    // doesn't reject the stream as unknown.
    const request_stream_id: u64 = 0;
    _ = try pair.client.openBidi(request_stream_id);
    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var headers_buf: [256]u8 = undefined;
    const headers_n = try null3.qpack.encodeFieldSection(&headers_buf, &request_fields);
    try fixture.writeFrame(&pair.client, request_stream_id, .{ .headers = headers_buf[0..headers_n] });

    // Send the PRIORITY_UPDATE through the public Session API and
    // pump until the server has processed it.
    try pair.client_h3.sendPriorityUpdateForRequest(request_stream_id, .{
        .urgency = 1,
        .incremental = true,
    });
    try fixture.pumpQuiet(allocator, &pair, 64);

    const stored = pair.server_h3.priorityForRequest(request_stream_id) orelse return error.MissingPriority;
    try std.testing.expectEqual(@as(u3, 1), stored.urgency);
    try std.testing.expect(stored.incremental);
}

test "NORMATIVE PRIORITY_UPDATE value overrides a Priority request header [RFC9218 §5 ¶?]" {
    // §5 ¶? "When merging signals from PRIORITY_UPDATE and the request
    // ... PRIORITY_UPDATE takes precedence." We send a request header
    // signalling u=6 then a PRIORITY_UPDATE signalling u=2; the
    // server's stored priority must be the most recent value (u=2).
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const request_stream_id: u64 = 0;
    _ = try pair.client.openBidi(request_stream_id);
    const request_fields = [_]null3.FieldLine{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=6" },
    };
    var headers_buf: [256]u8 = undefined;
    const headers_n = try null3.qpack.encodeFieldSection(&headers_buf, &request_fields);
    try fixture.writeFrame(&pair.client, request_stream_id, .{ .headers = headers_buf[0..headers_n] });

    try pair.client_h3.sendPriorityUpdateForRequest(request_stream_id, .{ .urgency = 2 });
    try fixture.pumpQuiet(allocator, &pair, 64);

    const stored = pair.server_h3.priorityForRequest(request_stream_id) orelse return error.MissingPriority;
    try std.testing.expectEqual(@as(u3, 2), stored.urgency);
}

test "NORMATIVE priorityForRequest returns null when no Priority signal has been seen [RFC9218 §4 ¶5]" {
    // §4 ¶5: "When receiving an HTTP request that does not carry these
    // priority parameters, a server SHOULD act as if their default
    // values were specified." null3 lets the caller distinguish "no
    // signal" from "explicit default" by returning null from
    // `priorityForRequest` when neither a Priority header nor a
    // PRIORITY_UPDATE has touched the stream id — the application
    // chooses how to apply defaults.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    try std.testing.expect(pair.server_h3.priorityForRequest(0) == null);
}

test "NORMATIVE server buffers PRIORITY_UPDATE received before the stream is open [RFC9218 §7 ¶4]" {
    // §7 ¶4: "A client MAY send a PRIORITY_UPDATE frame before the
    // stream that it references is open." §7.4 ¶2: "Servers SHOULD
    // buffer the most recently received PRIORITY_UPDATE frame and
    // apply it once the referenced stream is opened." null3's
    // `request_priorities` map is keyed on stream id, so the priority
    // is recorded immediately and remains visible via
    // `priorityForRequest` regardless of whether the stream has
    // arrived. We verify by sending PRIORITY_UPDATE for stream id 4
    // (a valid client-initiated bidi id) without ever opening that
    // stream and observing the stored value.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const future_stream_id: u64 = 4;
    try pair.client_h3.sendPriorityUpdateForRequest(future_stream_id, .{
        .urgency = 0,
        .incremental = true,
    });
    try fixture.pumpQuiet(allocator, &pair, 64);

    const stored = pair.server_h3.priorityForRequest(future_stream_id) orelse return error.MissingPriority;
    try std.testing.expectEqual(@as(u3, 0), stored.urgency);
    try std.testing.expect(stored.incremental);
}

test "NORMATIVE empty PRIORITY_UPDATE Priority Field Value applies the parameter defaults [RFC9218 §7 ¶3]" {
    // §7 ¶3: "A PRIORITY_UPDATE frame communicates a complete set of
    // all priority parameters in the Priority Field Value field.
    // Omitting a priority parameter is a signal to use its default
    // value." An empty Priority Field Value omits every parameter, so
    // the receiver MUST apply the defaults from §4.1 (urgency=3) and
    // §4.2 (incremental=false). We craft the frame on the wire (the
    // `Priority.encode` helper always emits "u=N") and then observe
    // `priorityForRequest`.
    const allocator = std.testing.allocator;

    var pair: fixture.H3Pair = undefined;
    try pair.initStarted(allocator, .{}, .{});
    defer pair.deinit();
    try fixture.exchangePairSettings(allocator, &pair);

    const request_stream_id: u64 = 0;
    try fixture.writeFrame(&pair.client, pair.client_h3.control_stream_id.?, .{
        .priority_update_request = .{
            .prioritized_element_id = request_stream_id,
            .priority_field_value = "",
        },
    });
    try fixture.pumpQuiet(allocator, &pair, 64);

    const stored = pair.server_h3.priorityForRequest(request_stream_id) orelse return error.MissingPriority;
    try std.testing.expectEqual(@as(u3, 3), stored.urgency);
    try std.testing.expect(!stored.incremental);
}
