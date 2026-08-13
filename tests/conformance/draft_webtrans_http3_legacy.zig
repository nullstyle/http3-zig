//! Browser-era WebTransport negotiation — the superseded draft revisions
//! this implementation deliberately keeps speaking.
//!
//! Shipped Chrome and shipped Firefox both negotiate WebTransport with
//! the draft-02 bootstrap today (verified in quiche and neqo source);
//! quiche additionally implements draft-07 behind a default-off feature
//! flag. The data path is identical from draft-02 through the pinned
//! modern revision, so browser interop is purely this negotiation layer.
//! Citations pin the superseded revision explicitly
//! (`[draft-ietf-webtrans-http3-02 §X]`) per the conformance README's
//! citation grammar; the modern suite is `draft_webtrans_http3.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   draft-ietf-webtrans-http3-02 §3.1/§8.2  MUST  SETTINGS_ENABLE_WEBTRANSPORT is 0x2b603742, value 0 or 1
//!   draft-ietf-webtrans-http3-07 §3.1/§8.2  MUST  SETTINGS_WEBTRANSPORT_MAX_SESSIONS is 0xc671706a; 0 = not willing
//!   draft-ietf-webtrans-http3-07 §6         NORMATIVE  most recent version supported by both peers is selected
//!   draft-ietf-webtrans-http3-02 §3.3       MUST  legacy :protocol token "webtransport" is accepted
//!   draft-ietf-webtrans-http3-02 §6         NORMATIVE  sec-webtransport-http3-draft02 request header carried in the draft-02 era profile
//!
//! Visible debt:
//!   none — era RESOLUTION is codec-level and covered here; per-era
//!   session behavior (stamping, flow-control gating, header emission)
//!   is integration-tested as the era layer lands.
//!
//! Out of scope (covered elsewhere):
//!   era stamping / gating / establishment → tests/integration/webtransport_eras.zig
//!   modern-revision claims → draft_webtrans_http3.zig

const std = @import("std");
const http3_zig = @import("http3_zig");

const wt = http3_zig.webtransport;

test "MUST: SETTINGS_ENABLE_WEBTRANSPORT uses codepoint 0x2b603742 and round-trips [draft-ietf-webtrans-http3-02 §3.1]" {
    try std.testing.expectEqual(@as(u64, 0x2b603742), http3_zig.protocol.SettingId.wt_draft02_enabled);
    try std.testing.expect(!http3_zig.protocol.isGreaseValue(http3_zig.protocol.SettingId.wt_draft02_enabled));

    const original: http3_zig.Settings = .{ .wt_draft02 = true };
    var buf: [64]u8 = undefined;
    const n = try original.encode(&buf);
    try std.testing.expect((try http3_zig.Settings.decode(buf[0..n])).wt_draft02);

    // Raw wire form: id 0x2b603742 as a 4-byte varint (0xab603742),
    // value 1.
    const raw = [_]u8{ 0xab, 0x60, 0x37, 0x42, 0x01 };
    try std.testing.expect((try http3_zig.Settings.decode(&raw)).wt_draft02);
    const raw_zero = [_]u8{ 0xab, 0x60, 0x37, 0x42, 0x00 };
    try std.testing.expect(!(try http3_zig.Settings.decode(&raw_zero)).wt_draft02);
}

test "MUST: SETTINGS_WEBTRANSPORT_MAX_SESSIONS uses codepoint 0xc671706a; zero means not willing [draft-ietf-webtrans-http3-07 §3.1]" {
    try std.testing.expectEqual(@as(u64, 0xc671706a), http3_zig.protocol.SettingId.wt_draft07_max_sessions);
    try std.testing.expect(!http3_zig.protocol.isGreaseValue(http3_zig.protocol.SettingId.wt_draft07_max_sessions));

    const original: http3_zig.Settings = .{ .wt_draft07_max_sessions = 16 };
    var buf: [64]u8 = undefined;
    const n = try original.encode(&buf);
    const decoded = try http3_zig.Settings.decode(buf[0..n]);
    try std.testing.expectEqual(@as(?u64, 16), decoded.wt_draft07_max_sessions);

    // Advertised-but-zero does not enable the era.
    try std.testing.expect(!wt.peerAdvertisedEras(.{ .wt_draft07_max_sessions = 0 }).draft07);
    try std.testing.expect(wt.peerAdvertisedEras(.{ .wt_draft07_max_sessions = 1 }).draft07);
}

test "NORMATIVE: the most recent version supported by both peers is selected [draft-ietf-webtrans-http3-07 §6]" {
    const all: wt.WtDraftSet = .{ .draft02 = true, .draft07 = true, .draft16 = true };
    try std.testing.expectEqual(
        @as(?wt.WtDraft, .draft16),
        wt.resolveDraft(all, .{ .wt_enabled = true, .wt_draft07_max_sessions = 4, .wt_draft02 = true }),
    );
    try std.testing.expectEqual(
        @as(?wt.WtDraft, .draft07),
        wt.resolveDraft(all, .{ .wt_draft07_max_sessions = 4, .wt_draft02 = true }),
    );
    // A Chrome-shaped peer (draft-02 only) lands on draft02.
    try std.testing.expectEqual(
        @as(?wt.WtDraft, .draft02),
        wt.resolveDraft(all, .{ .wt_draft02 = true }),
    );
    // A modern-only local set against a browser peer: clean no-WT, so
    // the facades surface PeerDidNotEnableWebTransport rather than a
    // connection error.
    try std.testing.expectEqual(
        @as(?wt.WtDraft, null),
        wt.resolveDraft(.{ .draft16 = true }, .{ .wt_draft02 = true }),
    );
}

test "MUST: the legacy :protocol token webtransport is accepted alongside the modern token [draft-ietf-webtrans-http3-02 §3.3]" {
    try std.testing.expectEqualStrings("webtransport", wt.legacy_protocol_token);
    try std.testing.expect(wt.isProtocolToken(wt.legacy_protocol_token));
    try std.testing.expect(wt.isProtocolToken(wt.protocol_token));
    try std.testing.expectEqualStrings("webtransport", wt.eraProfile(.draft02).protocol_token);
    try std.testing.expectEqualStrings("webtransport", wt.eraProfile(.draft07).protocol_token);
}

test "NORMATIVE: the draft-02 era profile carries sec-webtransport-http3-draft02 = 1 [draft-ietf-webtrans-http3-02 §6]" {
    // Chrome sends this request header unconditionally; servers do not
    // require it and no shipping client validates the response header.
    const profile = wt.eraProfile(.draft02);
    try std.testing.expectEqual(@as(usize, 1), profile.request_headers.len);
    try std.testing.expectEqualStrings("sec-webtransport-http3-draft02", profile.request_headers[0].name);
    try std.testing.expectEqualStrings("1", profile.request_headers[0].value);
    try std.testing.expectEqual(@as(usize, 1), profile.response_headers.len);
    try std.testing.expectEqualStrings("sec-webtransport-http3-draft", profile.response_headers[0].name);
    // The other eras add nothing.
    try std.testing.expectEqual(@as(usize, 0), wt.eraProfile(.draft07).request_headers.len);
    try std.testing.expectEqual(@as(usize, 0), wt.eraProfile(.draft16).request_headers.len);
}
