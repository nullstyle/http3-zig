//! External WebTransport interop **matrix** runner.
//!
//! Loops over the URLs in `WT_INTEROP_MATRIX_URLS` (newline- or
//! comma-separated) and runs `http3-zig-external-wt-client` against
//! each. Prints per-target status and exits non-zero only if **every**
//! non-skipped target failed — so a missing aioquic doesn't mask a
//! working quiche.
//!
//! When `WT_INTEROP_MATRIX_URLS` is unset, the matrix runner prints a
//! friendly skip message and exits 0. Same convention as the existing
//! interop entry points so this binary can be wired into CI without
//! requiring any external server be up.
//!
//! The runner shells out to the installed binary at
//! `zig-out/bin/http3-zig-external-wt-client` (or `--client-bin
//! <path>`). The `external-wt-client` install step is an explicit
//! dependency of `wt-interop-matrix` in build.zig, so a fresh build
//! always rebuilds the client as well.
//!
//! ### CLI
//!
//! * `--client-bin <path>` — override the client binary location.
//! * `--timeout-ms <ms>` — wall-clock cap per target. Forwarded to the
//!   client as `--max-time-ms`. Kept under the more conventional
//!   `--timeout-ms` spelling so the CI workflow doesn't need to know
//!   the client's flag name.
//! * `--` — sentinel; everything that follows is appended verbatim to
//!   the client's argv.
//! * Anything else is appended verbatim to the client's argv.

const std = @import("std");

const env_var = "WT_INTEROP_MATRIX_URLS";

const Outcome = enum { passed, failed };

const TargetResult = struct {
    url: []const u8,
    outcome: Outcome,
    exit_code: u8 = 0,
    note: []const u8 = "",
};

const Io = std.Io;

const default_client_bin = "zig-out/bin/http3-zig-external-wt-client";

const MatrixCli = struct {
    client_bin: []const u8 = default_client_bin,
    /// Wall-clock cap (ms) forwarded to the client as `--max-time-ms`.
    timeout_ms: ?u64 = null,
    extra_args: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *MatrixCli, allocator: std.mem.Allocator) void {
        self.extra_args.deinit(allocator);
    }
};

fn parseCli(allocator: std.mem.Allocator, raw_args: []const []const u8) !MatrixCli {
    var cli: MatrixCli = .{};
    errdefer cli.deinit(allocator);
    var i: usize = 0;
    while (i < raw_args.len) : (i += 1) {
        const arg = raw_args[i];
        if (std.mem.eql(u8, arg, "--client-bin")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingClientBin;
            cli.client_bin = raw_args[i];
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingTimeoutMs;
            cli.timeout_ms = try std.fmt.parseInt(u64, raw_args[i], 10);
        } else if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < raw_args.len) : (i += 1) {
                try cli.extra_args.append(allocator, raw_args[i]);
            }
            break;
        } else {
            try cli.extra_args.append(allocator, arg);
        }
    }
    return cli;
}

fn buildClientArgv(
    allocator: std.mem.Allocator,
    client_bin: []const u8,
    timeout_ms_str: ?[]const u8,
    extra_args: []const []const u8,
) !std.ArrayList([]const u8) {
    var argv: std.ArrayList([]const u8) = .empty;
    errdefer argv.deinit(allocator);
    try argv.append(allocator, client_bin);
    // Prepend the translated timeout so any user-supplied `--max-time-ms`
    // in extra_args wins (the client's parser keeps the last value).
    if (timeout_ms_str) |ms| {
        try argv.append(allocator, "--max-time-ms");
        try argv.append(allocator, ms);
    }
    try argv.appendSlice(allocator, extra_args);
    return argv;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var arg_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer arg_iter.deinit();
    _ = arg_iter.next(); // skip exe path

    var raw_args: std.ArrayList([]const u8) = .empty;
    defer raw_args.deinit(allocator);
    while (arg_iter.next()) |arg| try raw_args.append(allocator, arg);

    var cli = parseCli(allocator, raw_args.items) catch |err| {
        try stdout.print(
            "external_wt matrix: argument parse failed: {s}\n",
            .{@errorName(err)},
        );
        try stdout.flush();
        std.process.exit(2);
    };
    defer cli.deinit(allocator);

    var timeout_str_buf: [32]u8 = undefined;
    const timeout_str: ?[]const u8 = if (cli.timeout_ms) |ms|
        try std.fmt.bufPrint(&timeout_str_buf, "{d}", .{ms})
    else
        null;

    const raw = init.environ_map.get(env_var) orelse {
        try stdout.print(
            "external_wt: SKIP — set {s}=<url1>[,<url2>...] (or newline-separated) to run the matrix\n",
            .{env_var},
        );
        try stdout.flush();
        std.process.exit(0);
    };

    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(allocator);
    {
        var it = std.mem.tokenizeAny(u8, raw, "\n,");
        while (it.next()) |raw_url| {
            const trimmed = std.mem.trim(u8, raw_url, " \t");
            if (trimmed.len == 0) continue;
            try urls.append(allocator, trimmed);
        }
    }

    if (urls.items.len == 0) {
        try stdout.print(
            "external_wt: SKIP — {s} parsed to zero non-empty URLs\n",
            .{env_var},
        );
        try stdout.flush();
        std.process.exit(0);
    }

    var results: std.ArrayList(TargetResult) = .empty;
    defer results.deinit(allocator);

    try stdout.print("external_wt matrix: {d} target(s)\n", .{urls.items.len});
    try stdout.flush();

    for (urls.items, 0..) |url, idx| {
        try stdout.print("  [{d}/{d}] {s}: ", .{ idx + 1, urls.items.len, url });
        try stdout.flush();
        const outcome = runOne(
            allocator,
            io,
            init.environ_map.*,
            cli.client_bin,
            url,
            timeout_str,
            cli.extra_args.items,
        ) catch |err| TargetResult{
            .url = url,
            .outcome = .failed,
            .exit_code = 2,
            .note = @errorName(err),
        };
        switch (outcome.outcome) {
            .passed => try stdout.print("PASS\n", .{}),
            .failed => try stdout.print("FAIL (exit {d}) {s}\n", .{ outcome.exit_code, outcome.note }),
        }
        try stdout.flush();
        try results.append(allocator, outcome);
    }

    var passed: usize = 0;
    var failed: usize = 0;
    for (results.items) |r| {
        switch (r.outcome) {
            .passed => passed += 1,
            .failed => failed += 1,
        }
    }

    try stdout.print(
        "\nexternal_wt matrix: {d} passed, {d} failed (of {d})\n",
        .{ passed, failed, results.items.len },
    );
    try stdout.flush();

    // Exit non-zero only if **every** target failed. A single passing
    // target is enough to satisfy the matrix.
    if (passed == 0 and failed > 0) std.process.exit(1);
    std.process.exit(0);
}

fn runOne(
    allocator: std.mem.Allocator,
    io: Io,
    parent_env: std.process.Environ.Map,
    client_bin: []const u8,
    url: []const u8,
    timeout_ms_str: ?[]const u8,
    extra_args: []const []const u8,
) !TargetResult {
    var argv = try buildClientArgv(allocator, client_bin, timeout_ms_str, extra_args);
    defer argv.deinit(allocator);

    var env_map = try parent_env.clone(allocator);
    defer env_map.deinit();
    try env_map.put("WT_INTEROP_URL", url);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &env_map,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });

    const term = try child.wait(io);

    return switch (term) {
        .exited => |code| switch (code) {
            0 => TargetResult{ .url = url, .outcome = .passed, .exit_code = 0 },
            else => TargetResult{ .url = url, .outcome = .failed, .exit_code = code, .note = "non-zero exit" },
        },
        else => TargetResult{ .url = url, .outcome = .failed, .exit_code = 2, .note = "abnormal termination" },
    };
}

test "parseCli recognizes --timeout-ms and stores the integer value" {
    const allocator = std.testing.allocator;
    var cli = try parseCli(allocator, &.{ "--timeout-ms", "30000" });
    defer cli.deinit(allocator);
    try std.testing.expectEqual(@as(?u64, 30000), cli.timeout_ms);
    try std.testing.expectEqual(@as(usize, 0), cli.extra_args.items.len);
    try std.testing.expectEqualStrings(default_client_bin, cli.client_bin);
}

test "parseCli passes unknown flags through to extra_args" {
    const allocator = std.testing.allocator;
    var cli = try parseCli(allocator, &.{ "--insecure", "--max-iterations", "100" });
    defer cli.deinit(allocator);
    try std.testing.expect(cli.timeout_ms == null);
    try std.testing.expectEqual(@as(usize, 3), cli.extra_args.items.len);
    try std.testing.expectEqualStrings("--insecure", cli.extra_args.items[0]);
    try std.testing.expectEqualStrings("--max-iterations", cli.extra_args.items[1]);
    try std.testing.expectEqualStrings("100", cli.extra_args.items[2]);
}

test "parseCli treats -- as a passthrough sentinel" {
    const allocator = std.testing.allocator;
    var cli = try parseCli(allocator, &.{ "--", "--timeout-ms", "5000" });
    defer cli.deinit(allocator);
    try std.testing.expect(cli.timeout_ms == null);
    try std.testing.expectEqual(@as(usize, 2), cli.extra_args.items.len);
    try std.testing.expectEqualStrings("--timeout-ms", cli.extra_args.items[0]);
    try std.testing.expectEqualStrings("5000", cli.extra_args.items[1]);
}

test "parseCli rejects --timeout-ms with no value" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.MissingTimeoutMs,
        parseCli(allocator, &.{"--timeout-ms"}),
    );
}

test "parseCli rejects a non-numeric --timeout-ms value" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidCharacter,
        parseCli(allocator, &.{ "--timeout-ms", "soon" }),
    );
}

test "parseCli accepts --client-bin override" {
    const allocator = std.testing.allocator;
    var cli = try parseCli(allocator, &.{ "--client-bin", "/tmp/wt-client" });
    defer cli.deinit(allocator);
    try std.testing.expectEqualStrings("/tmp/wt-client", cli.client_bin);
}

test "buildClientArgv translates --timeout-ms to --max-time-ms" {
    const allocator = std.testing.allocator;
    var argv = try buildClientArgv(allocator, "bin", "30000", &.{"--insecure"});
    defer argv.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), argv.items.len);
    try std.testing.expectEqualStrings("bin", argv.items[0]);
    try std.testing.expectEqualStrings("--max-time-ms", argv.items[1]);
    try std.testing.expectEqualStrings("30000", argv.items[2]);
    try std.testing.expectEqualStrings("--insecure", argv.items[3]);
}

test "buildClientArgv omits the timeout flag entirely when unset" {
    const allocator = std.testing.allocator;
    var argv = try buildClientArgv(allocator, "bin", null, &.{"--insecure"});
    defer argv.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), argv.items.len);
    try std.testing.expectEqualStrings("bin", argv.items[0]);
    try std.testing.expectEqualStrings("--insecure", argv.items[1]);
}

test "buildClientArgv puts user --max-time-ms after the translation so user value wins" {
    // The client parses sequentially and keeps the last value, so the
    // user-supplied flag must be appended *after* the translated one.
    const allocator = std.testing.allocator;
    var argv = try buildClientArgv(
        allocator,
        "bin",
        "30000",
        &.{ "--max-time-ms", "5000" },
    );
    defer argv.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 5), argv.items.len);
    try std.testing.expectEqualStrings("bin", argv.items[0]);
    try std.testing.expectEqualStrings("--max-time-ms", argv.items[1]);
    try std.testing.expectEqualStrings("30000", argv.items[2]);
    try std.testing.expectEqualStrings("--max-time-ms", argv.items[3]);
    try std.testing.expectEqualStrings("5000", argv.items[4]);
}
