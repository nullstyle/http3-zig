//! Fuzz corpus runner.
//!
//! Walks every file under `fuzz/corpus/<target>/` and feeds it
//! through the matching codec target via `codecs.runTarget`. Bigger
//! and more thorough than the smoke corpus — runs as a non-gating CI
//! step (see `.github/workflows/fuzz.yml`). Coverage-guided fuzzers
//! can drop new files into the same directories to extend coverage
//! without code changes.
//!
//! Usage:
//!     zig build run-fuzz-corpus                    # all targets
//!     zig build run-fuzz-corpus -- frame settings  # specific targets

const std = @import("std");
const codecs = @import("codecs.zig");

const max_input_bytes = 64 * 1024;
const corpus_root = "fuzz/corpus";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    var requested: std.ArrayList(codecs.Target) = .empty;
    defer requested.deinit(allocator);
    while (args.next()) |arg| {
        const t = codecs.targetFromName(arg) orelse {
            try stdout.print("unknown target: {s}\n", .{arg});
            try stdout.flush();
            std.process.exit(2);
        };
        try requested.append(allocator, t);
    }

    // Default: every concrete target.
    const targets: []const codecs.Target = if (requested.items.len == 0)
        &codecs.concrete_targets
    else
        requested.items;

    var total_cases: usize = 0;
    var total_fails: usize = 0;

    const cwd = std.Io.Dir.cwd();

    for (targets) |target| {
        const name = codecs.targetName(target);
        var path_buf: [256]u8 = undefined;
        const dir_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ corpus_root, name }) catch unreachable;

        var subdir = cwd.openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => {
                try stdout.print("  {s}: corpus dir missing — skipping\n", .{name});
                continue;
            },
            else => return err,
        };
        defer subdir.close(io);

        var cases: usize = 0;
        var fails: usize = 0;

        var it = subdir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            const bytes = subdir.readFileAlloc(io, entry.name, allocator, .limited(max_input_bytes)) catch |err| {
                try stdout.print("  {s}/{s}: read failed ({s})\n", .{ name, entry.name, @errorName(err) });
                fails += 1;
                continue;
            };
            defer allocator.free(bytes);

            codecs.runTarget(allocator, target, bytes) catch |err| {
                try stdout.print("  {s}/{s}: target raised {s}\n", .{ name, entry.name, @errorName(err) });
                fails += 1;
                continue;
            };
            cases += 1;
        }

        try stdout.print("  {s}: cases={d} fails={d}\n", .{ name, cases, fails });
        total_cases += cases;
        total_fails += fails;
    }

    try stdout.print(
        "http3_zig fuzz corpus targets={d} cases={d} fails={d}\n",
        .{ targets.len, total_cases, total_fails },
    );
    try stdout.flush();

    if (total_fails > 0) std.process.exit(1);
}
