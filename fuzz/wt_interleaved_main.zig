//! Runner for the WebTransport interleaved-operations fuzz target.
//!
//! Walks every file under `fuzz/corpus/wt-interleaved/` and feeds it
//! through the harness in `wt_interleaved.zig`. Larger than the smoke
//! corpus on the codec targets — drives a real H3Pair for every input.
//!
//! Invariants the harness asserts (panic, leak, unexpected close, lingering
//! session state) bubble up here as a non-zero exit.

const std = @import("std");
const wt = @import("wt_interleaved.zig");

const max_input_bytes = 64 * 1024;
const corpus_dir_path = "fuzz/corpus/wt-interleaved";

pub fn main(init: std.process.Init) !void {
    // The harness uses Zig's DebugAllocator (the safety-checking GPA in
    // 0.15+) so leaks fail the run. The runner uses its own instance for
    // stable accounting of buffers it allocates outside per-input runs.
    var gpa: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const io = init.io;

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    const cwd = std.Io.Dir.cwd();

    var seed_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (seed_paths.items) |path| allocator.free(path);
        seed_paths.deinit(allocator);
    }

    while (args.next()) |arg| {
        // CLI args take precedence over the corpus directory.
        try seed_paths.append(allocator, try allocator.dupe(u8, arg));
    }

    if (seed_paths.items.len == 0) {
        // Walk the corpus dir.
        var dir = cwd.openDir(io, corpus_dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => {
                try stdout.print("wt-interleaved: corpus dir missing — nothing to do\n", .{});
                try stdout.flush();
                return;
            },
            else => return err,
        };
        defer dir.close(io);

        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ corpus_dir_path, entry.name });
            try seed_paths.append(allocator, path);
        }
    }

    // Sort for stable output ordering (cwd.iterate is filesystem
    // dependent).
    std.mem.sort([]u8, seed_paths.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    var cases: usize = 0;
    var fails: usize = 0;

    for (seed_paths.items) |path| {
        const bytes = cwd.readFileAlloc(io, path, allocator, .limited(max_input_bytes)) catch |err| {
            try stdout.print("  {s}: read failed ({s})\n", .{ path, @errorName(err) });
            fails += 1;
            continue;
        };
        defer allocator.free(bytes);

        // Each input gets its own GPA so a leak from input #N doesn't
        // contaminate input #N+1.
        var input_gpa: std.heap.DebugAllocator(.{ .safety = true }) = .init;
        const input_alloc = input_gpa.allocator();

        wt.run(input_alloc, bytes) catch |err| {
            try stdout.print("  {s}: harness raised {s}\n", .{ path, @errorName(err) });
            fails += 1;
            // Still teardown the GPA — a leak after a harness error is
            // separately interesting but we log just the first failure.
            _ = input_gpa.deinit();
            continue;
        };

        switch (input_gpa.deinit()) {
            .ok => {},
            .leak => {
                try stdout.print("  {s}: LEAK detected\n", .{path});
                fails += 1;
                continue;
            },
        }

        cases += 1;
    }

    try stdout.print(
        "http3_zig fuzz wt-interleaved cases={d} fails={d}\n",
        .{ cases, fails },
    );
    try stdout.flush();

    if (fails > 0) std.process.exit(1);
}
