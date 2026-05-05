const std = @import("std");
const codecs = @import("codecs.zig");

const max_input_bytes = 64 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    const target_arg = args.next() orelse "all";
    const target = codecs.targetFromName(target_arg) orelse {
        usage();
        return error.UnknownFuzzTarget;
    };

    var cases: usize = 0;
    while (args.next()) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_input_bytes));
        defer allocator.free(bytes);
        try codecs.runTarget(allocator, target, bytes);
        cases += 1;
    }

    if (cases == 0) {
        for (codecs.smokeInputs()) |input| {
            try codecs.runTarget(allocator, target, input);
            cases += 1;
        }
    }

    std.debug.print("null3 fuzz codecs target={s} cases={d}\n", .{ codecs.targetName(target), cases });
}

fn usage() void {
    std.debug.print(
        \\usage: null3-fuzz-codecs [target] [file ...]
        \\targets: all frame settings capsule datagram qpack-integer qpack-huffman
        \\         qpack-field-static qpack-field-literal qpack-field-dynamic
        \\         qpack-encoder-instruction qpack-decoder-instruction
        \\         websocket-frame websocket-message
        \\
    , .{});
}
