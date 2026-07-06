const std = @import("std");
const manifest = @import("manifest.zig");

pub fn main(init: std.process.Init) !void {
    var stdout_buf: [8192]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try manifest.writeJson(stdout);
    try stdout.flush();
}
