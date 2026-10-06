//! A stand-in for capnp-zig (and qmsg, qmesh-zig, nest): a package that
//! takes quic through quic's own exported modules with the option map
//! the coordinated set agreed on. Change this map only together with
//! those packages.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quic_dep = b.dependency("quic", .{
        .target = target,
        .release = optimize != .debug,
        .@"sanitize-c" = @as([]const u8, "trap"),
    });

    const mod = b.addModule("sibling", .{
        .root_source_file = b.path("src/sibling.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("quic", quic_dep.module("quic"));
    mod.addImport("boringssl", quic_dep.module("boringssl"));
}
