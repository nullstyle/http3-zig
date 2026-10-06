const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // An application that uses http3-zig and another quic package
    // (capnp-zig, qmsg, ...). Both get the same target and optimize, as
    // in a real build.
    const http3_dep = b.dependency("http3_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const sibling_dep = b.dependency("sibling", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("http3_zig", http3_dep.module("http3_zig"));
    exe_mod.addImport("sibling", sibling_dep.module("sibling"));

    const exe = b.addExecutable(.{
        .name = "coexist-smoke",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the coexist smoke binary");
    run_step.dependOn(&run.step);
}
