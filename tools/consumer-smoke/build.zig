const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const http3_dep = b.dependency("http3_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("http3_zig", http3_dep.module("http3_zig"));
    // The exported shared instances are the point of this smoke test: a
    // consumer must be able to name quic_zig/boringssl types that unify
    // with http3_zig's API without declaring its own copies of those deps.
    exe_mod.addImport("quic_zig", http3_dep.module("quic_zig"));
    exe_mod.addImport("boringssl", http3_dep.module("boringssl"));

    const exe = b.addExecutable(.{
        .name = "consumer-smoke",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the consumer smoke binary");
    run_step.dependOn(&run.step);
}
