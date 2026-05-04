const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const nullq_dep = b.dependency("nullq", .{
        .target = target,
        .optimize = optimize,
    });
    const nullq_mod = nullq_dep.module("nullq");

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const null3_mod = b.addModule("null3", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    null3_mod.addImport("nullq", nullq_mod);
    null3_mod.addImport("boringssl", boringssl_mod);

    const test_step = b.step("test", "Run null3 tests");

    const unit_tests = b.addTest(.{ .root_module = null3_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("null3", null3_mod);
    tests_mod.addImport("nullq", nullq_mod);
    tests_mod.addImport("boringssl", boringssl_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    const curl_h3_server_mod = b.createModule(.{
        .root_source_file = b.path("interop/curl_h3/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    curl_h3_server_mod.addImport("null3", null3_mod);
    curl_h3_server_mod.addImport("nullq", nullq_mod);
    curl_h3_server_mod.addImport("boringssl", boringssl_mod);
    const curl_h3_server = b.addExecutable(.{
        .name = "null3-curl-h3-server",
        .root_module = curl_h3_server_mod,
    });
    const install_curl_h3_server = b.addInstallArtifact(curl_h3_server, .{});
    const curl_h3_server_step = b.step("curl-h3-server", "Build the curl HTTP/3 interop server");
    curl_h3_server_step.dependOn(&install_curl_h3_server.step);
}
