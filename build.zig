const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const nullq_dep = b.dependency("nullq", .{
        .target = target,
        .optimize = optimize,
    });
    const nullq_mod = b.createModule(.{
        .root_source_file = nullq_dep.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    nullq_mod.addImport("boringssl", boringssl_mod);

    const null3_mod = b.addModule("null3", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    null3_mod.addImport("nullq", nullq_mod);
    null3_mod.addImport("boringssl", boringssl_mod);

    const fuzz_codecs_lib_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/codecs.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_codecs_lib_mod.addImport("null3", null3_mod);

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
    tests_mod.addImport("null3_fuzz_codecs", fuzz_codecs_lib_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    const qpack_dynamic_interop_mod = b.createModule(.{
        .root_source_file = b.path("interop/qpack_dynamic/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    qpack_dynamic_interop_mod.addImport("null3", null3_mod);
    const qpack_dynamic_interop_tests = b.addTest(.{ .root_module = qpack_dynamic_interop_mod });
    const run_qpack_dynamic_interop_tests = b.addRunArtifact(qpack_dynamic_interop_tests);
    test_step.dependOn(&run_qpack_dynamic_interop_tests.step);
    const qpack_dynamic_interop_step = b.step(
        "qpack-dynamic-interop",
        "Run the dynamic-table QPACK fixture runner",
    );
    qpack_dynamic_interop_step.dependOn(&run_qpack_dynamic_interop_tests.step);

    const fuzz_codecs_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/codecs_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_codecs_mod.addImport("null3", null3_mod);
    const fuzz_codecs = b.addExecutable(.{
        .name = "null3-fuzz-codecs",
        .root_module = fuzz_codecs_mod,
    });
    const install_fuzz_codecs = b.addInstallArtifact(fuzz_codecs, .{});
    const fuzz_codecs_step = b.step("fuzz-codecs", "Build the transport-free codec fuzz harness");
    fuzz_codecs_step.dependOn(&install_fuzz_codecs.step);

    const run_fuzz_smoke = b.addRunArtifact(fuzz_codecs);
    run_fuzz_smoke.addArg("all");
    const run_fuzz_smoke_step = b.step("run-fuzz-smoke", "Run the codec fuzz harness smoke corpus");
    run_fuzz_smoke_step.dependOn(&run_fuzz_smoke.step);

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

    const external_h3_client_mod = b.createModule(.{
        .root_source_file = b.path("interop/external_h3/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    external_h3_client_mod.addImport("null3", null3_mod);
    external_h3_client_mod.addImport("nullq", nullq_mod);
    external_h3_client_mod.addImport("boringssl", boringssl_mod);
    const external_h3_client = b.addExecutable(.{
        .name = "null3-external-h3-client",
        .root_module = external_h3_client_mod,
    });
    const install_external_h3_client = b.addInstallArtifact(external_h3_client, .{});
    const external_h3_client_step = b.step("external-h3-client", "Build the external HTTP/3 interop client");
    external_h3_client_step.dependOn(&install_external_h3_client.step);

    const loopback_get_mod = b.createModule(.{
        .root_source_file = b.path("examples/loopback_get.zig"),
        .target = target,
        .optimize = optimize,
    });
    loopback_get_mod.addImport("null3", null3_mod);
    loopback_get_mod.addImport("nullq", nullq_mod);
    const loopback_get = b.addExecutable(.{
        .name = "null3-loopback-get",
        .root_module = loopback_get_mod,
    });
    const install_loopback_get = b.addInstallArtifact(loopback_get, .{});
    const loopback_get_step = b.step("example-loopback-get", "Build the in-process HTTP/3 loopback example");
    loopback_get_step.dependOn(&install_loopback_get.step);

    const run_loopback_get = b.addRunArtifact(loopback_get);
    const run_loopback_get_step = b.step("run-example-loopback-get", "Run the in-process HTTP/3 loopback example");
    run_loopback_get_step.dependOn(&run_loopback_get.step);
}
