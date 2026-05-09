const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const quic_zig_dep = b.dependency("quic_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const quic_zig_mod = b.createModule(.{
        .root_source_file = quic_zig_dep.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_zig_mod.addImport("boringssl", boringssl_mod);

    const http3_zig_mod = b.addModule("http3_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    http3_zig_mod.addImport("quic_zig", quic_zig_mod);
    http3_zig_mod.addImport("boringssl", boringssl_mod);

    const fuzz_codecs_lib_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/codecs.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_codecs_lib_mod.addImport("http3_zig", http3_zig_mod);

    const test_step = b.step("test", "Run http3_zig tests");

    const unit_tests = b.addTest(.{ .root_module = http3_zig_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("http3_zig", http3_zig_mod);
    tests_mod.addImport("quic_zig", quic_zig_mod);
    tests_mod.addImport("boringssl", boringssl_mod);
    tests_mod.addImport("http3_zig_fuzz_codecs", fuzz_codecs_lib_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    // RFC-traceable conformance suites under tests/conformance/. Each
    // file mirrors a section of an RFC and uses BCP 14 keywords plus
    // `[RFC#### §X.Y ¶N]` citations in test names so failures point an
    // auditor straight at the offending requirement. See
    // `tests/conformance/README.md` for the full grammar.
    //
    // The conformance binary is its own `addTest` invocation so we can
    // expose a narrower `zig build conformance` entry point and so a
    // `-Dconformance-filter='RFC9114 §7.2'` invocation only walks the
    // conformance corpus. Uses the default Zig test runner — no
    // third-party runner dependency.
    const conformance_filter = b.option(
        []const u8,
        "conformance-filter",
        "Substring filter for the RFC conformance suite (e.g. 'RFC9114 §7.2')",
    );
    const conformance_filters: []const []const u8 =
        if (conformance_filter) |f| &.{f} else &.{};
    const conformance_mod = b.createModule(.{
        .root_source_file = b.path("tests/conformance.zig"),
        .target = target,
        .optimize = optimize,
    });
    conformance_mod.addImport("http3_zig", http3_zig_mod);
    conformance_mod.addImport("quic_zig", quic_zig_mod);
    conformance_mod.addImport("boringssl", boringssl_mod);
    const conformance_tests = b.addTest(.{
        .root_module = conformance_mod,
        .filters = conformance_filters,
    });
    const run_conformance_tests = b.addRunArtifact(conformance_tests);
    test_step.dependOn(&run_conformance_tests.step);

    const conformance_step = b.step("conformance", "Run http3_zig RFC-traceable conformance suites");
    conformance_step.dependOn(&run_conformance_tests.step);

    const qpack_dynamic_interop_mod = b.createModule(.{
        .root_source_file = b.path("interop/qpack_dynamic/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    qpack_dynamic_interop_mod.addImport("http3_zig", http3_zig_mod);
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
    fuzz_codecs_mod.addImport("http3_zig", http3_zig_mod);
    const fuzz_codecs = b.addExecutable(.{
        .name = "http3-zig-fuzz-codecs",
        .root_module = fuzz_codecs_mod,
    });
    const install_fuzz_codecs = b.addInstallArtifact(fuzz_codecs, .{});
    const fuzz_codecs_step = b.step("fuzz-codecs", "Build the transport-free codec fuzz harness");
    fuzz_codecs_step.dependOn(&install_fuzz_codecs.step);

    const run_fuzz_smoke = b.addRunArtifact(fuzz_codecs);
    run_fuzz_smoke.addArg("all");
    const run_fuzz_smoke_step = b.step("run-fuzz-smoke", "Run the codec fuzz harness smoke corpus");
    run_fuzz_smoke_step.dependOn(&run_fuzz_smoke.step);

    // Seed generator — encodes well-formed and boundary inputs into
    // `fuzz/corpus/<target>/`. The output directory is
    // version-controlled, so this only needs to run when the corpus
    // is being regenerated (new seed types added, codec wire format
    // changed, …). It depends on the http3_zig + quic_zig modules
    // because most of the well-formed seeds use the project's own
    // encoders.
    const fuzz_seed_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/seed.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_seed_mod.addImport("http3_zig", http3_zig_mod);
    fuzz_seed_mod.addImport("quic_zig", quic_zig_mod);
    const fuzz_seed = b.addExecutable(.{
        .name = "http3-zig-fuzz-seed",
        .root_module = fuzz_seed_mod,
    });
    const run_fuzz_seed = b.addRunArtifact(fuzz_seed);
    run_fuzz_seed.addArgs(b.args orelse &[_][]const u8{});
    const seed_fuzz_corpus_step = b.step(
        "seed-fuzz-corpus",
        "(Re)generate fuzz/corpus/ from the seed generator. Run after seed.zig changes.",
    );
    seed_fuzz_corpus_step.dependOn(&run_fuzz_seed.step);

    // Corpus runner — walks every file under `fuzz/corpus/<target>/`
    // and feeds it through the corresponding fuzz target. Heavier
    // than the smoke run; suitable as a non-gating CI step or as the
    // entry point for coverage-guided fuzzers seeded with this
    // corpus.
    const fuzz_corpus_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/corpus_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_corpus_mod.addImport("http3_zig", http3_zig_mod);
    const fuzz_corpus = b.addExecutable(.{
        .name = "http3-zig-fuzz-corpus",
        .root_module = fuzz_corpus_mod,
    });
    const install_fuzz_corpus = b.addInstallArtifact(fuzz_corpus, .{});
    const fuzz_corpus_step = b.step("fuzz-corpus", "Build the corpus-walking fuzz harness");
    fuzz_corpus_step.dependOn(&install_fuzz_corpus.step);

    const run_fuzz_corpus = b.addRunArtifact(fuzz_corpus);
    run_fuzz_corpus.addArgs(b.args orelse &[_][]const u8{});
    const run_fuzz_corpus_step = b.step(
        "run-fuzz-corpus",
        "Run every file in fuzz/corpus/<target>/ through its codec target",
    );
    run_fuzz_corpus_step.dependOn(&run_fuzz_corpus.step);

    const curl_h3_server_mod = b.createModule(.{
        .root_source_file = b.path("interop/curl_h3/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    curl_h3_server_mod.addImport("http3_zig", http3_zig_mod);
    curl_h3_server_mod.addImport("quic_zig", quic_zig_mod);
    curl_h3_server_mod.addImport("boringssl", boringssl_mod);
    const curl_h3_server = b.addExecutable(.{
        .name = "http3-zig-curl-h3-server",
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
    external_h3_client_mod.addImport("http3_zig", http3_zig_mod);
    external_h3_client_mod.addImport("quic_zig", quic_zig_mod);
    external_h3_client_mod.addImport("boringssl", boringssl_mod);
    const external_h3_client = b.addExecutable(.{
        .name = "http3-zig-external-h3-client",
        .root_module = external_h3_client_mod,
    });
    const install_external_h3_client = b.addInstallArtifact(external_h3_client, .{});
    const external_h3_client_step = b.step("external-h3-client", "Build the external HTTP/3 interop client");
    external_h3_client_step.dependOn(&install_external_h3_client.step);

    const external_wt_client_mod = b.createModule(.{
        .root_source_file = b.path("interop/external_wt/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    external_wt_client_mod.addImport("http3_zig", http3_zig_mod);
    external_wt_client_mod.addImport("quic_zig", quic_zig_mod);
    external_wt_client_mod.addImport("boringssl", boringssl_mod);
    const external_wt_client = b.addExecutable(.{
        .name = "http3-zig-external-wt-client",
        .root_module = external_wt_client_mod,
    });
    const install_external_wt_client = b.addInstallArtifact(external_wt_client, .{});
    const external_wt_client_step = b.step("external-wt-client", "Build the external WebTransport interop client");
    external_wt_client_step.dependOn(&install_external_wt_client.step);

    const run_external_wt_client = b.addRunArtifact(external_wt_client);
    run_external_wt_client.addArgs(b.args orelse &[_][]const u8{});
    const run_external_wt_client_step = b.step("run-external-wt-client", "Run the external WebTransport interop client");
    run_external_wt_client_step.dependOn(&run_external_wt_client.step);

    // Companion WebTransport echo server. Used by
    // `.github/workflows/wt-interop-self-test.yml` as the in-tree
    // peer the matrix runner exercises — gives CI a real-socket
    // round-trip target without depending on a third-party server.
    const external_wt_server_mod = b.createModule(.{
        .root_source_file = b.path("interop/external_wt/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    external_wt_server_mod.addImport("http3_zig", http3_zig_mod);
    external_wt_server_mod.addImport("quic_zig", quic_zig_mod);
    external_wt_server_mod.addImport("boringssl", boringssl_mod);
    const external_wt_server = b.addExecutable(.{
        .name = "http3-zig-external-wt-server",
        .root_module = external_wt_server_mod,
    });
    const install_external_wt_server = b.addInstallArtifact(external_wt_server, .{});
    const external_wt_server_step = b.step("external-wt-server", "Build the WebTransport echo server harness");
    external_wt_server_step.dependOn(&install_external_wt_server.step);

    const run_external_wt_server = b.addRunArtifact(external_wt_server);
    run_external_wt_server.addArgs(b.args orelse &[_][]const u8{});
    const run_external_wt_server_step = b.step("run-external-wt-server", "Run the WebTransport echo server harness");
    run_external_wt_server_step.dependOn(&run_external_wt_server.step);

    // Matrix wrapper that loops over `WT_INTEROP_MATRIX_URLS` and
    // shells out to the per-target client per URL. Skip-friendly when
    // the env var is unset. See `interop/external_wt/README.md`.
    const wt_interop_matrix_mod = b.createModule(.{
        .root_source_file = b.path("interop/external_wt/matrix.zig"),
        .target = target,
        .optimize = optimize,
    });
    const wt_interop_matrix = b.addExecutable(.{
        .name = "http3-zig-wt-interop-matrix",
        .root_module = wt_interop_matrix_mod,
    });
    const install_wt_interop_matrix = b.addInstallArtifact(wt_interop_matrix, .{});

    // Tests for the matrix runner's pure CLI translation logic
    // (`--timeout-ms` → `--max-time-ms`). The `addTest` invocation
    // produces a test binary using the same module as the executable,
    // so the `pub fn main` is just dead weight under the test runner.
    const wt_interop_matrix_tests = b.addTest(.{ .root_module = wt_interop_matrix_mod });
    const run_wt_interop_matrix_tests = b.addRunArtifact(wt_interop_matrix_tests);
    test_step.dependOn(&run_wt_interop_matrix_tests.step);
    // Building the matrix runner implies building the client it shells
    // out to — keep the dependency explicit so `zig build wt-interop-matrix`
    // never fails because the client wasn't installed.
    install_wt_interop_matrix.step.dependOn(&install_external_wt_client.step);
    const install_wt_interop_matrix_step = b.step(
        "install-wt-interop-matrix",
        "Install the matrix runner + per-target client into zig-out/bin/",
    );
    install_wt_interop_matrix_step.dependOn(&install_wt_interop_matrix.step);

    const run_wt_interop_matrix = b.addRunArtifact(wt_interop_matrix);
    run_wt_interop_matrix.step.dependOn(&install_external_wt_client.step);
    run_wt_interop_matrix.addArgs(b.args orelse &[_][]const u8{});
    const wt_interop_matrix_step = b.step(
        "wt-interop-matrix",
        "Run external_wt client against every URL in WT_INTEROP_MATRIX_URLS",
    );
    wt_interop_matrix_step.dependOn(&install_wt_interop_matrix.step);
    wt_interop_matrix_step.dependOn(&run_wt_interop_matrix.step);

    const loopback_get_mod = b.createModule(.{
        .root_source_file = b.path("examples/loopback_get.zig"),
        .target = target,
        .optimize = optimize,
    });
    loopback_get_mod.addImport("http3_zig", http3_zig_mod);
    loopback_get_mod.addImport("quic_zig", quic_zig_mod);
    const loopback_get = b.addExecutable(.{
        .name = "http3-zig-loopback-get",
        .root_module = loopback_get_mod,
    });
    const install_loopback_get = b.addInstallArtifact(loopback_get, .{});
    const loopback_get_step = b.step("example-loopback-get", "Build the in-process HTTP/3 loopback example");
    loopback_get_step.dependOn(&install_loopback_get.step);

    const run_loopback_get = b.addRunArtifact(loopback_get);
    const run_loopback_get_step = b.step("run-example-loopback-get", "Run the in-process HTTP/3 loopback example");
    run_loopback_get_step.dependOn(&run_loopback_get.step);

    const loopback_wt_mod = b.createModule(.{
        .root_source_file = b.path("examples/loopback_wt.zig"),
        .target = target,
        .optimize = optimize,
    });
    loopback_wt_mod.addImport("http3_zig", http3_zig_mod);
    loopback_wt_mod.addImport("quic_zig", quic_zig_mod);
    const loopback_wt = b.addExecutable(.{
        .name = "http3-zig-loopback-wt",
        .root_module = loopback_wt_mod,
    });
    const install_loopback_wt = b.addInstallArtifact(loopback_wt, .{});
    const loopback_wt_step = b.step("example-loopback-wt", "Build the in-process HTTP/3 WebTransport loopback example");
    loopback_wt_step.dependOn(&install_loopback_wt.step);

    const run_loopback_wt = b.addRunArtifact(loopback_wt);
    const run_loopback_wt_step = b.step("run-example-loopback-wt", "Run the in-process HTTP/3 WebTransport loopback example");
    run_loopback_wt_step.dependOn(&run_loopback_wt.step);
}
