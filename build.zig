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
    // quic-zig's root.zig single-sources version() from a `build_options`
    // module that its own build.zig provides. Because we recreate the
    // quic_zig module here (to share http3-zig's boringssl instance across
    // the diamond, see build.zig.zon), we must supply that module too or a
    // reference to quic_zig.version() fails to compile. Value is cosmetic —
    // http3-zig never calls version() — but kept correct for the pinned dep.
    const quic_build_options = b.addOptions();
    quic_build_options.addOption([]const u8, "version", "0.6.0");
    const quic_build_options_mod = quic_build_options.createModule();

    // Single-source http3-zig's own version() from build.zig.zon so it can
    // never drift from the manifest (mirrors quic-zig's build_options pattern).
    const h3_build_options = b.addOptions();
    h3_build_options.addOption([]const u8, "version", @import("build.zig.zon").version);
    const h3_build_options_mod = h3_build_options.createModule();

    const quic_zig_mod = b.createModule(.{
        .root_source_file = quic_zig_dep.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_zig_mod.addImport("boringssl", boringssl_mod);
    quic_zig_mod.addImport("build_options", quic_build_options_mod);

    const http3_zig_mod = b.addModule("http3_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    http3_zig_mod.addImport("quic_zig", quic_zig_mod);
    http3_zig_mod.addImport("boringssl", boringssl_mod);
    http3_zig_mod.addImport("build_options", h3_build_options_mod);

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

    const qpack_dynamic_manifest_mod = b.createModule(.{
        .root_source_file = b.path("interop/qpack_dynamic/manifest_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    qpack_dynamic_manifest_mod.addImport("http3_zig", http3_zig_mod);
    const qpack_dynamic_manifest = b.addExecutable(.{
        .name = "http3-zig-qpack-dynamic-fixtures",
        .root_module = qpack_dynamic_manifest_mod,
    });
    const run_qpack_dynamic_manifest = b.addRunArtifact(qpack_dynamic_manifest);
    const qpack_dynamic_manifest_step = b.step(
        "qpack-dynamic-fixtures",
        "Print the dynamic-table QPACK fixture JSON manifest",
    );
    qpack_dynamic_manifest_step.dependOn(&run_qpack_dynamic_manifest.step);

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
    run_fuzz_seed.addPassthruArgs();
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
    run_fuzz_corpus.addPassthruArgs();
    const run_fuzz_corpus_step = b.step(
        "run-fuzz-corpus",
        "Run every file in fuzz/corpus/<target>/ through its codec target",
    );
    run_fuzz_corpus_step.dependOn(&run_fuzz_corpus.step);

    // WebTransport interleaved-operations fuzz target. Drives a real
    // H3Pair through random sequences of WT ops (open / send / drain /
    // close / reset) interpreted from the corpus byte stream. See
    // `fuzz/wt_interleaved.zig` for the bytecode and invariants.
    const fuzz_wt_interleaved_mod = b.createModule(.{
        .root_source_file = b.path("fuzz/wt_interleaved_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_wt_interleaved_mod.addImport("http3_zig", http3_zig_mod);
    fuzz_wt_interleaved_mod.addImport("quic_zig", quic_zig_mod);
    fuzz_wt_interleaved_mod.addImport("boringssl", boringssl_mod);
    const fuzz_wt_interleaved = b.addExecutable(.{
        .name = "http3-zig-fuzz-wt-interleaved",
        .root_module = fuzz_wt_interleaved_mod,
    });
    const install_fuzz_wt_interleaved = b.addInstallArtifact(fuzz_wt_interleaved, .{});
    const fuzz_wt_interleaved_step = b.step(
        "fuzz-wt-interleaved",
        "Build the WebTransport interleaved-operations fuzz harness",
    );
    fuzz_wt_interleaved_step.dependOn(&install_fuzz_wt_interleaved.step);

    const run_fuzz_wt_interleaved = b.addRunArtifact(fuzz_wt_interleaved);
    run_fuzz_wt_interleaved.addPassthruArgs();
    const run_fuzz_wt_interleaved_step = b.step(
        "run-fuzz-wt-interleaved",
        "Run the WT interleaved fuzz harness over fuzz/corpus/wt-interleaved/",
    );
    run_fuzz_wt_interleaved_step.dependOn(&run_fuzz_wt_interleaved.step);

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
    run_external_wt_client.addPassthruArgs();
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
    run_external_wt_server.addPassthruArgs();
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
    run_wt_interop_matrix.addPassthruArgs();
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

    const manual_pump_mod = b.createModule(.{
        .root_source_file = b.path("examples/manual_pump_get.zig"),
        .target = target,
        .optimize = optimize,
    });
    manual_pump_mod.addImport("http3_zig", http3_zig_mod);
    manual_pump_mod.addImport("quic_zig", quic_zig_mod);
    const manual_pump = b.addExecutable(.{
        .name = "http3-zig-manual-pump-get",
        .root_module = manual_pump_mod,
    });
    const install_manual_pump = b.addInstallArtifact(manual_pump, .{});
    const manual_pump_step = b.step("example-manual-pump-get", "Build the manual event-loop pump GET example");
    manual_pump_step.dependOn(&install_manual_pump.step);

    const run_manual_pump = b.addRunArtifact(manual_pump);
    const run_manual_pump_step = b.step("run-example-manual-pump-get", "Run the manual event-loop pump GET example");
    run_manual_pump_step.dependOn(&run_manual_pump.step);

    const observability_metrics_mod = b.createModule(.{
        .root_source_file = b.path("examples/observability_metrics.zig"),
        .target = target,
        .optimize = optimize,
    });
    observability_metrics_mod.addImport("http3_zig", http3_zig_mod);
    observability_metrics_mod.addImport("quic_zig", quic_zig_mod);
    const observability_metrics = b.addExecutable(.{
        .name = "http3-zig-observability-metrics",
        .root_module = observability_metrics_mod,
    });
    const install_observability_metrics = b.addInstallArtifact(observability_metrics, .{});
    const observability_metrics_step = b.step("example-observability-metrics", "Build the observability metrics example");
    observability_metrics_step.dependOn(&install_observability_metrics.step);

    const run_observability_metrics = b.addRunArtifact(observability_metrics);
    const run_observability_metrics_step = b.step("run-example-observability-metrics", "Run the observability metrics example");
    run_observability_metrics_step.dependOn(&run_observability_metrics.step);

    const request_reset_mod = b.createModule(.{
        .root_source_file = b.path("examples/request_reset.zig"),
        .target = target,
        .optimize = optimize,
    });
    request_reset_mod.addImport("http3_zig", http3_zig_mod);
    request_reset_mod.addImport("quic_zig", quic_zig_mod);
    const request_reset = b.addExecutable(.{
        .name = "http3-zig-request-reset",
        .root_module = request_reset_mod,
    });
    const install_request_reset = b.addInstallArtifact(request_reset, .{});
    const request_reset_step = b.step("example-request-reset", "Build the request reset lifecycle example");
    request_reset_step.dependOn(&install_request_reset.step);

    const run_request_reset = b.addRunArtifact(request_reset);
    const run_request_reset_step = b.step("run-example-request-reset", "Run the request reset lifecycle example");
    run_request_reset_step.dependOn(&run_request_reset.step);

    const bounded_body_mod = b.createModule(.{
        .root_source_file = b.path("examples/bounded_body_sink.zig"),
        .target = target,
        .optimize = optimize,
    });
    bounded_body_mod.addImport("http3_zig", http3_zig_mod);
    bounded_body_mod.addImport("quic_zig", quic_zig_mod);
    const bounded_body = b.addExecutable(.{
        .name = "http3-zig-bounded-body-sink",
        .root_module = bounded_body_mod,
    });
    const install_bounded_body = b.addInstallArtifact(bounded_body, .{});
    const bounded_body_step = b.step("example-bounded-body-sink", "Build the bounded streaming body sink example");
    bounded_body_step.dependOn(&install_bounded_body.step);

    const run_bounded_body = b.addRunArtifact(bounded_body);
    const run_bounded_body_step = b.step("run-example-bounded-body-sink", "Run the bounded streaming body sink example");
    run_bounded_body_step.dependOn(&run_bounded_body.step);

    const streaming_upload_mod = b.createModule(.{
        .root_source_file = b.path("examples/streaming_upload.zig"),
        .target = target,
        .optimize = optimize,
    });
    streaming_upload_mod.addImport("http3_zig", http3_zig_mod);
    streaming_upload_mod.addImport("quic_zig", quic_zig_mod);
    const streaming_upload = b.addExecutable(.{
        .name = "http3-zig-streaming-upload",
        .root_module = streaming_upload_mod,
    });
    const install_streaming_upload = b.addInstallArtifact(streaming_upload, .{});
    const streaming_upload_step = b.step("example-streaming-upload", "Build the streaming request upload example");
    streaming_upload_step.dependOn(&install_streaming_upload.step);

    const run_streaming_upload = b.addRunArtifact(streaming_upload);
    const run_streaming_upload_step = b.step("run-example-streaming-upload", "Run the streaming request upload example");
    run_streaming_upload_step.dependOn(&run_streaming_upload.step);

    const graceful_shutdown_mod = b.createModule(.{
        .root_source_file = b.path("examples/graceful_shutdown.zig"),
        .target = target,
        .optimize = optimize,
    });
    graceful_shutdown_mod.addImport("http3_zig", http3_zig_mod);
    graceful_shutdown_mod.addImport("quic_zig", quic_zig_mod);
    const graceful_shutdown = b.addExecutable(.{
        .name = "http3-zig-graceful-shutdown",
        .root_module = graceful_shutdown_mod,
    });
    const install_graceful_shutdown = b.addInstallArtifact(graceful_shutdown, .{});
    const graceful_shutdown_step = b.step("example-graceful-shutdown", "Build the graceful GOAWAY shutdown example");
    graceful_shutdown_step.dependOn(&install_graceful_shutdown.step);

    const run_graceful_shutdown = b.addRunArtifact(graceful_shutdown);
    const run_graceful_shutdown_step = b.step("run-example-graceful-shutdown", "Run the graceful GOAWAY shutdown example");
    run_graceful_shutdown_step.dependOn(&run_graceful_shutdown.step);

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

    const wt_proxy_mod = b.createModule(.{
        .root_source_file = b.path("examples/webtransport_proxy.zig"),
        .target = target,
        .optimize = optimize,
    });
    wt_proxy_mod.addImport("http3_zig", http3_zig_mod);
    wt_proxy_mod.addImport("quic_zig", quic_zig_mod);
    wt_proxy_mod.addImport("boringssl", boringssl_mod);
    const wt_proxy = b.addExecutable(.{
        .name = "http3-zig-webtransport-proxy",
        .root_module = wt_proxy_mod,
    });
    const install_wt_proxy = b.addInstallArtifact(wt_proxy, .{});
    const wt_proxy_step = b.step("example-webtransport-proxy", "Build the in-process WebTransport proxy datapath example");
    wt_proxy_step.dependOn(&install_wt_proxy.step);

    const run_wt_proxy = b.addRunArtifact(wt_proxy);
    const run_wt_proxy_step = b.step("run-example-webtransport-proxy", "Run the in-process WebTransport proxy datapath example");
    run_wt_proxy_step.dependOn(&run_wt_proxy.step);

    const examples_step = b.step("examples", "Build all runnable examples");
    examples_step.dependOn(&install_loopback_get.step);
    examples_step.dependOn(&install_manual_pump.step);
    examples_step.dependOn(&install_observability_metrics.step);
    examples_step.dependOn(&install_request_reset.step);
    examples_step.dependOn(&install_bounded_body.step);
    examples_step.dependOn(&install_streaming_upload.step);
    examples_step.dependOn(&install_graceful_shutdown.step);
    examples_step.dependOn(&install_loopback_wt.step);
    examples_step.dependOn(&install_wt_proxy.step);

    const run_examples_step = b.step("run-examples", "Run all in-process examples");
    run_examples_step.dependOn(&run_loopback_get.step);
    run_examples_step.dependOn(&run_manual_pump.step);
    run_examples_step.dependOn(&run_observability_metrics.step);
    run_examples_step.dependOn(&run_request_reset.step);
    run_examples_step.dependOn(&run_bounded_body.step);
    run_examples_step.dependOn(&run_streaming_upload.step);
    run_examples_step.dependOn(&run_graceful_shutdown.step);
    run_examples_step.dependOn(&run_loopback_wt.step);
    run_examples_step.dependOn(&run_wt_proxy.step);

    // WebTransport baseline microbenchmark. Drives an in-process H3 +
    // QUIC pair through the loopback shim and reports p50/p99/mean/max
    // for session establishment, datagram round-trip, and uni stream
    // round-trip. See `docs/perf-baseline.md` for the published
    // numbers — this step is the source for that report.
    //
    // The benchmark sits outside `tests/` deliberately: it's a runtime
    // executable, not a `zig test` artifact, so it can use plain
    // wall-clock timing and stable stdout formatting.
    const wt_bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/wt_bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    wt_bench_mod.addImport("http3_zig", http3_zig_mod);
    wt_bench_mod.addImport("quic_zig", quic_zig_mod);
    wt_bench_mod.addImport("boringssl", boringssl_mod);
    const wt_bench = b.addExecutable(.{
        .name = "http3-zig-wt-bench",
        .root_module = wt_bench_mod,
    });
    const install_wt_bench = b.addInstallArtifact(wt_bench, .{});
    const wt_bench_step = b.step("bench-build", "Build the WebTransport baseline benchmark");
    wt_bench_step.dependOn(&install_wt_bench.step);

    const run_wt_bench = b.addRunArtifact(wt_bench);
    const bench_step = b.step("bench", "Run the WebTransport baseline benchmark (use -Doptimize=ReleaseFast for published numbers)");
    bench_step.dependOn(&run_wt_bench.step);

    // Long-running-session memory profile. Same loopback shim as
    // `bench/wt_bench.zig`, but the binary is dedicated to detecting
    // monotonic allocator growth across many drains on a single
    // WebTransport session. Always built ReleaseSafe regardless of the
    // top-level `-Doptimize` setting — the `DebugAllocator` leak
    // detector and the counting allocator we layer on top are the
    // whole point of this binary, and they only function with safety
    // on.
    //
    // Builds private boringssl + quic_zig + http3_zig module
    // instances at the same `.ReleaseSafe` mode so the link-time
    // ubsan handler symbols match across the C++ archives and the Zig
    // root. Mirrors the pattern `wt-load` uses for its own pinned
    // optimize. See `docs/memory-profile.md` for the published
    // numbers.
    const mem_profile_optimize: std.builtin.OptimizeMode = .ReleaseSafe;
    const boringssl_safe_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = mem_profile_optimize,
    });
    const boringssl_safe_mod = boringssl_safe_dep.module("boringssl");
    const quic_zig_safe_dep = b.dependency("quic_zig", .{
        .target = target,
        .optimize = mem_profile_optimize,
    });
    const quic_zig_safe_mod = b.createModule(.{
        .root_source_file = quic_zig_safe_dep.path("src/root.zig"),
        .target = target,
        .optimize = mem_profile_optimize,
    });
    quic_zig_safe_mod.addImport("boringssl", boringssl_safe_mod);
    quic_zig_safe_mod.addImport("build_options", quic_build_options_mod);
    const http3_zig_safe_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = mem_profile_optimize,
    });
    http3_zig_safe_mod.addImport("quic_zig", quic_zig_safe_mod);
    http3_zig_safe_mod.addImport("boringssl", boringssl_safe_mod);
    http3_zig_safe_mod.addImport("build_options", h3_build_options_mod);
    const wt_memory_mod = b.createModule(.{
        .root_source_file = b.path("bench/wt_memory.zig"),
        .target = target,
        .optimize = mem_profile_optimize,
    });
    wt_memory_mod.addImport("http3_zig", http3_zig_safe_mod);
    wt_memory_mod.addImport("quic_zig", quic_zig_safe_mod);
    wt_memory_mod.addImport("boringssl", boringssl_safe_mod);
    const wt_memory = b.addExecutable(.{
        .name = "http3-zig-wt-memory",
        .root_module = wt_memory_mod,
    });
    const install_wt_memory = b.addInstallArtifact(wt_memory, .{});
    const mem_profile_build_step = b.step(
        "mem-profile-build",
        "Build the WebTransport long-running memory profiler (always ReleaseSafe)",
    );
    mem_profile_build_step.dependOn(&install_wt_memory.step);

    const run_wt_memory = b.addRunArtifact(wt_memory);
    const mem_profile_step = b.step(
        "mem-profile",
        "Run the WebTransport long-running memory profiler (always ReleaseSafe)",
    );
    mem_profile_step.dependOn(&run_wt_memory.step);

    // WebTransport concurrent-session load test. Spins up 100 WT
    // sessions on a single QUIC connection and exercises uni
    // streams, bidirectional datagrams, and per-session WT_MAX_DATA
    // bumps under the same in-process loopback shim as `bench`. The
    // goal is finding scaling cliffs (allocator pressure, dispatch
    // hot path, drain-budget firing repeatedly) — not optimization.
    // See `docs/load-baseline.md` for the published numbers.
    //
    // Pinned to ReleaseFast regardless of the top-level
    // `-Doptimize` setting so successive runs publish comparable
    // numbers. Invariants (session-state checks, per-stream
    // attribution, lastCloseError == null) are asserted on every
    // iteration regardless of the optimize mode — the load test
    // returns explicit error tags rather than relying on `assert`.
    const wt_load_optimize: std.builtin.OptimizeMode = .ReleaseFast;
    const boringssl_release_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = wt_load_optimize,
    });
    const boringssl_release_mod = boringssl_release_dep.module("boringssl");
    const quic_zig_release_dep = b.dependency("quic_zig", .{
        .target = target,
        .optimize = wt_load_optimize,
    });
    const quic_zig_release_mod = b.createModule(.{
        .root_source_file = quic_zig_release_dep.path("src/root.zig"),
        .target = target,
        .optimize = wt_load_optimize,
    });
    quic_zig_release_mod.addImport("boringssl", boringssl_release_mod);
    quic_zig_release_mod.addImport("build_options", quic_build_options_mod);
    const http3_zig_release_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = wt_load_optimize,
    });
    http3_zig_release_mod.addImport("quic_zig", quic_zig_release_mod);
    http3_zig_release_mod.addImport("boringssl", boringssl_release_mod);
    http3_zig_release_mod.addImport("build_options", h3_build_options_mod);
    const wt_load_mod = b.createModule(.{
        .root_source_file = b.path("bench/wt_load.zig"),
        .target = target,
        .optimize = wt_load_optimize,
    });
    wt_load_mod.addImport("http3_zig", http3_zig_release_mod);
    wt_load_mod.addImport("quic_zig", quic_zig_release_mod);
    wt_load_mod.addImport("boringssl", boringssl_release_mod);
    const wt_load = b.addExecutable(.{
        .name = "http3-zig-wt-load",
        .root_module = wt_load_mod,
    });
    const install_wt_load = b.addInstallArtifact(wt_load, .{});
    const wt_load_build_step = b.step(
        "wt-load-build",
        "Build the WebTransport concurrent-session load test (always ReleaseFast)",
    );
    wt_load_build_step.dependOn(&install_wt_load.step);

    const run_wt_load = b.addRunArtifact(wt_load);
    const wt_load_step = b.step(
        "wt-load",
        "Run the 100-session WebTransport load test (always ReleaseFast)",
    );
    wt_load_step.dependOn(&run_wt_load.step);
}
