# Quality Analysis: http3-zig

> **Disposition (2026-09-03): CLOSED.** Every finding in this audit is
> resolved or explicitly dispositioned as of commit `16f193d` — the
> fixes landed across `0445702..16f193d` (toolchain/quic v0.19.0 wave,
> the OOM memory-safety batch plus the fault-injection sweep that found
> three bugs this audit missed, terminal-event budget survival, the
> Actions SHA-pinning/dependabot/fuzz-floor CI hardening, the RFC
> conformance sweep, the performance pass, the release artifact work,
> the session-engine split, local-CI-via-act, and the final polish
> items). The deliberately-outstanding exceptions, by design: F04
> (bus-factor — organizational), F11 (MASQUE session dispatch — ROADMAP
> out of scope), F22/F42 (live in the boringssl-zig / quic-zig repos),
> and the interop-expansion roadmap items (ngtcp2/lsquic legs, Windows
> CI leg, SLSA provenance). Findings below are the original 2026-08-16
> text, kept as the record.

**Repo:** `http3-zig` (v0.4.9) · **Date:** 2026-08-16 · **Method:** 13 parallel dimension agents + full test-suite verification (`zig build test`) + `zig fmt --check` + git-tree/artifact audit, on Zig 0.17.0-dev.1683+5ceec001b (macOS arm64).

## Build & Test Verification

- `zig build test` — **exit 0** (`BUILD_EXIT_CODE=0`). ⚠️ The provided log (`/tmp/h3zig-test.log`) is only 2 lines (exit code + a timestamp); it contains **no test counts, per-suite steps, or duration**. Source-derived block counts (not from the log): ~970 conformance + ~172 integration + ~147 src unit-test blocks, plus `qpack_dynamic_interop`. Wall-clock duration is unrecoverable from the provided log — a small auditability gap (F48).
- `zig fmt --check` — **passes clean**.
- Toolchain — pinned to `0.17.0-dev.1683+5ceec001b` (`mise.toml:9` == `build.zig.zon:5` `minimum_zig_version`); full suite green on macOS arm64.
- Git tree clean; no committed build artifacts (`zig-cache`/`zig-out`/`zig-pkg` gitignored).

## Executive Summary

- **Overall: genuinely strong.** A disciplined, unusually well-engineered pre-1.0 Zig implementation: green suite on a pinned toolchain, RFC-traceable conformance (970 tests with per-paragraph citations), a compile-enforced API-stability contract, rigorous URL+hash dependency pinning, and honest documentation. **No P0 (remotely-triggerable memory unsafety or unbounded resource exhaustion) was found**, and no peer-reachable `@panic`/`unreachable`/integer-narrowing remains.
- **Strongest areas:** the session-engine drain/iterator/budget discipline; RFC 9114 core-protocol correctness and scope split; QPACK static-table/Huffman/RIC arithmetic; the `check-api` signature pinning; the out-of-tree `consumer-smoke` that proves the quic/boringssl module-identity diamond.
- **Weakest areas:** supply-chain posture (bus-factor-1, tag-pinned Actions, no SBOM/dependabot) and the fuzz/CI safety net (nightly fuzz structurally cannot report a crash; "sanitizer-grade" claim runs ReleaseSafe only).
- **Headline risk #1 — memory safety:** a double-free on the OOM path of event-list append, replicated at 6 call sites (`src/session.zig`). Real, but OOM-gated — not remotely triggerable in steady state (F01). A second, smaller OOM double-free exists in the scratch buffer (F38).
- **Headline risk #2 — supply chain:** the entire tier (http3-zig → quic-zig → boringssl-zig → 243 MB BoringSSL C) is one maintainer's work, with quic-zig self-described as "vibe-coded … just for me"; no upstream to drift from or fall back to (F04).
- **Recurring correctness class:** a "consume/latch-then-reserve" ordering in the drain-budget path can drop one-shot terminal events under budget exhaustion — most seriously `connection_closed` (F05), plus `failMessageStream` (F39) and the at-most-once `early_data` event (F40).
- **Record correction:** 0-RTT anti-replay (SHA256(ticket||client_random)) is implemented in quic-zig, not this repo; `src/earlydata.zig` only binds a ticket to byte-identical SETTINGS (F42). The repo also makes no "signature-pinned Actions" claim — Actions are tag-pinned (F02).
- **Verification note:** the test log under-captures the run (no counts/duration), so the verification section relies on the exit code, `fmt` check, and source-derived counts (F48).

## Prioritized Fixes

Severity: **P0** critical (remotely-triggerable memory unsafety / unbounded resource exhaustion) · **P1** high · **P2** medium · **P3** low/nits. Findings merged across dimensions (all sources noted). `(speculative)` = agent confidence was speculative.

| ID | Sev | Dimension | Title | Fix | Files |
|----|-----|-----------|-------|-----|-------|
| F01 | P1 | session-engine | Double-free on drain event-list append failure (6 call sites) | Pick one ownership contract: delete the redundant `errdefer` free (appendRawEvent already deinits) or make appendRawEvent not deinit; add fault-injection test. | src/session.zig:6992-6997,2309-2316,2744-2752,3834-3842,3884-3909,4228-4238,5568-5583 |
| F02 | P1 | deps-supply-chain + ci-interop | All 9 workflows' third-party Actions are tag-pinned (mutable), none commit-SHA; no dependabot | Pin every `uses:` to a full commit SHA; add dependabot.yml; least-privilege job permissions (restrict release.yml `contents:write`). | .github/workflows/*.yml |
| F03 | P1 | ci-interop | Nightly corpus-loop fuzz job cannot report a found crash | Rewrite loop with `set -e` + propagate non-zero exits; make crash-artifact step `if: always()` or check crash-dir. | .github/workflows/fuzz-nightly.yml:69-78, fuzz/corpus_main.zig:115 |
| F04 | P1 | deps-supply-chain | Bus-factor-1 "vibe-coded" dependency chain, no upstream/update tooling/SBOM | Treat as bus-factor-1; add SBOM + scheduled freshness check; seek a second maintainer before production adoption. | build.zig.zon, LICENSE, CONTRIBUTING.md, SECURITY.md |
| F05 | P2 | concurrency-errors | `connection_closed` terminal event consumed then dropped on budget exhaustion | Make close event non-droppable (bypass budget, or stash + re-emit); at minimum set last_close_error + sync shutdown before the fallible reserve. | src/session.zig:3846-3910,3548 |
| F06 | P2 | security-hardening | DATA frames & QPACK encoder-string literals bypass H3 receive caps; Huffman transient alloc precedes capacity check | Receive-side declared-length pre-gate for DATA; pre-allocation decoded-bytes budget in readEncoderStringAlloc before huffman.decode. | src/session.zig:4646,4629, src/qpack/instructions.zig:283 |
| F07 | P2 | h3-core-protocol | Field-name/value characters not validated (only empty/uppercase rejected) | Add tchar/token name validator + field-value CTL rejection (RFC 9110 §5.1/§5.5), map to H3_MESSAGE_ERROR; add conformance tests. | src/headers.zig:256-261, tests/conformance/rfc9114_messages.zig |
| F08 | P2 | qpack | Invalid encoder-stream indices map to QPACK_DECOMPRESSION_FAILED (0x200), not QPACK_ENCODER_STREAM_ERROR (0x201) | Dedicated error (or map at session.zig:4821 call site) → 0x201; fix the false test comment; add session-level test asserting 0x201. | src/errors.zig:208-209, src/qpack/instructions.zig:179-189, tests/conformance/rfc9204_qpack_dynamic.zig:1276-1286 |
| F09 | P2 | extensions | WebSocket masking mis-cited to nonexistent "RFC 9220 §4.5"; default `mask_policy=.any` leaves RFC 6455 §5.1 unenforced | Correct citations; make decode policy role-aware (or document embedder MUST set .required/.forbidden) instead of defaulting .any. | src/websocket_frame.zig:54, tests/conformance/rfc6455_websocket.zig:11,129-146 |
| F10 | P2 | session-engine | `openWebTransportBidiStream` orphans a StreamState registry entry on prefix-write failure | Add the same remove+deinit+destroy errdefer as its uni/push siblings (session.zig:1899-1903). | src/session.zig:1926-1945 |
| F11 | P2 | extensions | MASQUE CONNECT-UDP & WebSocket-over-H3 are helper layers only — no session dispatch/reassembly | Document embedder-owned capsule reassembly/validation, or add session-level dispatch mirroring the WebTransport path. | src/session.zig, src/masque.zig, src/websocket.zig |
| F12 | P2 | testing-fuzzing + security-hardening | Semantic header validation & MessageDecoder state machine never fuzzed | Add fuzz target(s) running headers.validate* + message.Decoder.observe over adversarial input; consider a non-WT session bytecode fuzzer. | fuzz/codecs.zig:11-32, src/headers.zig, src/message.zig |
| F13 | P2 | testing-fuzzing | Coverage-guided CI claims "sanitizer-grade" but runs ReleaseSafe (no ASan/UBSan) | Soften claim to "safety-checked" or add a sanitizer leg; document residual UAF/OOB gap. | .github/workflows/fuzz-nightly.yml:146 |
| F14 | P2 | qpack + ci-interop | "QPACK interop" hard gate is a quic-go self-test; Go request fixture diverges (user-agent differs) | Generate hex fixtures from the Zig encoder at runtime (or wire qpack_dynamic into CI); reconcile fixture to one user-agent. | .github/workflows/h3-interop.yml:183-197, interop/qpack_quic_go/qpack_quic_go_test.go:31 |
| F15 | P2 | ci-interop | Coverage-guided fuzz can silently no-op via "advisory skip" (exit 0 after known runner bug) | Add failure threshold (require N executed inputs) + notification/annotation path rather than silent green. | .github/workflows/fuzz-nightly.yml:146-163 |
| F16 | P2 | ci-interop | Release produces no artifact/provenance/signing and no interop gate | Attach ReleaseFast artifact + checksums + SLSA provenance; require interop/self-test on tag. | .github/workflows/release.yml:77-84 |
| F17 | P2 | ci-interop | WT third-party matrix passes on a single target (`continue-on-error`) and never runs on PRs | Fail/annotate when any started peer fails; add `pull_request` trigger. | .github/workflows/wt-interop.yml:244, interop/external_wt/matrix.zig |
| F18 | P2 | performance | Every DATA/capsule/datagram send allocates a heap buffer + memcpy (capsule 2-3×) | streamWrite the varint header from stack, then streamWrite user data; reuse scratch for capsule/datagram encode. | src/session.zig:6157-6185,6209-6241,2930 |
| F19 | P2 | performance | QPACK decode does 2N+1 heap allocs per section, duping comptime static-table literals | Borrow static_table.entries slices for static refs; single arena alloc for literal bytes + array. | src/qpack/root.zig:930,950,989,811 |
| F20 | P2 | performance | QPACK DynamicTable eviction is O(n²) (`orderedRemove(0)`) | Circular buffer / head-index logical eviction → O(1); matters only when dynamic inserts enabled. | src/qpack/dynamic_table.zig:247-253 |
| F21 | P2 | deps-supply-chain | CI Zig-package cache targets wrong dir (`zig-pkg`), so the documented offline mitigation is a no-op | Cache `~/.cache/zig/p` or set `ZIG_GLOBAL_CACHE_DIR=zig-pkg` in every job env. | .github/workflows/test.yml:81-86 |
| F22 | P2 | deps-supply-chain | boringssl-zig wrapper ships with no LICENSE (its Zig build code unlicensed) | Add LICENSE/NOTICE to nullstyle/boringssl-zig and include in package .paths. | build.zig.zon, LICENSE |
| F23 | P2 | deps-supply-chain | Nested BoringSSL C source is a bare-SHA pin invisible to pin-check tooling | Surface resolved boringssl_src version in check/CI; prefer a release tag over bare commit. | tools/check-boringssl-pin.sh, build.zig.zon |
| F24 | P2 | api-docs-examples | Client.Config/Server.Config duplicate session.Config 1:1, carry stale "v0.1.0" docs, absent from stability tiers | Delete them + `toSessionConfig()`, or document as Deprecated/Internal and strip v0.1.0 language. | src/client.zig:1453-1591, src/server.zig:903-1041 |
| F25 | P2 | api-docs-examples | `installEarlyDataContext` returns bare `!void` (anyerror) | Named error union + docs, matching `earlyDataApplicationContext`. | src/server.zig:68-76 |
| F26 | P2 | build-tooling | CONTRIBUTING.md claims `zig build` installs examples+interop; default install emits only libhttp3_zig.a | Correct wording (or wire install steps into default install). | CONTRIBUTING.md, build.zig |
| F27 | P2 | build-tooling | release.yml "compiles them all" but only compiles examples; bench/wt-load binaries have no CI compile gate | Wire justfile build-all (or bench/wt-load/qpack-dynamic-fixtures) into CI; fix the comment. | .github/workflows/release.yml:69-75, justfile, build.zig |
| F28 | P3 | h3-core-protocol | Unknown/GREASE frame as first control-stream frame accepted, not H3_MISSING_SETTINGS | Perform §6.2.1 first-frame check before the unknown-type early return; add test. | src/stream.zig:89-95, src/session.zig:4783-4795 |
| F29 | P3 | h3-core-protocol | Standalone message codec compares SETTINGS_MAX_FIELD_SECTION_SIZE against compressed, not uncompressed, size | Enforce on decoded field section (mirror session.zig:5660-5674). | src/message.zig:186-188,341-343,357-359 |
| F30 | P3 | qpack | DecodeBudget applies Huffman-expansion bound to non-Huffman literals, over-rejecting valid sections | Skip reserveString (or reserve exact len) when huffman_encoded=false. | src/qpack/root.zig:84-93,762-766 |
| F31 | P3 | qpack | No coverage for out-of-range STATIC index; no test asserts the actual H3 error code | Add negative encoder-stream vector + session-level assert of 0x201. | interop/qpack_dynamic/fixtures.json, tests/conformance/rfc9204_qpack_dynamic.zig |
| F32 | P3 | qpack | Huffman comptime check validates contiguity only, not prefix-freeness/completeness | Add comptime prefix-free/canonical reconstruction check. | src/qpack/huffman.zig:376-401 |
| F33 | P3 | extensions | Unknown WT capsules surfaced as events vs RFC 9297 §3.1 "MUST silently drop" | Gate forwarding behind opt-in flag; default to silent drop. | src/session.zig:2726-2754 |
| F34 | P3 | extensions (speculative) | WebSocket close-code validation rejects extension-reserved/future codes on decode | Accept any well-formed 2-byte code on decode; strict check only on encode. | src/websocket_frame.zig:334-343,331 |
| F35 | P3 | session-engine + security-hardening | drainDatagrams drops the already-popped datagram on budget exhaustion | Peek-then-commit if lossless desired, or fix the "remaining stay queued" comment. | src/session.zig:3794-3843,3815-3818 |
| F36 | P3 | session-engine + concurrency-errors + security-hardening | Re-entrancy guard incomplete: only drain/trace latched; trace callback can re-enter mutators | Document "no session mutation from observability callback" and/or assert in_drain at send/close entry. | src/session.zig:3544-3546,6638-6648,5596-5612 |
| F37 | P3 | session-engine | session.zig (7733 lines) is a maintainability hazard | Split into session/{events,config,stream_state,webtransport,drain}.zig. | src/session.zig |
| F38 | P3 | concurrency-errors | ensureDrainScratch frees old buffer before fallible realloc → double-free on OOM | Allocate new buffer first, free old only on success (or zero len first). | src/session.zig:1686-1692,1677-1678 |
| F39 | P3 | concurrency-errors | failMessageStream mutates state before reserving event → rejection dropped under budget | Reserve before resetStream + mutations (mirror observeReset). | src/session.zig:6938-6968 |
| F40 | P3 | concurrency-errors | at-most-once early_data event can be lost (latch set before append) | Reserve before latching (or re-emit if latched but undelivered). | src/session.zig:1809-1836 |
| F41 | P3 | concurrency-errors | Error classification uses open anyerror `else` catch-alls (no exhaustiveness) | Comptime/unit test iterating @typeInfo(Session.Error) members. | src/errors.zig:123,298,382,406 |
| F42 | P3 | security-hardening | 0-RTT anti-replay is in quic-zig, not this repo (earlydata.zig only binds SETTINGS) | No code change; separately audit quic-zig anti-replay (single-use, window, persistence). | src/earlydata.zig, CHANGELOG.md:153-154 |
| F43 | P3 | performance | chooseFieldRepresentation (linear static+dynamic scans) runs up to 3× per field | Materialize the plan once; encode + ref-collection consume it. | src/qpack/root.zig:474,506,286-295,639-648 |
| F44 | P3 | performance | Static-table lookup is a 99-entry linear scan, 2× per field | Comptime hash / length+first-byte bucket index. | src/qpack/static_table.zig:119-133 |
| F45 | P3 | performance | Huffman decode grows ArrayList by doubling | Pre-size to the known bound (caller already computes it). | src/qpack/huffman.zig:320-355 |
| F46 | P3 | performance | WT stream-data event copies whole rx buffer per drain | App-supplied buffer path or borrow rx (defer compaction to freeEvent). | src/session.zig:4228-4236 |
| F47 | P3 | testing-fuzzing | "Drain loop resurrecting GC-reclaimed streams" fix has no regression test | Add test asserting no duplicate stream_finished / lingering half-closed entry. | CHANGELOG.md:409-417, tests/ |
| F48 | P3 | testing-fuzzing | Test counts/duration not recorded in the build log | Capture `zig build test --summary all` output into the log. | /tmp/h3zig-test.log, CI |
| F49 | P3 | testing-fuzzing (speculative) | Committed fuzz corpus has no CI drift check vs seed.zig | Add seed-fuzz-corpus → diff-against-corpus/ step. | build.zig, fuzz/seed.zig, .github/workflows/fuzz.yml |
| F50 | P3 | testing-fuzzing (speculative) | "Visible debt: none" self-asserted; skip mechanism unused | Optional lint for BCP-14 keyword/citation; keep skip_ as enforced escape hatch. | tests/conformance/README.md:55-68 |
| F51 | P3 | api-docs-examples | errors.zig (Stable tier) has zero per-decl docs; pub symbols unlisted/not re-exported | Add /// docs; promote or explicitly exclude LocalError/classify/codeForError/etc. | src/errors.zig, src/root.zig:309-314, docs/API_STABILITY.md:37-41 |
| F52 | P3 | api-docs-examples | `forwardSessionEventTo` takes `other: anytype` (untyped public param) | Comptime interface assertion (@compileError listing required methods). | src/client.zig:537-541, src/server.zig:582-586 |
| F53 | P3 | api-docs-examples | InformationalError & WebTransportRejectReason not promoted to root | Promote both for symmetry (or document omission). | src/server.zig:199,1523, src/root.zig:189-190 |
| F54 | P3 | api-docs-examples | rejectWebTransport takes allocator though only .status branch uses it | Split reset-only path from status-responding path. | src/server.zig:1548-1553 |
| F55 | P3 | api-docs-examples | Per-decl doc density ~zero on low-level codecs (masque.zig 9/1502, datagram.zig 0/132) | One-line /// on public masque/datagram/capsule constants + fields. | src/masque.zig, src/datagram.zig, src/websocket_frame.zig |
| F56 | P3 | build-tooling + deps-supply-chain | Hardcoded quic version '0.13.1' unlinted; guard skipped on bare-SHA pin | Derive version from resolved quic manifest, or assert on bare-SHA pins. | build.zig:26, tools/check-boringssl-pin.sh:111-134 |
| F57 | P3 | build-tooling | build.zig reaches into std.Build internals (modules.put/graph.arena) | Isolate behind helper + compile-time guard, or use public API. | build.zig:73-74 |
| F58 | P3 | build-tooling + repo-docs-hygiene | consumer-smoke pins stale, looser minimum_zig_version | Bump to match main manifest (or assert parity). | tools/consumer-smoke/build.zig.zon:9 |
| F59 | P3 | build-tooling | `go` toolchain for `just qpack-interop` not pinned in mise.toml | Add exact go pin (or document as unpinned prerequisite). | mise.toml, justfile, interop/qpack_quic_go/go.mod |
| F60 | P3 | build-tooling | 836-line monolithic build.zig with heavy copy-paste | Extract addExample/addModuleGraph helpers; split per-directory build files. | build.zig |
| F61 | P3 | build-tooling | wt_interop_matrix compiled twice (exe + addTest); dead pub fn main | Split CLI logic into main-free module. | build.zig:373-385 |
| F62 | P3 | repo-docs-hygiene | Broken intra-repo link in conformance README | Vendor referenced guide or replace with plain-text mention. | tests/conformance/README.md:7 |
| F63 | P3 | repo-docs-hygiene | `max_incoming_frame_length` hardening missing from CHANGELOG | Add [Unreleased] entry naming the knob + DATA-livelock fix. | CHANGELOG.md, src/session.zig:335,4667 |
| F64 | P3 | repo-docs-hygiene | Residual `quic_zig` naming in [Unreleased] draft after rename | Update entries to `quic` (or add note). | CHANGELOG.md:15,26,37,41,73 |
| F65 | P3 | repo-docs-hygiene | Tag prefix inconsistency + undocumented 0.2.0→0.4.1 version gap | Note the jump; uniform tag prefix. | CHANGELOG.md:559,869 |
| F66 | P3 | repo-docs-hygiene | `.claude/` excluded only by machine-local git config | Add `.claude/` to committed .gitignore. | .gitignore |
| F67 | P3 | repo-docs-hygiene | interop doc pins quic one version behind manifest | Refresh to 0.13.1 repin series. | docs/wt-third-party-interop.md:18 |
| F68 | P3 | repo-docs-hygiene | Eight patch releases share a single changelog date | Add "tagged in repoint series" note or normalize dates. | CHANGELOG.md:501-558 |
| F69 | P3 | ci-interop | No Windows leg; coverage-guided fuzz Linux-only | Add windows-latest Debug leg; mirror coverage fuzz when std supports macOS. | .github/workflows/test.yml, fuzz-nightly.yml |
| F70 | P3 | ci-interop | curl_h3/lsquic/ngtcp2 unwired; browser versions float | Wire curl_h3 into weekly cadence; pin Chrome/Firefox (or record resolved version). | interop/curl_h3/run.sh, .github/workflows/wt-browser-interop.yml |
| F71 | P3 | ci-interop | Setup boilerplate duplicated across 9 workflows | Extract composite action / reusable workflow. | .github/workflows/test.yml:64-100 |
| F72 | P3 | ci-interop | No dependabot/CodeQL; fuzz corpus + browser installs uncached | Add dependabot.yml + CodeQL; cache corpus + browsers. | .github/workflows/, fuzz-nightly.yml:172 |
| F73 | P3 | deps-supply-chain (speculative) | Toolchain dev-build provenance undocumented, not checksum-pinned | Document download source + record SHA-256 of the zig dev tarball. | mise.toml, build.zig.zon |

## Findings by Dimension

### 1. Build & Tooling
Verdict: unusually well-engineered for pre-1.0 Zig — exact toolchain pin (mise == minimum_zig_version), URL+hash dep pinning with a byte-for-byte boringssl mirror check, a load-bearing `check-api` that pins signatures via `@TypeOf`, and an out-of-tree consumer-smoke proving the module-identity diamond. No build-breaking or determinism defects; the issues are doc/CI-claim inaccuracies plus maintainability.

- **P2** CONTRIBUTING overstates the default install (F26) — build.zig has one `installArtifact` (line 61) vs `addInstallArtifact` elsewhere (194-823).
- **P2** release.yml "compiles them all" gate compiles only examples (F27) — release.yml:69-75; bench/wt-load/qpack-dynamic-fixtures compiled nowhere in CI.
- **P3** hardcoded quic version '0.13.1' unlinted (F56) — build.zig:26; guard skips bare-SHA pins.
- **P3** std.Build internals reach (F57) — build.zig:73-74.
- **P3** consumer-smoke stale `minimum_zig_version` (F58); unpinned Go toolchain (F59); 836-line build.zig (F60); wt_interop_matrix double-compile (F61).

Positives: `check-api` is genuinely signature-pinned (`@TypeOf(expr) == fn(...)`), and `consumer-smoke` compile-asserts `quic.Connection == http3_zig.quic.Connection` + boringssl `tls.Context` identity — the exact property that broke real consumers.

### 2. Deps & Supply Chain
Verdict: surface pinning is disciplined (content-hashed tarballs, guarded boringssl diamond), but the chain is bus-factor-1 and fragile: single-maintainer "vibe-coded" deps with no upstream, no SBOM/dependabot, a no-op CI package cache, tag-pinned Actions, and a missing license on the boringssl-zig wrapper.

- **P1** bus-factor-1 "vibe-coded" chain (F04) — quic-zig/boringssl-zig are fork=False, parent=None; no dependabot/renovate/SBOM.
- **P1** tag-pinned Actions (F02, with ci-interop) — ~57 `uses:`, zero SHAs; jdx/mise-action installs the compiler.
- **P2** wrong CI cache dir `zig-pkg` (F21) — global_cache_dir is `~/.cache/zig`, `ZIG_GLOBAL_CACHE_DIR` never set.
- **P2** boringssl-zig wrapper has no LICENSE (F22); nested BoringSSL C is a bare-SHA pin invisible to check tooling (F23).
- **P3** quic version guard dormant (F56); toolchain dev-build provenance unchecksummed (F73, speculative).

Positives: the boringssl diamond is both documented (build.zig.zon:7-58) and actively guarded in CI (`tools/check-boringssl-pin.sh`); license is Apache-2.0 end-to-end at the code level; SECURITY.md defines a 90-day coordinated-disclosure policy.

### 3. Repo, Docs & Hygiene
Verdict: excellent hygiene — a disciplined Keep-a-Changelog that reflects HEAD, useful SECURITY/CONTRIBUTING/API_STABILITY, zero TODO/FIXME/HACK in src/, and spot-checked README claims all verified. Issues are all low/nit.

- **P3** broken intra-repo link (F62) — tests/conformance/README.md:7; missing CHANGELOG entry for `max_incoming_frame_length` (F63); residual `quic_zig` naming (F64).
- **P3** tag-prefix/version-gap inconsistency (F65); `.claude/` not committed to .gitignore (F66); interop doc quic version behind (F67); eight patch releases share one date (F68).

Positives: CHANGELOG.md is exemplary (Keep-a-Changelog + semver caveat + a 409-line [Unreleased] draft that matches HEAD); API_STABILITY.md defines enforced Stable/Unstable/Internal tiers.

### 4. H3 Core Protocol
Verdict: RFC 9114 core is implemented to a high standard — wire layout, error-code registry, SETTINGS/push/GOAWAY semantics, and the malformed-vs-invalid-sequence scope split are correct and RFC-verified. Three receive-side/edge-path gaps remain.

- **P2** field-name/value characters not validated (F07) — headers.zig:256-261 rejects only empty/uppercase; RFC 9114 §4.1.2 requires tchar/CTL rejection.
- **P3** unknown/GREASE first control-stream frame accepted (F28) — stream.zig:89-95 early-returns before the §6.2.1 check.
- **P3** message codec measures compressed vs uncompressed field-section size (F29) — message.zig:186-188.

Positives: error-code table exact (§8.1 + QPACK + H3_DATAGRAM 0x33); `peekHeader`+`checkIncomingFrameLength` bound declared lengths before reassembly; the conformance suite is RFC-traceable with per-paragraph citations and no `skip_` debt.

### 5. QPACK
Verdict: high quality — exact 99-entry static table, correct Huffman codec with O(1) canonical lookup, correct prefixed-integer and RIC wrap arithmetic, careful allocator hygiene on decode error paths. One material error-code mis-mapping plus conservative over-rejection and interop gaps.

- **P2** invalid encoder-stream indices → 0x200 instead of 0x201 (F08) — errors.zig:208-209; instructions.zig:179-189; the conformance test even documents the wrong claim.
- **P3** Huffman bound applied to non-Huffman literals over-rejects (F30); out-of-range STATIC index untested + no error-code assert (F31); Huffman comptime check incomplete (F32).
- **P2** Go qpack interop is static-only and its fixture diverges (F14, with ci-interop).

Positives: static table verified value-for-value against RFC 9204 Appendix A; RIC wrap sweep-tested (state.zig:546-612); decoded-field-section cap uses correct §4.2.2 accounting (32+name+value).

### 6. Extensions
Verdict: strong — RFC 9218 priority is genuinely wired into the scheduler (not just parsed), WebTransport era layering (draft-02/07/16) matches the real wire format, WT flow control is folded in, and DATAGRAM/capsule/MASQUE codecs are spec-accurate. Issues are a fabricated masking citation and helper-only MASQUE/WS layers.

- **P2** WebSocket masking mis-cited to "RFC 9220 §4.5" (nonexistent); default `.any` leaves RFC 6455 §5.1 unenforced (F09).
- **P2** MASQUE CONNECT-UDP / WebSocket-over-H3 have no session-level dispatch/reassembly (F11).
- **P3** unknown WT capsules surfaced vs MUST silently drop (F33); WS close-code over-rejection (F34, speculative).

Positives: PRIORITY_UPDATE feeds quic-zig's scheduler with direction/ID validation (RFC 9218 §7.2); draft-02 data path verified byte-accurate against the fetched spec; write-path masking direction is correct (client masks, server doesn't).

### 7. Session Engine
Verdict: the most carefully engineered file — iterator-snapshot discipline, reserve-before-mutate ordering, saturating flow-control arithmetic, re-entrancy latches, and resource caps all correctly implemented. One genuine memory-safety bug (double-free, 6 sites) plus a leak-on-error and minor budget-drop.

- **P1** double-free on event-append failure (F01) — appendRawEvent deinits (session.zig:6992-6997) while 6 sites also `errdefer`-free the same owned buffer.
- **P2** `openWebTransportBidiStream` orphans a registry entry (F10) — session.zig:1926-1945 (siblings do cleanup at 1899-1903).
- **P3** datagram dropped on budget (F35); incomplete re-entrancy latch (F36); 7733-line file (F37).

Positives: integer safety holds (no peer-reachable u63→usize narrowing; `@intCast` sites are widening-only); drain-budget reserve-before-mutate ordering is correct in observeReset/emitWebTransportStreamOpened; no peer-controlled `@panic`/unreachable.

### 8. Concurrency & Errors
Verdict: fundamentally sound single-threaded, no-locking, drain-in-batches model, correctly documented, with RFC-accurate error classification. Residual "consume/latch-then-reserve" ordering can drop one-shot terminal events, plus an OOM double-free and an incomplete re-entrancy guard.

- **P2** `connection_closed` consumed then dropped under budget (F05) — session.zig:3846-3910; the documented "clearEvents then drain again" recovery cannot restore it.
- **P3** scratch-buffer double-free on OOM (F38); `failMessageStream` mutate-before-reserve (F39); early_data latch-before-append (F40); open anyerror `else` (F41).
- **P3** re-entrancy guard incomplete (F36, with session-engine + security-hardening).

Positives: no `std.Thread`/locks anywhere in src/ (the single-threaded claim is true); events are deep-cloned so no dangling pointers cross drain/destroy; no busy-loop found.

### 9. Security Hardening
Verdict: strong, deliberate untrusted-input hardening — varint/length/field-section/capsule/datagram/Huffman decode are all overflow+bounds-checked before allocation and fuzzed. No remotely-triggerable memory unsafety or unbounded exhaustion found. Gaps: DATA/QPACK-encoder receive-cap exemptions + a Huffman transient alloc; 0-RTT anti-replay lives in quic-zig, not here.

- **P2** DATA + QPACK encoder-string literals bypass H3 receive caps; Huffman transient alloc precedes capacity check (F06) — session.zig:4646/4629, instructions.zig:283.
- **P3** re-entrancy latch covers only drain (F36); datagram drop under budget (F35); 0-RTT anti-replay delegated (F42, informational); header/MessageDecoder unfuzzed (F12, with testing-fuzzing).

Positives: varint decode is overflow-safe (63-bit cap); every length-prefixed read uses checked cast + available-bytes check; client TLS verification defaults to `.system` (on by default).

### 10. Performance
Verdict: hot paths well-engineered in aggregate (amortized rx compaction, pooled scratch, zero-copy frame decode, O(1) Huffman, pre-allocation budget). But avoidable per-message/per-field allocs+memcpys on both directions dominate header/body-heavy CPU.

- **P2** DATA/capsule/datagram send alloc+memcpy (F18); 2N+1 QPACK decode allocs + static-literal dupes (F19); O(n²) dynamic-table eviction (F20).
- **P3** chooseFieldRepresentation 3× per field (F43); 99-entry linear static scan 2× (F44); Huffman ArrayList doubling (F45); WT data event copies rx (F46).

Positives: amortized rx compaction is real (cursor + one memmove/drain); scratch buffers pooled on Session; the memory-profile's 600-byte/iter gate is a real non-zero-exit regression check; bench harnesses match their docs.

### 11. Testing & Fuzzing
Verdict: unusually disciplined — RFC-traceable conformance (970 tests with BCP-14-keyword names + [RFC#### §X.Y ¶N] citations), deterministic iteration-capped race tests, a 19-target wire-codec fuzzer, a property-based WT bytecode fuzzer with real invariants, and leak-detecting standalone runners. Weaknesses: header validation + MessageDecoder never fuzzed; "sanitizer-grade" runs ReleaseSafe only.

- **P2** semantic header validation + MessageDecoder never fuzzed (F12, with security-hardening); "sanitizer-grade" claim vs ReleaseSafe (F13).
- **P3** drain-resurrect fix lacks a regression test (F47); counts/duration not in the log (F48); corpus drift check absent (F49, speculative); "Visible debt: none" self-asserted (F50, speculative).

Positives: all three standalone fuzz runners use a per-input DebugAllocator and fail on `.leak`; security fixes have regression tests (budgets.zig, production_preset.zig); layered per-push/nightly fuzz gates.

### 12. API, Docs & Examples
Verdict: exemplary API design — a tiered stability contract backed by compile-checked `check-api`, a landed self-audit, and dense RFC-cross-linked facade docs. Findings are modest ergonomic/documentation warts.

- **P2** Client.Config/Server.Config duplicate session.Config 1:1 with stale "v0.1.0" docs (F24); `installEarlyDataContext` bare `!void` (F25).
- **P3** errors.zig zero per-decl docs + unlisted pub symbols (F51); `anytype` param (F52); inconsistent re-export promotion (F53); unconditional allocator (F54); low-level codec doc density (F55).

Positives: root.zig:1-95 documents a precise allocator-ownership + concurrency contract (including the mismatched-allocator trap); README and embedding-guide verified current against the real API; api-narrowing-proposal's "LANDED in full" header is accurate.

### 13. CI & Interop
Verdict: mature, well-tiered CI (per-push hard gates vs weekly advisory vs nightly fuzz) with genuinely asserting, peer-pinned interop harnesses and a strong platform matrix. Four substantive gaps: nightly fuzz can't report crashes, tag-pinned actions, QPACK interop is a quic-go self-test, and releases carry no artifact/provenance/interop gate.

- **P1** nightly corpus-loop fuzz can't report a crash (F03); tag-pinned actions (F02, with deps).
- **P2** QPACK interop is a quic-go self-test (F14, with qpack); coverage-fuzz silent no-op skip (F15); release without artifact/provenance (F16); WT matrix passes on single target + no PR trigger (F17).
- **P3** no Windows leg (F69); curl_h3/lsquic/ngtcp2 unwired + floating browser versions (F70); 9-way boilerplate (F71); no dependabot/CodeQL + uncached corpus/browsers (F72).

Positives: interop harnesses assert (exact status/body match, datagram echo compare, draft-02 negotiation), not just log; peers are deterministic-pinned (quic-go v0.59.0, aioquic==1.3.0, webtransport-go v0.12.0, pywebtransport==0.17.1); release validates the tag against build.zig.zon .version.

## Quick Wins

1. **F03** — Rewrite the fuzz-nightly loop with `set -e` and propagate non-zero exits (a few shell lines; repairs a broken crash-reporting net).
2. **F02** — Pin all Actions to commit SHAs (mechanical; removes the compiler-injection vector).
3. **F25** — Give `installEarlyDataContext` a named error union (one signature change).
4. **F26** — Correct CONTRIBUTING.md's "zig build installs examples" wording (one-line doc fix).
5. **F63** — Add the `max_incoming_frame_length` hardening to CHANGELOG (matches its sibling knob's treatment).
6. **F62** — Fix the broken intra-repo link in tests/conformance/README.md:7.
7. **F66** — Add `.claude/` to the committed .gitignore.
8. **F58** — Bump `tools/consumer-smoke/build.zig.zon` minimum_zig_version to match the main manifest.

## Notable Positives

- **RFC-traceable conformance suite** (970 tests, per-paragraph citations, no `skip_` debt) — a rare level of spec rigor.
- **`check-api` signature pinning** (`@TypeOf` equality asserts) enforced across a Debug/ReleaseSafe × {x86_64, arm, macos} + 32-bit musl matrix.
- **Out-of-tree `consumer-smoke`** proving the quic/boringssl module-identity diamond that broke real consumers.
- **The boringssl diamond guard** (`tools/check-boringssl-pin.sh`) with extensive documented rationale — a genuine supply-chain hardening.
- **Reserve-before-mutate drain discipline** (mostly correct) and saturating flow-control arithmetic throughout the session engine.
- **Honest, precise documentation** — API_STABILITY tiers, the landed api-narrowing self-audit, the allocator-ownership contract, and a Keep-a-Changelog that actually tracks HEAD.
- **Leak-detecting fuzz runners** (per-input DebugAllocator, `exit(1)` on fail) and deterministic, timing-free integration tests.
- **Exact toolchain pinning** with a written reproducibility rationale, matching between mise.toml and build.zig.zon.

---

*Verification note: all 13 dimension inputs, both Phase B inputs, and the test log were readable. The only input shortfall is `/tmp/h3zig-test.log` itself — it captures only `BUILD_EXIT_CODE=0` and a timestamp, so test counts/duration are source-derived, not log-derived (F48).*
