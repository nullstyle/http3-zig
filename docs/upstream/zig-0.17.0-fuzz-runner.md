# Zig 0.17.0: `zig build test --fuzz` hides a found crash

Handoff for the maintainer's own Zig fork. Not filed upstream.

- **Zig version:** 0.17.0 (tagged). Also seen on 0.17.0-dev.1978+c961124d9.
- **Found:** 2026-10-04, in http3-zig, while moving to Zig 0.17.0.
- **Impact:** a CI job that runs the fuzzer and trusts the exit code
  passes when the fuzzer finds a crash. http3-zig's nightly job did
  this for 30 nights in a row (2026-09-05 to 2026-10-04).
- **Our workaround:** `.github/workflows/fuzz-nightly.yml` reads the log
  ("input saved to", "panic:") and fails an unbounded run that stops
  with exit 0. See commit `300e934`.

## Bug 1: a fuzz failure does not set the exit code

### What happens

1. A fuzz test panics (here: `panic: integer overflow`).
2. The build runner prints
   `error: test '…' terminated with signal ABRT; input saved to '.zig-cache/f/crash'`.
3. The fuzz run stops.
4. `zig build test --fuzz` exits **0**.

### Reproduce

```bash
git -C /Users/nullstyle/prj/zig/http3-zig checkout ce1ea8b -- fuzz/codecs.zig
mise exec -- zig build test -Doptimize=ReleaseSafe --fuzz=50000000
echo "exit=$?"
git -C /Users/nullstyle/prj/zig/http3-zig checkout HEAD -- fuzz/codecs.zig
```

Expected: a non-zero exit. Seen: `exit=0` (aarch64-macos, Zig 0.17.0),
after about one minute.

### Cause

`lib/compiler/Maker/Fuzz.zig`, `fuzzWorkerRun`:

```zig
run.rerunInFuzzMode(run_index, fuzz, fuzz.prog_node) catch |err| switch (err) {
    error.MakeFailed => {
        // prints the step's error messages ...
        return;
    },
    else => { log.err(...); return; },
};
```

The worker prints the failure and returns `void`. Nothing records the
failure. So the runner's final exit status does not see it.

`lib/compiler/Maker/Step/Run.zig` (~line 1449) does fail the step
correctly (`step.fail(maker, "test '{s}' {f}; input saved to …")`).
The failure is lost one level up.

### Fix sketch

1. Add a failure flag to `Fuzz` (an atomic bool or counter).
2. Set it in both arms of the `catch` in `fuzzWorkerRun`.
3. When the fuzz run ends, exit non-zero if the flag is set.

Test: a fuzz test that panics on any input. `zig build test --fuzz=1000`
must exit non-zero.

## Bug 2: the saved crash input is cut short

### What happens

`.zig-cache/f/crash` is cut to a multiple of 512 bytes. A short input
can come out empty. Seen: a 3,584-byte file (7 × 512). quic-zig saw the
same. The full input is still in `.zig-cache/f/in0`, after a 20-byte
header.

### Cause

`lib/compiler/Maker/Step/Run.zig`, near the "Save it to a seperate
file" comment (~line 1430):

```zig
var out_w_buf: [512]u8 = undefined;
var out_w = out.writerStreaming(io, &out_w_buf);
_ = out_w.interface.sendFileAll(&in_r, .limited(header.len)) catch …;
return step.fail(…);   // `defer out.close(io)` runs; no flush
```

The writer is never flushed. The last partial buffer is lost.

### Fix sketch

Call `out_w.interface.flush()` after `sendFileAll`, and map its error
like the `WriteFailed` arm.

## Note 3 (not confirmed): `tmp/libfuzzer.log` not found

Once, on a re-run in a cache that had fuzzed before, every fuzz
worker panicked at startup:

```
panic: failed to create file 'tmp/libfuzzer.log': FileNotFound
```

Source: `lib/fuzzer.zig:176`,
`cache_dir.createFile(io, "tmp/libfuzzer.log", …)`. It does not create
`tmp/` first. The next run in the same cache worked. Cause not
confirmed. A `makePath("tmp")` before the `createFile` would remove the
dependency on the directory being present.

## Not a bug: `@min` result type

`@min(runtime_usize, 253)` has type `u8`. Then `3 + result` overflows
at 256. This is the documented `@min` result-type rule, not a compiler
bug. It was the harness crash that Bug 1 hid. Fixed in http3-zig commit
`73f18ac`.
