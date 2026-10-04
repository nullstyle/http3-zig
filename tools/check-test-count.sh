#!/bin/sh
# Fail when `zig build test --summary all` ran fewer tests than the
# recorded floor (tests/test-count-floor). Guards against a test file
# that silently stops being imported, or a test binary that stops being
# built: both leave the build green with fewer tests.
#
# Usage: tools/check-test-count.sh <log of `zig build test --summary all`>
#
# Needs a fresh run: a fully cached `zig build test` prints no test
# count, and a partly cached one prints a partial count. CI runners
# start with an empty .zig-cache.
set -eu

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || die "usage: $0 <zig-build-test-summary-log>"
log=$1
[ -f "$log" ] || die "missing log: $log"

here=$(cd "$(dirname "$0")" && pwd)
floor_file=$here/../tests/test-count-floor
floor=$(grep -E '^[0-9]+$' "$floor_file" | head -n 1 || true)
[ -n "$floor" ] || die "no integer floor in $floor_file"

line=$(grep -E 'Build Summary: .* [0-9]+/[0-9]+ tests passed' "$log" | tail -n 1 || true)
[ -n "$line" ] ||
    die "no 'N/M tests passed' summary in $log (cached run, or the build failed?)"
passed=$(printf '%s\n' "$line" | sed -E 's/.* ([0-9]+)\/[0-9]+ tests passed.*/\1/')
case "$passed" in
    '' | *[!0-9]*) die "could not read the passed count from: $line" ;;
esac

if [ "$passed" -lt "$floor" ]; then
    printf 'error: %s tests passed, below the floor of %s (tests/test-count-floor)\n' "$passed" "$floor" >&2
    printf '  %s\n' "$line" >&2
    exit 1
fi
printf 'test count ok: %s passed (floor %s)\n' "$passed" "$floor"
