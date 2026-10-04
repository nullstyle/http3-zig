#!/bin/sh
# Print GitHub release notes for one version: its CHANGELOG.md section,
# then the build.zig.zon entry that pins the tag tarball.
#
# Usage: tools/release-notes.sh <version> <tarball-url> <package-hash>
# Fails when CHANGELOG.md has no "## [<version>]" section.
set -eu

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 3 ] || die "usage: $0 <version> <tarball-url> <package-hash>"
version=$1
url=$2
hash=$3
changelog=$(cd "$(dirname "$0")/.." && pwd)/CHANGELOG.md

section=$(awk -v v="$version" '
    index($0, "## [" v "]") == 1 { on = 1; next }
    on && index($0, "## [") == 1 { exit }
    on { print }
' "$changelog")
[ -n "$(printf '%s' "$section" | tr -d '[:space:]')" ] ||
    die "CHANGELOG.md has no section for $version"

printf '%s\n\n' "$section"
printf '## Pin this release\n\n'
printf 'In `build.zig.zon`:\n\n'
printf '```zig\n.http3_zig = .{\n    .url = "%s",\n    .hash = "%s",\n},\n```\n' "$url" "$hash"
