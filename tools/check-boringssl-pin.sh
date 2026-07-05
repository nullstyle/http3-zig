#!/bin/sh
set -eu

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

extract_dep_field() {
    dep=$1
    field=$2
    zon=$3

    awk -v dep="$dep" -v field="$field" '
        index($0, "." dep " = .{") {
            in_dep = 1
            next
        }
        in_dep && index($0, "." field " = ") {
            line = $0
            sub(/^[[:space:]]*\.[[:alnum:]_]+[[:space:]]*=[[:space:]]*"/, "", line)
            sub(/",[[:space:]]*$/, "", line)
            print line
            found = 1
            exit
        }
        in_dep && $0 ~ /^[[:space:]]*}[,]?[[:space:]]*$/ {
            exit
        }
        END {
            if (!found) exit 1
        }
    ' "$zon"
}

github_archive_raw_zon_url() {
    url=$1

    case "$url" in
        https://github.com/*/*/archive/*.tar.gz)
            path=${url#https://github.com/}
            owner=${path%%/*}
            path=${path#*/}
            repo=${path%%/*}
            archive_path=${path#*/archive/}
            ref=${archive_path%.tar.gz}
            case "$ref" in
                refs/tags/*) ref=${ref#refs/tags/} ;;
                refs/heads/*) ref=${ref#refs/heads/} ;;
            esac
            printf 'https://raw.githubusercontent.com/%s/%s/%s/build.zig.zon\n' "$owner" "$repo" "$ref"
            ;;
        *)
            die "unsupported quic_zig archive URL: $url"
            ;;
    esac
}

http3_zon=${1:-build.zig.zon}
[ -f "$http3_zon" ] || die "missing http3-zig manifest: $http3_zon"

quic_url=$(extract_dep_field quic_zig url "$http3_zon") ||
    die "could not read quic_zig.url from $http3_zon"
http3_boringssl_url=$(extract_dep_field boringssl_zig url "$http3_zon") ||
    die "could not read boringssl_zig.url from $http3_zon"
http3_boringssl_hash=$(extract_dep_field boringssl_zig hash "$http3_zon") ||
    die "could not read boringssl_zig.hash from $http3_zon"

if [ "${QUIC_ZIG_BUILD_ZON:-}" ]; then
    quic_zon=$QUIC_ZIG_BUILD_ZON
    [ -f "$quic_zon" ] || die "missing quic-zig manifest: $quic_zon"
else
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
    quic_zon=$tmp_dir/quic-build.zig.zon
    raw_url=$(github_archive_raw_zon_url "$quic_url")
    curl -fsSL "$raw_url" -o "$quic_zon"
fi

quic_boringssl_url=$(extract_dep_field boringssl_zig url "$quic_zon") ||
    die "could not read boringssl_zig.url from $quic_zon"
quic_boringssl_hash=$(extract_dep_field boringssl_zig hash "$quic_zon") ||
    die "could not read boringssl_zig.hash from $quic_zon"

if [ "$http3_boringssl_url" != "$quic_boringssl_url" ] ||
    [ "$http3_boringssl_hash" != "$quic_boringssl_hash" ]; then
    printf 'boringssl_zig pin mismatch between http3-zig and pinned quic-zig\n' >&2
    printf '  http3-zig url: %s\n' "$http3_boringssl_url" >&2
    printf '  quic-zig  url: %s\n' "$quic_boringssl_url" >&2
    printf '  http3-zig hash: %s\n' "$http3_boringssl_hash" >&2
    printf '  quic-zig  hash: %s\n' "$quic_boringssl_hash" >&2
    exit 1
fi

printf 'boringssl_zig pin matches pinned quic-zig (%s)\n' "$http3_boringssl_hash"
