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

github_raw_zon_url() {
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
        git+https://github.com/*/*.git#*)
            path=${url#git+https://github.com/}
            owner=${path%%/*}
            path=${path#*/}
            repo=${path%%.git#*}
            ref=${path#*.git#}
            [ "$repo" != "$path" ] || die "unsupported quic git URL: $url"
            [ -n "$ref" ] || die "missing ref in quic git URL: $url"
            printf 'https://raw.githubusercontent.com/%s/%s/%s/build.zig.zon\n' "$owner" "$repo" "$ref"
            ;;
        *)
            die "unsupported quic URL: $url"
            ;;
    esac
}

http3_zon=${1:-build.zig.zon}
[ -f "$http3_zon" ] || die "missing http3-zig manifest: $http3_zon"

quic_url=$(extract_dep_field quic url "$http3_zon") ||
    die "could not read quic.url from $http3_zon"
http3_boringssl_url=$(extract_dep_field boringssl url "$http3_zon") ||
    die "could not read boringssl.url from $http3_zon"
http3_boringssl_hash=$(extract_dep_field boringssl hash "$http3_zon") ||
    die "could not read boringssl.hash from $http3_zon"

if [ "${QUIC_BUILD_ZON:-}" ]; then
    quic_zon=$QUIC_BUILD_ZON
    [ -f "$quic_zon" ] || die "missing quic-zig manifest: $quic_zon"
else
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
    quic_zon=$tmp_dir/quic-build.zig.zon
    raw_url=$(github_raw_zon_url "$quic_url")
    curl -fsSL "$raw_url" -o "$quic_zon"
fi

quic_boringssl_url=$(extract_dep_field boringssl url "$quic_zon") ||
    die "could not read boringssl.url from $quic_zon"
quic_boringssl_hash=$(extract_dep_field boringssl hash "$quic_zon") ||
    die "could not read boringssl.hash from $quic_zon"

if [ "$http3_boringssl_url" != "$quic_boringssl_url" ] ||
    [ "$http3_boringssl_hash" != "$quic_boringssl_hash" ]; then
    printf 'boringssl pin mismatch between http3-zig and pinned quic-zig\n' >&2
    printf '  http3-zig url: %s\n' "$http3_boringssl_url" >&2
    printf '  quic-zig  url: %s\n' "$quic_boringssl_url" >&2
    printf '  http3-zig hash: %s\n' "$http3_boringssl_hash" >&2
    printf '  quic-zig  hash: %s\n' "$quic_boringssl_hash" >&2
    exit 1
fi

printf 'boringssl pin matches pinned quic-zig (%s)\n' "$http3_boringssl_hash"

# tools/coexist-smoke/sibling stands in for capnp-zig & co. It must pin
# the same quic package as http3-zig (url and hash): a different pin is a
# different package, and the coexist smoke test would prove nothing.
sibling_zon=$(dirname "$http3_zon")/tools/coexist-smoke/sibling/build.zig.zon
[ -f "$sibling_zon" ] || die "missing coexist sibling manifest: $sibling_zon"
quic_hash=$(extract_dep_field quic hash "$http3_zon") ||
    die "could not read quic.hash from $http3_zon"
sibling_quic_url=$(extract_dep_field quic url "$sibling_zon") ||
    die "could not read quic.url from $sibling_zon"
sibling_quic_hash=$(extract_dep_field quic hash "$sibling_zon") ||
    die "could not read quic.hash from $sibling_zon"
if [ "$quic_url" != "$sibling_quic_url" ] || [ "$quic_hash" != "$sibling_quic_hash" ]; then
    printf 'quic pin mismatch between build.zig.zon and %s\n' "$sibling_zon" >&2
    printf '  http3-zig url:  %s\n  sibling   url:  %s\n' "$quic_url" "$sibling_quic_url" >&2
    printf '  http3-zig hash: %s\n  sibling   hash: %s\n' "$quic_hash" "$sibling_quic_hash" >&2
    exit 1
fi
printf 'coexist sibling pins the same quic (%s)\n' "$quic_hash"
