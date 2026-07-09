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
            [ "$repo" != "$path" ] || die "unsupported quic_zig git URL: $url"
            [ -n "$ref" ] || die "missing ref in quic_zig git URL: $url"
            printf 'https://raw.githubusercontent.com/%s/%s/%s/build.zig.zon\n' "$owner" "$repo" "$ref"
            ;;
        *)
            die "unsupported quic_zig URL: $url"
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
    raw_url=$(github_raw_zon_url "$quic_url")
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

# build.zig recreates the quic_zig module and must hand it a build_options
# "version" string. The value is cosmetic, but it must not drift from the
# tag pinned in build.zig.zon (it did once: 0.6.0 vs v0.7.5).
quic_tag=""
case "$quic_url" in
    git+https://github.com/*/*.git#*)
        quic_tag=${quic_url#*.git#}
        ;;
    https://github.com/*/*/archive/refs/tags/*.tar.gz)
        quic_tag=${quic_url#*/archive/refs/tags/}
        quic_tag=${quic_tag%.tar.gz}
        ;;
esac
case "$quic_tag" in
    v*)
        quic_version=${quic_tag#v}
        build_zig=$(dirname "$http3_zon")/build.zig
        [ -f "$build_zig" ] || die "missing build.zig next to $http3_zon"
        if ! grep -q "addOption(\[\]const u8, \"version\", \"$quic_version\")" "$build_zig"; then
            printf 'quic_zig build_options version in build.zig does not match pinned tag %s\n' "$quic_tag" >&2
            grep -n 'addOption(\[\]const u8, "version"' "$build_zig" >&2 || true
            exit 1
        fi
        printf 'quic_zig build_options version matches pinned tag (%s)\n' "$quic_tag"
        ;;
    *)
        printf 'note: quic_zig pin is not a release tag (%s); skipping build_options version check\n' "${quic_tag:-$quic_url}"
        ;;
esac
