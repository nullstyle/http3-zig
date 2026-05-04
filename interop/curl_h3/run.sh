#!/usr/bin/env bash
set -euo pipefail

CURL_H3="${CURL_H3:-/opt/homebrew/opt/curl/bin/curl}"
SERVER_BIN="${SERVER_BIN:-./zig-out/bin/null3-curl-h3-server}"
CERT="${CERT:-tests/data/test_cert.pem}"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/null3-curl-h3.XXXXXX")}"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [[ ! -x "$CURL_H3" ]]; then
    echo "SKIP: curl HTTP/3 binary is not executable: $CURL_H3"
    exit 0
fi

if ! "$CURL_H3" --version | grep -q 'HTTP3'; then
    echo "SKIP: curl at $CURL_H3 does not report HTTP3 support"
    exit 0
fi

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "missing server binary: $SERVER_BIN" >&2
    echo "run: zig build curl-h3-server" >&2
    exit 1
fi

SERVER_PID=""
SERVER_OUT=""
SERVER_LOG=""
SERVER_PORT=""

start_server() {
    local max_requests="$1"
    SERVER_OUT="$WORK_DIR/server.out"
    SERVER_LOG="$WORK_DIR/server.log"
    : >"$SERVER_OUT"
    : >"$SERVER_LOG"
    "$SERVER_BIN" --listen 127.0.0.1:0 --max-requests "$max_requests" >"$SERVER_OUT" 2>"$SERVER_LOG" &
    SERVER_PID="$!"

    for _ in $(seq 1 100); do
        if SERVER_PORT="$(sed -n 's/^READY //p' "$SERVER_OUT" | tail -n 1)"; [[ -n "$SERVER_PORT" ]]; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "server exited before READY" >&2
            cat "$SERVER_LOG" >&2 || true
            return 1
        fi
        sleep 0.05
    done

    echo "server did not report READY" >&2
    cat "$SERVER_LOG" >&2 || true
    return 1
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        for _ in $(seq 1 100); do
            if ! kill -0 "$SERVER_PID" 2>/dev/null; then
                wait "$SERVER_PID" 2>/dev/null || true
                SERVER_PID=""
                return 0
            fi
            sleep 0.05
        done
        echo "server did not exit after test; terminating" >&2
        cat "$SERVER_LOG" >&2 || true
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        return 1
    fi
}

curl_common() {
    "$CURL_H3" --http3-only --max-time 10 --silent --show-error \
        --cacert "$CERT" \
        --resolve "localhost:${SERVER_PORT}:127.0.0.1" \
        "$@"
}

expect_body() {
    local name="$1"
    local want="$2"
    local url_path="$3"
    start_server 1
    local body
    body="$(curl_common "https://localhost:${SERVER_PORT}${url_path}")"
    if [[ "$body" != "$want" ]]; then
        echo "FAIL ${name}: unexpected body" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$body" "$want" >&2
        return 1
    fi
    stop_server
    echo "PASS ${name}"
}

expect_body "hello" "hello" "/hello"

start_server 1
inspect_body="$(curl_common -H 'x-null3-test: curl' "https://localhost:${SERVER_PORT}/inspect?x=1")"
for expected in \
    "method=GET" \
    "path=/inspect?x=1" \
    "x-null3-test=curl"
do
    if ! grep -q "^${expected}$" <<<"$inspect_body"; then
        echo "FAIL inspect: missing ${expected}" >&2
        printf '%s\n' "$inspect_body" >&2
        exit 1
    fi
done
stop_server
echo "PASS inspect"

start_server 1
echo_body="$(printf 'curl-post-body' | curl_common --request POST --data-binary @- "https://localhost:${SERVER_PORT}/echo")"
if [[ "$echo_body" != "curl-post-body" ]]; then
    echo "FAIL post echo: unexpected body" >&2
    printf '%s\n' "$echo_body" >&2
    exit 1
fi
stop_server
echo "PASS post echo"

start_server 1
large_out="$WORK_DIR/large.bin"
curl_common --output "$large_out" "https://localhost:${SERVER_PORT}/large?bytes=262144"
large_size="$(wc -c <"$large_out" | tr -d ' ')"
if [[ "$large_size" != "262144" ]]; then
    echo "FAIL large response: got ${large_size} bytes" >&2
    exit 1
fi
if [[ "$(head -c 16 "$large_out")" != "0123456789abcdef" ]]; then
    echo "FAIL large response: pattern prefix mismatch" >&2
    exit 1
fi
stop_server
echo "PASS large response"

start_server 1
goaway_body="$(curl_common "https://localhost:${SERVER_PORT}/goaway")"
if [[ "$goaway_body" != "bye" ]]; then
    echo "FAIL goaway: unexpected body" >&2
    printf '%s\n' "$goaway_body" >&2
    exit 1
fi
stop_server
echo "PASS goaway"

echo "curl HTTP/3 interop tests passed with $("$CURL_H3" --version | head -n 1)"
