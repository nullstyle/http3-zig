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

show_server_log() {
    if [[ -n "${SERVER_LOG:-}" && -s "$SERVER_LOG" ]]; then
        echo "server log:" >&2
        cat "$SERVER_LOG" >&2 || true
    fi
}

wait_for_server_log() {
    local pattern="$1"
    for _ in $(seq 1 120); do
        if [[ -n "${SERVER_LOG:-}" ]] && grep -Eq "$pattern" "$SERVER_LOG"; then
            return 0
        fi
        if [[ -n "${SERVER_PID:-}" ]] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
            [[ -n "${SERVER_LOG:-}" ]] && grep -Eq "$pattern" "$SERVER_LOG"
            return "$?"
        fi
        sleep 0.05
    done
    return 1
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
    if ! body="$(curl_common "https://localhost:${SERVER_PORT}${url_path}")"; then
        echo "FAIL ${name}: curl request failed" >&2
        show_server_log
        return 1
    fi
    if [[ "$body" != "$want" ]]; then
        echo "FAIL ${name}: unexpected body" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$body" "$want" >&2
        show_server_log
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

start_server 3
if ! multi_body="$(curl_common \
    "https://localhost:${SERVER_PORT}/hello?first" \
    "https://localhost:${SERVER_PORT}/hello?second" \
    "https://localhost:${SERVER_PORT}/hello?third")"; then
    echo "FAIL multi request: curl request failed" >&2
    show_server_log
    exit 1
fi
if [[ "$multi_body" != $'hello\nhello\nhello' ]]; then
    echo "FAIL multi request: unexpected concatenated body" >&2
    printf 'got:\n%s\n' "$multi_body" >&2
    show_server_log
    exit 1
fi
stop_server
echo "PASS multi request"

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
cancel_payload="$WORK_DIR/cancel-upload.bin"
cancel_body="$WORK_DIR/cancel-upload.body"
cancel_err="$WORK_DIR/cancel-upload.err"
dd if=/dev/zero of="$cancel_payload" bs=1024 count=8192 >/dev/null 2>&1
set +e
curl_common --max-time 1 --limit-rate 1024 --request POST \
    --data-binary @"$cancel_payload" \
    --output "$cancel_body" \
    "https://localhost:${SERVER_PORT}/cancel-upload" 2>"$cancel_err"
cancel_status="$?"
set -e
if [[ "$cancel_status" == "0" ]]; then
    echo "FAIL client cancellation: curl unexpectedly completed upload" >&2
    show_server_log
    exit 1
fi
if ! wait_for_server_log 'OBSERVED (request reset|connection close)'; then
    echo "FAIL client cancellation: server did not observe reset or close" >&2
    printf 'curl stderr:\n%s\n' "$(cat "$cancel_err")" >&2
    show_server_log
    exit 1
fi
stop_server
echo "PASS client cancellation"

start_server 1
reset_body="$WORK_DIR/reset.body"
reset_err="$WORK_DIR/reset.err"
set +e
curl_common --output "$reset_body" "https://localhost:${SERVER_PORT}/reset" 2>"$reset_err"
reset_status="$?"
set -e
if [[ "$reset_status" == "0" ]]; then
    echo "FAIL response reset: curl unexpectedly succeeded" >&2
    show_server_log
    exit 1
fi
if ! grep -Eiq 'reset|stream|HTTP/3|QUIC' "$reset_err"; then
    echo "FAIL response reset: curl failed without an HTTP/3 reset-like diagnostic" >&2
    printf 'curl stderr:\n%s\n' "$(cat "$reset_err")" >&2
    show_server_log
    exit 1
fi
stop_server
echo "PASS response reset"

expect_body "connection close" "closing" "/close"

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
