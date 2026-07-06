#!/usr/bin/env bash
set -euo pipefail

CLIENT_BIN="${CLIENT_BIN:-./zig-out/bin/http3-zig-external-h3-client}"
CERT="${CERT:-tests/data/test_cert.pem}"
KEY="${KEY:-tests/data/test_key.pem}"
HOST="${HOST:-127.0.0.1}"
BASE_PORT="${BASE_PORT:-44330}"
SNI="${SNI:-localhost}"
PATH_UNDER_TEST="${PATH_UNDER_TEST:-/hello.txt}"
BODY_EXPECT="${BODY_EXPECT:-http3-zig external h3 interop}"
CLIENT_TIMEOUT_MS="${CLIENT_TIMEOUT_MS:-10000}"
STARTUP_DELAY_MS="${STARTUP_DELAY_MS:-500}"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/http3-zig-external-h3.XXXXXX")}"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"

abs_path() {
    case "$1" in
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$PWD" "$1" ;;
    esac
}

cleanup() {
    if [[ -n "${PEER_PID:-}" ]] && kill -0 "$PEER_PID" 2>/dev/null; then
        kill "$PEER_PID" 2>/dev/null || true
        wait "$PEER_PID" 2>/dev/null || true
    fi
    if [[ "$KEEP_WORK_DIR" == "1" ]]; then
        echo "preserving external-h3 work dir: $WORK_DIR"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

if [[ ! -x "$CLIENT_BIN" ]]; then
    echo "missing client binary: $CLIENT_BIN" >&2
    echo "run: zig build external-h3-client" >&2
    exit 1
fi

CERT="$(abs_path "$CERT")"
KEY="$(abs_path "$KEY")"
mkdir -p "$WORK_DIR/www"
printf '%s\n' "$BODY_EXPECT" >"$WORK_DIR/www/hello.txt"

upper_peer() {
    printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

peer_cmd() {
    local prefix
    prefix="$(upper_peer "$1")"
    local var="${prefix}_H3_SERVER_CMD"
    printf '%s' "${!var:-}"
}

peer_ready_pattern() {
    local prefix
    prefix="$(upper_peer "$1")"
    local var="${prefix}_READY_PATTERN"
    printf '%s' "${!var:-}"
}

wait_for_ready() {
    local peer="$1"
    local log="$2"
    local pattern
    pattern="$(peer_ready_pattern "$peer")"
    if [[ -z "$pattern" ]]; then
        sleep "$(awk "BEGIN { printf \"%.3f\", ${STARTUP_DELAY_MS} / 1000 }")"
        return 0
    fi

    for _ in $(seq 1 200); do
        if grep -Eq "$pattern" "$log"; then
            return 0
        fi
        if ! kill -0 "$PEER_PID" 2>/dev/null; then
            grep -Eq "$pattern" "$log"
            return "$?"
        fi
        sleep 0.05
    done
    return 1
}

stop_peer() {
    if [[ -n "${PEER_PID:-}" ]]; then
        if kill -0 "$PEER_PID" 2>/dev/null; then
            kill "$PEER_PID" 2>/dev/null || true
            wait "$PEER_PID" 2>/dev/null || true
        fi
        PEER_PID=""
    fi
}

run_peer() {
    local peer="$1"
    local cmd
    cmd="$(peer_cmd "$peer")"
    if [[ -z "$cmd" ]]; then
        echo "SKIP ${peer}: set $(upper_peer "$peer")_H3_SERVER_CMD to enable"
        return 2
    fi

    local port="$2"
    local log="$WORK_DIR/${peer}.server.log"
    local out="$WORK_DIR/${peer}.client.out"
    : >"$log"
    : >"$out"

    (
        export H3_HOST="$HOST"
        export H3_PORT="$port"
        export H3_ADDR="${HOST}:${port}"
        export H3_CERT="$CERT"
        export H3_KEY="$KEY"
        export H3_ROOT="$WORK_DIR/www"
        export H3_PATH="$PATH_UNDER_TEST"
        eval "$cmd"
    ) >"$log" 2>&1 &
    PEER_PID="$!"

    if ! wait_for_ready "$peer" "$log"; then
        echo "FAIL ${peer}: server did not become ready" >&2
        cat "$log" >&2 || true
        stop_peer
        return 1
    fi

    if ! "$CLIENT_BIN" \
        --connect "${HOST}:${port}" \
        --sni "$SNI" \
        --authority "${SNI}:${port}" \
        --path "$PATH_UNDER_TEST" \
        --insecure \
        --max-time-ms "$CLIENT_TIMEOUT_MS" >"$out" 2>&1; then
        echo "FAIL ${peer}: http3-zig external client failed" >&2
        cat "$out" >&2 || true
        echo "server log:" >&2
        cat "$log" >&2 || true
        stop_peer
        return 1
    fi

    stop_peer

    if ! grep -q '^STATUS 200$' "$out"; then
        echo "FAIL ${peer}: missing STATUS 200" >&2
        cat "$out" >&2 || true
        return 1
    fi

    local body
    body="$(sed '1,/^$/d' "$out")"
    if [[ "$body" != "$BODY_EXPECT" ]]; then
        echo "FAIL ${peer}: unexpected response body" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$body" "$BODY_EXPECT" >&2
        return 1
    fi

    echo "PASS ${peer}"
    return 0
}

if [[ "$#" -gt 0 ]]; then
    PEERS=("$@")
else
    read -r -a PEERS <<<"${PEERS:-quic-go ngtcp2 lsquic aioquic}"
fi

passed=0
skipped=0
failed=0
index=0
for peer in "${PEERS[@]}"; do
    port=$((BASE_PORT + index))
    index=$((index + 1))
    set +e
    run_peer "$peer" "$port"
    rc="$?"
    set -e
    case "$rc" in
        0) passed=$((passed + 1)) ;;
        2) skipped=$((skipped + 1)) ;;
        *) failed=$((failed + 1)) ;;
    esac
done

echo "external-h3 matrix: passed=${passed} skipped=${skipped} failed=${failed}"
if [[ "$failed" -ne 0 ]]; then
    exit 1
fi
