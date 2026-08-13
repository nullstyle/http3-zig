#!/usr/bin/env bash
# Browser interop leg: real Firefox vs the in-tree WT echo server.
#
# Exit codes: 0 = RESULT PASS and the server logged era=draft02;
#             1 = browser reported RESULT FAIL, or the echo passed but the
#                 negotiated era drifted off draft02 (a silent era change is
#                 a regression even when the bytes still echo);
#             2 = setup failure (missing browser/certutil, no READY,
#                 no RESULT).
set -euo pipefail

WT_SERVER_BIN="${WT_SERVER_BIN:-./zig-out/bin/http3-zig-external-wt-server}"
PAGE_DIR="interop/browser_wt/page"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/http3-zig-browser-wt.XXXXXX")"
# Logs land in WT_BROWSER_LOG_DIR when set (CI points it at an uploadable
# artifact dir that survives this script); default to the throwaway workdir.
LOG_DIR="${WT_BROWSER_LOG_DIR:-$WORK}"
mkdir -p "$LOG_DIR"

WT_PID=""
CTRL_PID=""
BROWSER_PID=""

cleanup() {
    for pid in "$BROWSER_PID" "$CTRL_PID" "$WT_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

dump_logs() {
    for log in server.log control.log browser.log; do
        if [[ -s "$LOG_DIR/$log" ]]; then
            echo "=== $log ===" >&2
            cat "$LOG_DIR/$log" >&2
        fi
    done
}

# Poll a log file for a line matching the pattern; fail early if the
# producing process died (its log then explains why, not a timeout).
wait_for_line() {
    local pattern="$1" file="$2" tries="$3" pid="$4"
    for _ in $(seq 1 "$tries"); do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
            grep -q "$pattern" "$file" 2>/dev/null && return 0
            return 1
        fi
        sleep 0.05
    done
    return 1
}

find_browser() {
    if [[ -n "${FIREFOX_BIN:-}" ]]; then
        echo "$FIREFOX_BIN"
        return 0
    fi
    if command -v firefox >/dev/null 2>&1; then
        echo "firefox"
        return 0
    fi
    return 1
}

if ! BROWSER="$(find_browser)"; then
    echo "no Firefox found (set FIREFOX_BIN, or install firefox)" >&2
    exit 2
fi

# Firefox has no SPKI-allowlist flag; trust is injected into a fresh
# profile's NSS db with certutil (the WPT approach). certutil ships in
# libnss3-tools on Debian/Ubuntu, nss via Homebrew.
if ! command -v certutil >/dev/null 2>&1; then
    echo "certutil not found; install libnss3-tools (Debian/Ubuntu) or nss (brew)" >&2
    exit 2
fi

if [[ ! -x "$WT_SERVER_BIN" ]]; then
    echo "missing server binary: $WT_SERVER_BIN" >&2
    echo "run: zig build external-wt-server" >&2
    exit 2
fi

# In-run P-256 cert, 10-day validity: matches run_chrome.sh so the same
# cert recipe covers both browsers and the manual hash-pinning variant.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 10 -nodes \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    2>/dev/null

# Fresh profile with the self-signed leaf installed as a trusted CA
# ("C,,"): self-signed means it is its own issuer, so CA trust makes the
# chain verify without touching the system trust store.
PROFILE="$WORK/ff-profile"
mkdir -p "$PROFILE"
certutil -N -d "sql:$PROFILE" --empty-password
certutil -A -n wt-interop -t "C,," -i "$WORK/cert.pem" -d "sql:$PROFILE"

# All eras advertised: shipped Firefox must land on draft02 on its own -
# that negotiation (not a pinned-era server) is what this leg verifies.
"$WT_SERVER_BIN" \
    --listen 127.0.0.1:0 \
    --cert "$WORK/cert.pem" \
    --key "$WORK/key.pem" \
    --max-sessions 1 \
    --max-lifetime-ms 90000 \
    --eras modern,draft07,draft02 \
    > "$LOG_DIR/server.log" 2>&1 &
WT_PID="$!"

if ! wait_for_line "^READY " "$LOG_DIR/server.log" 200 "$WT_PID"; then
    echo "WT server never reported READY" >&2
    dump_logs
    exit 2
fi
WT_PORT="$(awk '/^READY / {print $2; exit}' "$LOG_DIR/server.log")"

python3 interop/browser_wt/control_server.py \
    --listen 127.0.0.1:0 \
    --page-dir "$PAGE_DIR" \
    --out "$LOG_DIR/result.json" \
    > "$LOG_DIR/control.log" 2>&1 &
CTRL_PID="$!"

if ! wait_for_line "^READY " "$LOG_DIR/control.log" 200 "$CTRL_PID"; then
    echo "control server never reported READY" >&2
    dump_logs
    exit 2
fi
CTRL_PORT="$(awk '/^READY / {print $2; exit}' "$LOG_DIR/control.log")"

# WebTransport is on by default (network.webtransport.enabled=true); no
# geckodriver needed - the page POSTs its own verdict. --no-remote keeps
# this instance from handing the URL to an already-running Firefox.
"$BROWSER" \
    --headless \
    --no-remote \
    --profile "$PROFILE" \
    "http://127.0.0.1:$CTRL_PORT/index.html?wt=https://127.0.0.1:$WT_PORT/wt-browser" \
    > "$LOG_DIR/browser.log" 2>&1 &
BROWSER_PID="$!"

# 60s wall clock for the whole browser flow (the page's own per-phase
# watchdogs report a FAIL verdict well inside this).
if ! wait_for_line "^RESULT " "$LOG_DIR/control.log" 1200 "$BROWSER_PID"; then
    echo "no RESULT within 60s (browser never delivered a verdict)" >&2
    dump_logs
    exit 2
fi

if ! grep -q "^RESULT PASS" "$LOG_DIR/control.log"; then
    echo "browser reported RESULT FAIL" >&2
    dump_logs
    exit 1
fi

if ! grep -q "era=draft02" "$LOG_DIR/server.log"; then
    echo "echo passed but the server never logged era=draft02" >&2
    dump_logs
    exit 1
fi

echo "PASS firefox browser interop (era=draft02)"
