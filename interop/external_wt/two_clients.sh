#!/usr/bin/env bash
# Multi-connection gate: two WebTransport clients at once against ONE
# in-tree WT server. Firefox opens two QUIC connections to one origin;
# a server that serves one connection fails it (the single-Connection
# server this replaced did: the second client timed out on SETTINGS).
#
# Usage: two_clients.sh [server_bin] [client_bin]
# Exit: 0 when both clients pass and the server accepted two
# connections and two sessions; 1 otherwise; 2 on setup failure.
set -euo pipefail

SRV="${1:-./zig-out/bin/http3-zig-external-wt-server}"
CLI="${2:-./zig-out/bin/http3-zig-external-wt-client}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/http3-zig-wt-two.XXXXXX")"
SRV_PID=""
cleanup() {
    if [[ -n "$SRV_PID" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

for bin in "$SRV" "$CLI"; do
    [[ -x "$bin" ]] || { echo "missing binary: $bin" >&2; exit 2; }
done

"$SRV" --listen 127.0.0.1:0 --max-sessions 2 --max-lifetime-ms 60000 > "$WORK/server.log" 2>&1 &
SRV_PID="$!"
for _ in $(seq 1 200); do
    grep -q '^READY ' "$WORK/server.log" && break
    sleep 0.05
done
if ! grep -q '^READY ' "$WORK/server.log"; then
    echo "server never reported READY" >&2
    cat "$WORK/server.log" >&2
    exit 2
fi
PORT="$(awk '/^READY / {print $2; exit}' "$WORK/server.log")"

# The harness binaries report on stderr: capture it (2>&1).
WT_INTEROP_URL="https://127.0.0.1:$PORT/wt-two-a" "$CLI" --max-time-ms 15000 > "$WORK/a.log" 2>&1 &
A="$!"
WT_INTEROP_URL="https://127.0.0.1:$PORT/wt-two-b" "$CLI" --max-time-ms 15000 > "$WORK/b.log" 2>&1 &
B="$!"
set +e
wait "$A"; RA="$?"
wait "$B"; RB="$?"
set -e

conns="$(grep -c '^OBSERVED connection accepted' "$WORK/server.log" || true)"
sessions="$(grep -c '^OBSERVED wt accepted' "$WORK/server.log" || true)"
echo "two clients: a=$RA b=$RB; server accepted connections=$conns sessions=$sessions"
if [[ "$RA" -ne 0 || "$RB" -ne 0 || "$conns" -lt 2 || "$sessions" -lt 2 ]]; then
    for log in server.log a.log b.log; do
        echo "=== $log ===" >&2
        cat "$WORK/$log" >&2
    done
    exit 1
fi
echo "PASS two concurrent connections"
