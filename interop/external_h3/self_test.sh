#!/usr/bin/env bash
# In-tree HTTP/3 interop self-test.
#
# Brings up the http3-zig `curl-h3` server on a real UDP socket and drives
# it with the http3-zig `external-h3-client` over loopback — a full QUIC
# handshake + HTTP/3 request/response, entirely between http3-zig binaries
# with no external dependency (no curl-with-HTTP3, no foreign server). This
# is the HTTP/3 counterpart to `wt-interop-self-test.yml`: it gates the
# real-socket pump path that the in-process integration tests can't reach
# (a real client MUST call `conn.advance()` to emit the first ClientHello;
# the loopback driver hides that).
#
# The third-party matrix (`interop/external_h3/run_matrix.sh`) covers the
# cross-implementation story against foreign servers; this stays as the
# self-contained per-push gate.
#
# Usage: self_test.sh [server_bin] [client_bin]
#   defaults: zig-out/bin/http3-zig-curl-h3-server
#             zig-out/bin/http3-zig-external-h3-client
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
server_bin="${1:-$root/zig-out/bin/http3-zig-curl-h3-server}"
client_bin="${2:-$root/zig-out/bin/http3-zig-external-h3-client}"
workdir="$(mktemp -d)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

for bin in "$server_bin" "$client_bin"; do
  if [ ! -x "$bin" ]; then
    echo "::error::missing binary: $bin (run: zig build curl-h3-server external-h3-client)" >&2
    exit 2
  fi
done

fail=0

# run_case <name> <method> <path> <body-or-empty> <expected-status> <expected-substr>
run_case() {
  local name="$1" method="$2" path="$3" body="$4" want_status="$5" want_substr="$6"
  local srv_log="$workdir/srv-$name.log"
  local srv_out="$workdir/srv-$name.out"
  local cli_out="$workdir/cli-$name.out"

  # Each client run opens a fresh connection; the server accepts one
  # connection per process, so use one server instance per case.
  ( cd "$root" && "$server_bin" --listen 127.0.0.1:0 --max-requests 1 ) \
    >"$srv_out" 2>"$srv_log" &
  local srv_pid=$!

  local port=""
  local i
  for i in $(seq 1 200); do
    port="$(awk '/^READY / {print $2; exit}' "$srv_out" 2>/dev/null || true)"
    [ -n "$port" ] && break
    sleep 0.05
  done
  if [ -z "$port" ]; then
    echo "FAIL  $name: server never reported READY"
    cat "$srv_log" >&2 || true
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    fail=1
    return
  fi

  local args=(--connect "127.0.0.1:$port" --method "$method" --path "$path"
              --insecure --max-time-ms 10000)
  [ -n "$body" ] && args+=(--body "$body")

  local rc=0
  "$client_bin" "${args[@]}" >"$cli_out" 2>>"$cli_out" || rc=$?

  kill "$srv_pid" 2>/dev/null || true
  wait "$srv_pid" 2>/dev/null || true

  if [ "$rc" -ne 0 ]; then
    echo "FAIL  $name: client exited $rc"
    cat "$cli_out" >&2 || true
    fail=1
    return
  fi
  if ! grep -q "^STATUS $want_status" "$cli_out"; then
    echo "FAIL  $name: expected STATUS $want_status"
    cat "$cli_out" >&2 || true
    fail=1
    return
  fi
  if ! grep -qF "$want_substr" "$cli_out"; then
    echo "FAIL  $name: response missing '$want_substr'"
    cat "$cli_out" >&2 || true
    fail=1
    return
  fi
  echo "ok    $name: $method $path -> $want_status (matched '$want_substr')"
}

echo "== http3-zig HTTP/3 interop self-test =="
run_case hello GET  /hello ""                200 "hello"
run_case echo  POST /echo  "ping-http3-zig"  200 "ping-http3-zig"

if [ "$fail" -ne 0 ]; then
  echo "== self-test FAILED =="
  exit 1
fi
echo "== self-test passed =="
