#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

export AIOQUIC_H3_SERVER_CMD="${AIOQUIC_H3_SERVER_CMD:-python3 \"$ROOT/interop/external_h3/server_aioquic/main.py\" --host \"\$H3_HOST\" --port \"\$H3_PORT\" --cert \"\$H3_CERT\" --key \"\$H3_KEY\" --root \"\$H3_ROOT\" --max-requests 1 --max-lifetime-ms 60000}"
export AIOQUIC_READY_PATTERN="${AIOQUIC_READY_PATTERN:-^READY }"

exec bash interop/external_h3/run_matrix.sh aioquic
