#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

export QUIC_GO_H3_SERVER_CMD="${QUIC_GO_H3_SERVER_CMD:-cd \"$ROOT/interop/external_h3/server_quic_go\" && go run . --listen \"\$H3_ADDR\" --cert \"\$H3_CERT\" --key \"\$H3_KEY\" --root \"\$H3_ROOT\" --max-requests 1 --max-lifetime-ms 60000}"
export QUIC_GO_READY_PATTERN="${QUIC_GO_READY_PATTERN:-^READY }"

exec bash interop/external_h3/run_matrix.sh quic-go
