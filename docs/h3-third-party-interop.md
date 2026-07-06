# HTTP/3 third-party interop

## Status

The `h3-interop` GitHub Actions workflow is advisory third-party HTTP/3
coverage. It builds http3-zig's external H3 client and drives a pinned
`quic-go/http3` server through a real UDP loopback request/response:

1. quic-go serves `GET /hello.txt` with the repo test certificate.
2. `http3-zig-external-h3-client` connects with `h3` ALPN and insecure test
   trust.
3. The runner requires `STATUS 200` and an exact response body match.

The hard per-push gate remains `h3-interop-self-test.yml`, where both peers are
http3-zig binaries. The quic-go matrix is intentionally `continue-on-error:
true` while third-party setup is still treated as advisory release signal.

## Pinned peer

The first in-repo foreign peer is
[`interop/external_h3/server_quic_go`](../interop/external_h3/server_quic_go),
a tiny Go module pinned to `github.com/quic-go/quic-go v0.59.0`. It binds a
caller-owned UDP socket, prints `READY <port>`, serves static files through
`http3.Server`, and exits after the configured request budget.

Additional peers remain scriptable through
[`interop/external_h3/run_matrix.sh`](../interop/external_h3/run_matrix.sh):

- `NGTCP2_H3_SERVER_CMD`
- `LSQUIC_H3_SERVER_CMD`
- `AIOQUIC_H3_SERVER_CMD`

Unset peer commands are skipped. A peer command receives `H3_HOST`, `H3_PORT`,
`H3_ADDR`, `H3_CERT`, `H3_KEY`, `H3_ROOT`, and `H3_PATH`.

## Local run

```sh
zig build external-h3-client
bash interop/external_h3/peers/quic-go.sh
```

For CI-style logs:

```sh
WORK_DIR=/tmp/http3-zig-external-h3 KEEP_WORK_DIR=1 \
  bash interop/external_h3/peers/quic-go.sh
```

The expected summary is:

```text
PASS quic-go
external-h3 matrix: passed=1 skipped=0 failed=0
```
