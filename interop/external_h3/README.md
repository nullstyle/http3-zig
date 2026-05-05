# External HTTP/3 Client Interop

`null3-external-h3-client` is a small null3-as-client harness for external
HTTP/3 peers. It intentionally keeps peer-specific logic out of `src/`: the
binary owns UDP socket plumbing and CLI parsing, while request/response handling
uses the public `null3.Client`, `ClientRunner`, and `TransportEndpoint` APIs.

Build it with:

```sh
zig build external-h3-client
```

Example against an HTTP/3 server listening on a local UDP port:

```sh
./zig-out/bin/null3-external-h3-client \
  --connect 127.0.0.1:4433 \
  --sni localhost \
  --authority localhost:4433 \
  --path /hello \
  --insecure
```

The first pass accepts IP-literal `--connect` addresses. DNS and peer-specific
matrix scripts can layer above this harness.

## Optional Matrix Runner

`run_matrix.sh` starts external peer servers from caller-provided commands, then
drives each peer with `null3-external-h3-client`.

```sh
zig build external-h3-client
bash interop/external_h3/run_matrix.sh
```

By default it attempts `quic-go`, `ngtcp2`, `lsquic`, and `aioquic`, but each
peer is skipped unless its command variable is set:

- `QUIC_GO_H3_SERVER_CMD`
- `NGTCP2_H3_SERVER_CMD`
- `LSQUIC_H3_SERVER_CMD`
- `AIOQUIC_H3_SERVER_CMD`

The command is evaluated with these environment variables:

- `H3_HOST`: bind host, default `127.0.0.1`
- `H3_PORT`: bind port selected for the peer
- `H3_ADDR`: combined `host:port`
- `H3_CERT` / `H3_KEY`: test certificate paths
- `H3_ROOT`: directory containing `hello.txt`
- `H3_PATH`: request path, default `/hello.txt`

Example shape:

```sh
export AIOQUIC_H3_SERVER_CMD='python3 examples/http3_server.py --certificate "$H3_CERT" --private-key "$H3_KEY" --host "$H3_HOST" --port "$H3_PORT" --root "$H3_ROOT"'
bash interop/external_h3/peers/aioquic.sh
```

If a peer prints a readiness line, set `<PEER>_READY_PATTERN`, for example
`AIOQUIC_READY_PATTERN='listening|serving|ready'`. Without a readiness pattern
the runner sleeps briefly before connecting.
