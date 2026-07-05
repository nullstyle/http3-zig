# WebTransport third-party interop

## Status

The `wt-interop` GitHub Actions workflow runs http3-zig's external-WT
client against two unmodified third-party WebTransport servers:

- `webtransport-go` (Go, quic-go core)
- `pywebtransport` (Python over a Rust QUIC core)

**Both peers currently fail at the QUIC handshake stage**, before HTTP/3
SETTINGS has a chance to surface. The workflow step is `continue-on-error:
true` so it does not block merges; the per-push real-socket gate
(`wt-interop-self-test.yml`) exercises http3-zig's own pump path against its
own server and is hard-gating.

For comparison, the in-tree self-test (http3-zig client → http3-zig server)
completes SETTINGS, CONNECT, and datagram/uni-stream/CLOSE_WT exchange over
the same pump loop, so the gap is specific to the cross-implementation QUIC
handshake, not http3-zig's WebTransport layer.

## Observed failure

Against the local Go peer, http3-zig transmits a 1200-byte Initial (correct
RFC 9000 §14.1 padding) and receives a single ~116-byte Initial reply, after
which no further packets flow in either direction. The reply is a valid QUIC
v1 Initial, but its encrypted payload is too small to carry a complete TLS
1.3 ServerHello — only a partial first fragment. The deadlock (one server
datagram, no follow-up) points at Initial-level ACK / handshake-flight
handling in the QUIC layer (`quic_zig`) rather than the HTTP/3 layer.

## Reproducing locally

```sh
# In one terminal, build + start the Go peer.
zig build install-wt-interop-matrix external-wt-server
go build -C interop/external_wt/server_go -o /tmp/wt-go-server .
/tmp/wt-go-server \
  --listen 127.0.0.1:0 \
  --cert tests/data/test_cert.pem \
  --key tests/data/test_key.pem \
  --max-sessions 1 --max-lifetime-ms 60000 \
  > /tmp/wt-go.log 2>&1 &

# Read the bound port out of the READY line.
PORT=$(awk '/^READY / {print $2; exit}' /tmp/wt-go.log)

# Run the client against it. It fails with SettingsExchangeTimedOut after
# the timeout — the QUIC handshake never completes.
WT_INTEROP_URL="https://127.0.0.1:$PORT/wt-go-interop" \
  ./zig-out/bin/http3-zig-external-wt-client --max-time-ms 5000

# Self-test (client → our own server) for comparison; this progresses
# through the SETTINGS / CONNECT / datagram phases with the same pump loop:
./zig-out/bin/http3-zig-external-wt-server \
  --listen 127.0.0.1:0 --max-sessions 1 --max-lifetime-ms 60000 \
  > /tmp/wt-self.log 2>&1 &
SELF_PORT=$(awk '/^READY / {print $2; exit}' /tmp/wt-self.log)
WT_INTEROP_URL="https://127.0.0.1:$SELF_PORT/path" \
  ./zig-out/bin/http3-zig-external-wt-client --max-time-ms 5000
```

A packet capture on `lo` and a `quic_zig`-side ACK / loss-detection qlog
trace are the tools for narrowing the handshake stall.
