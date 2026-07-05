# WebTransport third-party interop

## Status

The `wt-interop` GitHub Actions workflow runs http3-zig's external-WT client
against unmodified third-party WebTransport servers, primarily
`webtransport-go` (Go, quic-go core).

**The full WebTransport flow now completes against webtransport-go** —
SETTINGS exchange, Extended CONNECT (200), a datagram round-trip, a
client-initiated uni stream, and `CLOSE_WEBTRANSPORT_SESSION`. Two fixes got
it there (see below). The only residual is the harness's final phase — a
clean-shutdown read that still times out (`HarnessTimedOut`) *after* the
protocol exchange has succeeded; that's a harness-exit nuance, not a protocol
failure.

http3-zig pins **quic-zig v0.6.1**, which carries the
`initial_source_connection_id` fix, so the handshake completes. The
third-party matrix stays `continue-on-error: true` — building and running an
external Go server in CI is inherently flaky, so the in-tree self-test
(`wt-interop-self-test.yml`) remains the hard gate while the foreign-peer
matrix is advisory.

## Root cause (resolved)

Diagnosed live against webtransport-go using in-process qlog
(`Connection.setQlogCallback` + `setQlogPacketEvents`) — no packet capture or
root needed, since the QUIC layer's own `packet_dropped` / `connection_close`
events name the failure directly. Two independent bugs stacked:

1. **Missing `initial_source_connection_id` (RFC 9000 §7.3).** quic-zig's
   low-level `Connection` API didn't advertise it, so quic-go rejected the
   handshake with `TRANSPORT_PARAMETER_ERROR` and the client's connection
   entered draining. In-tree loopback (quic-zig ↔ quic-zig, lenient both
   ways) never validated it — which is exactly why the self-test passed while
   every real peer failed. Fixed in quic-zig (`setTransportParams` fills ISCID
   from the connection's SCID).
2. **Over-tight `max_udp_payload_size`.** The harness advertised `1200` (the
   RFC minimum receive limit), so quic-go's ~1280-byte coalesced
   Initial+Handshake datagram — carrying the ServerHello — was dropped as
   `payload_too_large` and the handshake never progressed. Fixed by
   advertising the RFC default (65527).

## Reproducing locally

```sh
# Build the client + the pinned Go peer.
zig build external-wt-client
go build -C interop/external_wt/server_go -o /tmp/wt-go-server .
/tmp/wt-go-server \
  --listen 127.0.0.1:0 \
  --cert tests/data/test_cert.pem \
  --key tests/data/test_key.pem \
  --max-sessions 1 --max-lifetime-ms 20000 \
  > /tmp/wt-go.log 2>&1 &
PORT=$(awk '/^READY / {print $2; exit}' /tmp/wt-go.log)

# Against a quic-zig that carries the ISCID fix, this progresses through
# SETTINGS, CONNECT (200), a datagram round-trip, a uni stream, and CLOSE.
WT_INTEROP_URL="https://127.0.0.1:$PORT/wt-go-interop" \
  ./zig-out/bin/http3-zig-external-wt-client --max-time-ms 8000
```
