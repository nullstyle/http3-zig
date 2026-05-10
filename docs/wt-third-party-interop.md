# WebTransport third-party interop — known-broken state (v0.3.x)

## TL;DR

The `wt-interop` GitHub Actions workflow runs http3-zig's external-WT
client against two unmodified third-party WT servers:

- `webtransport-go` (Go, quic-go core)
- `pywebtransport` (Python over a Rust QUIC core)

As of v0.3.x **both peers fail at the QUIC handshake stage**, before
HTTP/3 SETTINGS even has a chance to surface. The workflow step is
explicitly `continue-on-error: true` so this regression doesn't block
merges; the per-push real-socket gate
(`wt-interop-self-test.yml`) covers our own pump path against our own
server and IS treated as gating.

## What the v0.3 follow-up commit fixed

The interop client's pump loop (`interop/external_wt/client.zig`)
was missing an explicit `quic_zig.Connection.advance()` call. Without
it, the TLS state machine never produced a ClientHello, so QUIC's
`poll()` had nothing to emit. The first symptom was
`SettingsExchangeTimedOut` after 30 s of zero outbound traffic.

After the v0.3 follow-up commit:

- `wt-interop-self-test.yml` (our client → our server): completes
  phase 1 (SETTINGS), phase 2 (CONNECT), phase 3 (datagram + uni
  stream + CLOSE_WT). Phase 4 (clean-shutdown read) still times out
  but the failure mode is now `HarnessTimedOut`, not
  `SettingsExchangeTimedOut`.
- `wt-interop.yml` against webtransport-go: still
  `SettingsExchangeTimedOut`. Manual capture against the local Go peer
  shows we transmit a 1200-byte Initial (correct §14.1 padding) and
  receive a single 116-byte Initial reply from the server, after
  which no further packets flow either direction. The 116-byte reply
  is a valid QUIC v1 Initial (long-header type byte `0xc3`, version
  `0x00000001`, valid DCID/SCID/length framing), but its 94-byte
  encrypted payload is too small to carry a complete TLS 1.3
  ServerHello — only a partial first fragment.

## Diagnostic next steps for the v0.4 cycle

The deadlock pattern (one server datagram, no follow-up traffic)
points at one of:

1. **Missing client ACK at Initial level.** quic-go-side flow-control
   may be holding back the rest of the ServerHello / EncryptedExtensions
   pending an ACK from us. We should verify quic-zig's
   `handleInitial` queues an ACK frame at Initial level for the next
   `poll`, and that `poll` actually emits it (separate from any CRYPTO
   continuation).

2. **Initial-PN-space ACK pacing.** quic-zig may be deferring the ACK
   per RFC 9000 §13.2.2 (max_ack_delay) and our 5 ms `receiveTimeout`
   loop arrives ahead of the timer. Try pumping `tick(now_us)` BEFORE
   `flush` so the ACK timer can fire on the next iteration.

3. **Coalesced ServerHello fragmentation.** RFC 9368 §6 "multi-Initial
   fragmented ClientHello" is in the local quic-zig HEAD but might
   not be in the pinned `f46137b` build hash — meaning we cannot
   reassemble a fragmented server response. Bumping the dependency
   pin to a quic-zig that includes
   `00a8e64 Merge branch 'followup-multi-initial-ch': streaming CH
   reassembly for fragmented Initials` may close the gap.

4. **Transport-parameter mismatch.** Our advertised
   `max_udp_payload_size = 1200` may be tighter than the server
   expects for a coalesced response. Try raising it to the
   draft-default 65527 or the quic-zig default and see if the
   server's reply grows.

The cheapest first move is (3) — bump the quic-zig pin and re-run the
matrix; the local repo has the multi-Initial reassembly path landed,
so a refreshed build hash may just make this go away.

## How to reproduce locally

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

# Run our client against it. With the v0.3 follow-up's `advance()`
# fix in place, this fails with `SettingsExchangeTimedOut` after the
# 5s timeout — the QUIC handshake never completes.
WT_INTEROP_URL="https://127.0.0.1:$PORT/wt-go-interop" \
  ./zig-out/bin/http3-zig-external-wt-client --max-time-ms 5000

# Self-test (our client → our server) for comparison; this DOES
# progress through phases 1-3 with the same pump loop:
./zig-out/bin/http3-zig-external-wt-server \
  --listen 127.0.0.1:0 --max-sessions 1 --max-lifetime-ms 60000 \
  > /tmp/wt-self.log 2>&1 &
SELF_PORT=$(awk '/^READY / {print $2; exit}' /tmp/wt-self.log)
WT_INTEROP_URL="https://127.0.0.1:$SELF_PORT/path" \
  ./zig-out/bin/http3-zig-external-wt-client --max-time-ms 5000
```

## Why this is non-blocking

The QUIC layer is a separate package (`quic_zig`) and the gap most
likely lives there, not in http3-zig. The deeper investigation
needs:

- Wireshark / `pcap` on `lo` (requires sudo on macOS, easy on Linux)
  to see exactly which datagrams the Go server emits and when.
- A quic-zig-side ACK / loss-detection trace (qlog) to see what we
  decoded from the 116-byte Initial and what we queued in response.
- Possibly a quic-zig dependency bump (item 3 above).

These are reasonable v0.4 follow-up tasks but not "block the next
http3-zig release" tasks. Hence the workflow's `continue-on-error`
treatment.
