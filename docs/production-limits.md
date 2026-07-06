# Production Limits and Backpressure

This is the current resource-control inventory for http3-zig's public
production preset and the session-level knobs behind it. Defaults remain
compatibility-oriented; opt into the bounded posture with
`SessionConfig.production(.{})`, `Client.Config.production.toSessionConfig()`,
or `Server.Config.production.toSessionConfig()`.

## Bounded Today

| Surface | Config | Production default |
| --- | --- | ---: |
| Encoded HEADERS payload | `max_field_section_size` | 64 KiB (`SessionConfig.production`) / 16 KiB (`Client` / `Server` facade presets) |
| Decoded QPACK fields | `max_field_lines`, `max_decoded_field_section_bytes` | 128 lines / 128 KiB |
| Non-DATA frame declared length | `max_incoming_frame_length` | 128 KiB |
| Outgoing DATA chunk size | `max_data_frame_payload` | 16 KiB |
| Outgoing HTTP/3 DATAGRAM payload | `max_datagram_payload_size` | 16 KiB |
| Outgoing capsule value allocation | `max_capsule_value_size` | 64 KiB |
| Per-stream unacked send buffer | `max_stream_send_buffered` | 1 MiB |
| Single emitted event payload | `max_event_payload_size` | 1 MiB |
| Per-drain emitted event bytes | `max_event_payload_bytes_per_drain` | 4 MiB |
| Per-drain event count | `max_events_per_drain` | 512 |
| Concurrent peer-opened streams tracked by H3 | `max_concurrent_peer_streams` | 1024 (`SessionConfig.production`) / 256 (`Client` / `Server` facade presets) |
| RFC 9218 priority hint maps | `max_tracked_priorities` | 1024 |
| Received PUSH_PROMISE state | `max_tracked_push_promises` | 256 |
| Pending WebTransport CONNECT sessions | `max_pending_wt_sessions` | 256 |
| Per-stream pre-confirmation WT buffering | `wt_max_buffered_bytes_per_stream` | 64 KiB (`SessionConfig.production`) / 16 KiB (`Client` / `Server` facade presets) |
| Aggregate pre-confirmation WT buffering | `wt_max_total_buffered_bytes` | 4 MiB |

## Backpressure Signals

- `StreamSendState` reports written, acknowledged, buffered, and pending send
  bytes so embedders can pause producers before `max_stream_send_buffered`
  fails a write.
- Drain-budget errors (`EventPayloadTooLarge`, `EventQueueFull`) are local
  backpressure signals. Callers should free emitted events and drain again.
- Raw `RequestEvent` / `ResponseEvent` body events let embedders stream into
  their own sinks instead of using facade tracker accumulation. Request and
  response producers can pair that with `RequestWriter.canWrite` or
  `ResponseWriter.canWrite` before emitting more DATA.
- WebTransport flow-control errors (`WebTransportFlowControlExceeded`,
  `WebTransportStreamLimitExceeded`, `WebTransportSessionDraining`) indicate
  session-level or peer-advertised limits rather than transport failure.
- `WebTransport*Stream.forwardCapsuleTo` is an explicit intermediary hook:
  inbound WT control capsules are observed locally and forwarded unchanged to
  a paired outbound handle, while stream/datagram copy policy stays with the
  application. `examples/webtransport_proxy.zig` demonstrates that caller-owned
  datapath end to end.

## Still Caller-Owned

- QUIC transport flow-control windows and datagram queue sizing live in
  quic-zig transport configuration.
- Intermediaries own their proxy datapath: socket binding, WT stream copy
  loops, QUIC-DATAGRAM routing, and CONNECT FIN/reset policy are intentionally
  outside http3-zig's forwarding helper. The proxy example models those loops
  with explicit stream-id maps rather than hiding them in a library-level proxy.
- Application body accumulation is owned by `RequestTracker` /
  `ResponseTracker` budgets when using the facade runners, or entirely by the
  caller when consuming raw events.
- QPACK dynamic encoder table use is opt-in through the indexing policy and
  capacity knobs.
- Third-party interop workflows are advisory signal, not production health
  gates.

## Regression Coverage

- `tests/integration/production_preset.zig` locks the documented preset values
  and drives a basic GET through the facade presets.
- `tests/integration/webtransport.zig` covers per-stream and aggregate
  pre-confirmation WebTransport buffering caps plus replay under tight drain
  budgets.
- `tests/integration/webtransport_forwarding.zig` covers two-hop WT
  control-capsule forwarding, including MAX_DATA, BLOCKED, DRAIN, unknown, and
  CLOSE capsule behavior.
- `zig build run-examples` runs the in-process embedding cookbook on CI,
  covering facade GET, manual QUIC/H3 pump ordering, observability metrics
  wiring, request reset lifecycle classification, tracked HTTP/3 DATAGRAM
  ACK correlation, raw response body budgeting, streaming upload budgeting,
  graceful GOAWAY shutdown, endpoint WebTransport, and WT proxy datapath
  ownership.
- `examples/webtransport_proxy.zig` is a compile-checked, runnable two-hop WT
  datapath example covering capsule, DATAGRAM, stream-data, FIN, and reset
  forwarding ownership.
- `examples/bounded_body_sink.zig` is a compile-checked, runnable raw-event
  example that streams response DATA into a fixed application budget while the
  server side checks `ResponseWriter.canWrite`.
- `examples/streaming_upload.zig` is a compile-checked, runnable upload
  example that checks `RequestWriter.canWrite` before sending request DATA and
  streams server-side request events into a fixed application budget.
- `bench/wt_memory.zig` / `zig build mem-profile` gates long-running
  WebTransport memory growth; see [memory-profile.md](memory-profile.md).
