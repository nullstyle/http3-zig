# bench-e2e baselines

`zig build bench-e2e -- --check bench/baselines/e2e-<os>.json` compares
a fresh run with one of these files (`just bench-e2e` picks the file for
the current OS). CI checks `e2e-linux.json` on `ubuntu-latest`.

What is gated, and why (the constants are in `bench/e2e.zig`):

| Number | Limit | Why |
| --- | --- | --- |
| allocations per operation, client and server | baseline + 0.5 | Deterministic: the same code path per operation. One new allocation per request or connection fails. |
| packets and bytes per operation (client) | baseline x 1.25 + slack | They move with ACK timing on a busy machine. |
| soak: malloc bytes left per connection | 16 | Absolute. After the server has reaped every connection, nothing may stay behind. Read over the second of two phases, so one-time table growth does not count. |
| wall time, latency | not gated | Several percent of noise on a shared runner with nothing changed. |

Ablations (each must fail the gate): `--seed-allocs 1` (one extra
allocation per GET) and `--seed-leak 64` (a 64-byte C-heap leak per
connection; reads back as exactly 64.0).

## Updating a baseline

Only when a change is meant to move a gated number:

```sh
zig build bench-e2e -- --json bench/baselines/e2e-macos.json
```

For Linux, take the `bench-e2e.json` artifact of the CI run on the
commit that moves the number. Say in the commit message which number
moved and why.
