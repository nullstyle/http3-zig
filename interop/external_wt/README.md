# External WebTransport Interop Harness

`http3-zig`-as-client harness that drives a real
WebTransport-over-HTTP/3 handshake against an **external** server. Mirrors
the approach of [`interop/external_h3/`](../external_h3/) but exercises
the full WebTransport bring-up, datagrams, a unidirectional stream, and a
clean `CLOSE_WEBTRANSPORT_SESSION`.

The binary lives at:

* Source: `interop/external_wt/client.zig`
* Build: `zig build external-wt-client`
* Run:   `zig build run-external-wt-client -- [flags]`

Or invoke the installed binary directly:

```sh
zig build external-wt-client
./zig-out/bin/http3-zig-external-wt-client [flags]
```

## Configuration

The harness reads its target URL from the `WT_INTEROP_URL` environment
variable. The URL form is `https://host:port/path` (or `https://host/path`
— a missing port resolves to the default `:443`).

```sh
export WT_INTEROP_URL="https://localhost:4433/wt-echo"
zig build run-external-wt-client
```

If `WT_INTEROP_URL` is unset, the harness prints a friendly skip
message and exits 0. This makes it safe to wire into CI without
requiring an external server be up.

### CLI flags

| Flag | Meaning |
|---|---|
| `--insecure` (default) | TLS verify mode `.none` — accepts any server cert. Right for interop, **wrong for production**. |
| `--verify-system` | Use the system trust store. |
| `--max-time-ms <int>` | Wall-clock cap for the run (default 30000). |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success **or** skip (no `WT_INTEROP_URL` set). |
| 1 | Protocol failure (server returned non-2xx, handshake failed, etc.). |
| 2 | Setup / network error (URL parse, DNS, socket bring-up, argument errors). |

## Wire-format pin

This harness pins to **draft-ietf-webtrans-http3-15**. The most
visible knob is the SETTINGS bootstrap: http3-zig advertises only
the draft-15 codepoint `SETTINGS_WT_ENABLED = 0x2c7cf000` (boolean).
Earlier drafts used a numeric `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29`
with no overlap — peers from different revisions will not interop
by accident.

When picking a third-party server, verify it speaks draft-15:

| Implementation | draft-15 status (as of 2026-05-09) | Notes |
|---|---|---|
| `quic-go/webtransport-go` | master only | tagged releases (latest `v0.10.0`, June 2025) still emit draft-13. PR [#254](https://github.com/quic-go/webtransport-go/pull/254) brought master to draft-15 on 2026-03-12; advertises both `0x2b603742` (draft-06) and `0x2c7cf000` (draft-15). The pinned peer in [`server_go/`](./server_go/) uses this. |
| `wtransport/pywebtransport` | shipped (v0.16.0+) | Python facade over a Rust core (`quinn-proto` + `pyo3`); v0.16.0 (2026-03-13) introduced `SETTINGS_WT_ENABLED = 0x2c7cf000` directly. The pinned peer in [`server_python/`](./server_python/) uses v0.17.1. |
| `BiagioFesta/wtransport` | not yet | latest tag (v0.7.1, May 2026) still uses only the legacy `0x2b603742` draft-06 codepoint in `wtransport-proto/src/settings.rs`. Worth re-evaluating whenever a new release lands. |
| `cloudflare/quiche` | not supported | issue [#1114](https://github.com/cloudflare/quiche/issues/1114) open since 2022; no native WT path in the `quiche-server` example. |
| `aiortc/aioquic` | not yet | `src/aioquic/h3/connection.py` still defines `ENABLE_WEBTRANSPORT = 0x2B603742` and the `examples/webtransport.py` demo emits draft-13 codepoints. Track upstream for a draft-15 update. |
| `mozilla/neqo` | not yet | `neqo-http3/src/settings.rs` still uses `SETTINGS_ENABLE_WEB_TRANSPORT: SettingsType = 0x2b60_3742`. |

## Pinned third-party server: `webtransport-go`

The repo ships a small Go program in [`server_go/`](./server_go/) that
boots a webtransport-go echo server on a real UDP socket. The
[`wt-interop` workflow](../../.github/workflows/wt-interop.yml)
installs Go, builds the binary, brings it up against
`tests/data/test_cert.pem`, and runs the matrix runner against it.

To repro locally:

```sh
# In a clone of this repo
cd interop/external_wt/server_go
go build -o /tmp/wt-go-server .

/tmp/wt-go-server \
  --listen 127.0.0.1:4433 \
  --cert ../../../tests/data/test_cert.pem \
  --key  ../../../tests/data/test_key.pem \
  --max-sessions 1 \
  --max-lifetime-ms 60000 &

# In another terminal, in the repo root
WT_INTEROP_URL=https://127.0.0.1:4433/wt-go-interop \
  zig build run-external-wt-client
```

Server CLI:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:0` | UDP listen address. `:0` asks the kernel to pick a port; the chosen port is printed as `READY <port>` on stdout once the listener is up. |
| `--cert` | `tests/data/test_cert.pem` | PEM cert chain. |
| `--key`  | `tests/data/test_key.pem` | PEM private key. |
| `--max-sessions` | `1` | Exit after this many sessions complete. `0` runs until killed. |
| `--max-lifetime-ms` | `30000` | Wallclock cap before the server force-shuts itself, defends against a stuck client wedging CI. |

The pinned commit in [`server_go/go.mod`](./server_go/go.mod) is a
master pseudo-version (`v0.10.1-0.20260509...`). When a tagged
release ships with draft-15 in the changelog, swap the
pseudo-version for it and re-run `go mod tidy` from the
`server_go/` directory.

## Pinned third-party server: `pywebtransport`

The repo also ships a small Python program in [`server_python/`](./server_python/)
that boots a [`pywebtransport`](https://github.com/wtransport/pywebtransport)
echo server on a real UDP socket. Adding a second peer in a
different language/library stack makes regressions easier to
localize: a failure that hits *both* peers is almost certainly an
http3-zig bug, while one that only hits one peer is more likely a
peer-specific draft disagreement.

`pywebtransport` is a Python facade over a Rust state machine
(quinn-proto + pyo3) and pins to `draft-ietf-webtrans-http3-15`
explicitly — its v0.16.0 changelog (2026-03-13) introduced
`SETTINGS_WT_ENABLED = 0x2c7cf000` directly, the same codepoint
http3-zig pins to in `src/protocol.zig`.

To repro locally:

```sh
# In a clone of this repo (Python 3.12+ on PATH)
python -m venv /tmp/wt-py
source /tmp/wt-py/bin/activate
pip install -r interop/external_wt/server_python/requirements.txt

python -u interop/external_wt/server_python/main.py \
  --listen 127.0.0.1:4433 \
  --cert tests/data/test_cert.pem \
  --key  tests/data/test_key.pem \
  --max-sessions 1 \
  --max-lifetime-ms 60000 &

# In another terminal, in the repo root
WT_INTEROP_URL=https://127.0.0.1:4433/wt-py-interop \
  zig build run-external-wt-client
```

The `python -u` flag flushes stdout immediately so the workflow's
`READY <port>` grep doesn't race against block buffering on cold
runners.

Server CLI mirrors the Go peer exactly so the same workflow YAML
can drive either:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:0` | UDP listen address. `:0` asks the kernel to pick a port (via a throwaway probe socket — `pywebtransport`'s config validator rejects `bind_port=0`). |
| `--cert` | `tests/data/test_cert.pem` | PEM cert chain. |
| `--key`  | `tests/data/test_key.pem` | PEM private key. |
| `--max-sessions` | `1` | Exit after this many sessions complete. `0` runs until killed. |
| `--max-lifetime-ms` | `30000` | Wallclock cap before the server force-shuts itself, defends against a stuck client wedging CI. |

The pinned version in
[`server_python/requirements.txt`](./server_python/requirements.txt)
is `pywebtransport==0.17.1` (May 2026). When a tagged release
of `BiagioFesta/wtransport` (Rust) or `aiortc/aioquic` (Python)
finally ships draft-15, consider swapping the second peer for it
to keep language *and* underlying-library diversity.

## Other recipes

The actual server commands change with every release of every
implementation. Cross-reference with each project's docs before relying
on these. The recipes below are kept for posterity; only
`webtransport-go` is currently exercised in CI.

### Chromium origin trial / `webtransport-test-server`

For a turnkey browser-compatible target,
[GoogleChrome/samples](https://github.com/GoogleChrome/samples/tree/gh-pages/webtransport)
links to `webtransport-test-server.glitch.me`. There's no fixed local
recipe — copy whatever URL the project recommends today, and verify it
speaks draft-15 before pointing the matrix at it.

```sh
WT_INTEROP_URL=https://webtransport-test-server.example/wt zig build run-external-wt-client
```

## Matrix runner

The `wt-interop-matrix` build step iterates over a list of URLs supplied
via the `WT_INTEROP_MATRIX_URLS` environment variable (newline- or
comma-separated). It runs the harness against each URL, prints
per-target status, and exits non-zero only if **every** target failed
(so a missing aioquic doesn't mask a working webtransport-go).

```sh
export WT_INTEROP_MATRIX_URLS="\
https://127.0.0.1:4433/wt-go-interop
https://webtransport-test-server.example/wt"
zig build wt-interop-matrix
```

If `WT_INTEROP_MATRIX_URLS` is unset, the matrix step prints a skip
message and exits 0.

## What the harness verifies

1. UDP socket bring-up against the resolved host.
2. QUIC handshake completion.
3. SETTINGS exchange — peer must advertise WebTransport
   (`SETTINGS_WT_ENABLED`, `SETTINGS_H3_DATAGRAM`,
   `SETTINGS_ENABLE_CONNECT_PROTOCOL`).
4. Extended CONNECT with `:protocol = webtransport` returns 2xx.
5. One WebTransport datagram is sent.
6. One client-initiated unidirectional WT stream carrying a payload is
   sent and finished.
7. A `CLOSE_WEBTRANSPORT_SESSION` capsule is sent and the CONNECT
   stream is finished cleanly.

The harness does **not** verify echo behavior — the server is free to
ignore the inbound bytes. Echo verification is left to per-server
adapter scripts because each server uses a different echo path /
protocol shape.
