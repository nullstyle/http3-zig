# Browser WebTransport Interop Leg

Real browser (shipped Chrome / Firefox) against the in-tree WT echo server
(`zig build external-wt-server`) over real sockets. This is the one leg
where the peer is an actual browser engine, so it verifies the things the
in-tree and third-party matrices structurally cannot:

1. **Era negotiation lands on draft-02.** The server advertises every era
   (`--eras modern,draft07,draft02`); shipped browsers must resolve to
   `era=draft02` (`SETTINGS_ENABLE_WEBTRANSPORT`, `:protocol =
   webtransport`). The runner requires the `era=draft02` server log line
   even when the echo passes — a silent era change is a regression.
2. **Datagram echo** — `browser-ping` out on `wt.datagrams`, byte-exact
   echo back.
3. **Uni-stream echo** — client uni stream carrying `browser-stream`,
   server opens a uni stream echoing the bytes, read to EOF, byte-exact.
4. **Clean close** — `wt.close(...)`, which reaches the server as a CLOSE
   capsule (how browsers close; the server logs `how=close_capsule`).

## How it runs

No webdriver. `run_chrome.sh` / `run_firefox.sh` start the WT server and a
stdlib-Python control server ([`control_server.py`](./control_server.py)),
then launch the headless browser at
[`page/index.html`](./page/index.html)`?wt=https://127.0.0.1:<port>/wt-browser`.
The page drives the flow (10s watchdog per phase) and POSTs
`{pass, log}` to `/result` on the control server in both outcomes; the
runner greps the control log for the `RESULT` verdict.

Locally:

```sh
zig build external-wt-server
just wt-browser-chrome     # or: bash interop/browser_wt/run_chrome.sh
just wt-browser-firefox    # needs certutil (libnss3-tools / brew nss)
```

Env knobs: `CHROME_BIN` / `FIREFOX_BIN` (browser binary), `WT_SERVER_BIN`
(server binary), `WT_BROWSER_LOG_DIR` (log destination; CI points it at an
uploadable dir, default is the run's throwaway mktemp workdir).

## Cert recipes

Each run generates a throwaway **P-256** cert, **10-day** validity,
`CN=127.0.0.1` + IP SAN. Trust differs per browser:

* **Chrome (CI recipe):**
  `--ignore-certificate-errors-spki-list=<base64 sha-256 of the SPKI>`
  plus `--headless=new --enable-experimental-web-platform-features
  --webtransport-developer-mode` (the WPT runner's recipe). Deliberately
  **not** `serverCertificateHashes` (its failures are opaque in CI) and
  **not** `--origin-to-force-quic-on` (unnecessary for WebTransport).
* **Firefox:** no SPKI flag exists; `certutil -A -n wt-interop -t "C,,"`
  injects the cert into a fresh profile's NSS db (the WPT approach).
  WebTransport is on by default (`network.webtransport.enabled`).
* **Manual `serverCertificateHashes` variant:** the same cert already
  satisfies the hard constraints (ECDSA P-256, validity ≤ 14 days — hence
  the 10-day choice). Compute the **cert** hash
  (`openssl x509 -in cert.pem -outform der | openssl dgst -sha256 -binary
  | base64`) and pass it as the page's `?hash=` param; the page then adds
  `serverCertificateHashes` and needs zero browser trust flags.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `RESULT PASS` **and** the server logged `era=draft02`. |
| 1 | Browser reported `RESULT FAIL`, or echo passed with the wrong era. |
| 2 | Setup failure: missing browser/certutil, no `READY`, or no `RESULT` within 60s. |

## CI posture

Both jobs in
[`wt-browser-interop.yml`](../../.github/workflows/wt-browser-interop.yml)
are **advisory** (`continue-on-error: true`); the promotion criterion and
pre-agreed demotion rule live in that workflow's header comment. The
Firefox job is `workflow_dispatch`-gated until it has two green runs.
