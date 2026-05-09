"""Echo WebTransport server used as a third-party interop peer for
http3-zig's `wt-interop-matrix` runner.

This is the Python sibling of `interop/external_wt/server_go/`. Having
two third-party peers in different language/library stacks (Go's
`quic-go/webtransport-go` vs. Python's `wtransport/pywebtransport`)
makes it easier to spot regressions: if both peers fail the matrix
the bug is almost certainly on the http3-zig side, but if only one
peer fails the bug is more likely peer-specific (a draft-15
disagreement, a socket-pump quirk, ...).

The flow this peer is asked to participate in (see
`interop/external_wt/client.zig`):

  1. Client opens a WebTransport CONNECT session against `<path>`.
  2. Client sends one datagram with payload `hello-from-http3-zig`.
  3. Client opens one client-initiated unidirectional stream and
     writes `hello-uni` onto it, then finishes it.
  4. Client sends `CLOSE_WEBTRANSPORT_SESSION` and finishes the
     CONNECT stream.

The matrix client doesn't care about echoes, but for symmetry with
the in-tree Zig echo server (`interop/external_wt/server.zig`) and
the Go peer we also:

  * Echo every incoming datagram back to the peer.
  * For every accepted uni stream, drain it and open a server-
    initiated uni stream that writes the same bytes back.

This server uses pywebtransport because it explicitly aligns with
draft-ietf-webtrans-http3-15 — see its v0.16.0 changelog entry
(2026-03-13) "Protocol Constants Alignment ... SETTINGS_WT_ENABLED
(0x2c7cf000)" and the `SETTINGS_WT_ENABLED: u64 = 0x2C7C_F000`
constant in its Rust core (`crates/src/common/constants.rs`). At the
time of writing, the most popular Rust WebTransport library
(`BiagioFesta/wtransport` v0.7.1) still emits only the legacy
draft-06 codepoint (`0x2b603742`), so it is not yet a viable second
peer; this Python server fills the language-diversity gap until
either `wtransport` or `aioquic` ships draft-15 support.

CLI surface mirrors the Go peer so the same workflow YAML can drive
either:

  --listen 127.0.0.1:0    listen address (`:0` asks the kernel for
                          a free port; the port is reported via the
                          `READY <port>\\n` line on stdout).
  --cert  tests/data/test_cert.pem
  --key   tests/data/test_key.pem
  --max-sessions N        exit after N sessions complete (0 = forever)
  --max-lifetime-ms N     wallclock deadline before forced shutdown

stdout protocol contract:

  READY <port>\\n         printed once the listener is up; the GH
                          Actions workflow grep's for it.

Exit codes:

  0  clean shutdown (max_sessions reached or deadline expired)
  1  protocol failure (a session ended badly)
  2  setup failure (cert load, listen, ...)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import ssl
import sys
from typing import Any

# pywebtransport >= 0.16.0 is required for draft-15 wire-format
# alignment. We pin to 0.17.1 in `requirements.txt` — see that file
# for the full rationale.
from pywebtransport import (
    Event,
    ServerApp,
    ServerConfig,
    SessionClosedError,
    WebTransportSession,
)
from pywebtransport.types import EventType


def parse_listen(spec: str) -> tuple[str, int]:
    """Parse a `host:port` listen spec into (host, port).

    Accepts both bare-IPv4 (`127.0.0.1:4433`) and IPv6 (`[::1]:4433`)
    forms. We mirror the Go peer's flag shape exactly so the workflow
    YAML can pass `--listen 127.0.0.1:0` to either.
    """
    if spec.startswith("["):
        end = spec.rfind("]")
        if end < 0 or end + 1 >= len(spec) or spec[end + 1] != ":":
            raise ValueError(f"invalid IPv6 listen spec: {spec!r}")
        host = spec[1:end]
        port = int(spec[end + 2:])
    else:
        host_part, _, port_part = spec.rpartition(":")
        if not host_part or not port_part:
            raise ValueError(f"invalid listen spec: {spec!r}")
        host = host_part
        port = int(port_part)
    return host, port


def pick_free_port(host: str) -> int:
    """Return a kernel-assigned free UDP port on `host`.

    pywebtransport's `ServerConfig` rejects `bind_port=0` outright
    (its validator requires `1 <= port <= 65535`). To honour the
    `--listen :0` convention without patching the library we open a
    short-lived UDP socket, ask the kernel for a free port via
    `getsockname()`, then close it and pass the resulting port back
    to pywebtransport.

    There is a tiny TOCTOU window between this socket closing and
    `WebTransportServer.listen()` re-binding the same port. In
    practice the kernel will not hand the same port to another
    process within microseconds, and the workflow's `READY` parsing
    will surface any actual collision.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


async def run_server(args: argparse.Namespace) -> int:
    """Bring up the echo server and run it until shutdown.

    Returns the process exit code:
      0 — clean shutdown (max-sessions reached or deadline expired);
      1 — at least one session ended in a protocol error;
      2 — setup failure (cert load, bind, ...).
    """
    try:
        host, requested_port = parse_listen(args.listen)
    except ValueError as e:
        print(f"external_wt server (python): bad --listen: {e}", file=sys.stderr)
        return 2

    bind_port = pick_free_port(host) if requested_port == 0 else requested_port

    try:
        config = ServerConfig(
            bind_host=host,
            bind_port=bind_port,
            certfile=args.cert,
            keyfile=args.key,
            verify_mode=ssl.CERT_NONE,
        )
    except Exception as e:
        print(f"external_wt server (python): config invalid: {e}", file=sys.stderr)
        return 2

    # Track session count + protocol failures so we can shut down
    # gracefully once the matrix runner has exercised us. Starts at
    # `args.max_sessions` and counts down; when it hits zero we set
    # `done` and the deadline coroutine wakes the server up.
    state = {
        "sessions_remaining": args.max_sessions if args.max_sessions > 0 else None,
        "protocol_failure": False,
    }
    done = asyncio.Event()

    app = ServerApp(config=config)

    async def echo(session: WebTransportSession, **_: Any) -> None:
        """Per-session echo loop.

        Attaches a datagram handler that mirrors every received
        datagram back to the peer, then iterates over incoming
        unidirectional streams; for each one, drains it into memory
        and writes the bytes back on a fresh server-initiated uni
        stream (matching the in-tree Zig server's behaviour).

        The matrix client itself doesn't read echoes back — it just
        finishes its CONNECT stream after sending one datagram and
        one uni stream — so this loop only really needs to *not
        crash*. We still mirror traffic for symmetry with the Go peer
        and so a future matrix client can turn echo verification on
        without changing servers.
        """
        sid = session.session_id

        async def on_datagram(event: Event) -> None:
            data = event.data.get("data") if isinstance(event.data, dict) else None
            if not data:
                return
            try:
                await session.send_datagram(data=data)
            except Exception:
                # Datagrams are unreliable; a send failure is not a
                # protocol failure on its own.
                pass

        session.events.on(event_type=EventType.DATAGRAM_RECEIVED, handler=on_datagram)

        try:
            async for stream in session.incoming_unidirectional_streams():
                payload = await stream.read_all()
                try:
                    out = await session.create_unidirectional_stream()
                    await out.write_all(data=payload, end_stream=True)
                except Exception as e:
                    logging.warning("session %d: uni echo failed: %s", sid, e)
                    state["protocol_failure"] = True
        except SessionClosedError:
            pass
        except Exception as e:
            logging.warning("session %d: uni-stream loop failed: %s", sid, e)
            state["protocol_failure"] = True
        finally:
            session.events.off(event_type=EventType.DATAGRAM_RECEIVED, handler=on_datagram)

            if state["sessions_remaining"] is not None:
                state["sessions_remaining"] -= 1
                if state["sessions_remaining"] <= 0:
                    done.set()

    # Match any path. The matrix client picks its own
    # `/wt-self-test`-style URL; we just upgrade.
    app.pattern_route(pattern=r".*")(echo)

    try:
        async with app:
            await app.server.listen(host=host, port=bind_port)

            addresses = app.server.local_addresses
            actual_port = addresses[0][1] if addresses else bind_port
            # Single-line stdout contract the workflow greps for.
            print(f"READY {actual_port}", flush=True)

            async def deadline() -> None:
                await asyncio.sleep(args.max_lifetime_ms / 1000.0)
                done.set()

            deadline_task = asyncio.create_task(deadline())
            serve_task = asyncio.create_task(app.server.serve_forever())
            wait_task = asyncio.create_task(done.wait())

            try:
                await asyncio.wait(
                    {deadline_task, serve_task, wait_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                for task in (deadline_task, serve_task, wait_task):
                    if not task.done():
                        task.cancel()
                # Drain cancelled tasks so we don't leak warnings.
                await asyncio.gather(
                    deadline_task,
                    serve_task,
                    wait_task,
                    return_exceptions=True,
                )
    except FileNotFoundError as e:
        print(f"external_wt server (python): cert/key not found: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"external_wt server (python): listen failed: {e}", file=sys.stderr)
        return 2

    return 1 if state["protocol_failure"] else 0


def main() -> None:
    """CLI entry point — parse flags and run the server."""
    parser = argparse.ArgumentParser(
        description="Echo WebTransport server (pywebtransport, draft-15) for http3-zig interop.",
        allow_abbrev=False,
    )
    parser.add_argument("--listen", default="127.0.0.1:0",
                        help="UDP listen address (default: 127.0.0.1:0)")
    parser.add_argument("--cert", default="tests/data/test_cert.pem",
                        help="PEM cert chain (default: tests/data/test_cert.pem)")
    parser.add_argument("--key", default="tests/data/test_key.pem",
                        help="PEM private key (default: tests/data/test_key.pem)")
    parser.add_argument("--max-sessions", type=int, default=1,
                        help="exit after this many sessions complete (0 = forever; default 1)")
    parser.add_argument("--max-lifetime-ms", type=int, default=30_000,
                        help="wallclock cap on the server's lifetime in ms (default 30000)")
    args = parser.parse_args()

    # Send pywebtransport's logging chatter to stderr so the
    # workflow's READY-line grep on stdout stays clean.
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    try:
        exit_code = asyncio.run(run_server(args))
    except KeyboardInterrupt:
        exit_code = 0
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
