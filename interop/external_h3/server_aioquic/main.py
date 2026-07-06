#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 file server for advisory interop.

The command-line contract mirrors interop/external_h3/run_matrix.sh:

  --host 127.0.0.1
  --port 44330
  --cert tests/data/test_cert.pem
  --key tests/data/test_key.pem
  --root <dir>
  --max-requests 1
  --max-lifetime-ms 60000

stdout protocol:

  READY <port>
"""

from __future__ import annotations

import argparse
import asyncio
import mimetypes
import posixpath
from pathlib import Path
from urllib.parse import unquote

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


class FileServerProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        root: Path,
        max_requests: int,
        done: asyncio.Event,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._done = done
        self._http: H3Connection | None = None
        self._max_requests = max_requests
        self._requests_seen = 0
        self._root = root

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic)
            else:
                return

        if self._http is None:
            return

        for http_event in self._http.handle_event(event):
            self.http_event_received(http_event)

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            self._handle_headers(event)
        elif isinstance(event, DataReceived):
            # The matrix only sends GET requests. Consume unexpected request
            # body events without changing the response path.
            pass

    def _handle_headers(self, event: HeadersReceived) -> None:
        headers = dict(event.headers)
        method = headers.get(b":method", b"").decode("ascii", "replace")
        raw_path = headers.get(b":path", b"/").decode("utf-8", "replace")

        if method != "GET":
            self._send_response(event.stream_id, 405, b"method not allowed\n")
        else:
            status, body, content_type = self._read_path(raw_path)
            self._send_response(event.stream_id, status, body, content_type)

        self._requests_seen += 1
        if self._max_requests > 0 and self._requests_seen >= self._max_requests:
            asyncio.get_running_loop().call_soon(self._done.set)

    def _read_path(self, raw_path: str) -> tuple[int, bytes, bytes]:
        path = raw_path.split("?", 1)[0]
        normalized = posixpath.normpath(unquote(path)).lstrip("/")
        candidate = (self._root / normalized).resolve()
        root = self._root.resolve()

        try:
            candidate.relative_to(root)
        except ValueError:
            return 403, b"forbidden\n", b"text/plain"

        if not candidate.is_file():
            return 404, b"not found\n", b"text/plain"

        content_type = (mimetypes.guess_type(candidate.name)[0] or "application/octet-stream").encode()
        return 200, candidate.read_bytes(), content_type

    def _send_response(
        self,
        stream_id: int,
        status: int,
        body: bytes,
        content_type: bytes = b"text/plain",
    ) -> None:
        assert self._http is not None
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", str(status).encode()),
                (b"server", b"aioquic-http3-zig-interop"),
                (b"content-length", str(len(body)).encode()),
                (b"content-type", content_type),
            ],
        )
        self._http.send_data(stream_id=stream_id, data=body, end_stream=True)
        self.transmit()


async def run(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    done = asyncio.Event()

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(args.cert, args.key)

    def protocol_factory(*factory_args, **factory_kwargs):
        return FileServerProtocol(
            *factory_args,
            root=root,
            max_requests=args.max_requests,
            done=done,
            **factory_kwargs,
        )

    server = await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=protocol_factory,
    )
    print(f"READY {args.port}", flush=True)

    try:
        await asyncio.wait_for(done.wait(), timeout=args.max_lifetime_ms / 1000)
    except asyncio.TimeoutError:
        pass
    finally:
        server.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="aioquic HTTP/3 interop server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--max-requests", type=int, default=1)
    parser.add_argument("--max-lifetime-ms", type=int, default=30000)
    return parser.parse_args()


def main() -> None:
    asyncio.run(run(parse_args()))


if __name__ == "__main__":
    main()
