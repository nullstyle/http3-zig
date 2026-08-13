#!/usr/bin/env python3
"""Control server for the browser WebTransport interop leg.

Serves the static test page over plain HTTP and receives the page's JSON
verdict on POST /result. Stdlib only (http.server) so the CI leg needs no
Python dependency install - the browsers are enough moving parts already.

Protocol with the shell runner:
  - prints "READY <port>" on stdout once listening (runner polls for it)
  - on POST /result: writes the raw body to --out, prints each browser log
    line prefixed "BROWSER ", then "RESULT PASS" or "RESULT FAIL" based on
    the JSON's "pass" field (runner polls for "^RESULT ")
  - keeps serving afterwards; the runner owns the lifecycle and kills it
"""

import argparse
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:0",
                        help="host:port to bind; port 0 lets the kernel pick")
    parser.add_argument("--page-dir", required=True,
                        help="directory to serve static files from")
    parser.add_argument("--out", required=True,
                        help="path to write the POSTed /result body to")
    args = parser.parse_args()

    host, _, port_str = args.listen.rpartition(":")
    if not host:
        parser.error("--listen must be host:port")

    class Handler(SimpleHTTPRequestHandler):
        # SimpleHTTPRequestHandler already confines GETs to this directory
        # (it rejects traversal), so serving is just the directory kwarg.
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=args.page_dir,
                             **handler_kwargs)

        def do_POST(self) -> None:
            if self.path != "/result":
                self.send_error(404, "only POST /result is supported")
                return
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            with open(args.out, "wb") as out_file:
                out_file.write(body)
            try:
                result = json.loads(body)
                passed = bool(result.get("pass"))
                log_lines = result.get("log", [])
            except (ValueError, AttributeError):
                # An unparseable verdict is a fail, not a crash: the runner
                # still needs its RESULT line to stop polling.
                passed = False
                log_lines = ["control server: /result body was not valid JSON"]
            for line in log_lines:
                print(f"BROWSER {line}", flush=True)
            print("RESULT PASS" if passed else "RESULT FAIL", flush=True)
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer((host, int(port_str)), Handler)
    # Flush immediately: the runner greps a log file for this line and
    # block-buffered stdout would make it race pipe buffering.
    print(f"READY {server.server_address[1]}", flush=True)
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
