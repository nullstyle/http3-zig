# External HTTP/3 Client Interop

`null3-external-h3-client` is a small null3-as-client harness for external
HTTP/3 peers. It intentionally keeps peer-specific logic out of `src/`: the
binary owns UDP socket plumbing and CLI parsing, while request/response handling
uses the public `null3.Client`, `ClientRunner`, and `TransportEndpoint` APIs.

Build it with:

```sh
zig build external-h3-client
```

Example against an HTTP/3 server listening on a local UDP port:

```sh
./zig-out/bin/null3-external-h3-client \
  --connect 127.0.0.1:4433 \
  --sni localhost \
  --authority localhost:4433 \
  --path /hello \
  --insecure
```

The first pass accepts IP-literal `--connect` addresses. DNS and peer-specific
matrix scripts can layer above this harness.
