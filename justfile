set shell := ["bash", "-ceu"]

test:
    zig build test

qpack-interop:
    cd interop/qpack_quic_go && go test -v

qpack-dynamic-interop:
    zig build qpack-dynamic-interop

qpack-dynamic-fixtures:
    zig build qpack-dynamic-fixtures

curl-h3-interop:
    zig build curl-h3-server
    bash interop/curl_h3/run.sh

external-h3-client:
    zig build external-h3-client

external-h3-interop:
    zig build external-h3-client
    bash interop/external_h3/run_matrix.sh

example-loopback-get:
    zig build run-example-loopback-get

example-bounded-body-sink:
    zig build run-example-bounded-body-sink

example-streaming-upload:
    zig build run-example-streaming-upload

example-loopback-wt:
    zig build run-example-loopback-wt

example-webtransport-proxy:
    zig build run-example-webtransport-proxy

fuzz-codecs:
    zig build fuzz-codecs

fuzz-smoke:
    zig build run-fuzz-smoke

fmt:
    zig fmt build.zig src tests interop examples fuzz

check: fmt test
