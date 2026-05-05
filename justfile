set shell := ["bash", "-ceu"]

test:
    zig build test

qpack-interop:
    cd interop/qpack_quic_go && go test -v

curl-h3-interop:
    zig build curl-h3-server
    bash interop/curl_h3/run.sh

external-h3-client:
    zig build external-h3-client

example-loopback-get:
    zig build run-example-loopback-get

fuzz-codecs:
    zig build fuzz-codecs

fuzz-smoke:
    zig build run-fuzz-smoke

fmt:
    zig fmt build.zig src tests interop examples fuzz

check: fmt test
