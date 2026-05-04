set shell := ["bash", "-ceu"]

test:
    zig build test

qpack-interop:
    cd interop/qpack_quic_go && go test -v

fmt:
    zig fmt build.zig src tests

check: fmt test
