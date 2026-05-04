set shell := ["bash", "-ceu"]

test:
    zig build test

fmt:
    zig fmt build.zig src tests

check: fmt test
