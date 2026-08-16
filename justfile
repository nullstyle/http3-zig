set shell := ["bash", "-ceu"]

test:
    zig build test

check-api:
    zig build check-api

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

examples:
    zig build examples

run-examples:
    zig build run-examples

example-loopback-get:
    zig build run-example-loopback-get

example-manual-pump-get:
    zig build run-example-manual-pump-get

example-observability-metrics:
    zig build run-example-observability-metrics

example-request-reset:
    zig build run-example-request-reset

example-tracked-datagram:
    zig build run-example-tracked-datagram

example-bounded-body-sink:
    zig build run-example-bounded-body-sink

example-streaming-upload:
    zig build run-example-streaming-upload

example-graceful-shutdown:
    zig build run-example-graceful-shutdown

example-loopback-wt:
    zig build run-example-loopback-wt

example-webtransport-proxy:
    zig build run-example-webtransport-proxy

example-udp-server:
    zig build example-udp-server

example-udp-client:
    zig build example-udp-client

udp-smoke:
    zig build run-udp-smoke

fuzz-codecs:
    zig build fuzz-codecs

fuzz-smoke:
    zig build run-fuzz-smoke

wt-browser-chrome:
    zig build external-wt-server
    bash interop/browser_wt/run_chrome.sh

wt-browser-firefox:
    zig build external-wt-server
    bash interop/browser_wt/run_firefox.sh

fmt:
    # Mirror the CI gate exactly: every tracked .zig/.zon file.
    git ls-files -z '*.zig' '*.zon' | xargs -0 zig fmt --check

# Compile every out-of-test binary target. `zig build test` does NOT
# build these, so a signature change in src/ can pass the whole test
# suite and still break CI at the interop/example build step (this bit
# us on 5ee87e1: a role parameter added to `peerEnabledFor` left the
# external-wt client uncompiled locally and red in CI).
build-all:
    zig build external-wt-client external-wt-server external-h3-client curl-h3-server
    zig build examples
    zig build fuzz-codecs fuzz-corpus fuzz-wt-interleaved seed-fuzz-corpus
    zig build qpack-dynamic-fixtures install-wt-interop-matrix
    zig build bench-build mem-profile-build wt-load-build

check: fmt test build-all
