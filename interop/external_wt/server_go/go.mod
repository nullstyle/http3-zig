// Pinned third-party WebTransport interop server.
//
// As of 2026-05-09 the latest tagged release of webtransport-go is
// v0.10.0 (June 2025) which still emits the draft-13 numeric
// `SETTINGS_WT_MAX_SESSIONS = 0x14e9cd29` codepoint. Draft-15
// support (the `SETTINGS_WT_ENABLED = 0x2c7cf000` boolean codepoint
// http3-zig pins to in `src/protocol.zig`) was added on master in
// PR #254. We therefore pin to a master pseudo-version below; when
// the next tagged release ships, swap the pseudo-version for it and
// re-run `go mod tidy` from this directory.
//
// To verify your pin still speaks draft-15, look for these constants
// in the resolved webtransport-go module's `protocol.go`:
//
//   const settingsEnableWebtransportDraft06 = 0x2b603742
//   const settingsWebTransportEnabled       = 0x2c7cf000
//
// Both must be present and `ConfigureHTTP3Server` must advertise the
// second one.

module github.com/nullstyle/http3-zig/interop/external_wt/server_go

go 1.25

require (
	github.com/quic-go/quic-go v0.59.0
	github.com/quic-go/webtransport-go v0.10.1-0.20260509123036-27e20996f86d
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)
