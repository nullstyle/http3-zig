// Pinned third-party WebTransport interop server.
//
// webtransport-go v0.12.0 (2026-07-28) is the first TAGGED release on
// the current draft (-16; same codepoints as -15) — it replaced the
// master pseudo-version we carried while tagged releases still spoke
// the old draft-13 numeric codepoint. Release pins keep the leg
// deterministic; bump deliberately with the draft pin.
//
// To verify a pin speaks the current draft, look for these constants
// in the resolved webtransport-go module's `protocol.go`:
//
//   const settingsEnableWebtransportDraft06 = 0x2b603742
//   const settingsWebTransportEnabled       = 0x2c7cf000
//
// Both must be present and `ConfigureHTTP3Server` must advertise the
// second one.

module github.com/nullstyle/http3-zig/interop/external_wt/server_go

go 1.25.0

require (
	github.com/quic-go/quic-go v0.61.0
	github.com/quic-go/webtransport-go v0.12.0
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
