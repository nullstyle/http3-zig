// Pinned third-party WebTransport interop server.
//
// webtransport-go v0.13.0 (2026-08-30) is the latest tagged release on
// the current draft (-16). It updates quic-go to v0.62.0 and queues
// WT_CLOSE_SESSION without blocking on flow control. Release pins keep
// the leg deterministic; bump deliberately with the draft pin.
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

go 1.27.0

require (
	github.com/quic-go/quic-go v0.62.0
	github.com/quic-go/webtransport-go v0.13.0
)

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
