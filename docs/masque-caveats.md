# MASQUE (CONNECT-UDP) caveats

The `Masque*` / `ConnectUdp*` surface is marked **Experimental
(Unstable-with-SLA)** in [API_STABILITY.md](API_STABILITY.md). This document
says exactly what that means for MASQUE, so you can decide whether to build on
it.

## What it is

http3-zig implements the **framing** for CONNECT-UDP — the MASQUE method for
tunneling UDP over HTTP (**RFC 9298**), carried by the **Capsule Protocol**
(**RFC 9297**) over Extended CONNECT and HTTP Datagrams. Concretely, the
module owns:

- Request classification (is this an Extended CONNECT for `connect-udp`?) and
  target-path construction / parsing (`ConnectUdpTarget`).
- The Context ID 0 UDP payload codec (`encodeUdpPayload` and the datagram
  helpers) for the datagram fast path.
- Capsule handling on the CONNECT stream, including a registry for extension
  capsules (`MasqueCapsuleRegistry`, `MasqueExtensionCapsule`) and context IDs
  (`MasqueContextRegistry`, `MasqueContextIdAllocator`).
- Receiver-side classification and buffering (`ConnectUdpReceiver`,
  `MasquePendingDatagramBuffer`).

The wire formats above are RFC-anchored and round-trip-tested in the
conformance suite. That is the SLA: **the bytes are correct.**

## What it is not

- **Not a proxy.** http3-zig never owns sockets (see the concurrency /
  allocator contract in `src/root.zig`). A working CONNECT-UDP proxy must bind
  its own UDP socket and run the forwarding loop between that socket and the
  tunnel, using the framing helpers here. The library gives you the framing;
  you provide the datapath.
- **Not full MASQUE.** CONNECT-UDP is the only concrete protocol covered.
  CONNECT-IP (RFC 9484) and other MASQUE methods are not implemented.
- **Not a frozen API.** The context/extension-capsule registry surface is the
  part most likely to move as it is exercised against real peers.

## Why "Unstable-with-SLA" rather than "Stable"

The *wire* is anchored on published RFCs, but the *http3-zig API* around it is
still maturing — particularly the extension/context registries and the
receiver buffering knobs. Under the SLA:

- Wire constants and framing stay correct and are covered by tests.
- The **API shape may change at any minor release** (renames, signature
  refinements, registry restructuring). Changes are noted in `CHANGELOG.md`.
- The surface may be withdrawn if it does not earn its keep.

If you embed it, **pin the exact http3-zig version** and treat a version bump
as a review point for this surface. When the API has proven itself against
real CONNECT-UDP peers, individual pieces will graduate to the Stable tier.

## Reassembly reminder

A capsule (RFC 9297) may legally span multiple HTTP/3 DATA frames. Decode
CONNECT-stream DATA through `capsule.Reassembler`
(`http3_zig.CapsuleReassembler`) — push each DATA event, drain complete
capsules — rather than decoding each DATA event independently.
