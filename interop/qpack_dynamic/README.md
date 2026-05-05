# Dynamic QPACK Fixtures

This directory contains exact-byte dynamic-table QPACK vectors for null3's
transport-free interop runner.

The current Go peer in `../qpack_quic_go` remains useful for the shared
static/literal/Huffman profile, but `github.com/quic-go/qpack` v0.6.0 does not
expose dynamic-table encoder/decoder stream support. These fixtures therefore
pin the dynamic contract in null3 now, using RFC 9204 Appendix B bytes that a
future peer can mirror directly.

Run them with:

```sh
zig build qpack-dynamic-interop
```

`fixtures.zig` records:

- encoder stream instruction bytes and resulting dynamic table snapshots;
- dynamic field-section bytes and decoded fields;
- decoder stream feedback bytes for section acknowledgments, insert count
  increments, and stream cancellations.
- negative vectors for truncated encoder streams, over-capacity instructions,
  invalid dynamic references, not-ready Required Insert Count values, and
  malformed decoder feedback.
