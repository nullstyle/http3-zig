# Dynamic QPACK Fixtures

This directory contains exact-byte dynamic-table QPACK vectors for http3-zig's
transport-free interop runner and for external peer harnesses.

The Go peer in `../qpack_quic_go` covers the shared static/literal/Huffman
profile. Since `github.com/quic-go/qpack` v0.6.0 does not expose dynamic-table
encoder/decoder stream support, these fixtures pin the dynamic-table contract
using RFC 9204 Appendix B bytes that another implementation can mirror directly.
`fixtures.json` is the implementation-neutral exchange format; it is rendered
from `fixtures.zig` and checked by the `qpack-dynamic-interop` test target so
the committed JSON cannot drift from the bytes the Zig runner exercises.

Run and export them with:

```sh
zig build qpack-dynamic-interop
zig build qpack-dynamic-fixtures
```

`fixtures.zig` records:

- encoder stream instruction bytes and resulting dynamic table snapshots;
- dynamic field-section bytes and decoded fields;
- decoder stream feedback bytes for section acknowledgments, insert count
  increments, and stream cancellations.
- negative vectors for truncated encoder streams, over-capacity instructions,
  invalid dynamic references, not-ready Required Insert Count values, and
  malformed decoder feedback.

`fixtures.json` records the same corpus as JSON:

- byte sequences are lowercase hex strings;
- encoder instructions and decoder feedback are represented semantically as
  tagged objects;
- table snapshots use absolute indices plus an explicit
  `absent_absolute_indices` list for eviction checks;
- `expected_error` values are the http3-zig error tag names observed by the
  in-tree runner.
