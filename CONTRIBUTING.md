# Contributing to http3-zig

Thanks for your interest in http3-zig.

## Project status

http3-zig is **pre-1.0**. It implements HTTP/3 (RFC 9114), QPACK
(RFC 9204), HTTP Datagrams (RFC 9297), Extended CONNECT (RFC 9220),
HTTP/3 Priority + PRIORITY_UPDATE (RFC 9218), WebSocket-over-H3,
CONNECT-UDP / MASQUE (RFC 9298), and WebTransport-over-HTTP/3
(draft-ietf-webtrans-http3-15) on top of sister project
[`quic-zig`](https://github.com/nullstyle/quic-zig). The public API
may still churn — treat 0.x releases as potentially breaking.

See [`README.md`](README.md) for an overview, [`CHANGELOG.md`](CHANGELOG.md)
for what has shipped, and [`ROADMAP.md`](ROADMAP.md) for the broader
phase-by-phase plan.

## Building

http3-zig pins its toolchain via [`mise`](https://mise.jdx.dev/).
The project file at [`mise.toml`](mise.toml) installs Zig 0.16.0
plus the project's auxiliary tools.

```sh
mise install
zig build
```

`zig build` produces the library plus the example binaries and the
interop harnesses under `zig-out/bin/`.

## Tests

```sh
zig build test
```

This runs the unit, integration, conformance (RFC-traceable), and
fuzz-smoke suites. The conformance suite anchors normative MUSTs
back to spec sections — run a focused slice with
`zig build conformance -Dconformance-filter='[RFC9114 §4.1]'` for
example.

The seeded fuzz corpus lives under [`fuzz/corpus/`](fuzz/corpus/);
walk every file with `zig build run-fuzz-corpus`. To regenerate
the corpus from `fuzz/seed.zig` after changing it, run
`zig build seed-fuzz-corpus`.

## Interop

The WebTransport interop matrix lives under
[`interop/external_wt/`](interop/external_wt/). It pins two
third-party peers in CI:

- `webtransport-go` (Go, master pseudo-version since draft-15
  support has not yet shipped in a tagged release).
- `pywebtransport` (Python facade over a Rust core, v0.17.1).

The
[`wt-interop-self-test`](.github/workflows/wt-interop-self-test.yml)
workflow brings up the in-tree
[`interop/external_wt/server.zig`](interop/external_wt/server.zig)
echo server on a real UDP socket on every push;
[`wt-interop`](.github/workflows/wt-interop.yml) runs the full
third-party matrix on a weekly schedule (and on manual dispatch).

See [`interop/external_wt/README.md`](interop/external_wt/README.md)
for the full list of pinned peers, local-repro recipes, and
operator notes.

## Commits

- One-line summary, imperative mood, ~72 chars or less.
- Optional body explains the *why*, wrapped at ~72 chars.
- Reference RFCs / drafts in the body when relevant (e.g.
  `RFC 9114 §4.1`, `draft-ietf-webtrans-http3-15 §5.5`).
- Keep one logical change per commit.

## Pull requests

- Don't.  This is extensively vibe-coded at the moment and probably
  shouldn't be used by anyone but me.
