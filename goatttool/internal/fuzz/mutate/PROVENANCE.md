# Provenance

`mutator.go` in this directory is adapted from
[dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz), file
`go-fuzz/mutator.go`, at commit
[`e577bee`](https://github.com/dvyukov/go-fuzz/commit/e577bee5275a4f29d6c0b1f99d4f3b14a37b9c79)
(latest as of 2026-06-01).

Upstream is Apache 2.0; the LICENSE text is preserved at the top of the
vendored file.

## Changes from upstream

- Package renamed from `main` (it was a go-fuzz-internal file) to `mutate`.
- Random source: replaced `internal/pcg.Rand` with stdlib `math/rand`.
  Helpers `bool()`/`exp2()` re-implemented on top of `rand.Rand`. The
  mutation distributions are unchanged.
- Removed `ROData` parameter and its corpus-weighting machinery
  (`runningScoreSum`, depth tracking, etc.). The engine drives parent
  selection; this package just mutates one seed against an optional
  corpus pool used for splice/insert.
- Removed `generate()` (parent selection moved up to the engine).
- Removed literal-insertion / replace-with-literal mutator cases (18, 19).
  We don't carry a string/int literal corpus from source — if we want
  dictionary mutators later, they get added as a separate package
  consumer of `Mutator.Mutate`.
- `MaxInputSize` becomes a `Mutator` config field (`MaxLen`).
- Exported the type and one method (`New`, `Mutate`).

The actual mutation algorithms — bitflip, byte/word/dword arith,
interesting-value substitution, range delete/insert/duplicate/swap, ASCII
digit/number replacement, splice, insert-part-of — are byte-for-byte the
same as upstream.
