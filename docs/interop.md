# Interop live tests (§8)

The §8 rows of `docs/spec-conformance.md` are **live tests**: they run an
external ecosystem verifier against the exact bytes mosskeys-witness serves.
They are gated because they need a Go toolchain and module downloads.

| Row | External verifier | What it proves |
|-----|-------------------|----------------|
| omniwitness | `golang.org/x/mod/sumdb/note` (the signed-note library omniwitness is built on) with a `cosignature/v1` verifier — the same construction transparency-dev's witness package verifies for every checkpoint it countersigns | Our served checkpoint parses as a signed note; the log signature verifies; **our `0x04` cosignature verifies**; the witness key id matches the spec formula (CS-08); our `0x06` line is ignored as an unknown key, exactly as deployed tooling ignores types it does not know |
| sigsum | `sigsum.org/sigsum-go` v0.14.1 `pkg/checkpoint` (`FromASCII`, `Verify`, `CosignatureLinesFromASCII`, `VerifyCosignatureByKey`, `NewWitnessKeyId`) | sigsum-go parses our checkpoint, verifies the log signature, **verifies our `0x04` cosignature by key**, and its witness key-id formula agrees with our vkey (CS-08). (Its `ContentTypeTlogSize` constant is byte-identical to our 409 content type, pinned in the conformance suite's ST-06 test.) |

The tests drive the real `mosskeys-witness` binary: submit a checkpoint over
loopback TCP, fetch the cosigned note from the monitoring prefix, and hand
those exact bytes to the Go verifier. Nothing is mocked.

## One-time setup

1. Install a Go toolchain (1.23+): <https://go.dev/dl/> or `brew install go`.
2. Resolve the verifier modules (writes `scripts/interop/go.sum`):

   ```sh
   cd scripts/interop && go mod tidy
   ```

   This downloads `golang.org/x/mod` and `sigsum.org/sigsum-go` via the
   public Go module proxy. If `go mod tidy` asks for a newer toolchain, let
   it (Go ≥1.21 auto-downloads toolchains).

## Run

```sh
MOSSKEYS_WITNESS_INTEROP=1 cargo test --locked --test conformance interop -- --nocapture
```

Without the env var both tests skip with a pointer here. With it, each test
asserts the verifier exits 0 and prints its `OK:` line — a failed
verification fails the test, so flipping a §8 row to ✅ requires an actual
green run.

## Notes

- The sigsum verifier is written against the documented
  `sigsum.org/sigsum-go@v0.14.1/pkg/checkpoint` API (pinned in
  `scripts/interop/go.mod`). It has not yet been compiled in this repo's CI;
  if a future sigsum-go changes that API, pin or adapt in
  `scripts/interop/sigsum/main.go`.
- Fuller manual flows (not gated tests):
  - **omniwitness multi-homing**: our config is a plain `(origin, vkey)`
    allowlist in the same spirit as omniwitness's, so one log fleet can list
    the same logs in both witnesses' configs and submit the same
    `add-checkpoint` traffic to both, unmodified.
  - **sigsum policy**: add our `0x04` vkey to a sigsum witness policy and
    verify proofs of logging with `sigsum-verify` once a sigsum log is
    configured to use mosskeys-witness.
