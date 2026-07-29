# mosskeys-witness

A post-quantum-native [C2SP tlog-witness](https://c2sp.org/tlog-witness),
written in Rust (`#![forbid(unsafe_code)]`) on the audited
[`metamorphic-log`](https://github.com/moss-piglet/metamorphic-log) crate.

Every accepted checkpoint is **dual-signed** from two independently minted
keypairs: an Ed25519 (`0x04`) cosignature for interop with today's tooling,
and an ML-DSA-44 (`0x06`) cosignature — the post-quantum type the tlog-witness
spec recommends and no other shipping witness produces.

> **Status: early development.** The protocol-conformance checklist
> ([docs/spec-conformance.md](docs/spec-conformance.md)) and threat model
> ([docs/threat-model.md](docs/threat-model.md)) are the source of truth for
> what is implemented.

## Install

```sh
cargo install mosskeys-witness --locked
```

Use `--locked` so the build uses the versions pinned in the published
`Cargo.lock`. Prebuilt binaries (below) are already built and are unaffected.

On macOS and Linux, Homebrew installs the same prebuilt, signed binary from a
tap:

```sh
brew install moss-piglet/mosskeys-witness/mosskeys-witness
```

The fully-qualified name trusts and installs just that formula (Homebrew 6+
requires explicit trust for third-party taps).

Prebuilt, signed binaries for macOS (arm64/x64) and Linux (x64/arm64) are
attached to every
[GitHub Release](https://github.com/moss-piglet/mosskeys-witness/releases),
each with a CycloneDX SBOM, `SHA512SUMS`, a cosign signature, and SLSA build
provenance. Verify a download before running it:

```sh
# checksum
sha512sum -c SHA512SUMS

# cosign signature (keyless; the identity is the GitHub Actions release workflow)
cosign verify-blob \
  --bundle mosskeys-witness-<version>-<target>.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/moss-piglet/mosskeys-witness/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mosskeys-witness-<version>-<target>.tar.gz

# build provenance
gh attestation verify mosskeys-witness-<version>-<target>.tar.gz \
  --repo moss-piglet/mosskeys-witness
```

See [RELEASING.md](RELEASING.md) for the full supply-chain controls.

## Quickstart

Five minutes from zero to a running dual-signing witness.

```sh
# 1. Mint the witness identity — two INDEPENDENTLY generated keypairs:
#    Ed25519 (0x04) for interop with today's tooling, and ML-DSA-44 (0x06),
#    the cosignature spec's recommended post-quantum type. Fully offline.
#    Writes two seed files (0600, never overwritten) and prints only the
#    public C2SP vkey lines.
mosskeys-witness keygen --name witness.example/w1 --out-dir ./keys

# 2. Configure: copy config.example.toml, set name/listen/state_file/[keys],
#    and add one [[log]] stanza per log you cosign — the (origin, vkeys)
#    allowlist. A mosskeys deployment publishes its relay set as a
#    machine-readable feed of exactly the origins + checkpoint vkeys to follow:
curl -s https://mosskeys.com/api/witness/logs

# 3. Run. Every startup hard-check is enforced first: owner-only seed files
#    whose derived vkeys match the configured name, no duplicate origins,
#    state file exclusive-locked and replayed. Any failure is fatal (fail
#    closed). Both cosigner vkeys are re-printed in the startup banner.
mosskeys-witness run --config ./witness.toml
```

Then **register** with every log you cosign. On a mosskeys deployment, apply
at [mosskeys.com/witness/apply](https://mosskeys.com/witness/apply) with the
cosigner name, your submission prefix URL, and BOTH printed vkeys — the
registry accepts the `0x06` ML-DSA-44 vkey alongside the classical `0x04` one.
After review and activation, checkpoints start arriving at your endpoint
automatically; your operator identity joins the public
[witness directory](https://mosskeys.com/witnesses).

## Releases

Tagged releases ship prebuilt, cosign-signed binaries (macOS + Linux, arm +
x86) with a CycloneDX SBOM, SHA-512 checksums, and SLSA build provenance, and
publish the crate to crates.io via OIDC trusted publishing — see
[RELEASING.md](RELEASING.md) for the supply-chain controls and how to verify a
download.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
