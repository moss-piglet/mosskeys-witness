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
> what is implemented; install and quickstart docs land with the first
> release.

## Releases

Tagged releases ship prebuilt, cosign-signed binaries (macOS + Linux, arm +
x86) with a CycloneDX SBOM, SHA-512 checksums, and SLSA build provenance, and
publish the crate to crates.io via OIDC trusted publishing — see
[RELEASING.md](RELEASING.md) for the supply-chain controls and how to verify a
download.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
