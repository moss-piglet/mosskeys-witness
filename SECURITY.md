# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/moss-piglet/mosskeys-witness/security/advisories/new)
- **Email**: security@mosspiglet.dev

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `mosskeys-witness` crate: the HTTP witness service
(add-checkpoint, monitoring prefix), the per-log state store, and the keygen
tooling.

The cryptographic core lives in [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto)
and [`metamorphic-log`](https://github.com/moss-piglet/metamorphic-log); report
issues in the primitives there.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Security Design

- The witness never cosigns two conflicting checkpoints at one tree size: the
  old-size check, consistency verification, and state update are atomic per
  log, and state is persisted before any cosignature is sent
  (`docs/spec-conformance.md` SM-01…SM-05).
- Signing keys (Ed25519 + ML-DSA-44, independently minted) are read from
  `0600` files at startup, never logged, never sent over the wire, and
  zeroized on drop.
- Fail closed: corrupt state, unreadable keys, or duplicate configuration
  abort startup or the request — never produce a cosignature.
- Supply chain: releases are built `--locked`, scanned with `cargo audit` and
  `cargo deny`, ship a CycloneDX SBOM and `SHA512SUMS`, and are signed with
  keyless cosign plus a SLSA build-provenance attestation. See
  [RELEASING.md](RELEASING.md) to verify a download.

The full analysis lives in [`docs/threat-model.md`](docs/threat-model.md).
