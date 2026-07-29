# Releasing mosskeys-witness

A single `v*` tag ships two things:

1. **crates.io publish**, so `cargo install mosskeys-witness` works (it installs
   the `mosskeys-witness` binary).
2. **Prebuilt, signed binaries** attached to the GitHub Release for every
   supported platform (macOS arm/x86, Linux arm/x86), plus a CycloneDX SBOM and
   `SHA512SUMS`.

The pipeline follows the supply-chain house style of `metamorphic-crypto`,
`metamorphic-log`, and `mosskeys-cli`: hand-written workflows (no cargo-dist),
third-party actions pinned to a full commit SHA, OIDC trusted publishing (no
long-lived registry token), keyless cosign signatures, and SLSA
build-provenance attestations.

## Versioning

Semantic versioning and conventional commits. The Git tag drives the release
and must match `Cargo.toml` (`v0.1.0` and `version = "0.1.0"`). The `guard`
job fails fast if they disagree.

## Cutting a release

1. Bump `version` in `Cargo.toml`.
2. Run `cargo build` to update `Cargo.lock`, then commit.
3. Tag and push:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The `Release` workflow runs the quality gates, builds the cross-platform
   binary matrix (signing and attesting each artifact), aggregates the SBOM,
   `SHA512SUMS`, and GitHub Release, and publishes to crates.io.

Re-running a partially failed release is safe: the crates.io publish step is
idempotent (an already-published version is skipped, not treated as an error).

## Sibling crates and crates.io (dev vs release)

During local co-development `Cargo.toml` pins `metamorphic-log` to the sibling
working tree (`../metamorphic-log`) with a `path` key. (`metamorphic-crypto`
is a pure crates.io dependency here, so there is still exactly ONE crypto core
in the graph.)

That path does not exist on a CI runner and must not influence a published
release. Before any build or publish, CI runs
[`.github/scripts/decouple-from-siblings.sh`](.github/scripts/decouple-from-siblings.sh),
which strips the `path` key and deletes the source-less `metamorphic-log`
entry from `Cargo.lock`, leaving the pinned crates.io version requirement
(`=0.4.0`). The workflow then re-fetches (`cargo fetch`) so `--locked` stays
honest for the rest of the tree.

## Supply-chain controls

| Control | Where |
|---|---|
| `cargo fmt --check`, `clippy -D warnings`, tests | CI and release `guard` |
| MSRV (1.85) `--locked` build | CI `msrv` |
| `cargo deny` (licenses/advisories/bans) | CI `deny` |
| RustSec advisory scan (`cargo audit`) | CI `audit` and release `guard` |
| CycloneDX SBOM | release `sbom.json` |
| SHA-512 checksums | release `SHA512SUMS` |
| Keyless cosign `sign-blob --bundle` (per artifact and SBOM) | release |
| SLSA build-provenance attestation | release (per artifact) |
| crates.io OIDC trusted publish (protected `release` env) | release `publish` |

## Verifying a download

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

## One-time setup

Before the first tag:

1. Create a `release` environment on the GitHub repo (Settings → Environments),
   optionally with required reviewers / protected branches.
2. Configure crates.io trusted publishing for the `mosskeys-witness` crate:
   publisher `moss-piglet/mosskeys-witness`, workflow `release.yml`,
   environment `release` (crates.io → crate Settings → Trusted Publishing; a
   not-yet-published crate name can be pre-registered from the crates.io
   account Trusted Publishing page).

No long-lived secrets are stored anywhere: cosign is keyless (GitHub OIDC),
and the crates.io token is minted per-run from the OIDC exchange.

## Homebrew

A Homebrew tap (`brew install mosskeys-witness`) is planned and reuses the
signed tarballs produced here; the `update-tap` job lands with the tap task
(see the NOTE in [`.github/workflows/release.yml`](.github/workflows/release.yml)).
