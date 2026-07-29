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
2. Bootstrap crates.io. Trusted publishing can only be configured on an
   ALREADY-published crate (per the crates.io docs: "initial publish requires
   an API token"), so the first publish is manual:
   1. Create a short-lived API token (crates.io → Account Settings → API
      Tokens), `cargo publish --locked` from a clean checkout, then DELETE the
      token immediately. (`cargo publish` strips the `path` key from the
      `metamorphic-log` dep and publishes against the `=0.4.0` version
      requirement, so no decouple step is needed locally.)
   2. Configure trusted publishing on the now-existing crate: crate Settings
      → Trusted Publishing → Add → GitHub: repository owner `moss-piglet`,
      repository name `mosskeys-witness`, workflow filename `release.yml`,
      environment `release`.
   From then on the tag-driven `publish` job mints OIDC tokens; the manual
   step is idempotent-skipped on re-runs ("already exists on crates.io").

No long-lived secrets are stored anywhere: cosign is keyless (GitHub OIDC),
and the crates.io token is minted per-run from the OIDC exchange. (The Homebrew
tap below has its own one-time setup.)

## Homebrew

Shipped as a tap. `brew install mosskeys-witness` installs the
`mosskeys-witness` binary from the signed GitHub Release tarball (the prebuilt
artifact, not a from-source build), so Homebrew users get the same
SBOM-tracked, cosign-signed, provenance-attested binary as a direct download.

- tap repo: `moss-piglet/homebrew-mosskeys-witness`
- formula: `Formula/mosskeys-witness.rb` (class `MosskeysWitness`)
- install:

  ```sh
  # Recommended: the fully-qualified name trusts and installs just this formula
  # (Homebrew 6+ requires explicit trust for third-party taps).
  brew install moss-piglet/mosskeys-witness/mosskeys-witness

  # Or tap first, then trust the formula before the short name resolves:
  brew tap moss-piglet/mosskeys-witness
  brew trust --formula moss-piglet/mosskeys-witness/mosskeys-witness
  brew install mosskeys-witness
  ```

The formula is regenerated on every `v*` tag by the release workflow's
`update-tap` job, which runs
[`.github/scripts/render-homebrew-formula.sh`](.github/scripts/render-homebrew-formula.sh)
against the freshly published tarballs (computing SHA-256, since Homebrew requires
it while the release standardizes on SHA-512) and pushes the result to the tap
repo. The canonical copy of the current formula also lives in-repo at
[`packaging/homebrew/mosskeys-witness.rb`](packaging/homebrew/mosskeys-witness.rb);
refresh it from the tap after each release (until the first tag it holds
placeholder checksums and is the seed for the tap repo).

### Tap security model

`brew install` trusts only the formula's `url` + `sha256`; it does not run
cosign, the SBOM, or the SLSA attestation. Write access to the tap is therefore
release-critical, so the tap is hardened the same way as this repo, with one
adjustment for automation:

- `main` ruleset: block deletion and force-push, require signed commits, and
  require a reviewed PR (1 approval). Human changes always go through review.
- The release automation is a **GitHub App** (contents:write, installed on ONLY
  the tap repo) added as a **bypass actor** on that ruleset, so `update-tap` can
  push the formula bump directly while humans cannot.
- `update-tap` mints a **short-lived** App installation token at runtime
  (auto-expires ~1h, scoped to the single tap repo). No long-lived cross-repo PAT
  is stored anywhere. The App credentials live in the protected `release`
  environment, so only the tag-triggered release job can mint a token.
- Enable secret scanning + push protection and Dependabot on the tap, and keep
  org write access least-privilege.

**App decision: a NEW GitHub App per tap, not the mosskeys-cli tap App
reused.** An App's private key can mint an installation token for EVERY repo
the App is installed on. Reusing the `homebrew-mosskeys-cli` App would mean the
private key stored in this repo's `release` environment could also write to the
CLI tap (and vice versa) — widening the blast radius of either repo's stored
credential beyond its own tap. A dedicated App (installed on ONLY
`homebrew-mosskeys-witness`) keeps the credential's blast radius exactly one
tap repo, at the cost of one more App registration and key rotation.

One-time setup, before the first tag that should update the tap:

1. Create the tap repo `moss-piglet/homebrew-mosskeys-witness` with a `Formula/`
   directory and seed `Formula/mosskeys-witness.rb` (copy
   `packaging/homebrew/mosskeys-witness.rb`).
2. Register a GitHub App (owner `moss-piglet`) with repository permission
   **Contents: Read and write**, generate a private key, and install the App on
   ONLY `homebrew-mosskeys-witness`.
3. Add two secrets to the `release` environment of `moss-piglet/mosskeys-witness`:
   `HOMEBREW_TAP_APP_ID` (the App's numeric ID) and `HOMEBREW_TAP_APP_PRIVATE_KEY`
   (the full `.pem` contents).
4. On the tap repo, create the `main` ruleset above and add the App as a bypass
   actor; enable secret scanning + push protection and Dependabot.
