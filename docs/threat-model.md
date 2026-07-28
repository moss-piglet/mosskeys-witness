# mosskeys-witness Threat Model

Status: v0 draft, living document. Reviewed each release; security contact in
`SECURITY.md`.

A witness is a **trust anchor**: its cosignatures are the evidence that detects
(or deters) log split-view attacks. The two catastrophic failures are
(1) cosigning two conflicting checkpoints for one log at the same tree size,
and (2) compromise of the witness signing keys. Everything in this document is
organized around preventing those, then degrading gracefully under everything
else.

## 1. Assets

| Asset | Why it matters |
|-------|----------------|
| Ed25519 secret seed (0x04 cosigner) | Classical interop identity. Theft → attacker cosigns forked views undetectably until key is rotated out of registries. |
| ML-DSA-44 secret seed (0x06 cosigner) | Post-quantum identity. Same impact profile as above; minted **separately** so one compromise does not imply the other. |
| Per-log state (latest verified checkpoint: origin → size, root hash, cosigned note) | Integrity of this state *is* the anti-split-view guarantee. Rollback or corruption → the witness can be tricked into cosigning a fork (SM-02/SM-04 in `spec-conformance.md`). |
| Availability of the HTTP service | Logs stall witnessed checkpoints without cosignatures; monitors lose the retrieval endpoint. (Not a correctness asset: downtime never forges a cosignature.) |
| Clock | Cosignature timestamps must be non-zero, ≤ 2^63−1, and not absurdly future; verifiers may reject future timestamps. |

## 2. Adversaries

- **Malicious or compromised log**: submits forks (same size, different root),
  rewinds (smaller old size), replays, or bikesheds proofs. This is the *design
  case* — the protocol exists to catch it. The witness must reject, never
  cosign, and (MAY) log evidence.
- **Unauthenticated network client**: the spec has no request authentication
  beyond checkpoint signatures. Anyone who can reach the listener can submit
  garbage, probe, or flood.
- **Malicious-but-valid log operator** gaming state: e.g. racing two valid
  checkpoints (N and N+K) to exploit non-atomic check-and-update (the spec's
  worked race example).
- **Local attacker / supply-chain attacker**: reads key files off disk, tampers
  with the state file, or ships a malicious dependency.
- **Passive observer**: learns log origins/sizes the witness tracks (metadata
  privacy; low sensitivity for public logs, noted for completeness).

Non-goals: we do not defend against a fully compromised host (game over for
software key storage — that is what https-bastion/HSM-class deployments are
for, both out of scope for v0 code), and we do not validate log *contents*
(only checkpoint consistency).

## 3. Threats and mitigations

### T1. Split-view cosigning (catastrophic)

*Attack.* A log shows the witness checkpoint B (size N) after it already
cosigned checkpoint A (size N, different root), or races A and B concurrently.

*Mitigations.*
- Single-writer, check-and-update **atomic** per origin: the old-size check,
  consistency verification, state mutation, and fsync happen under one per-log
  lock (SM-01, SM-02). No async gap between check and persist.
- Equal-size root comparison rejects forks with 422 (ST-10); size mismatch
  rejects rewinds with 409 + `text/x.tlog.size` (ST-06).
- Persist-before-respond: the cosignature is never sent for a checkpoint the
  store has not durably recorded (SM-01, SM-05).
- Property test in the conformance suite: under randomized concurrent valid
  submissions, the set of cosigned checkpoints for one origin is always a
  single chain (no two cosigned heads at one size) (SM-04).

### T2. Signing-key compromise (catastrophic)

*Attack.* Read of the seed files via path traversal in config, world-readable
install, process memory disclosure, or accidental commit.

*Mitigations.*
- `#![forbid(unsafe_code)]` crate-wide; all cryptography delegated to the
  audited `metamorphic-crypto` primitives (same stack as metamorphic-log /
  mosskeys-cli).
- Key files are created/read with `0600` permissions; startup refuses
  group/world-readable key files with a clear error.
- Seeds are loaded once at startup, held in memory only as long as needed, and
  zeroized on drop. No key material in logs, metrics, error messages, or HTTP
  responses (error paths are audited in review).
- The two cosigner keypairs are minted independently (0x04 and 0x06 share no
  seed material), so one file leak does not compromise both identities.
- Config validates that key paths are regular files, not symlinks pointing
  outside expected directories.

### T3. State rollback / corruption

*Attack.* Crash or power loss between check and persist; disk corruption;
attacker with local write access rewinds the state file to re-enable a fork.

*Mitigations.*
- Store writes are write-ahead + `fsync` before the HTTP response is generated
  (SM-05); on startup the store is validated (parse + self-consistency) and a
  corrupt store fails closed (witness refuses to cosign until repaired).
- Crash after persist, before respond: client retries and receives 409 with
  the current size — the witness never double-signs.
- State file format carries the full cosigned note (origin, size, root, log
  signature, our cosignatures), so recovery never invents state.
- sqlite (bundled, single-file, WAL) or append-only file backend; both fsync
  on commit. Documented operator trade-off; sqlite is the default for its
  corruption resistance.

### T4. Denial of service

*Attack.* Unauthenticated floods: huge bodies, >63 proof lines, slow
connections (slowloris), oversized origins, garbage base64, decompression
bombs if a proxy adds encoding.

*Mitigations.*
- Hard request-body cap (default 1 MiB — a checkpoint with 63 proof lines is
  a few KiB) enforced at the HTTP layer before parsing.
- Parser enforces the spec's ≤63 proof-line limit and strict line grammar
  (AC-01…AC-05) with linear-time parsing, no regex, no recursion.
- Per-connection read/write timeouts and a bounded concurrency limit; HTTP
  keep-alive retained (GI-03) but capped.
- No allocation proportional to claimed sizes: sizes are u64s, proofs are
  bounded, checkpoints are size-agnostic byte strings until verified.
- Rate limiting is documented as a reverse-proxy concern (the spec's
  unauthenticated model means protocol-level auth cannot help); the witness
  exposes standard access logs for fail2ban-style tooling.

### T5. Malformed-input parser attacks

*Attack.* Handcrafted notes/proofs/vkeys targeting parser panics, integer
overflow, or pathological Merkle verification cost.

*Mitigations.*
- All parsing via `metamorphic-log`'s checkpoint/note types (fuzzed upstream);
  our own body parser is a line splitter with explicit length checks.
- Consistency-proof verification cost is O(log n) hashes by construction
  (RFC 6962); the 63-line cap bounds it absolutely.
- No panics in request paths: every fallible operation maps to the spec's
  status taxonomy; a panic handler returns 500 without state mutation.

### T6. Clock manipulation / skew

*Attack.* Host clock jumps far future → cosignatures verifiers reject (DoS on
us), or far past → cosignatures that look stale.

*Mitigations.*
- Timestamp sourced from the host clock at signing time; startup warns loudly
  if the clock looks unreasonable (before a build-time floor, or ahead by
  more than an operator-tunable skew).
- Timestamps are informational ordering hints, not correctness inputs: state
  decisions never depend on the wall clock (only on sizes and hashes).

### T7. Supply-chain compromise

*Attack.* Malicious or vulnerable dependency shipped in the binary or on
crates.io.

*Mitigations.* (Mirrors metamorphic-crypto / metamorphic-log / mosskeys-cli.)
- Minimal dependency surface; `cargo-deny` (licenses, bans, advisories) and
  `cargo-audit` in CI, blocking.
- `Cargo.lock` committed; releases built from the locked tree.
- CycloneDX SBOM, SHA-512 checksums, keyless cosign signatures on release
  artifacts, SLSA build provenance, crates.io publish via OIDC trusted
  publishing (no long-lived tokens), reproducible release workflow.
- Signed prebuilt binaries for linux/macOS × arm/x86; Homebrew formula
  generated from the same checksums.

### T8. Misconfiguration

*Attack.* Operator points the witness at the wrong vkey for an origin (cosigns
for an impostor log), reuses one cosigner keypair across multiple witness
names, or runs two witness instances on one state file.

*Mitigations.*
- Config is an explicit (origin, vkey) allowlist — unknown origins are 404 by
  construction, and there is no wildcard.
- Startup cross-checks: derived public keys match the configured witness name;
  duplicate origins are a hard error.
- The store takes an exclusive file lock at startup; a second instance on the
  same state file fails fast instead of silently racing.
- `keygen` prints the exact vkey lines to hand to log operators, with the
  witness name embedded, so copy-paste errors surface as key-id mismatches
  (403 class) rather than silent mis-cosigning.

### T9. Monitoring-prefix information disclosure

*Attack.* Anyone can enumerate witnessed origins via SHA-256(origin) lookups.

*Assessment.* Accepted: origins of public transparency logs are public, the
spec defines the endpoint unauthenticated, and the response contains only data
the log itself publishes. Rate limits from T4 apply. Private logs should not
be registered with a public witness (documented for operators).

## 4. Security invariants (test-anchored)

1. **I1 — No conflicting cosignatures.** For any origin, the witness never
   emits cosignatures for two checkpoints with the same size and different
   roots. (T1; conformance suite property test.)
2. **I2 — No unpersisted cosignatures.** Every 200 response corresponds to a
   durably recorded state transition. (T1/T3; fault-injection test.)
3. **I3 — No key material egress.** Secret bytes appear only in the key files
   and process memory — never in HTTP output, logs, or errors. (T2; log
   scrubbing test + review.)
4. **I4 — Fail closed.** Corrupt state, unreadable keys, duplicate config:
   startup or request fails without cosigning. (T3/T8; integration tests.)
5. **I5 — Spec taxonomy.** Failure responses use exactly the spec's status
   codes, and 409 bodies are `text/x.tlog.size` with the current size. (ST-*;
   conformance suite.)

## 5. Operator hardening guide (summary, expanded in README)

- Run as an unprivileged user; state dir `0700`, key files `0600`.
- Front with a TLS-terminating reverse proxy for rate limiting (the protocol
  itself is plaintext-agnostic; authenticity comes from signatures, not the
  channel).
- Keep NTP disciplined; alert on clock skew.
- Back up the state file — losing it forces re-sync (409-driven) with every
  log but never causes mis-cosigning; losing the *keys* requires registry
  rotation everywhere the vkeys are published.
- To keep key material off the Internet-facing host entirely, deploy behind an
  [https-bastion](https://c2sp.org/https-bastion) (future-work doc link).
