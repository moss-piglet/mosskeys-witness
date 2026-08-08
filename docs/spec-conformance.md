# C2SP tlog-witness Conformance Checklist

This document tracks `mosskeys-witness` against the normative requirements of
[C2SP tlog-witness](https://c2sp.org/tlog-witness) (`tlog-witness.md @ main`),
with its dependencies [tlog-cosignature](https://c2sp.org/tlog-cosignature),
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint@v1.0.0),
[signed-note](https://c2sp.org/signed-note@v1.0.0), and
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) §2.1.

Every row is a spec requirement. The **Status** column is one of:

- ✅ implemented and covered by a conformance test
- 🟡 implemented, not yet conformance-tested
- ⬜ not yet implemented
- ➖ not applicable / deliberately out of scope (rationale given)

The conformance tests live in `tests/conformance/` (task 7); each test cites
the checklist ID it covers, e.g. `// covers AC-04`.

## 1. HTTP interface — general

| ID | Level | Requirement | Spec section | Status |
|----|-------|-------------|--------------|--------|
| GI-01 | MUST | `add-checkpoint` is served at `POST <submission prefix>/add-checkpoint` | HTTP Interface | ✅ |
| GI-02 | MUST | The request is an HTTP POST (reject other methods) | add-checkpoint | ✅ |
| GI-03 | SHOULD | Support HTTP keep-alive to reduce latency/load | HTTP Interface | ✅ |
| GI-04 | MAY | Submission and monitoring prefixes MAY share a value (we serve both from one listener) | HTTP Interface | ✅ |
| GI-05 | MAY | Operators MAY front the witness with an https-bastion; out of scope for v0 code, documented only | HTTP Interface | ➖ v0 |

Prefix note: the spec defines a witness by its name plus submission and
monitoring URL prefixes, and the ecosystem registration convention derives
those prefixes from the witness name itself (`https://` + name, e.g.
`https://witness.example/w1`). mosskeys-witness therefore serves the full
API **under the configured name's path component** (`/w1` here) AND **at
the listener root**, so name-derived and root-registered prefixes reach the
same handlers with the same taxonomy (see `config::prefix_from_name`;
conformance tests in `tests/conformance/gi.rs`). A host-only name serves at
the root only. A name whose path component is not a plain static URL path
(empty segments, or the router's `{`/`}`/`*` syntax characters) is a fatal
config error (fail closed, I4).

## 2. add-checkpoint — request parsing

| ID | Level | Requirement | Spec section | Status |
|----|-------|-------------|--------------|--------|
| AC-01 | MUST | Body is: old-size line, zero or more consistency-proof lines, an empty line, then a checkpoint | add-checkpoint | ✅ |
| AC-02 | MUST | Every line terminated by U+000A | add-checkpoint | ✅ |
| AC-03 | MUST | Old-size line is `old` + 0x20 + decimal tree size, no leading zeroes (except `0` itself) | add-checkpoint | ✅ |
| AC-04 | MUST | Each proof line is one base64-encoded hash | add-checkpoint | ✅ |
| AC-05 | MUST NOT (client) | Reject (>63 proof lines) gracefully; we treat as 400 malformed | add-checkpoint | ✅ |
| AC-06 | MAY | Checkpoint may carry multiple signatures; all are parsed, unknown ones ignored | add-checkpoint | ✅ |

## 3. add-checkpoint — status taxonomy (in evaluation order)

| ID | Level | Requirement | Status code | Status |
|----|-------|-------------|-------------|--------|
| ST-01 | MUST | Unknown checkpoint origin → 404 | `404 Not Found` | ✅ |
| ST-02 | MUST | No signature from a trusted key for the origin → 403 | `403 Forbidden` | ✅ |
| ST-03 | MUST | Signature line's key name **and** key ID match a trusted key but the signature fails to verify → 403 (note is malformed per signed-note) | `403 Forbidden` | ✅ |
| ST-04 | MUST | Signatures from unknown keys are ignored (never trusted, never fatal by themselves) | — | ✅ |
| ST-05 | MUST | `old size > checkpoint size` → 400 | `400 Bad Request` | ✅ |
| ST-06 | MUST | `old size` ≠ size of latest cosigned checkpoint for the origin (or ≠ 0 if none) → 409, body = decimal latest size + `\n`, `Content-Type: text/x.tlog.size` | `409 Conflict` | ✅ |
| ST-07 | MUST | Checkpoint size 0 with root hash ≠ RFC 6962 §2.1 empty-tree root (SHA-256 of empty string) → 422 | `422 Unprocessable Entity` | ✅ |
| ST-08 | MUST | `old size == 0` but consistency proof is non-empty → 422 | `422 Unprocessable Entity` | ✅ |
| ST-09 | MUST | Consistency proof does not verify per RFC 6962 §2.1.2 → 422 | `422 Unprocessable Entity` | ✅ |
| ST-10 | MUST | `old size == checkpoint size` but root hashes differ → 422 | `422 Unprocessable Entity` | ✅ |
| ST-11 | MAY | Origin known + signature valid but consistency check failed → request MAY be logged as misbehavior evidence; checkpoint MUST NOT be cosigned | — | ✅ (stderr evidence line machine-asserted in `st::st_11_…` — subprocess test) |
| ST-12 | MUST | All checks pass → update latest-checkpoint record, respond 200 with one or more note signature lines, each starting `—` (U+2014), ending `\n` | `200 Success` | ✅ |

Evaluation-order note: the spec fixes origin lookup (404) before signature
checks (403) before size/consistency checks (400/409/422). Our handler
implements the checks in exactly this order so clients can rely on the
taxonomy to diagnose failures (and so the size-discovery flow in ST-06
works before any proof verification).

## 4. add-checkpoint — cosignature production

| ID | Level | Requirement | Spec section | Status |
|----|-------|-------------|--------------|--------|
| CS-01 | MUST | Response signatures are tlog-cosignatures from the witness key(s) on the checkpoint | add-checkpoint | ✅ |
| CS-02 | SHOULD | Witnesses SHOULD use ML-DSA-44 cosignatures | add-checkpoint | ✅ |
| CS-03 | MUST | For subtree-capable formats (0x06): whole-tree cosignature — `start == 0`, `end == checkpoint size` | add-checkpoint | ✅ |
| CS-04 | MUST NOT | Cosignature timestamp MUST NOT be zero | add-checkpoint | ✅ |
| CS-05 | MUST | (tlog-cosignature) timestamp is POSIX seconds, ≤ 2^63−1, big-endian in the `timestamped_signature` blob | Format | ✅ |
| CS-06 | MUST | (tlog-cosignature) Ed25519 signed message = `cosignature/v1\n` + `time <decimal>\n` + whole note body incl. final newline, excl. signature lines | Ed25519 signed message | ✅ |
| CS-07 | MUST | (tlog-cosignature) ML-DSA-44 signed message = `cosigned_message` struct: label `"subtree/v1\n\0"`, cosigner name, timestamp, log origin, start, end, root hash | ML-DSA-44 signed message | ✅ |
| CS-08 | MUST | Key IDs: `SHA-256(name ‖ "\n" ‖ 0x04 ‖ 32-byte pk)[:4]` (Ed25519) / `SHA-256(name ‖ "\n" ‖ 0x06 ‖ 1312-byte pk)[:4]` (ML-DSA-44) | Format | ✅ |
| CS-09 | MUST | vkey encodings: sig type `0x04` + 32-byte pk; sig type `0x06` + 1312-byte pk | Format | ✅ |
| CS-10 | SHOULD | Dual-signing policy: every accepted checkpoint gets **both** a `0x04` Ed25519 and a `0x06` ML-DSA-44 cosignature, from **separately minted** keypairs (project differentiator; stricter than the spec baseline) | — | ✅ |

## 5. State management & atomicity

| ID | Level | Requirement | Spec section | Status |
|----|-------|-------------|--------------|--------|
| SM-01 | MUST | Persist the new checkpoint **before** responding | add-checkpoint | ✅ |
| SM-02 | MUST | Old-size check and state update are atomic per origin (no check-then-update race; see spec's A/B rollback example) | add-checkpoint | ✅ |
| SM-03 | MUST | Only the latest checkpoint per origin is required to be tracked (we store exactly that, plus the cosigned note for serving) | Introduction | ✅ |
| SM-04 | — | Never cosign two conflicting checkpoints at one size (consequence of ST-06 + ST-10 + SM-02; stated as its own invariant and property-tested) | — | ✅ (adversarial fork-attempt matrix + concurrent-race test in `sm.rs`, I1) |
| SM-05 | — | Crash safety: a crash after persist but before respond is safe — the client retries, gets 409 with the now-current size, and can rebase | — | ✅ (crash-retry flow: restart, 409, rebase in `sm.rs`, I2) |

## 6. Monitoring prefix

| ID | Level | Requirement | Spec section | Status |
|----|-------|-------------|--------------|--------|
| MP-01 | SHOULD | Serve a recent checkpoint for each cosigned log at `GET <monitoring prefix>/<origin hash>/checkpoint` | Monitor Retrieval | ✅ |
| MP-02 | MUST | `<origin hash>` = lowercase hex of SHA-256 over the log's origin (the checkpoint origin line's content, without its trailing newline) | Monitor Retrieval | ✅ |
| MP-03 | MUST | Response body is a checkpoint including the witness cosignature(s) returned from add-checkpoint **and** the log signature(s) the witness verified | Monitor Retrieval | ✅ |
| MP-04 | MUST | Never cosigned a checkpoint for that origin hash → 404 | Monitor Retrieval | ✅ |
| MP-05 | SHOULD NOT | Do not delay checkpoint updates by more than one hour (we serve synchronously from the same store, so delay is ~0) | Monitor Retrieval | ✅ (same-store synchronous serving is the mechanism) |

## 7. Out of scope for v0 (documented as future work)

| Item | Spec status | v0 decision |
|------|-------------|-------------|
| `POST <submission prefix>/sign-subtree` | OPTIONAL | Not implemented in v0. The endpoint returns `404 Not Found` (unimplemented route). ML-DSA-44 keypairs are minted per-cosigner (not per-tree), keeping a future subtree implementation unblocked. |
| https-bastion deployment mode | MAY | Documentation-only pointer for operators who do not want key material on an Internet-facing host. |
| Request authentication | — | None beyond checkpoint signature validation, exactly as the spec designs it. Rate limiting / body caps are operator-level hardening, not protocol features. |

## 8. Interop targets

| Target | What conformance means here | Status |
|--------|------------------------------|--------|
| [omniwitness](https://github.com/transparency-dev/witness) | A log configured for omniwitness can point the same `add-checkpoint` traffic at mosskeys-witness unmodified; our `0x04` line verifies against omniwitness-compatible verifiers. Config file is a (origin, vkey) list in the same spirit so operators can multi-home both witnesses on the same logs. | ✅ live test (task 7): gated test + `x/mod`-based verifier, run green (`tests/conformance/interop.rs`, `scripts/interop/omniwitness/`; setup in docs/interop.md) — a generic-origin log's served checkpoint verifies, the `0x06` line ignored as an unknown key |
| [sigsum](https://git.glasklar.is/sigsum) | Our `0x04` cosignatures verify with sigsum's note verification. | ✅ live test (task 7): gated test + sigsum-go v0.14.1 `pkg/checkpoint` verifier, run green (`tests/conformance/interop.rs`, `scripts/interop/sigsum/`; setup in docs/interop.md) — a sigsum-convention-origin log's served checkpoint verifies end-to-end (log signature + `0x04` by key + CS-08 key id) |
| mosskeys dev deployment | mosskeys' witness registry accepts our `0x06` vkey, submits checkpoints, verifies both returned cosignatures, and counts them toward witnessed quorum (as an independent, non-mosskeys-operated witness). | ⬜ dogfood (task 10) |
