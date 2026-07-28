//! The add-checkpoint protocol core: request parsing, the spec's status
//! taxonomy, and dual cosignature production — everything except the HTTP
//! plumbing (which lives in `crate::server`).
//!
//! Conformance rows covered here: AC-01…AC-06 (request grammar), ST-01…ST-12
//! (status taxonomy, in the spec's evaluation order), CS-01…CS-10
//! (cosignature production), SM-01/SM-02 (persist-before-respond and atomic
//! check-and-update, via one [`Store::update`] call per submission).
//!
//! The wire flow for `POST <submission prefix>/add-checkpoint`:
//!
//! 1. [`parse_request`] splits the body into the `old <size>` line, ≤63
//!    base64 consistency-proof lines, and the signed checkpoint (a
//!    signed-note). Grammar violations are `400` ([`Reject::Malformed`]).
//! 2. [`Witness::add_checkpoint`] applies the taxonomy in the spec's exact
//!    evaluation order: `404` unknown origin → `403` signature failure →
//!    `400` old size above checkpoint size → `409` stale old size (with a
//!    `text/x.tlog.size` body) → `422` consistency failures → `200`.
//! 3. Only then are both cosignatures minted — `0x04` Ed25519 and `0x06`
//!    ML-DSA-44 from independently loaded seeds — inside the single
//!    [`Store::update`] closure, so the stored note carries them (MP-03) and
//!    the response is only built after append+fsync (SM-01).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::merkle;
use metamorphic_log::note::{self, Signature, SignedNote, VerifierKey};

use crate::config::Config;
use crate::keygen::{self, KeygenError, LoadedKey, Suite};
use crate::store::{LogState, Store, StoreError, UpdateError};

/// Maximum consistency-proof lines the spec allows (AC-05).
pub const MAX_PROOF_LINES: usize = 63;

/// A parsed `add-checkpoint` request body, ready for the taxonomy.
#[derive(Debug)]
pub struct ParsedRequest {
    /// The `old <size>` line's tree size (AC-03).
    pub old_size: u64,
    /// The decoded consistency-proof hashes (each exactly 32 bytes, AC-04).
    pub proof: Vec<Vec<u8>>,
    /// The signed checkpoint as a note (body + signature lines).
    pub note: SignedNote,
    /// The checkpoint body parsed (origin, size, root hash, extensions).
    pub checkpoint: Checkpoint,
}

/// Parse an `add-checkpoint` request body byte-for-byte per AC-01…AC-06:
///
/// ```text
/// old <decimal size, no leading zeroes>\n
/// <base64 hash>\n            (0..=63 of these)
/// \n
/// <checkpoint body>\n
/// \n
/// — <log name> <signature>\n  (1.. of these; unknown keys allowed, AC-06)
/// ```
///
/// Strict and linear: one left-to-right pass, no regex, no recursion, no
/// allocation proportional to anything but the actual body (T4/T5). Every
/// grammar violation is a `400` ([`Reject::Malformed`]) — malformed input is
/// pre-taxonomy: the spec's status order can only start once the origin is
/// known.
pub fn parse_request(body: &str) -> Result<ParsedRequest, Reject> {
    // AC-02: every line terminates in U+000A, so the body must end with one.
    // (An empty body fails here too.)
    if !body.ends_with('\n') {
        return Err(Reject::Malformed("body is not newline-terminated"));
    }

    // AC-03: the old-size line.
    let (old_line, mut rest) = body
        .split_once('\n')
        .ok_or(Reject::Malformed("missing old-size line"))?;
    let old_size = parse_old_size(old_line)?;

    // AC-01/AC-04/AC-05: proof lines up to the empty separator line; what
    // follows is the checkpoint (a signed note, consumed whole).
    let mut proof = Vec::new();
    let note_text = loop {
        let (line, tail) = rest.split_once('\n').ok_or(Reject::Malformed(
            "missing empty line before the checkpoint",
        ))?;
        if line.is_empty() {
            break tail;
        }
        let hash = B64
            .decode(line)
            .map_err(|_| Reject::Malformed("consistency-proof line is not valid base64"))?;
        if hash.len() != 32 {
            return Err(Reject::Malformed(
                "consistency-proof line must decode to a 32-byte hash",
            ));
        }
        proof.push(hash);
        if proof.len() > MAX_PROOF_LINES {
            return Err(Reject::Malformed("more than 63 consistency-proof lines"));
        }
        rest = tail;
    };
    if note_text.is_empty() {
        return Err(Reject::Malformed("missing checkpoint"));
    }

    // The checkpoint section is a signed note: body, blank line, signature
    // lines (AC-06: multiple signatures parse; unknown ones are ignored at
    // verification, never fatal — ST-04).
    let note = SignedNote::parse(note_text)
        .map_err(|_| Reject::Malformed("checkpoint is not a well-formed signed note"))?;
    let checkpoint = Checkpoint::parse(note.text())
        .map_err(|_| Reject::Malformed("checkpoint body is malformed"))?;

    Ok(ParsedRequest {
        old_size,
        proof,
        note,
        checkpoint,
    })
}

/// The `old <size>` line: `old`, one 0x20, ASCII decimal, no leading zeroes
/// (except `0` itself) — AC-03.
fn parse_old_size(line: &str) -> Result<u64, Reject> {
    let digits = line
        .strip_prefix("old ")
        .ok_or(Reject::Malformed("old-size line must be `old <size>`"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Reject::Malformed("old size is not an ASCII decimal"));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(Reject::Malformed("old size has a leading zero"));
    }
    digits
        .parse()
        .map_err(|_| Reject::Malformed("old size overflows u64"))
}

/// A protocol-level rejection, in the spec's taxonomy (ST-01…ST-10) plus the
/// pre-taxonomy `400` for malformed bodies. The exact HTTP mapping lives in
/// [`Reject::status`] / [`Reject::message`]; the server renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// AC-01…AC-06: the body violated the request grammar → `400`.
    Malformed(&'static str),
    /// ST-01: the checkpoint origin is not in the configured allowlist → `404`.
    UnknownOrigin,
    /// ST-02: no signature from a trusted key for the origin → `403`.
    /// (ST-04: unknown-key signatures were ignored, never fatal.)
    NoTrustedSignature,
    /// ST-03: a signature line whose key name AND key ID match a trusted key
    /// failed to verify (malformed per signed-note) → `403`.
    InvalidTrustedSignature,
    /// ST-05: old size is greater than the checkpoint size → `400`.
    OldSizeExceedsCheckpoint,
    /// ST-06: old size ≠ latest cosigned size (or 0) → `409` with the latest
    /// size as a `text/x.tlog.size` body.
    SizeConflict(u64),
    /// ST-07: size-0 checkpoint whose root is not the empty-tree root → `422`.
    EmptySizeNonEmptyRoot,
    /// ST-08: old size 0 but the consistency proof is non-empty → `422`.
    ProofWithZeroOldSize,
    /// ST-09: the consistency proof does not verify (RFC 6962 §2.1.2) → `422`.
    ConsistencyProofFailed,
    /// ST-10: old size == checkpoint size but the roots differ → `422`.
    SameSizeRootMismatch,
}

impl Reject {
    /// The spec-mandated HTTP status code.
    pub fn status(self) -> u16 {
        match self {
            Reject::Malformed(_) | Reject::OldSizeExceedsCheckpoint => 400,
            Reject::NoTrustedSignature | Reject::InvalidTrustedSignature => 403,
            Reject::UnknownOrigin => 404,
            Reject::SizeConflict(_) => 409,
            Reject::EmptySizeNonEmptyRoot
            | Reject::ProofWithZeroOldSize
            | Reject::ConsistencyProofFailed
            | Reject::SameSizeRootMismatch => 422,
        }
    }

    /// A static, operator-facing one-liner (no request data, no key
    /// material — I3). The 409 body is rendered separately by the server.
    pub fn message(self) -> &'static str {
        match self {
            Reject::Malformed(reason) => reason,
            Reject::UnknownOrigin => "unknown checkpoint origin",
            Reject::NoTrustedSignature => "no signature from a trusted key for this origin",
            Reject::InvalidTrustedSignature => "signature from a trusted key failed to verify",
            Reject::OldSizeExceedsCheckpoint => "old size exceeds checkpoint size",
            Reject::SizeConflict(_) => "old size does not match the latest cosigned size",
            Reject::EmptySizeNonEmptyRoot => "size-0 checkpoint must have the empty-tree root hash",
            Reject::ProofWithZeroOldSize => "old size 0 requires an empty consistency proof",
            Reject::ConsistencyProofFailed => "consistency proof does not verify",
            Reject::SameSizeRootMismatch => {
                "same tree size but different root hash (possible fork)"
            }
        }
    }
}

/// Failures of [`Witness::add_checkpoint`]: a protocol rejection (mapped to
/// the spec's status codes) or an internal failure (`500`).
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("{0:?}")]
    Rejected(Reject),

    #[error("state store failure: {0}")]
    Store(#[from] StoreError),

    #[error(
        "system clock is at or before the UNIX epoch; cannot mint a nonzero \
         cosignature timestamp (CS-04)"
    )]
    Clock,

    #[error("cosignature production failed: {0}")]
    Sign(String),

    #[error("internal invariant violated: {0}")]
    Internal(&'static str),
}

/// Startup failures building a [`Witness`] (fail closed, I4).
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("{0}")]
    Key(#[from] KeygenError),

    #[error("{0}")]
    Store(#[from] StoreError),
}

/// The witness: identity, trusted-log allowlist, and the atomic state store.
pub struct Witness {
    name: String,
    ed25519: LoadedKey,
    mldsa44: LoadedKey,
    logs: HashMap<String, Vec<VerifierKey>>,
    store: Store,
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Witness")
            .field("name", &self.name)
            .field("logs", &self.logs.len())
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Witness {
    /// Build the running witness from a validated config, applying the
    /// remaining startup hard-checks (T2/T8/I4): both seeds load owner-only
    /// and match the configured name, and the state store opens
    /// (exclusive-locked, replayed, fail-closed on corruption).
    pub fn from_config(config: &Config) -> Result<Self, StartupError> {
        let ed25519 = keygen::load_seed(&config.ed25519_seed, Suite::Ed25519, &config.name)?;
        let mldsa44 = keygen::load_seed(&config.mldsa44_seed, Suite::MlDsa44, &config.name)?;
        let store = Store::open(&config.state_file)?;
        let logs = config
            .logs
            .iter()
            .map(|l| (l.origin.clone(), l.vkeys.clone()))
            .collect();
        Ok(Witness {
            name: config.name.clone(),
            ed25519,
            mldsa44,
            logs,
            store,
        })
    }

    /// The witness key name (embedded in every cosignature).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The derived public vkeys of both cosigners, for the startup banner.
    pub fn vkeys(&self) -> [&str; 2] {
        [&self.ed25519.vkey, &self.mldsa44.vkey]
    }

    /// Number of logs in the allowlist (startup banner/diagnostics).
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// The latest cosigned state for `origin` (monitoring prefix, tests).
    pub fn latest(&self, origin: &str) -> Option<LogState> {
        self.store.latest(origin)
    }

    /// Handle one `add-checkpoint` request body end to end, returning the
    /// response body (the two cosignature lines) on success.
    ///
    /// The taxonomy is applied in the spec's exact evaluation order
    /// (ST-01 → ST-10); see the variant docs on [`Reject`].
    pub fn add_checkpoint(&self, body: &str) -> Result<String, WitnessError> {
        let req = parse_request(body).map_err(WitnessError::Rejected)?;
        let origin = req.checkpoint.origin();
        let new_size = req.checkpoint.size();
        let new_root = *req.checkpoint.root_hash();

        // ST-01: unknown origin → 404, by construction (exact allowlist
        // lookup; there is no wildcard).
        let trusted = self
            .logs
            .get(origin)
            .ok_or(WitnessError::Rejected(Reject::UnknownOrigin))?;

        // ST-02/ST-03: the note must verify against the origin's trusted
        // keys. SignedNote::verify already implements the signed-note rules
        // this row pairs with (ST-04): unknown-key signatures are ignored;
        // a name+key-id match that fails verification is InvalidSignature.
        let verified: Vec<Signature> = req
            .note
            .verify(trusted)
            .map_err(|e| match e {
                metamorphic_log::Error::InvalidSignature { .. } => {
                    WitnessError::Rejected(Reject::InvalidTrustedSignature)
                }
                _ => WitnessError::Rejected(Reject::NoTrustedSignature),
            })?
            .into_iter()
            .cloned()
            .collect();

        // ST-05: old size must not exceed the checkpoint size → 400. (This
        // check needs no stored state, so it precedes the atomic section.)
        if req.old_size > new_size {
            return Err(WitnessError::Rejected(Reject::OldSizeExceedsCheckpoint));
        }

        // CS-04/CS-05: one nonzero POSIX-seconds timestamp for both
        // cosignatures, taken before the atomic section (it is not
        // state-dependent).
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WitnessError::Clock)?
            .as_secs();
        if timestamp == 0 {
            return Err(WitnessError::Clock);
        }

        let note_text = req.note.text().to_string();
        let old_size = req.old_size;
        let proof = req.proof;
        let checkpoint = &req.checkpoint;

        // SM-01/SM-02: the remaining checks (which depend on stored state),
        // cosignature production, and the state update happen inside ONE
        // Store::update closure — under the store's writer lock, with the
        // response payload released only after append+fsync.
        let result = self.store.update(origin, |current| {
            // ST-06: the client's old size must equal our latest cosigned
            // size (0 if we never cosigned for this origin) → 409 + size.
            let latest_size = current.map_or(0, |s| s.size);
            if old_size != latest_size {
                return Err(WitnessError::Rejected(Reject::SizeConflict(latest_size)));
            }

            // ST-07: a size-0 checkpoint must carry the RFC 6962 §2.1
            // empty-tree root (SHA-256 of the empty string) → 422.
            if new_size == 0 && new_root != merkle::empty_root() {
                return Err(WitnessError::Rejected(Reject::EmptySizeNonEmptyRoot));
            }

            // ST-08: old size 0 admits no consistency proof (the empty tree
            // is consistent with any tree) → 422.
            if old_size == 0 && !proof.is_empty() {
                return Err(WitnessError::Rejected(Reject::ProofWithZeroOldSize));
            }

            // ST-09/ST-10: for a nonzero old size we hold the checkpoint we
            // cosigned at exactly that size (ST-06 passed), so verify the
            // consistency proof against it. The verifier covers both rows: a
            // proof that does not bind both heads is ST-09; equal sizes with
            // differing roots surfaces as RootMismatch, which is ST-10.
            if old_size > 0 {
                let current = current.expect("old size > 0 implies a cosigned checkpoint exists");
                let old_checkpoint = Checkpoint::new(origin, current.size, current.root)
                    .map_err(|_| WitnessError::Internal("stored state fails checkpoint parse"))?;
                old_checkpoint
                    .verify_consistency(checkpoint, &proof)
                    .map_err(|e| match e {
                        metamorphic_log::Error::RootMismatch if old_size == new_size => {
                            WitnessError::Rejected(Reject::SameSizeRootMismatch)
                        }
                        _ => WitnessError::Rejected(Reject::ConsistencyProofFailed),
                    })?;
            }

            // CS-01/CS-02/CS-10: dual-sign — the Ed25519 (0x04) cosignature
            // for interop and the ML-DSA-44 (0x06) cosignature, from
            // independently minted seeds. CS-03: the ML-DSA-44 cosignature
            // covers the whole tree (start 0, end checkpoint size), enforced
            // inside metamorphic-log's signer.
            let ed_sig = note::sign_cosignature_ed25519(
                &note_text,
                &self.name,
                &*self.ed25519.seed,
                timestamp,
            )
            .map_err(|e| WitnessError::Sign(e.to_string()))?;
            let ml_sig = note::sign_cosignature_mldsa44(
                &note_text,
                &self.name,
                &*self.mldsa44.seed,
                timestamp,
            )
            .map_err(|e| WitnessError::Sign(e.to_string()))?;

            // ST-12/MP-03: the stored note is the checkpoint text plus the
            // log signature(s) we verified plus our two cosignatures — served
            // verbatim by the monitoring prefix.
            let ed_line = ed_sig.marshal_line();
            let ml_line = ml_sig.marshal_line();
            let mut signatures = verified;
            signatures.push(ed_sig);
            signatures.push(ml_sig);
            let stored_note = SignedNote::new(note_text, signatures)
                .map_err(|_| WitnessError::Internal("note framing"))?
                .marshal();

            let new_state = LogState {
                origin: origin.to_string(),
                size: new_size,
                root: new_root,
                note: stored_note,
            };
            Ok((new_state, format!("{ed_line}\n{ml_line}\n")))
        });

        match result {
            Ok(response_body) => Ok(response_body),
            Err(UpdateError::Rejected(e)) => {
                // ST-11: origin known + signature valid + a consistency
                // failure — log the would-be evidence, cosign nothing.
                if let WitnessError::Rejected(reject) = &e {
                    if matches!(
                        reject,
                        Reject::EmptySizeNonEmptyRoot
                            | Reject::ProofWithZeroOldSize
                            | Reject::ConsistencyProofFailed
                            | Reject::SameSizeRootMismatch
                    ) {
                        eprintln!(
                            "mosskeys-witness: possible log misbehavior from {origin:?}: {} \
                             (old size {old_size}, checkpoint size {new_size})",
                            reject.message(),
                        );
                    }
                }
                Err(e)
            }
            Err(UpdateError::Store(e)) => Err(WitnessError::Store(e)),
        }
    }
}

#[cfg(test)]
mod tests;
