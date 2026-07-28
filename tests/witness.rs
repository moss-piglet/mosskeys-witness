//! Handler-level tests for the add-checkpoint protocol core (task 5):
//! the status taxonomy in evaluation order, dual cosignature production,
//! and persistence — the full HTTP conformance suite is task 7.
//!
//! Each test cites the conformance rows it covers (docs/spec-conformance.md).

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::{MerkleTree, empty_root, hash_leaf};
use metamorphic_log::note::{self, Signature, SignatureType, SignedNote, VerifierKey};
use mosskeys_witness::config;
use mosskeys_witness::keygen::{self, Suite};
use mosskeys_witness::store::StoreError;
use mosskeys_witness::witness::{Reject, StartupError, Witness, WitnessError};
use tempfile::TempDir;

const WITNESS_NAME: &str = "witness.example/test";
const LOG_ORIGIN: &str = "example.com/behind-the-sofa";

/// A throwaway log identity (Ed25519 0x01) that produces signed checkpoints.
struct TestLog {
    origin: String,
    seed: [u8; 32],
}

impl TestLog {
    fn new(origin: &str) -> Self {
        let (seed, _pk) = metamorphic_crypto::ed25519_generate_keypair();
        TestLog {
            origin: origin.to_string(),
            seed,
        }
    }

    fn vkey(&self) -> String {
        let pk = metamorphic_crypto::ed25519_public_key(&self.seed).unwrap();
        VerifierKey::new_ed25519(&self.origin, &pk)
            .unwrap()
            .encode()
    }

    fn checkpoint_text(&self, tree: &MerkleTree, size: u64) -> String {
        format!(
            "{}\n{size}\n{}\n",
            self.origin,
            B64.encode(tree.root_at(size))
        )
    }

    fn sign(&self, text: &str) -> Signature {
        note::sign_ed25519(text, &self.origin, &self.seed).unwrap()
    }

    /// A complete signed-note checkpoint over `tree`'s first `size` leaves.
    fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        let text = self.checkpoint_text(tree, size);
        SignedNote::new(text.clone(), vec![self.sign(&text)])
            .unwrap()
            .marshal()
    }
}

/// A running witness over a tempdir: minted seeds, config, state file.
struct Fixture {
    witness: Witness,
    log: TestLog,
    /// The witness cosigner vkeys (0x04 / 0x06), as printed at keygen time.
    ed_vkey: String,
    ml_vkey: String,
    config_path: PathBuf,
    #[allow(dead_code)]
    dir: TempDir, // kept alive for the fixture's lifetime
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let log = TestLog::new(LOG_ORIGIN);

        let keys_dir = dir.path().join("keys");
        let identity = keygen::generate(WITNESS_NAME, &keys_dir).unwrap();
        let vkey_of = |suite: Suite| {
            identity
                .keys
                .iter()
                .find(|k| k.suite == suite)
                .unwrap()
                .vkey
                .clone()
        };

        let config_path = dir.path().join("witness.toml");
        fs::write(
            &config_path,
            format!(
                r#"
name = "{WITNESS_NAME}"
listen = "127.0.0.1:0"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"

[[log]]
origin = "{LOG_ORIGIN}"
vkeys = ["{}"]
"#,
                dir.path().join("state.jsonl").display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
                log.vkey(),
            ),
        )
        .unwrap();

        let witness = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
        Fixture {
            witness,
            log,
            ed_vkey: vkey_of(Suite::Ed25519),
            ml_vkey: vkey_of(Suite::MlDsa44),
            config_path,
            dir,
        }
    }

    /// A fresh witness over the same config/state. The store lock is
    /// exclusive: the previous instance must be dropped first.
    fn reopen(&self) -> Result<Witness, StartupError> {
        Witness::from_config(&config::load(&self.config_path).unwrap())
    }

    fn ed_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ed_vkey).unwrap()
    }

    fn ml_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ml_vkey).unwrap()
    }

    fn log_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.log.vkey()).unwrap()
    }
}

/// Build a request body: `old <old_size>`, proof lines, empty line, note.
fn request_body(old_size: u64, proof: &[[u8; 32]], note: &str) -> String {
    let mut body = format!("old {old_size}\n");
    for hash in proof {
        body.push_str(&B64.encode(hash));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(note);
    body
}

fn reject(err: WitnessError) -> Reject {
    match err {
        WitnessError::Rejected(r) => r,
        other => panic!("expected a protocol rejection, got {other:?}"),
    }
}

fn tree_with_leaves(leaves: &[&[u8]]) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for leaf in leaves {
        tree.push(leaf);
    }
    tree
}

#[test]
fn unknown_origin_gets_404() {
    // covers ST-01 (allowlist-by-construction, T8)
    let fx = Fixture::new();
    let stranger = TestLog::new("stranger.example/not-registered");
    let tree = tree_with_leaves(&[b"a"]);
    let body = request_body(0, &[], &stranger.checkpoint_note(&tree, 1));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::UnknownOrigin);
    assert_eq!(Reject::UnknownOrigin.status(), 404);
}

#[test]
fn no_signature_from_a_trusted_key_gets_403() {
    // covers ST-02 + ST-04 (the unknown key is ignored, never fatal)
    let fx = Fixture::new();
    let impostor = TestLog::new(LOG_ORIGIN); // same name, wrong key
    let tree = tree_with_leaves(&[b"a"]);
    let body = request_body(0, &[], &impostor.checkpoint_note(&tree, 1));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::NoTrustedSignature);
    assert_eq!(Reject::NoTrustedSignature.status(), 403);
}

#[test]
fn failed_signature_from_a_trusted_key_gets_403() {
    // covers ST-03: key name AND key id match, but the signature is bad.
    let fx = Fixture::new();
    let tree = tree_with_leaves(&[b"a"]);
    let note = fx.log.checkpoint_note(&tree, 1);

    // Flip one bit in the signature blob, keeping name + key id intact.
    let mut lines: Vec<String> = note.lines().map(str::to_string).collect();
    let sig_line = lines.pop().unwrap();
    let (prefix, blob64) = sig_line.rsplit_once(' ').unwrap();
    let mut blob = B64.decode(blob64).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    lines.push(format!("{prefix} {}", B64.encode(blob)));
    let tampered_note = format!("{}\n", lines.join("\n"));

    let err = fx
        .witness
        .add_checkpoint(&request_body(0, &[], &tampered_note))
        .unwrap_err();
    assert_eq!(reject(err), Reject::InvalidTrustedSignature);
    assert_eq!(Reject::InvalidTrustedSignature.status(), 403);
}

#[test]
fn old_size_above_checkpoint_size_gets_400() {
    // covers ST-05 (evaluated after the signature checks: the checkpoint is
    // validly signed here)
    let fx = Fixture::new();
    let tree = tree_with_leaves(&[b"a", b"b", b"c"]);
    let body = request_body(5, &[], &fx.log.checkpoint_note(&tree, 3));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::OldSizeExceedsCheckpoint);
    assert_eq!(Reject::OldSizeExceedsCheckpoint.status(), 400);
}

#[test]
fn stale_old_size_gets_409_with_latest_size() {
    // covers ST-06, including the size-discovery flow (old 0 → learn size)
    let fx = Fixture::new();
    let tree = tree_with_leaves(&[b"a", b"b", b"c"]);
    fx.witness
        .add_checkpoint(&request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)))
        .unwrap();

    // Any old size other than 3 now conflicts and reports the latest size.
    let tree5 = tree_with_leaves(&[b"a", b"b", b"c", b"d", b"e"]);
    for stale in [0, 2, 4] {
        let err = fx
            .witness
            .add_checkpoint(&request_body(
                stale,
                &[],
                &fx.log.checkpoint_note(&tree5, 5),
            ))
            .unwrap_err();
        assert_eq!(reject(err), Reject::SizeConflict(3), "stale old {stale}");
        assert_eq!(Reject::SizeConflict(3).status(), 409);
    }
}

#[test]
fn size_zero_checkpoint_with_wrong_root_gets_422() {
    // covers ST-07: size 0 must carry the RFC 6962 empty-tree root
    let fx = Fixture::new();
    let text = format!("{LOG_ORIGIN}\n0\n{}\n", B64.encode(hash_leaf(b"not-empty")));
    let note = SignedNote::new(text.clone(), vec![fx.log.sign(&text)])
        .unwrap()
        .marshal();

    let err = fx
        .witness
        .add_checkpoint(&request_body(0, &[], &note))
        .unwrap_err();
    assert_eq!(reject(err), Reject::EmptySizeNonEmptyRoot);
    assert_eq!(Reject::EmptySizeNonEmptyRoot.status(), 422);
}

#[test]
fn size_zero_checkpoint_with_empty_root_is_cosigned() {
    // covers ST-07's accept branch (and ST-08's: empty proof with old 0)
    let fx = Fixture::new();
    let tree = MerkleTree::new();
    assert_eq!(tree.root(), empty_root());
    fx.witness
        .add_checkpoint(&request_body(0, &[], &fx.log.checkpoint_note(&tree, 0)))
        .unwrap();
    assert_eq!(fx.witness.latest(LOG_ORIGIN).unwrap().size, 0);
}

#[test]
fn proof_with_zero_old_size_gets_422() {
    // covers ST-08
    let fx = Fixture::new();
    let tree = tree_with_leaves(&[b"a"]);
    let body = request_body(0, &[[7u8; 32]], &fx.log.checkpoint_note(&tree, 1));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::ProofWithZeroOldSize);
    assert_eq!(Reject::ProofWithZeroOldSize.status(), 422);
}

#[test]
fn broken_consistency_proof_gets_422() {
    // covers ST-09
    let fx = Fixture::new();
    let mut tree = tree_with_leaves(&[b"a", b"b", b"c"]);
    fx.witness
        .add_checkpoint(&request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)))
        .unwrap();

    tree.push(b"d");
    tree.push(b"e");
    let garbage_proof = [[9u8; 32]];
    let body = request_body(3, &garbage_proof, &fx.log.checkpoint_note(&tree, 5));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::ConsistencyProofFailed);
    assert_eq!(Reject::ConsistencyProofFailed.status(), 422);

    // Nothing was cosigned at size 5 (I1: the rejection left no trace).
    assert_eq!(fx.witness.latest(LOG_ORIGIN).unwrap().size, 3);
}

#[test]
fn same_size_different_root_gets_422() {
    // covers ST-10 (the fork attempt; ST-11 logs it — stderr in tests)
    let fx = Fixture::new();
    let tree = tree_with_leaves(&[b"a", b"b", b"c"]);
    fx.witness
        .add_checkpoint(&request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)))
        .unwrap();

    // A *different* three-leaf history at the same size.
    let forked = tree_with_leaves(&[b"x", b"y", b"z"]);
    let body = request_body(3, &[], &fx.log.checkpoint_note(&forked, 3));

    let err = fx.witness.add_checkpoint(&body).unwrap_err();
    assert_eq!(reject(err), Reject::SameSizeRootMismatch);
    assert_eq!(Reject::SameSizeRootMismatch.status(), 422);
}

#[test]
fn happy_path_dual_cosigns_persists_and_chains() {
    // covers ST-12, CS-01…CS-06, CS-08…CS-10, SM-01…SM-03, MP-03 (readiness)
    let fx = Fixture::new();
    let mut tree = tree_with_leaves(&[b"a", b"b", b"c"]);

    let response = fx
        .witness
        .add_checkpoint(&request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)))
        .unwrap();

    // ST-12: the body is exactly two signature lines, each `— name ...\n`.
    let lines: Vec<&str> = response.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(response.ends_with('\n'));
    for line in &lines {
        assert!(line.starts_with("\u{2014} "));
        assert!(line.contains(WITNESS_NAME));
    }

    // CS-01/CS-02/CS-10: both cosignatures verify against the keygen-produced
    // vkeys — one 0x04 Ed25519, one 0x06 ML-DSA-44.
    let checkpoint_text = fx.log.checkpoint_text(&tree, 3);
    let combined = format!("{checkpoint_text}\n{response}");
    let combined_note = SignedNote::parse(&combined).unwrap();
    let trusted = [fx.ed_vkey(), fx.ml_vkey()];
    assert_eq!(
        trusted[0].signature_type(),
        SignatureType::CosignatureV1Ed25519
    );
    assert_eq!(
        trusted[1].signature_type(),
        SignatureType::CosignatureV1MlDsa44
    );
    let verified = combined_note.verify(&trusted).unwrap();
    assert_eq!(verified.len(), 2);
    for vkey in &trusted {
        assert!(
            verified
                .iter()
                .any(|s| s.name() == vkey.name() && s.key_id() == vkey.key_id()),
            "cosignature for {:?} must verify",
            vkey.signature_type()
        );
    }

    // CS-04: cosignature timestamps are present and nonzero (each line's
    // blob embeds `u64 timestamp || signature`).
    for sig in &verified {
        let ts = u64::from_be_bytes(sig.signature()[..8].try_into().unwrap());
        assert!(ts > 0, "cosignature timestamp must be nonzero");
    }

    // SM-01/SM-03: the store recorded size 3 with the full cosigned note —
    // checkpoint text + the log's signature + our two cosignatures (MP-03).
    let state = fx.witness.latest(LOG_ORIGIN).unwrap();
    assert_eq!(state.size, 3);
    assert_eq!(state.root, tree.root_at(3));
    let stored = SignedNote::parse(&state.note).unwrap();
    assert_eq!(stored.text(), checkpoint_text);
    assert_eq!(stored.signatures().len(), 3);
    stored
        .verify(&[fx.log_vkey(), fx.ed_vkey(), fx.ml_vkey()])
        .unwrap();

    // SM-02 + ST-09 accept branch: chain to size 5 with a valid RFC 6962
    // consistency proof from the cosigned size-3 head.
    tree.push(b"d");
    tree.push(b"e");
    let proof = tree.consistency_proof(3, 5);
    let response2 = fx
        .witness
        .add_checkpoint(&request_body(3, &proof, &fx.log.checkpoint_note(&tree, 5)))
        .unwrap();
    assert_eq!(response2.lines().count(), 2);
    assert_eq!(fx.witness.latest(LOG_ORIGIN).unwrap().size, 5);

    // SM-01/SM-05: persist-before-respond made it durable — a fresh instance
    // over the same state file replays size 5 (I4). Dropping the witness
    // releases the exclusive store lock.
    let config_path = fx.config_path.clone();
    drop(fx.witness);
    let w2 = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
    assert_eq!(w2.latest(LOG_ORIGIN).unwrap().size, 5);
}

#[test]
fn a_second_instance_on_the_same_state_file_fails_fast() {
    // covers I4/T8 (the exclusive store lock)
    let fx = Fixture::new();
    let err = fx.reopen().unwrap_err();
    assert!(
        matches!(err, StartupError::Store(StoreError::Locked(_))),
        "got {err:?}"
    );
}
