//! HTTP-level tests for the monitoring prefix (task 6):
//! `GET /<origin hash>/checkpoint`, served on the same listener as the
//! submission prefix (GI-04) and wrapped by the same T4 layers (the route
//! is registered before the `.layer(...)` calls — a 200 through the full
//! stack proves the wiring). Covers MP-01…MP-05; the full conformance
//! suite is task 7.

use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{SignatureType, SignedNote, VerifierKey};
use mosskeys_witness::config;
use mosskeys_witness::keygen::{self, Suite};
use mosskeys_witness::server;
use mosskeys_witness::witness::Witness;
use tempfile::TempDir;
use tower::ServiceExt as _;

const WITNESS_NAME: &str = "witness.example/test";
const LOG_ORIGIN: &str = "example.com/behind-the-sofa";
/// A second registered log that is never cosigned in these tests: its
/// origin hash must still 404 (MP-04 covers registered-but-never-cosigned).
const OTHER_ORIGIN: &str = "example.com/registered-but-quiet";

/// Lowercase hex (no external hex crate needed).
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// MP-02: the origin hash is the lowercase hex of SHA-256 over the origin
/// line's content (no trailing newline).
fn origin_hash(origin: &str) -> String {
    hex(&metamorphic_crypto::hash::sha256(origin.as_bytes()))
}

/// A witness router over a tempdir with TWO registered logs, plus the log
/// and witness identities to submit and re-verify with.
struct MonitoringFixture {
    app: axum::Router,
    log_seed: [u8; 32],
    log_vkey: String,
    ed_vkey: String,
    ml_vkey: String,
    state_file: PathBuf,
    #[allow(dead_code)]
    dir: TempDir, // kept alive for the fixture's lifetime
}

impl MonitoringFixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (log_seed, log_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let log_vkey = VerifierKey::new_ed25519(LOG_ORIGIN, &log_pk)
            .unwrap()
            .encode();
        let (_other_seed, other_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let other_vkey = VerifierKey::new_ed25519(OTHER_ORIGIN, &other_pk)
            .unwrap()
            .encode();

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

        let state_file = dir.path().join("state.jsonl");
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
vkeys = ["{log_vkey}"]

[[log]]
origin = "{OTHER_ORIGIN}"
vkeys = ["{other_vkey}"]
"#,
                state_file.display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
            ),
        )
        .unwrap();

        let witness = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
        MonitoringFixture {
            app: server::router(witness),
            log_seed,
            log_vkey,
            ed_vkey: vkey_of(Suite::Ed25519),
            ml_vkey: vkey_of(Suite::MlDsa44),
            state_file,
            dir,
        }
    }

    fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        let text = format!("{LOG_ORIGIN}\n{size}\n{}\n", B64.encode(tree.root_at(size)));
        let sig = metamorphic_log::note::sign_ed25519(&text, LOG_ORIGIN, &self.log_seed).unwrap();
        SignedNote::new(text, vec![sig]).unwrap().marshal()
    }

    fn checkpoint_path(origin: &str) -> String {
        format!("/{}/checkpoint", origin_hash(origin))
    }

    /// The persisted `LogState.note` for `origin`, read back from the state
    /// file (last record wins, as at replay). These are exactly the bytes
    /// `witness.latest(origin).note` returns.
    fn stored_note(&self, origin: &str) -> Option<String> {
        fs::read_to_string(&self.state_file)
            .unwrap()
            .lines()
            .rev()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|record| record["origin"] == origin)
            .map(|record| record["note"].as_str().unwrap().to_string())
    }

    fn log_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.log_vkey).unwrap()
    }

    fn ed_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ed_vkey).unwrap()
    }

    fn ml_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ml_vkey).unwrap()
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

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .body(body.into())
        .unwrap()
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Cosign `note` at `old_size` (with `proof`) through the full stack.
async fn cosign(fx: &MonitoringFixture, old_size: u64, proof: &[[u8; 32]], note: &str) {
    let response = fx
        .app
        .clone()
        .oneshot(post("/add-checkpoint", request_body(old_size, proof, note)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A 5-leaf tree, the fixture's workhorse.
fn tree_with_5_leaves() -> MerkleTree {
    let mut tree = MerkleTree::new();
    for i in 0..5u64 {
        tree.push(format!("leaf-{i}").as_bytes());
    }
    tree
}

#[tokio::test]
async fn get_checkpoint_serves_the_cosigned_note_verbatim() {
    // covers MP-01 + MP-03 (and GI-04: the same listener serves submission
    // and monitoring; this 200 also proves the route sits under the T4
    // timeout/concurrency layers, i.e. registered before them)
    let fx = MonitoringFixture::new();
    let tree = tree_with_5_leaves();
    cosign(&fx, 0, &[], &fx.checkpoint_note(&tree, 3)).await;

    let response = fx
        .app
        .clone()
        .oneshot(get(&MonitoringFixture::checkpoint_path(LOG_ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;

    // MP-03: the body is byte-equal to the stored cosigned note — served
    // verbatim, nothing reconstructed or re-signed.
    let stored = fx.stored_note(LOG_ORIGIN).expect("cosigned state exists");
    assert_eq!(body, stored);
    assert!(body.ends_with('\n'));

    // MP-03 content: the note parses over the checkpoint text and verifies
    // against the log vkey AND both keygen-produced witness vkeys — three
    // signatures: the log's plus the 0x04 Ed25519 and 0x06 ML-DSA-44 cosigs.
    let served = SignedNote::parse(&body).unwrap();
    assert_eq!(
        served.text(),
        format!("{LOG_ORIGIN}\n3\n{}\n", B64.encode(tree.root_at(3)))
    );
    let trusted = [fx.log_vkey(), fx.ed_vkey(), fx.ml_vkey()];
    assert_eq!(
        trusted[1].signature_type(),
        SignatureType::CosignatureV1Ed25519
    );
    assert_eq!(
        trusted[2].signature_type(),
        SignatureType::CosignatureV1MlDsa44
    );
    let verified = served.verify(&trusted).unwrap();
    assert_eq!(verified.len(), 3);
    for vkey in &trusted {
        assert!(
            verified
                .iter()
                .any(|s| s.name() == vkey.name() && s.key_id() == vkey.key_id()),
            "signature for {:?} must verify",
            vkey.signature_type()
        );
    }
}

#[tokio::test]
async fn origin_hash_is_lowercase_hex_sha256_of_the_origin() {
    // covers MP-02, pinned by a known-answer hash of the fixture origin
    // (SHA-256 over the origin line's content, no trailing newline)
    let fx = MonitoringFixture::new();
    let tree = tree_with_5_leaves();
    cosign(&fx, 0, &[], &fx.checkpoint_note(&tree, 3)).await;

    const KAT: &str = "5fd2dc0beb4ce54da5050cf6d5c75248b023abad441c3cecde3976fbe9da4fe4";
    assert_eq!(origin_hash(LOG_ORIGIN), KAT);
    let response = fx
        .app
        .clone()
        .oneshot(get(&format!("/{KAT}/checkpoint")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A DIFFERENT registered origin's hash: known to the witness as a log,
    // but never cosigned → 404 (MP-04, via the MP-02 lookup).
    let response = fx
        .app
        .oneshot(get(&MonitoringFixture::checkpoint_path(OTHER_ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn never_cosigned_origin_hash_is_404() {
    // covers MP-04: well-formed hash, nothing cosigned yet
    let fx = MonitoringFixture::new();
    let response = fx
        .app
        .oneshot(get(&MonitoringFixture::checkpoint_path(LOG_ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_origin_hashes_are_404() {
    // covers MP-02's by-construction rejection: only exact lowercase hex
    // can match a computed hash; every other shape misses the lookup and
    // 404s (MP-04) — no special-casing per shape. The store is non-empty
    // so a lookup miss (not an empty store) drives each 404.
    let fx = MonitoringFixture::new();
    let tree = tree_with_5_leaves();
    cosign(&fx, 0, &[], &fx.checkpoint_note(&tree, 3)).await;

    let good = origin_hash(LOG_ORIGIN);
    let cases = [
        good.to_uppercase(),                         // uppercase hex
        good[..63].to_string(),                      // too short
        format!("{good}00"),                         // too long
        "z".repeat(64),                              // right length, non-hex
        "not-a-hash".to_string(),                    // garbage
        origin_hash("example.com/never-registered"), // well-formed, unknown log
    ];
    for bad in &cases {
        let response = fx
            .app
            .clone()
            .oneshot(get(&format!("/{bad}/checkpoint")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "hash {bad:?} must 404"
        );
    }
}

#[tokio::test]
async fn monitoring_path_is_get_only() {
    // GI-02 discipline on the monitoring route (axum answers 405; HEAD is
    // served by axum for any GET route and is not part of the taxonomy)
    let fx = MonitoringFixture::new();
    let path = MonitoringFixture::checkpoint_path(LOG_ORIGIN);
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .body(Body::empty())
            .unwrap();
        let response = fx.app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not reach the handler"
        );
    }
}

#[tokio::test]
async fn get_checkpoint_reflects_the_new_head_immediately() {
    // covers MP-05 by construction: serving is synchronous from the same
    // store the submission path updates — no caching, no refresh loop, so
    // a cosigned head is visible on the very next request.
    let fx = MonitoringFixture::new();
    let tree = tree_with_5_leaves();
    cosign(&fx, 0, &[], &fx.checkpoint_note(&tree, 3)).await;

    let path = MonitoringFixture::checkpoint_path(LOG_ORIGIN);
    let response = fx.app.clone().oneshot(get(&path)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first = body_string(response).await;
    let first_note = SignedNote::parse(&first).unwrap();
    assert_eq!(Checkpoint::parse(first_note.text()).unwrap().size(), 3);

    // Chain to size 5 with a valid RFC 6962 consistency proof from the
    // cosigned size-3 head.
    let proof = tree.consistency_proof(3, 5);
    cosign(&fx, 3, &proof, &fx.checkpoint_note(&tree, 5)).await;

    let response = fx.app.clone().oneshot(get(&path)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second = body_string(response).await;
    assert_ne!(first, second, "the served head must advance with cosigning");
    let second_note = SignedNote::parse(&second).unwrap();
    assert_eq!(Checkpoint::parse(second_note.text()).unwrap().size(), 5);
    // Still verbatim: byte-equal to the freshly stored note.
    assert_eq!(second, fx.stored_note(LOG_ORIGIN).unwrap());
}
