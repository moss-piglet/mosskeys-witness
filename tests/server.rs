//! HTTP-level tests for the axum wiring (task 5): method routing, the body
//! cap, and the exact wire format of the taxonomy (GI-01…GI-03, ST-06's
//! `text/x.tlog.size` body, T4). The protocol itself is covered in
//! `tests/witness.rs`; the full conformance suite is task 7.

use std::fs;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{SignedNote, VerifierKey};
use mosskeys_witness::config;
use mosskeys_witness::keygen;
use mosskeys_witness::server::{self, MAX_BODY_BYTES};
use mosskeys_witness::witness::Witness;
use tempfile::TempDir;
use tower::ServiceExt as _;

const WITNESS_NAME: &str = "witness.example/test";
const LOG_ORIGIN: &str = "example.com/behind-the-sofa";

/// A witness router over a tempdir, plus the log identity to submit as.
struct HttpFixture {
    app: axum::Router,
    log_seed: [u8; 32],
    #[allow(dead_code)]
    dir: TempDir,
}

impl HttpFixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (log_seed, log_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let log_vkey = VerifierKey::new_ed25519(LOG_ORIGIN, &log_pk)
            .unwrap()
            .encode();

        let keys_dir = dir.path().join("keys");
        keygen::generate(WITNESS_NAME, &keys_dir).unwrap();

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
"#,
                dir.path().join("state.jsonl").display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
            ),
        )
        .unwrap();

        let witness = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
        HttpFixture {
            app: server::router(witness),
            log_seed,
            dir,
        }
    }

    fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        let text = format!("{LOG_ORIGIN}\n{size}\n{}\n", B64.encode(tree.root_at(size)));
        let sig = metamorphic_log::note::sign_ed25519(&text, LOG_ORIGIN, &self.log_seed).unwrap();
        SignedNote::new(text, vec![sig]).unwrap().marshal()
    }
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

#[tokio::test]
async fn post_add_checkpoint_happy_path() {
    // covers GI-01 + ST-12 over the wire
    let fx = HttpFixture::new();
    let mut tree = MerkleTree::new();
    tree.push(b"leaf");
    let body = format!("old 0\n\n{}", fx.checkpoint_note(&tree, 1));

    let response = fx.app.oneshot(post("/add-checkpoint", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let text = body_string(response).await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(line.starts_with("\u{2014} "));
        assert!(line.contains(WITNESS_NAME));
    }
}

#[tokio::test]
async fn non_post_methods_are_rejected() {
    // covers GI-02 (axum answers 405 Method Not Allowed)
    let fx = HttpFixture::new();
    for method in ["GET", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
        let request = Request::builder()
            .method(method)
            .uri("/add-checkpoint")
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
async fn unknown_paths_are_404() {
    // covers GI-01's corollary: no wildcard routes — including the v0
    // out-of-scope sign-subtree endpoint (docs/spec-conformance.md §7).
    let fx = HttpFixture::new();
    for path in ["/", "/sign-subtree", "/add-checkpoint/", "/checkpoint"] {
        let response = fx.app.clone().oneshot(post(path, "old 0\n")).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

#[tokio::test]
async fn unknown_origin_is_404_over_the_wire() {
    // covers ST-01 end to end
    let fx = HttpFixture::new();
    let stranger_seed = metamorphic_crypto::ed25519_generate_keypair().0;
    let text = "stranger.example/not-registered\n1\nAARpcm88QZxj7jR9izc5sCygNRvIk0Ym2MCPmtKGxBk=\n";
    let sig = metamorphic_log::note::sign_ed25519(
        text,
        "stranger.example/not-registered",
        &stranger_seed,
    )
    .unwrap();
    let note = SignedNote::new(text.to_string(), vec![sig])
        .unwrap()
        .marshal();

    let response = fx
        .app
        .oneshot(post("/add-checkpoint", format!("old 0\n\n{note}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn conflict_carries_text_tlog_size_body() {
    // covers ST-06's exact wire format: decimal size + '\n',
    // Content-Type: text/x.tlog.size
    let fx = HttpFixture::new();
    let mut tree = MerkleTree::new();
    for i in 0..3u64 {
        tree.push(format!("leaf-{i}").as_bytes());
    }
    let body = format!("old 0\n\n{}", fx.checkpoint_note(&tree, 3));
    let response = fx
        .app
        .clone()
        .oneshot(post("/add-checkpoint", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Resubmit with a stale old size → 409 with the size-discovery body.
    let stale = format!("old 0\n\n{}", fx.checkpoint_note(&tree, 3));
    let response = fx
        .app
        .oneshot(post("/add-checkpoint", stale))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/x.tlog.size"
    );
    assert_eq!(body_string(response).await, "3\n");
}

#[tokio::test]
async fn oversized_bodies_are_capped_before_parsing() {
    // covers T4 (1 MiB cap at the extractor, before a byte is parsed).
    // The body begins like a valid request so only the cap can reject it.
    let mut body = format!("old {}\n", u64::MAX);
    body.push_str(&"A".repeat(MAX_BODY_BYTES));
    assert!(body.len() > MAX_BODY_BYTES);

    let fx = HttpFixture::new();
    let response = fx.app.oneshot(post("/add-checkpoint", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn non_utf8_bodies_are_400() {
    // T5: the note grammar is UTF-8; invalid bytes never reach the parser.
    let fx = HttpFixture::new();
    let response = fx
        .app
        .oneshot(post("/add-checkpoint", Body::from(vec![0xff, 0xfe, 0x0a])))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_bodies_are_400() {
    // AC-01…AC-06 over the wire (parser detail lives in src/witness/tests.rs)
    let fx = HttpFixture::new();
    for body in ["", "old", "old 01\n\nx\n", "old 0\n"] {
        let response = fx
            .app
            .clone()
            .oneshot(post("/add-checkpoint", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body {body:?}");
    }
}
