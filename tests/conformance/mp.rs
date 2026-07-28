//! §6 Monitoring prefix (MP-01…MP-05), black-box. Layered with
//! `tests/monitoring.rs` (cross-referenced per row): the assertions there
//! pin the same behaviors; these are the conformance-suite citations, kept
//! compact on purpose.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::note::{SignatureType, SignedNote};
use tower::ServiceExt as _;

use crate::support::{
    HttpFixture, LOG_ORIGIN, cosign_ok, get, monitoring_body, origin_hash,
    tree_with_numbered_leaves,
};

#[tokio::test]
async fn mp_01_and_mp_03_the_cosigned_note_is_served_verbatim() {
    // covers MP-01 (a recent checkpoint is served per cosigned log) + MP-03
    // (the body IS the stored checkpoint with the log signature(s) AND the
    // witness cosignatures — served verbatim, never reconstructed).
    // Cross-ref: `get_checkpoint_serves_the_cosigned_note_verbatim` in
    // tests/monitoring.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let body = monitoring_body(&fx.app, LOG_ORIGIN).await;

    // MP-03: byte-equal to the stored note (read back from the state file).
    let stored = fx.stored_note(LOG_ORIGIN).expect("cosigned state exists");
    assert_eq!(body, stored.as_bytes());
    assert!(stored.ends_with('\n'));

    // Content: checkpoint text + the log signature + BOTH witness
    // cosignatures (0x04 and 0x06), all verifying.
    let served = SignedNote::parse(&stored).unwrap();
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
}

#[tokio::test]
async fn mp_02_origin_hash_is_lowercase_hex_sha256_of_the_origin() {
    // covers MP-02, pinned by the known-answer hash of the fixture origin
    // (cross-ref `origin_hash_is_lowercase_hex_sha256_of_the_origin` and
    // `malformed_origin_hashes_are_404` in tests/monitoring.rs).
    const KAT: &str = "5fd2dc0beb4ce54da5050cf6d5c75248b023abad441c3cecde3976fbe9da4fe4";
    assert_eq!(origin_hash(LOG_ORIGIN), KAT);

    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let response = fx
        .app
        .clone()
        .oneshot(get(&format!("/{KAT}/checkpoint")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Every non-lowercase-hex-64 shape misses the lookup → 404 (MP-02's
    // by-construction rejection; the outcome is MP-04's).
    let good = origin_hash(LOG_ORIGIN);
    for bad in [
        good.to_uppercase(),             // uppercase hex
        good[..63].to_string(),          // too short
        format!("{good}00"),             // too long
        "z".repeat(64),                  // right length, non-hex
        origin_hash("example.com/nope"), // well-formed, never registered
    ] {
        let response = fx
            .app
            .clone()
            .oneshot(get(&format!("/{bad}/checkpoint")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "hash {bad:?}");
    }
}

#[tokio::test]
async fn mp_04_never_cosigned_origin_hash_is_404() {
    // covers MP-04: the origin is REGISTERED (so this is not ST-01's
    // allowlist miss) but nothing was ever cosigned for it → 404.
    // Cross-ref: `never_cosigned_origin_hash_is_404` in tests/monitoring.rs.
    let fx = HttpFixture::new();
    let response = fx
        .app
        .clone()
        .oneshot(get(&HttpFixture::monitoring_path(LOG_ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // …and 404 for an origin the witness has never heard of either.
    let stranger_hash = origin_hash("stranger.example/not-registered");
    let response = fx
        .app
        .clone()
        .oneshot(get(&format!("/{stranger_hash}/checkpoint")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mp_05_a_cosigned_head_is_visible_on_the_next_request() {
    // covers MP-05 (SHOULD NOT delay updates by more than an hour): serving
    // is synchronous from the same store the submission path updates, so the
    // delay is zero. Cross-ref:
    // `get_checkpoint_reflects_the_new_head_immediately` in tests/monitoring.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let first = monitoring_body(&fx.app, LOG_ORIGIN).await;
    let first_note = SignedNote::parse(std::str::from_utf8(&first).unwrap()).unwrap();
    assert_eq!(Checkpoint::parse(first_note.text()).unwrap().size(), 3);

    // Chain to 5 with a valid proof; the very next GET serves the new head.
    let proof = tree.consistency_proof(3, 5);
    cosign_ok(&fx.app, 3, &proof, &fx.log.checkpoint_note(&tree, 5)).await;

    let second = monitoring_body(&fx.app, LOG_ORIGIN).await;
    assert_ne!(first, second);
    let second_note = SignedNote::parse(std::str::from_utf8(&second).unwrap()).unwrap();
    assert_eq!(Checkpoint::parse(second_note.text()).unwrap().size(), 5);
    assert_eq!(second, fx.stored_note(LOG_ORIGIN).unwrap().as_bytes());
}

#[tokio::test]
async fn mp_route_is_get_only() {
    // MP-01 discipline: the monitoring path answers GET and nothing else
    // (405; HEAD is axum's automatic GET companion and stays outside the
    // taxonomy). Cross-ref: `monitoring_path_is_get_only` in
    // tests/monitoring.rs.
    let fx = HttpFixture::new();
    let path = HttpFixture::monitoring_path(LOG_ORIGIN);
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let response = fx
            .app
            .clone()
            .oneshot(crate::support::method(method, &path))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not reach the handler"
        );
    }
}
