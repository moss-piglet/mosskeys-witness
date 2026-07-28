//! §3 add-checkpoint — status taxonomy (ST-01…ST-12), in the spec's
//! evaluation order, with the exact wire formats and the multi-violation
//! order guarantees. Protocol-level counterparts live in tests/witness.rs
//! (cross-referenced per row); ST-11's evidence line needs process stderr,
//! so it drives the real binary.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::hash_leaf;
use metamorphic_log::note::SignedNote;

use crate::support::{
    self, HttpFixture, LOG_ORIGIN, TestLog, WitnessProcess, body_string, connect, cosign_ok,
    forked_tree, raw_request, request_body, submit, tamper_last_signature,
    tree_with_numbered_leaves,
};

#[tokio::test]
async fn st_01_unknown_origin_is_404_even_without_a_trusted_signature() {
    // covers ST-01, and the order guarantee "404 before 403": the origin
    // lookup precedes every signature check, so an unknown origin gets 404
    // even when its note could never have verified (signed by an arbitrary
    // third party). Cross-ref: `unknown_origin_gets_404` in tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(1);
    let stranger = TestLog::new("stranger.example/not-registered");
    let third_party = TestLog::new("third-party.example/also-unknown");

    // Signed by a key even the stranger origin wouldn't trust: still 404.
    let text = stranger.checkpoint_text(&tree, 1);
    let note = SignedNote::new(text.clone(), vec![third_party.sign(&text)])
        .unwrap()
        .marshal();
    let response = submit(&fx.app, request_body(0, &[], &note)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Old size above the checkpoint size too: still 404 (origin before
    // every size check).
    let response = submit(
        &fx.app,
        request_body(9, &[], &stranger.checkpoint_note(&tree, 1)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn st_02_and_st_04_no_trusted_signature_is_403_unknown_keys_never_fatal() {
    // covers ST-02 (no signature from a trusted key → 403) and ST-04
    // (signatures from unknown keys are ignored — they neither count nor
    // error). Cross-ref: `no_signature_from_a_trusted_key_gets_403` in
    // tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(1);
    let text = fx.log.checkpoint_text(&tree, 1);

    // The registered ORIGIN, but the note is signed only by unknown keys
    // (several of them — volume changes nothing per ST-04).
    let strangers: Vec<TestLog> = (0..3)
        .map(|i| TestLog::new(&format!("stranger-{i}.example/not-registered")))
        .collect();
    let sigs = strangers.iter().map(|s| s.sign(&text)).collect();
    let note = SignedNote::new(text, sigs).unwrap().marshal();

    let response = submit(&fx.app, request_body(0, &[], &note)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn st_03_trusted_name_and_key_id_but_bad_signature_is_403() {
    // covers ST-03: the signature line's key name AND key id match a trusted
    // key, but the signature fails to verify (the note is malformed per
    // signed-note) → 403. Cross-ref:
    // `failed_signature_from_a_trusted_key_gets_403` in tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(1);
    let tampered = tamper_last_signature(&fx.log.checkpoint_note(&tree, 1));

    let response = submit(&fx.app, request_body(0, &[], &tampered)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn st_05_old_size_above_checkpoint_size_is_400() {
    // covers ST-05, with the state EMPTY: without ST-05's early check this
    // request would be a 409 (old 5 ≠ latest 0) — getting 400 pins the
    // evaluation order. Cross-ref:
    // `old_size_above_checkpoint_size_gets_400` in tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let response = submit(
        &fx.app,
        request_body(5, &[], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn st_06_stale_old_size_is_409_with_the_exact_tlog_size_wire_format() {
    // covers ST-06 and its exact wire format: the body is the decimal latest
    // size + '\n' and NOTHING else, with Content-Type text/x.tlog.size.
    // Cross-ref: `conflict_carries_text_tlog_size_body` in tests/server.rs,
    // `stale_old_size_gets_409_with_latest_size` in tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    for stale in [0, 2] {
        let response = submit(
            &fx.app,
            request_body(stale, &[], &fx.log.checkpoint_note(&tree, 5)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "stale old {stale}");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/x.tlog.size",
            "exact content type — no parameters, nothing else"
        );
        assert_eq!(response.headers().get("content-length").unwrap(), "2");
        assert_eq!(support::body_bytes(response).await, b"3\n");
    }
}

#[tokio::test]
async fn st_07_size_zero_checkpoint_must_carry_the_empty_tree_root() {
    // covers ST-07: size 0 with root ≠ SHA-256("") → 422; with the RFC 6962
    // empty-tree root → cosigned. Cross-ref:
    // `size_zero_checkpoint_with_wrong_root_gets_422` and
    // `size_zero_checkpoint_with_empty_root_is_cosigned` in tests/witness.rs.
    let fx = HttpFixture::new();

    let text = format!("{LOG_ORIGIN}\n0\n{}\n", B64.encode(hash_leaf(b"not-empty")));
    let note = SignedNote::new(text.clone(), vec![fx.log.sign(&text)])
        .unwrap()
        .marshal();
    let response = submit(&fx.app, request_body(0, &[], &note)).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let empty = metamorphic_log::merkle::MerkleTree::new();
    let response = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(&empty, 0)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn st_08_old_size_zero_with_a_proof_is_422() {
    // covers ST-08. Cross-ref: `proof_with_zero_old_size_gets_422` in
    // tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(1);
    let response = submit(
        &fx.app,
        request_body(0, &[[7u8; 32]], &fx.log.checkpoint_note(&tree, 1)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn st_09_a_proof_that_does_not_verify_is_422() {
    // covers ST-09 (RFC 6962 §2.1.2). Cross-ref:
    // `broken_consistency_proof_gets_422` in tests/witness.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let response = submit(
        &fx.app,
        request_body(3, &[[9u8; 32]], &fx.log.checkpoint_note(&tree, 5)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Nothing was cosigned at size 5: the stored head is still 3.
    let state = fx.stored_note(LOG_ORIGIN).unwrap();
    assert!(state.contains("\n3\n"));
}

#[tokio::test]
async fn st_10_same_size_different_root_is_422() {
    // covers ST-10 (the fork attempt). Cross-ref:
    // `same_size_different_root_gets_422` in tests/witness.rs. The full
    // adversarial matrix is sm.rs's SM-04 test.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let forked = forked_tree(3);
    let response = submit(
        &fx.app,
        request_body(3, &[], &fx.log.checkpoint_note(&forked, 3)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn st_11_a_validly_signed_consistency_failure_is_logged_and_nothing_cosigned() {
    // covers ST-11 (MAY log misbehavior evidence; MUST NOT cosign). The
    // evidence line goes to process stderr, which only the real binary
    // exposes — so this spawns it. (In-process coverage of the rejection
    // itself: st.rs's ST-09/ST-10 tests.)
    let proc = WitnessProcess::spawn();
    let mut stream = connect(proc.port);

    // Cosign (3, root A).
    let tree = tree_with_numbered_leaves(3);
    let body_a = request_body(0, &[], &proc.log.checkpoint_note(&tree, 3));
    let first = raw_request(&mut stream, "POST", "/add-checkpoint", body_a.as_bytes());
    assert_eq!(first.status, 200);

    // Snapshot what monitoring serves (the A note).
    let path = HttpFixture::monitoring_path(LOG_ORIGIN);
    let before = raw_request(&mut stream, "GET", &path, &[]);
    assert_eq!(before.status, 200);

    // The fork attempt: validly signed, old size matches, root differs.
    let forked = forked_tree(3);
    let body_b = request_body(3, &[], &proc.log.checkpoint_note(&forked, 3));
    let rejected = raw_request(&mut stream, "POST", "/add-checkpoint", body_b.as_bytes());
    assert_eq!(rejected.status, 422);
    assert_eq!(
        String::from_utf8(rejected.body).unwrap(),
        "same tree size but different root hash (possible fork)\n"
    );

    // MUST NOT cosign: monitoring still serves the A note, byte-for-byte,
    // and the state file holds exactly the one accepted record.
    let after = raw_request(&mut stream, "GET", &path, &[]);
    assert_eq!(after.status, 200);
    assert_eq!(after.body, before.body);
    let state_text = std::fs::read_to_string(&proc.state_file).unwrap();
    let records: Vec<&str> = state_text.lines().collect();
    assert_eq!(records.len(), 1);
    assert!(records[0].contains("\"size\":3"));

    // The evidence line fired on stderr, naming the origin, the reason, and
    // both sizes — and nothing else protocol-level was logged.
    let stderr = proc.into_stderr();
    let evidence: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("possible log misbehavior"))
        .collect();
    assert_eq!(evidence.len(), 1, "stderr was:\n{stderr}");
    assert!(evidence[0].contains(LOG_ORIGIN));
    assert!(evidence[0].contains("same tree size but different root hash"));
    assert!(evidence[0].contains("old size 3"));
    assert!(evidence[0].contains("checkpoint size 3"));
}

#[tokio::test]
async fn st_12_success_is_exactly_the_cosignature_lines() {
    // covers ST-12's exact wire format: one or more note signature lines,
    // each starting `— ` (U+2014 + 0x20) and ending '\n' — and nothing else.
    // Cross-ref: `post_add_checkpoint_happy_path` in tests/server.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let response = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;

    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "dual-signed: exactly two lines");
    assert!(body.ends_with('\n'), "last line terminated");
    assert!(!body.ends_with("\n\n"), "no trailing blank line");
    assert!(!body.starts_with('\n'), "no leading blank line");
    assert_eq!(body.matches('\n').count(), 2, "no other bytes");
    for line in &lines {
        assert!(line.starts_with("\u{2014} "), "line starts `— ` (U+2014)");
        assert!(!line.contains('\r'), "LF only");
    }

    // The lines ARE valid note signature lines for this checkpoint (the
    // response carries only the two cosignatures; the full cryptographic
    // assertions — and the log signature's presence in the STORED note —
    // are cs.rs's and sm.rs's sections).
    let combined = format!("{}\n{body}", fx.log.checkpoint_text(&tree, 3));
    let note = SignedNote::parse(&combined).unwrap();
    assert_eq!(note.signatures().len(), 2);
}

#[tokio::test]
async fn the_taxonomy_evaluation_order_is_the_specs() {
    // covers the §3 evaluation-order note (ST-01 → ST-02/03 → ST-05 → ST-06
    // → ST-07/08/09/10): requests that violate MULTIPLE rules must get the
    // EARLIER status. Cross-refs for the single-rule anchors: ST-01, ST-05
    // tests above (unknown origin beats 403/400; 400 beats 409 on empty
    // state).
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);

    // (a) malformed beats everything — a grammar violation is pre-taxonomy,
    //     so even an unknown origin gets 400, not 404.
    let response = submit(&fx.app, "old nope\n\nwhatever\n").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // (b) 403 beats 400: a trusted-key signature that fails verification is
    //     answered before any size check (old 9 > size 3 here).
    let tampered = tamper_last_signature(&fx.log.checkpoint_note(&tree, 3));
    let response = submit(&fx.app, request_body(9, &[], &tampered)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // (c) 400 beats 409/422: validly signed, old size above the checkpoint
    //     size, state still empty (a 409 would say 0; a garbage proof would
    //     be 422 — neither is reached).
    let response = submit(
        &fx.app,
        request_body(9, &[[7u8; 32]], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // (d) 409 beats 422: after cosigning 3, a stale old size with a BROKEN
    //     proof gets the size conflict, never the proof failure.
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;
    let response = submit(
        &fx.app,
        request_body(2, &[[9u8; 32]], &fx.log.checkpoint_note(&tree, 5)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(support::body_bytes(response).await, b"3\n");

    // (e) 409 beats 422 (ST-06 before ST-08): old 0 with a proof is a 422
    //     shape, but old 0 is also stale now — the conflict wins.
    let response = submit(
        &fx.app,
        request_body(0, &[[9u8; 32]], &fx.log.checkpoint_note(&tree, 5)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
