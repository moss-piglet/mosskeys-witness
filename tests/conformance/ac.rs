//! §2 add-checkpoint — request parsing (AC-01…AC-06), black-box through the
//! full stack. The parser's per-case detail has unit coverage in
//! `src/witness/tests.rs` (cross-referenced below); here every row is pinned
//! over HTTP.
//!
//! Assertion idiom: a grammar violation is pre-taxonomy → 400. A body that
//! PARSES reaches the taxonomy — with a checkpoint from an unregistered
//! origin that means 404 (ST-01), so "404 not 400" proves the grammar
//! accepted the body.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::note::SignedNote;

use crate::support::{HttpFixture, TestLog, request_body, submit, tree_with_numbered_leaves};

/// An unregistered origin: its notes parse fine but hit ST-01 → 404.
fn stranger() -> TestLog {
    TestLog::new("stranger.example/not-registered")
}

#[tokio::test]
async fn ac_01_body_shape_old_line_proofs_empty_line_checkpoint() {
    // covers AC-01 (cross-ref src/witness/tests.rs
    // `parses_a_minimal_valid_request`, `rejects_missing_separator_or_checkpoint`)
    let fx = HttpFixture::new();
    let stranger = stranger();
    let tree = tree_with_numbered_leaves(1);
    let note = stranger.checkpoint_note(&tree, 1);

    // Well-formed (no proof lines) → parsed; taxonomy reached (404).
    let response = submit(&fx.app, request_body(0, &[], &note)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Well-formed WITH proof lines and the empty separator → parsed (404).
    let proof = [[7u8; 32], [8u8; 32]];
    let response = submit(&fx.app, request_body(1, &proof, &note)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Missing the empty separator line: the note's first line is read as a
    // (non-base64) proof line → 400.
    let response = submit(&fx.app, format!("old 0\n{note}")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing the checkpoint entirely → 400.
    let response = submit(&fx.app, "old 0\n\n").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Empty body → 400.
    let response = submit(&fx.app, "").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ac_02_every_line_terminated_by_lf() {
    // covers AC-02 (cross-ref src/witness/tests.rs `rejects_missing_trailing_newline`)
    let fx = HttpFixture::new();
    let stranger = stranger();
    let tree = tree_with_numbered_leaves(1);
    let note = stranger.checkpoint_note(&tree, 1);

    // A body whose final line lacks its U+000A → 400.
    let mut body = request_body(0, &[], &note);
    assert_eq!(body.pop(), Some('\n'));
    let response = submit(&fx.app, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // CRLF line endings are not the grammar (the old-size line becomes
    // `old 0\r`) → 400.
    let crlf = request_body(0, &[], &note).replace('\n', "\r\n");
    let response = submit(&fx.app, crlf).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ac_03_old_size_line_grammar() {
    // covers AC-03: `old` + 0x20 + ASCII decimal, no leading zeroes.
    // (cross-ref src/witness/tests.rs `rejects_malformed_old_size_lines`)
    let fx = HttpFixture::new();
    let stranger = stranger();
    let tree = tree_with_numbered_leaves(1);
    let note = stranger.checkpoint_note(&tree, 1);

    for bad in [
        "old",                      // missing the size
        "old ",                     // empty size
        "old  1",                   // two spaces
        "old\t1",                   // tab is not 0x20
        "old 1 ",                   // trailing space
        " old 1",                   // leading space
        "old 00",                   // leading zero
        "old 01",                   // leading zero
        "old +1",                   // sign
        "old -1",                   // negative
        "old 1.0",                  // not an integer
        "old 0x10",                 // not decimal
        "old 18446744073709551616", // u64::MAX + 1 overflows
    ] {
        let response = submit(&fx.app, format!("{bad}\n\n{note}")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "line {bad:?}");
    }

    for good in [
        "old 0",                    // zero itself
        "old 1",                    // ordinary
        "old 18446744073709551615", // u64::MAX parses (taxonomy then 404s)
    ] {
        let response = submit(&fx.app, format!("{good}\n\n{note}")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "line {good:?}");
    }
}

#[tokio::test]
async fn ac_04_each_proof_line_is_one_base64_hash() {
    // covers AC-04 (cross-ref src/witness/tests.rs `rejects_bad_proof_lines`,
    // `parses_proof_lines`)
    let fx = HttpFixture::new();
    let stranger = stranger();
    let tree = tree_with_numbered_leaves(1);
    let note = stranger.checkpoint_note(&tree, 1);

    for line in [
        "not-base64!!!".to_string(), // invalid alphabet
        B64.encode([7u8; 31]),       // decodes to 31 bytes
        B64.encode([7u8; 33]),       // decodes to 33 bytes
        B64.encode([7u8; 32]).trim_end_matches('=').to_string(), // padding stripped
    ] {
        let response = submit(&fx.app, format!("old 1\n{line}\n\n{note}")).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "proof line {line:?}"
        );
    }

    // A proof line that IS one base64-encoded 32-byte hash parses → 404.
    let line = B64.encode([7u8; 32]);
    let response = submit(&fx.app, format!("old 1\n{line}\n\n{note}")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ac_05_proof_line_cap_is_exactly_63() {
    // covers AC-05: ≤63 proof lines is the spec's client-side MUST NOT; we
    // reject >63 gracefully as 400 malformed. The boundary is exact: 63
    // parses (the taxonomy then applies), 64 is 400.
    // (cross-ref src/witness/tests.rs `rejects_more_than_63_proof_lines`)
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(1);
    let note = fx.log.checkpoint_note(&tree, 1);

    // 63 lines parse; old 0 with a non-empty proof is then ST-08 → 422.
    let proof63 = vec![[7u8; 32]; 63];
    let response = submit(&fx.app, request_body(0, &proof63, &note)).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 64 lines never reach the taxonomy → 400.
    let proof64 = vec![[7u8; 32]; 64];
    let response = submit(&fx.app, request_body(0, &proof64, &note)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ac_06_multiple_signatures_parse_unknown_ones_ignored() {
    // covers AC-06 (+ ST-04): a checkpoint may carry several signature
    // lines; all are parsed and unknown keys are ignored — in EITHER order.
    // (cross-ref src/witness/tests.rs
    // `parses_multiple_signatures_including_unknown_keys`)
    let fx = HttpFixture::new();
    let stranger = stranger();

    let mut tree = tree_with_numbered_leaves(3);
    let text3 = fx.log.checkpoint_text(&tree, 3);
    let sigs = vec![fx.log.sign(&text3), stranger.sign(&text3)];
    let note = SignedNote::new(text3, sigs).unwrap().marshal();
    let response = submit(&fx.app, request_body(0, &[], &note)).await;
    assert_eq!(response.status(), StatusCode::OK);

    // The same pair in reverse order, chaining 3→5 with a valid proof.
    tree.push(b"leaf-3");
    tree.push(b"leaf-4");
    let text5 = fx.log.checkpoint_text(&tree, 5);
    let sigs = vec![stranger.sign(&text5), fx.log.sign(&text5)];
    let note = SignedNote::new(text5, sigs).unwrap().marshal();
    let proof = tree.consistency_proof(3, 5);
    let response = submit(&fx.app, request_body(3, &proof, &note)).await;
    assert_eq!(response.status(), StatusCode::OK);
}
