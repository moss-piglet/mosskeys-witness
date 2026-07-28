//! §5 State management & atomicity (SM-01…SM-05), anchoring threat-model
//! invariants I1 (no conflicting cosignatures at one size) and I2 (no
//! unpersisted cosignatures). This is the section that closes the
//! checklist's two 🟡 state rows.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::note::SignedNote;
use tower::ServiceExt as _;

use crate::support::{
    self, HttpFixture, LOG_ORIGIN, cosign_ok, forked_tree, monitoring_body, post, request_body,
    submit, tree_with_numbered_leaves,
};

#[tokio::test]
async fn sm_01_the_record_is_durable_before_the_200_is_sent() {
    // covers SM-01 + I2 (persist-before-respond): once the 200 exists, the
    // state file ALREADY holds the record — read the JSONL immediately.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let body = cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let records = fx.state_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["origin"], LOG_ORIGIN);
    assert_eq!(records[0]["size"], 3);
    assert_eq!(records[0]["root"], B64.encode(tree.root_at(3)));

    // The stored note is the checkpoint text + the log signature + exactly
    // the two cosignature lines the 200 returned (MP-03 readiness).
    let note = records[0]["note"].as_str().unwrap();
    let parsed = SignedNote::parse(note).unwrap();
    assert_eq!(parsed.text(), fx.log.checkpoint_text(&tree, 3));
    assert_eq!(parsed.signatures().len(), 3);
    parsed
        .verify(&[fx.log_vkey(), fx.ed_vkey(), fx.ml_vkey()])
        .unwrap();
    assert!(
        note.ends_with(&body),
        "the response lines are the stored note's last two lines"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sm_02_check_and_update_is_atomic_under_concurrent_submissions() {
    // covers SM-02: the old-size check and the state update happen under one
    // writer lock (the spec's worked race example). Eight IDENTICAL valid
    // 3→5 transitions race; exactly one may cosign.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;

    let proof = tree.consistency_proof(3, 5);
    let note = fx.log.checkpoint_note(&tree, 5);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let app = fx.app.clone();
        let body = request_body(3, &proof, &note);
        handles.push(tokio::spawn(async move {
            let response = app.oneshot(post("/add-checkpoint", body)).await.unwrap();
            (
                response.status(),
                crate::support::body_bytes(response).await,
            )
        }));
    }

    let mut oks = 0;
    let mut conflicts = 0;
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        match status {
            StatusCode::OK => {
                oks += 1;
                assert_eq!(String::from_utf8(body).unwrap().lines().count(), 2);
            }
            StatusCode::CONFLICT => {
                conflicts += 1;
                assert_eq!(body, b"5\n", "losers learn the new head");
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(oks, 1, "exactly one racer may cosign the 3→5 transition");
    assert_eq!(conflicts, 7);

    // The store recorded exactly the two accepted transitions (0→3, 3→5): a
    // single chain, no branching (I1 holds under concurrency).
    let records = fx.state_records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["size"], 3);
    assert_eq!(records[1]["size"], 5);
}

#[tokio::test]
async fn sm_03_only_the_latest_checkpoint_is_tracked_per_origin() {
    // covers SM-03: exactly the latest checkpoint per origin is tracked
    // (plus its cosigned note). After chaining 0→3→5, the size-3 head is
    // superseded everywhere — monitoring serves only 5.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;
    let proof = tree.consistency_proof(3, 5);
    cosign_ok(&fx.app, 3, &proof, &fx.log.checkpoint_note(&tree, 5)).await;

    let served = monitoring_body(&fx.app, LOG_ORIGIN).await;
    let note = SignedNote::parse(std::str::from_utf8(&served).unwrap()).unwrap();
    let checkpoint = metamorphic_log::checkpoint::Checkpoint::parse(note.text()).unwrap();
    assert_eq!(checkpoint.size(), 5);
    assert_eq!(served, fx.stored_note(LOG_ORIGIN).unwrap().as_bytes());
}

/// The store and the monitoring body must be EXACTLY as after the baseline
/// cosign: no record appended, the A note still served byte-for-byte.
async fn assert_untouched(fx: &HttpFixture, note_a3: &str, served_a3: &[u8]) {
    assert_eq!(
        fx.stored_note(LOG_ORIGIN).as_deref(),
        Some(note_a3),
        "store unchanged"
    );
    assert_eq!(fx.state_records().len(), 1, "no record appended");
    assert_eq!(
        monitoring_body(&fx.app, LOG_ORIGIN).await,
        served_a3,
        "monitoring unchanged"
    );
}

#[tokio::test]
async fn sm_04_the_witness_never_cosigns_two_roots_at_one_size() {
    // covers SM-04 + I1 (no conflicting cosignatures): the adversarial
    // fork-attempt matrix, with the store and the monitoring body asserted
    // after EVERY attempt.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5); // history A
    let forked = forked_tree(5); // history B ≠ A, same sizes

    // Baseline: cosign (3, root A).
    cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;
    let note_a3 = fx.stored_note(LOG_ORIGIN).unwrap();
    let served_a3 = monitoring_body(&fx.app, LOG_ORIGIN).await;

    // Attempt 1 — the classic fork: same size 3, different root → 422
    // (ST-10 SameSizeRootMismatch).
    let r = submit(
        &fx.app,
        request_body(3, &[], &fx.log.checkpoint_note(&forked, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_untouched(&fx, &note_a3, &served_a3).await;

    // Attempt 2 — a fork smuggled under a LARGER size: B's 5-leaf checkpoint
    // with B's own (for-B-valid) 3→5 consistency proof → 422 (ST-09: the
    // proof cannot bind A's stored head).
    let proof_b = forked.consistency_proof(3, 5);
    let r = submit(
        &fx.app,
        request_body(3, &proof_b, &fx.log.checkpoint_note(&forked, 5)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_untouched(&fx, &note_a3, &served_a3).await;

    // Attempt 3 — a rewind: old size < 3 → 409 carrying the current size
    // (ST-06 SizeConflict).
    let r = submit(
        &fx.app,
        request_body(1, &[], &fx.log.checkpoint_note(&tree, 5)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(support::body_bytes(r).await, b"3\n");
    assert_untouched(&fx, &note_a3, &served_a3).await;

    // Attempt 4 — idempotent re-sign of the SAME (3, A) checkpoint → 200:
    // roots are equal so there is no conflict (the consistency proof from 3
    // to 3 is empty). Re-signing the same view is safe.
    let proof_idem = tree.consistency_proof(3, 3);
    assert!(proof_idem.is_empty());
    let r = submit(
        &fx.app,
        request_body(3, &proof_idem, &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);

    // After the idempotent re-sign the head is still (3, A): the stored
    // size/root are unchanged, and the (freshly cosigned) monitoring body
    // still carries A's checkpoint text and verifies.
    let records = fx.state_records();
    let last = records.last().unwrap();
    assert_eq!(last["size"], 3);
    assert_eq!(last["root"], B64.encode(tree.root_at(3)));
    let served = monitoring_body(&fx.app, LOG_ORIGIN).await;
    let note = SignedNote::parse(std::str::from_utf8(&served).unwrap()).unwrap();
    assert_eq!(note.text(), fx.log.checkpoint_text(&tree, 3));
    note.verify(&[fx.log_vkey(), fx.ed_vkey(), fx.ml_vkey()])
        .unwrap();
}

#[tokio::test]
async fn sm_05_a_crash_after_persist_is_safe_the_retry_rebases_via_409() {
    // covers SM-05 + I2 (crash safety): the record is durable before the
    // response (SM-01), so a crash after persist but before respond leaves
    // exactly this state. The client then retries → 409 → rebases → 200.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(5);
    let note3 = fx.log.checkpoint_note(&tree, 3);
    let body = request_body(0, &[], &note3);
    let r = submit(&fx.app, body.clone()).await;
    assert_eq!(r.status(), StatusCode::OK);

    // Persist-before-respond: the state file already holds the record.
    assert_eq!(fx.state_records().len(), 1);

    // "Crash" and restart over the same state file (dropping the router
    // releases the exclusive store lock; replay rebuilds the state).
    // Cross-ref: the reopen pattern of tests/witness.rs's happy-path test.
    let fx = fx.restart();

    // The retry of the SAME request gets 409 with the now-current size —
    // the witness never double-signs.
    let r = submit(&fx.app, body).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.headers().get("content-type").unwrap(), "text/x.tlog.size");
    assert_eq!(support::body_bytes(r).await, b"3\n");

    // The client rebases onto the learned size with a valid proof → 200.
    let proof = tree.consistency_proof(3, 5);
    let r = submit(
        &fx.app,
        request_body(3, &proof, &fx.log.checkpoint_note(&tree, 5)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);

    // Final state after the restart: head 5, recorded and served.
    assert_eq!(fx.state_records().len(), 2);
    let served = monitoring_body(&fx.app, LOG_ORIGIN).await;
    let note = SignedNote::parse(std::str::from_utf8(&served).unwrap()).unwrap();
    let checkpoint = metamorphic_log::checkpoint::Checkpoint::parse(note.text()).unwrap();
    assert_eq!(checkpoint.size(), 5);
}
