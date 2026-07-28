//! Threat-model invariant I3 (T2, docs/threat-model.md §4): no key material
//! egress. For BOTH cosigner seeds, the raw 32 bytes and their hex/base64
//! spellings must appear in NO HTTP response body across the whole status
//! taxonomy, nor in the startup banner, nor in ST-11's stderr evidence line.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mosskeys_witness::server::MAX_BODY_BYTES;
use tower::ServiceExt as _;

use crate::support::{
    self, HttpFixture, LOG_ORIGIN, TestLog, WitnessProcess, body_bytes, connect, forked_tree, get,
    origin_hash, post, raw_request, request_body, submit, tamper_last_signature,
    tree_with_numbered_leaves,
};

/// Assert `bytes` contains neither seed in any spelling (raw, hex, base64).
fn assert_scrubbed(context: &str, bytes: &[u8], seeds: &[[u8; 32]; 2]) {
    for (i, seed) in seeds.iter().enumerate() {
        let hex = support::hex(seed);
        let b64 = B64.encode(seed);
        for (spelling, needle) in [
            ("raw", &seed[..]),
            ("hex", hex.as_bytes()),
            ("base64", b64.as_bytes()),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "{context}: cosigner seed {i} leaked in {spelling} spelling"
            );
        }
    }
}

#[tokio::test]
async fn no_http_response_body_carries_seed_material() {
    // covers I3 across the whole taxonomy: 200 / 400 / 403 / 404 / 405 /
    // 409 / 413 / 422, submission and monitoring prefixes alike.
    let fx = HttpFixture::new();
    let seeds = fx.seeds();
    let tree = tree_with_numbered_leaves(3);
    let forked = forked_tree(3);
    let mut bodies: Vec<(&str, Vec<u8>)> = Vec::new();

    // 200 — the dual cosignature lines (they embed key ids and public
    // signatures: public material).
    let r = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    bodies.push(("200 POST /add-checkpoint", body_bytes(r).await));

    // 200 — the monitoring body (the full stored note).
    let r = fx
        .app
        .clone()
        .oneshot(get(&HttpFixture::monitoring_path(LOG_ORIGIN)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    bodies.push(("200 GET /{origin hash}/checkpoint", body_bytes(r).await));

    // 400 — malformed body.
    let r = submit(&fx.app, "old nope\n").await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    bodies.push(("400 malformed", body_bytes(r).await));

    // 403 — trusted name + key id, bad signature.
    let tampered = tamper_last_signature(&fx.log.checkpoint_note(&forked, 3));
    let r = submit(&fx.app, request_body(3, &[], &tampered)).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    bodies.push(("403 bad signature", body_bytes(r).await));

    // 404 — unknown origin.
    let stranger = TestLog::new("stranger.example/not-registered");
    let r = submit(
        &fx.app,
        request_body(0, &[], &stranger.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    bodies.push(("404 unknown origin", body_bytes(r).await));

    // 404 — unknown path.
    let r = fx
        .app
        .clone()
        .oneshot(post("/nope", "old 0\n"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    bodies.push(("404 unknown path", body_bytes(r).await));

    // 404 — monitoring, never-cosigned origin hash.
    let r = fx
        .app
        .clone()
        .oneshot(get(&format!(
            "/{}/checkpoint",
            origin_hash("example.com/never-cosigned")
        )))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    bodies.push(("404 monitoring miss", body_bytes(r).await));

    // 405 — GET on the submission path.
    let r = fx
        .app
        .clone()
        .oneshot(get("/add-checkpoint"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    bodies.push(("405 wrong method", body_bytes(r).await));

    // 409 — stale old size (the text/x.tlog.size body).
    let r = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    bodies.push(("409 size conflict", body_bytes(r).await));

    // 413 — over the 1 MiB body cap.
    let mut big = format!("old {}\n", u64::MAX);
    big.push_str(&"A".repeat(MAX_BODY_BYTES));
    let r = submit(&fx.app, big).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    bodies.push(("413 body cap", body_bytes(r).await));

    // 422 — a validly signed fork attempt at the cosigned size.
    let r = submit(
        &fx.app,
        request_body(3, &[], &fx.log.checkpoint_note(&forked, 3)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    bodies.push(("422 fork attempt", body_bytes(r).await));

    for (context, body) in &bodies {
        assert_scrubbed(context, body, &seeds);
    }
}

#[test]
fn the_startup_banner_and_st11_stderr_carry_no_seed_material() {
    // covers I3 for the two process-stderr surfaces: the startup banner
    // (public material only — name, vkeys, counts, paths) and ST-11's
    // misbehavior evidence line.
    let proc = WitnessProcess::spawn();
    let seeds = proc.seeds();

    // Drive ST-11's case so the evidence line is in stderr too.
    let mut stream = connect(proc.port);
    let tree = tree_with_numbered_leaves(3);
    let a = request_body(0, &[], &proc.log.checkpoint_note(&tree, 3));
    let first = raw_request(&mut stream, "POST", "/add-checkpoint", a.as_bytes());
    assert_eq!(first.status, 200);
    let forked = forked_tree(3);
    let b = request_body(3, &[], &proc.log.checkpoint_note(&forked, 3));
    let rejected = raw_request(&mut stream, "POST", "/add-checkpoint", b.as_bytes());
    assert_eq!(rejected.status, 422);

    let stderr = proc.into_stderr();

    // Sanity: we really captured the banner AND the evidence line.
    assert!(stderr.contains("witness name:"), "stderr was:\n{stderr}");
    assert!(stderr.contains("cosigner vkey:"), "stderr was:\n{stderr}");
    assert!(
        stderr.contains("possible log misbehavior"),
        "stderr was:\n{stderr}"
    );

    assert_scrubbed("process stderr", stderr.as_bytes(), &seeds);
}
