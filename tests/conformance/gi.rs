//! §1 HTTP interface — general (GI-01…GI-05). GI-05 (https-bastion) is ➖
//! out of scope for v0 (documented in the checklist §7), so it has no test.

use axum::http::StatusCode;
use tower::ServiceExt as _;

use crate::support::{
    self, HttpFixture, WitnessProcess, connect, origin_hash, post, raw_request, request_body,
    submit, tree_with_numbered_leaves,
};

#[tokio::test]
async fn add_checkpoint_lives_at_the_exact_submission_path() {
    // covers GI-01: the endpoint is exactly `POST <prefix>/add-checkpoint`
    // (the prefix is the listener root here); near-miss paths are NOT the
    // endpoint. Cross-ref: `unknown_paths_are_404` in tests/server.rs.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let response = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(&tree, 3)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    for path in [
        "/add-checkpoint/",  // trailing slash
        "/Add-Checkpoint",   // case
        "/add-checkpoint/x", // extra segment
        "/checkpoint",       // monitoring path without its origin hash
        "/",                 // listener root
    ] {
        let response = fx.app.clone().oneshot(post(path, "old 0\n")).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

#[tokio::test]
async fn only_post_reaches_add_checkpoint() {
    // covers GI-02: the request is an HTTP POST; every other method is 405.
    // Cross-ref: `non_post_methods_are_rejected` in tests/server.rs (same
    // matrix; this is the conformance-suite citation).
    let fx = HttpFixture::new();
    for method in ["GET", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
        let response = fx
            .app
            .clone()
            .oneshot(support::method(method, "/add-checkpoint"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not reach the handler"
        );
    }
}

#[test]
fn one_keep_alive_connection_serves_sequential_requests_on_both_prefixes() {
    // covers GI-03 (keep-alive) + GI-04 (submission and monitoring prefixes
    // share one listener). These are connection-level properties that
    // `Router::oneshot` bypasses, so they drive the real binary over TCP.
    // GI-04 is also pinned in-process by every mp.rs test (one router serves
    // both prefixes).
    let proc = WitnessProcess::spawn();
    let mut stream = connect(proc.port);

    let tree = tree_with_numbered_leaves(3);
    let body = request_body(0, &[], &proc.log.checkpoint_note(&tree, 3));

    let first = raw_request(&mut stream, "POST", "/add-checkpoint", body.as_bytes());
    assert_eq!(first.status, 200);
    assert!(first.body.starts_with("\u{2014} ".as_bytes()));

    // The SAME connection takes a second request (keep-alive, GI-03) — and
    // the protocol answers with live state (ST-06's 409), proving the first
    // exchange completed on this socket.
    let second = raw_request(&mut stream, "POST", "/add-checkpoint", body.as_bytes());
    assert_eq!(second.status, 409);
    assert_eq!(second.header("content-type"), Some("text/x.tlog.size"));
    assert_eq!(second.body, b"3\n");

    // Third request, still one connection: the monitoring prefix on the same
    // listener (GI-04).
    let path = format!("/{}/checkpoint", origin_hash(support::LOG_ORIGIN));
    let third = raw_request(&mut stream, "GET", &path, &[]);
    assert_eq!(third.status, 200);
    assert!(third.body.starts_with(support::LOG_ORIGIN.as_bytes()));
    assert!(String::from_utf8(third.body).unwrap().contains("\u{2014} "));

    let _ = proc.into_stderr();
}

#[tokio::test]
async fn both_prefixes_share_one_listener_in_process() {
    // covers GI-04 at the router level: one `server::router` (one listener
    // in production) serves a POST submission and the GET for what it just
    // cosigned. The wire-level citation is the keep-alive test above.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let cosigned = support::cosign_ok(&fx.app, 0, &[], &fx.log.checkpoint_note(&tree, 3)).await;
    assert_eq!(cosigned.lines().count(), 2);

    let body = support::monitoring_body(&fx.app, support::LOG_ORIGIN).await;
    let text = String::from_utf8(body).unwrap();
    assert!(text.starts_with(&fx.log.checkpoint_text(&tree, 3)));
}
