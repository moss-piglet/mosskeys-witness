//! The HTTP surface: one listener serving both the submission prefix
//! (`POST /add-checkpoint`) and the monitoring prefix
//! (`GET /<origin hash>/checkpoint`, MP-01) — the single-listener layout
//! GI-04 permits — with the threat model's T4 hardening applied
//! (GI-01…GI-03).
//!
//! The full API is mounted TWICE on that listener: at the root, and —
//! when the configured witness `name` carries a path component — under
//! that path (C2SP tlog-witness: a witness's API prefix is its name's
//! path, so a witness named `witness.example/mosskeys` answers under
//! `/mosskeys`). The root mount is back-compat for root-registered
//! prefixes already in the wild and is the only mount for host-only
//! names. Both mounts are the same handlers over the same state.
//!
//! Deliberately thin: every protocol decision lives in [`crate::witness`];
//! this module only renders the taxonomy onto the wire and owns the
//! socket-level concerns, plus the one background task of `run`: the
//! discovery poller ([`crate::discovery`]) spawned when `[discovery]` is
//! configured.
//!
//! - **1 MiB body cap**, enforced by axum's extractor layer *before* a
//!   single byte is parsed (T4; a max-size request is a few KiB).
//! - **Header-read timeout** on the HTTP/1 connection (slowloris guard)
//!   plus a whole-request timeout (body dribble + handling) (T4).
//! - **Bounded in-flight concurrency** (T4), with HTTP keep-alive retained
//!   (GI-03): latency-friendly for the log↔witness long-tail, cheap under
//!   flood.
//! - **Method-strict** routing: POST-only for `/add-checkpoint` (GI-02),
//!   GET-only for the monitoring path; everything else falls through to
//!   `404`, unimplemented spec routes (`sign-subtree`) included (v0
//!   out-of-scope, see docs/spec-conformance.md §7).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path as PathParam, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::signal;
use tower::ServiceExt as _;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::config::{self, ConfigError};
use crate::discovery;
use crate::sync::FeedTarget;
use crate::witness::{Reject, StartupError, Witness, WitnessError};

/// Hard request-body cap, enforced before parsing (T4). A checkpoint with
/// the maximum 63 proof lines is a few KiB; 1 MiB is generous headroom.
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// Slowloris guard: a connection must deliver its request headers within
/// this budget (T4).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Whole-request guard: body read + handling (T4). The protocol is
/// synchronous and handling is milliseconds, so this is entirely about
/// dribbling clients.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// In-flight request bound (T4). Witness traffic is a long tail of rarely
/// active logs; 512 concurrent submissions is far above expected load and
/// far below resource exhaustion.
const MAX_CONCURRENT_REQUESTS: usize = 512;

/// Build the service router. Separated from [`run`] so tests can drive the
/// full stack in-process (task 7's conformance suite uses it too).
pub fn router(witness: Witness) -> Router {
    router_shared(Arc::new(witness))
}

/// Build the router over an already-shared witness — the shape `run` needs,
/// so the discovery poller can hot-swap the same instance the router serves.
pub fn router_shared(witness: Arc<Witness>) -> Router {
    // C2SP tlog-witness: the API prefix is the witness name's path
    // component (`Witness::prefix`). Mount the full API under it, and at
    // the listener root too — back-compat for root-registered prefixes
    // already in the wild, and the only mount for host-only names. Same
    // handlers, same state; the layers below wrap both mounts.
    let mut app = mount_api(Router::new(), "");
    let prefix = witness.prefix();
    if !prefix.is_empty() {
        app = mount_api(app, prefix);
    }
    app
        // Layers apply outward-in: the concurrency bound is the cheap outer
        // gate, then the request timeout, then the body cap at extraction.
        // Routes are all registered BEFORE the layers — axum layers only
        // wrap routes registered before them, and the T4 timeout/concurrency
        // bounds must cover every mount.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .with_state(witness)
}

/// The whole protocol surface under one base path: the submission endpoint
/// (`POST <base>/add-checkpoint`, GI-01) and the monitoring endpoint
/// (`GET <base>/<origin hash>/checkpoint`, MP-01, on the same listener —
/// GI-04). `base` is `""` for the root mount or the name-derived prefix
/// (e.g. `"/mosskeys"`); [`crate::config::prefix_from_name`] guarantees the
/// prefix is a plain static path, so it can never smuggle router syntax
/// into these patterns.
fn mount_api(router: Router<Arc<Witness>>, base: &str) -> Router<Arc<Witness>> {
    router
        .route(&format!("{base}/add-checkpoint"), post(add_checkpoint))
        .route(
            &format!("{base}/{{origin_hash}}/checkpoint"),
            get(latest_checkpoint),
        )
}

/// `POST /add-checkpoint` (GI-01): the entire submission protocol.
async fn add_checkpoint(State(witness): State<Arc<Witness>>, body: String) -> Response {
    match witness.add_checkpoint(&body) {
        // ST-12/CS-01: one or more cosignature lines, `— name ...\n` each.
        Ok(cosignatures) => (StatusCode::OK, cosignatures).into_response(),
        Err(WitnessError::Rejected(reject)) => reject_response(reject),
        Err(e) => {
            // 500: nothing was persisted for this request (I2), so the
            // client's retry simply re-syncs via the 409 flow (SM-05).
            eprintln!("mosskeys-witness: internal error serving add-checkpoint: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /<origin hash>/checkpoint` (MP-01): the monitoring prefix. Serves
/// the stored cosigned note **verbatim** — nothing is reconstructed or
/// re-signed (MP-03), and the read is synchronous from the same store the
/// submission path writes, so the served head is never stale (MP-05).
async fn latest_checkpoint(
    State(witness): State<Arc<Witness>>,
    PathParam(origin_hash): PathParam<String>,
) -> Response {
    // MP-02: the origin hash is exactly 64 lowercase-hex chars (SHA-256).
    // Any other shape can never equal a hash the store computed, so it
    // misses the lookup either way — this guard is only a cheap fast path,
    // and 404 remains the single permitted outcome for every miss.
    if !is_origin_hash(&origin_hash) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match witness.latest_by_origin_hash(&origin_hash) {
        // MP-03: the note already carries the checkpoint text, the log
        // signature(s) the witness verified, and our two cosignature lines,
        // and ends in '\n'. The spec mandates no Content-Type here, so the
        // String default (text/plain; charset=utf-8) stands.
        Some(state) => state.note.into_response(),
        // MP-04: never cosigned a checkpoint for this origin hash.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The MP-02 shape: exactly 64 lowercase-hex characters (SHA-256). Inputs
/// of any other shape (uppercase, wrong length, non-hex) cannot match a
/// computed hash, so they 404 without touching the store.
fn is_origin_hash(param: &str) -> bool {
    param.len() == 64
        && param
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b <= b'f')
}

/// Render the spec's status taxonomy onto the wire (I5).
fn reject_response(reject: Reject) -> Response {
    match reject {
        // ST-06: the body is the latest cosigned size in decimal + '\n',
        // with the spec-mandated content type.
        Reject::SizeConflict(latest_size) => (
            StatusCode::CONFLICT,
            [(header::CONTENT_TYPE, "text/x.tlog.size")],
            format!("{latest_size}\n"),
        )
            .into_response(),
        other => (
            StatusCode::from_u16(other.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            format!("{}\n", other.message()),
        )
            .into_response(),
    }
}

/// `mosskeys-witness run` failures.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    Config(#[from] ConfigError),

    #[error("{0}")]
    Startup(#[from] StartupError),

    #[error("cannot bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Load the config, build the witness (all startup hard-checks, I4), bind
/// the listener, and serve until SIGINT/SIGTERM. When the config carries a
/// `[discovery]` section, the in-process poller is spawned alongside: its
/// first poll runs immediately but async, so boot never waits on the feed.
pub async fn run(config_path: &Path) -> Result<(), RunError> {
    let config = config::load(config_path)?;
    let listen = config.listen;
    let state_file = config.state_file.clone();
    let discovery_target = config
        .discovery
        .as_ref()
        .map(|d| (FeedTarget::from_config(&config, None), d.interval()));
    let witness = Arc::new(Witness::from_config(&config)?);

    // Startup banner: public material only (I3 — never seed bytes).
    eprintln!("mosskeys-witness {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  witness name: {}", witness.name());
    for vkey in witness.vkeys() {
        eprintln!("  cosigner vkey: {vkey}");
    }
    eprintln!("  logs configured: {}", witness.log_count());
    eprintln!("  state file: {}", state_file.display());
    if let Some((target, interval)) = &discovery_target {
        eprintln!(
            "  discovery: polling {} every {}s (hot-reload; failures keep the current set)",
            target.feed_url,
            interval.as_secs()
        );
    }

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| RunError::Bind {
            addr: listen,
            source: e,
        })?;
    eprintln!("  listening on {listen} — POST /add-checkpoint, GET /<origin hash>/checkpoint");
    let prefix = witness.prefix();
    if !prefix.is_empty() {
        eprintln!(
            "  name prefix {prefix} — also serving POST {prefix}/add-checkpoint, GET {prefix}/<origin hash>/checkpoint"
        );
    }

    // The poller is spawned only after the bind succeeds: a witness that
    // cannot serve has no business learning new origins.
    let poller = discovery_target
        .map(|(target, interval)| discovery::spawn(witness.clone(), target, interval));

    serve(listener, router_shared(witness)).await;
    if let Some(handle) = poller {
        handle.abort();
    }
    eprintln!("mosskeys-witness: stopped");
    Ok(())
}

/// Accept connections until the shutdown signal, serving each on the shared
/// router through hyper's HTTP/1+2 auto-detect with the T4 timeouts.
/// Keep-alive stays on (GI-03); the header-read timeout bounds its abuse.
async fn serve(listener: TcpListener, app: Router) {
    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let stream = match accept {
                    Ok((stream, _peer)) => stream,
                    Err(e) => {
                        eprintln!("mosskeys-witness: accept error (continuing): {e}");
                        continue;
                    }
                };
                let tower_service = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().oneshot(request)
                    });
                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT);
                    builder.http2().timer(TokioTimer::new());
                    let _ = builder.serve_connection_with_upgrades(io, service).await;
                });
            }
            () = &mut shutdown => {
                eprintln!("mosskeys-witness: shutdown signal received, draining");
                break;
            }
        }
    }
}

/// SIGINT (Ctrl+C) everywhere, SIGTERM on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
