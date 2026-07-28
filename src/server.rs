//! The HTTP surface: one listener serving the submission prefix
//! (`POST /add-checkpoint`) — and, from the next task, the monitoring
//! prefix on the same listener (GI-04) — with the threat model's T4
//! hardening applied (GI-01…GI-03).
//!
//! Deliberately thin: every protocol decision lives in [`crate::witness`];
//! this module only renders the taxonomy onto the wire and owns the
//! socket-level concerns:
//!
//! - **1 MiB body cap**, enforced by axum's extractor layer *before* a
//!   single byte is parsed (T4; a max-size request is a few KiB).
//! - **Header-read timeout** on the HTTP/1 connection (slowloris guard)
//!   plus a whole-request timeout (body dribble + handling) (T4).
//! - **Bounded in-flight concurrency** (T4), with HTTP keep-alive retained
//!   (GI-03): latency-friendly for the log↔witness long-tail, cheap under
//!   flood.
//! - **POST-only** routing for `/add-checkpoint` (GI-02); everything else
//!   falls through to `404`, unimplemented spec routes (`sign-subtree`)
//!   included (v0 out-of-scope, see docs/spec-conformance.md §7).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::signal;
use tower::ServiceExt as _;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::config::{self, ConfigError};
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
    Router::new()
        .route("/add-checkpoint", post(add_checkpoint))
        // Layers apply outward-in: the concurrency bound is the cheap outer
        // gate, then the request timeout, then the body cap at extraction.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .with_state(Arc::new(witness))
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
/// the listener, and serve until SIGINT/SIGTERM.
pub async fn run(config_path: &Path) -> Result<(), RunError> {
    let config = config::load(config_path)?;
    let listen = config.listen;
    let state_file = config.state_file.clone();
    let witness = Witness::from_config(&config)?;

    // Startup banner: public material only (I3 — never seed bytes).
    eprintln!("mosskeys-witness {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  witness name: {}", witness.name());
    for vkey in witness.vkeys() {
        eprintln!("  cosigner vkey: {vkey}");
    }
    eprintln!("  logs configured: {}", witness.log_count());
    eprintln!("  state file: {}", state_file.display());

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| RunError::Bind {
            addr: listen,
            source: e,
        })?;
    eprintln!("  listening on {listen} — POST /add-checkpoint");

    serve(listener, router(witness)).await;
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
