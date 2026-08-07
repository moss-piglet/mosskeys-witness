//! The in-process discovery poller: when `[discovery]` is present in
//! `witness.toml`, `run` keeps the origin allowlist current with zero
//! operator action — no cron, no restarts.
//!
//! One poll is exactly the one-shot `sync` pass ([`crate::sync::sync_feed`]:
//! ETag-conditional fetch, fail-closed validation identical to config load,
//! atomic managed-file rewrite), run on a blocking thread so the async
//! runtime never stalls. A changed set is then hot-swapped into the witness
//! ([`Witness::apply_managed_entries`]): new origins are cosigned within one
//! interval, dropped origins 404 (their cosignature state is never touched),
//! and vkey rotations apply as served — the operator-pinned feed is the
//! vetting boundary for managed entries (threat model T8).
//!
//! Deliberate asymmetry (I4): a corrupt managed file at *boot* is fatal —
//! there is no known-good state to fall back to — but a failed poll mid-run
//! (feed down, invalid JSON, an entry that fails validation) is logged and
//! the witness keeps serving the last known set. The poller can therefore
//! never shrink the allowlist below what validation accepts, and never take
//! the serving path down.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::sync::{FeedTarget, SyncOutcome, sync_feed};
use crate::witness::Witness;

/// Spawn the poll loop as a background task. The first poll runs immediately
/// (async — it never delays boot), then every `interval`. The loop runs until
/// the handle is aborted or the runtime shuts down.
pub fn spawn(witness: Arc<Witness>, target: FeedTarget, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(poll_loop(witness, target, interval))
}

/// The loop itself: tick, poll, apply, repeat. A late poll (e.g. a slow feed
/// hitting the request timeout) delays the next tick rather than bursting
/// catch-up polls at the feed — the operator's interval is a rate limit too.
async fn poll_loop(witness: Arc<Witness>, target: FeedTarget, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        poll_once(&witness, &target).await;
    }
}

/// One poll-and-apply pass: fetch/validate/write via the shared sync
/// primitive, and hot-swap the allowlist when the set changed. Every failure
/// is logged and non-fatal — the witness keeps serving the last known set.
pub async fn poll_once(witness: &Witness, target: &FeedTarget) {
    let blocking_target = target.clone();
    let result = tokio::task::spawn_blocking(move || sync_feed(&blocking_target)).await;
    match result {
        Ok(Ok(report)) => {
            if report.outcome == SyncOutcome::Updated {
                let entries = report
                    .entries
                    .expect("an Updated outcome always carries the feed's entries");
                let update = witness.apply_managed_entries(entries);
                eprintln!(
                    "mosskeys-witness: discovery update applied — allowlist now {} origins \
                     (+{} -{}, {} rotated)",
                    update.total,
                    update.added.len(),
                    update.removed.len(),
                    update.rotated.len(),
                );
                for (label, origins) in [
                    ("added", &update.added),
                    ("removed", &update.removed),
                    ("rotated", &update.rotated),
                ] {
                    if !origins.is_empty() {
                        eprintln!("  {label}: {}", origins.join(", "));
                    }
                }
            }
        }
        Ok(Err(e)) => eprintln!(
            "mosskeys-witness: discovery poll failed — keeping the current allowlist of \
             {} origins: {e}",
            witness.log_count(),
        ),
        Err(e) => eprintln!(
            "mosskeys-witness: discovery poll task failed — keeping the current allowlist of \
             {} origins: {e}",
            witness.log_count(),
        ),
    }
}
