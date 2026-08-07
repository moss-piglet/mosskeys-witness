//! One-shot discovery-feed sync (`mosskeys-witness sync`) — the certbot-renew
//! pattern for keeping the origin allowlist current without hand-editing
//! `witness.toml`.
//!
//! A witness only cosigns origins it is configured to trust (T8), so learning
//! about *new* origins is a polling problem. This module is the pull side:
//! fetch the log-discovery feed (default
//! <https://mosskeys.com/api/witness/logs>), validate every entry with the
//! **same fail-closed rules as config load** ([`crate::config::validate_log_entry`]
//! — no new trust in malformed input, wherever it came from), and write the
//! result atomically to the managed file
//! ([`crate::config::MANAGED_FILE_NAME`], a sibling of the state file). `run`
//! merges that file at startup whenever present, so a cron'd
//! `mosskeys-witness sync && systemctl restart mosskeys-witness` keeps the
//! allowlist current on its own.
//!
//! Polling is ETag-conditional: the validator from the last `200` is cached
//! next to the state file and sent as `If-None-Match`, so a tight cron costs
//! a `304` until the set actually changes. Exit codes follow the certbot
//! contract: `0` unchanged, `10` updated (restart the witness), `1` error.
//!
//! Trust posture: the configured feed is the vetting boundary for managed
//! entries — vkey changes on a managed origin are applied as served. Operators
//! who want to pin an origin's keys keep a manual `[[log]]` stanza for it,
//! which always wins over the managed file. Origins dropped from the feed are
//! dropped from the managed file, but their cosignature state is NEVER
//! deleted (see [`crate::store`]).
//!
//! This module is the ONLY networking client code in the crate; the `run`
//! serving path never dials out.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::config::{self, ConfigError, LogConfig};

/// The default log-discovery feed (a mosskeys deployment's public relay set).
pub const DEFAULT_FEED_URL: &str = "https://mosskeys.com/api/witness/logs";

/// File name of the ETag cache, a sibling of the state file.
pub const ETAG_FILE_NAME: &str = "discovered_logs.etag";

/// Response body cap for the feed (T4 spirit, applied client-side). The real
/// feed is KiB; anything near 1 MiB is not a log list.
const MAX_FEED_BYTES: u64 = 1 << 20;

/// Whole-request timeout: connect, TLS, headers, and body. One-shot cron
/// tooling fails fast and lets the next interval retry.
const FEED_TIMEOUT: Duration = Duration::from_secs(30);

/// What a sync run decided; the binary maps this onto the exit-code contract
/// (`0` unchanged, `10` updated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The feed was not modified (304), or served the set already on disk.
    Unchanged,
    /// The managed file was (re)written; a witness restart picks it up.
    Updated,
}

/// `sync` failures; every variant maps to exit code `1`.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{0}")]
    Config(#[from] ConfigError),

    #[error("discovery feed request failed: {0}")]
    Http(#[from] Box<ureq::Error>),

    #[error("discovery feed answered HTTP {0} (expected 200 or 304)")]
    Status(u16),

    #[error("discovery feed is not valid JSON: {0}")]
    FeedJson(#[from] serde_json::Error),

    #[error("discovery feed failed validation: {0}")]
    FeedEntry(ConfigError),

    #[error(
        "discovery feed served zero logs; refusing to empty the managed allowlist \
         (fail closed — an empty allowlist would 404 every submission, T8)"
    )]
    EmptyFeed,

    #[error("I/O error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// The feed's JSON shape: `{logs: [{origin, vkeys: {hybrid, ed25519}}]}`.
/// Unknown fields are tolerated (the feed may grow additively); missing ones
/// are a hard error (fail closed on a shape change).
#[derive(Debug, Deserialize)]
struct Feed {
    logs: Vec<FeedLog>,
}

#[derive(Debug, Deserialize)]
struct FeedLog {
    origin: String,
    vkeys: FeedVkeys,
}

#[derive(Debug, Deserialize)]
struct FeedVkeys {
    hybrid: String,
    ed25519: String,
}

/// The managed file's TOML shape: bare `[[log]]` stanzas, exactly what
/// [`crate::config`] merges at startup.
#[derive(Debug, Serialize)]
struct ManagedFile {
    #[serde(rename = "log")]
    logs: Vec<ManagedLog>,
}

#[derive(Debug, Serialize)]
struct ManagedLog {
    origin: String,
    vkeys: Vec<String>,
}

/// Run one sync pass: load the config (for the state file's directory and any
/// `[discovery] feed_url`), fetch the feed ETag-conditionally, and on change
/// validate + atomically rewrite the managed file.
///
/// `feed_url_override` (the `--feed-url` flag) wins over the config's
/// `[discovery] feed_url`, which wins over [`DEFAULT_FEED_URL`].
pub fn sync(
    config_path: &Path,
    feed_url_override: Option<&str>,
    quiet: bool,
) -> Result<SyncOutcome, SyncError> {
    let config = config::load(config_path)?;
    let feed_url = feed_url_override
        .or(config.discovery.feed_url.as_deref())
        .unwrap_or(DEFAULT_FEED_URL);
    let managed_path = config::managed_file_path(&config.state_file);
    let etag_path = config.state_file.with_file_name(ETAG_FILE_NAME);

    // Only condition the request when the managed file actually exists: a
    // cached ETag without the file it validated would turn a 304 into a
    // no-op that never restores the allowlist.
    let cached_etag = if managed_path.exists() {
        std::fs::read_to_string(&etag_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(FEED_TIMEOUT))
        .http_status_as_error(false)
        .user_agent(concat!("mosskeys-witness/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let mut request = agent.get(feed_url).header("Accept", "application/json");
    if let Some(etag) = &cached_etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().map_err(Box::new)?;

    match response.status().as_u16() {
        304 => {
            if !quiet {
                println!("mosskeys-witness sync: origin set unchanged (feed not modified)");
            }
            Ok(SyncOutcome::Unchanged)
        }
        200 => {
            let new_etag = response
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_FEED_BYTES)
                .read_to_string()
                .map_err(Box::new)?;
            let logs = parse_feed(&body)?;

            // The change check is the allowlist itself, not the bytes on
            // disk: a re-rendered header (e.g. a new feed URL serving the
            // same set) must not trigger a restart. A present-but-corrupt
            // managed file fails here, closed — same posture as config load.
            let existing = config::load_managed_entries(&managed_path)?;
            let outcome = if existing.is_some_and(|e| entries_of(&e) == entries_of(&logs)) {
                SyncOutcome::Unchanged
            } else {
                write_atomic(&managed_path, &render_managed(&logs, feed_url))?;
                SyncOutcome::Updated
            };
            save_etag(&etag_path, new_etag.as_deref());

            if !quiet {
                match outcome {
                    SyncOutcome::Unchanged => println!(
                        "mosskeys-witness sync: origin set unchanged ({} logs)",
                        logs.len()
                    ),
                    SyncOutcome::Updated => println!(
                        "mosskeys-witness sync: {} logs written to {} — restart the witness to apply",
                        logs.len(),
                        managed_path.display()
                    ),
                }
            }
            Ok(outcome)
        }
        status => Err(SyncError::Status(status)),
    }
}

/// Parse and validate the feed body into allowlist entries, applying the same
/// fail-closed rules as config load (plus: no duplicates, never empty).
fn parse_feed(body: &str) -> Result<Vec<LogConfig>, SyncError> {
    let feed: Feed = serde_json::from_str(body)?;
    if feed.logs.is_empty() {
        return Err(SyncError::EmptyFeed);
    }
    let mut seen = HashSet::with_capacity(feed.logs.len());
    let mut logs = Vec::with_capacity(feed.logs.len());
    for entry in feed.logs {
        if !seen.insert(entry.origin.clone()) {
            return Err(SyncError::FeedEntry(ConfigError::DuplicateOrigin(
                entry.origin,
            )));
        }
        logs.push(
            config::validate_log_entry(entry.origin, vec![entry.vkeys.hybrid, entry.vkeys.ed25519])
                .map_err(SyncError::FeedEntry)?,
        );
    }
    Ok(logs)
}

/// Canonical `(origin, encoded vkeys)` form for the change check.
fn entries_of(logs: &[LogConfig]) -> Vec<(String, Vec<String>)> {
    logs.iter()
        .map(|log| {
            (
                log.origin.clone(),
                log.vkeys.iter().map(|v| v.encode()).collect(),
            )
        })
        .collect()
}

/// Render the managed file deterministically (feed order, canonical vkey
/// encodings) with a provenance header.
fn render_managed(logs: &[LogConfig], feed_url: &str) -> String {
    let managed = ManagedFile {
        logs: logs
            .iter()
            .map(|log| ManagedLog {
                origin: log.origin.clone(),
                vkeys: log.vkeys.iter().map(|v| v.encode()).collect(),
            })
            .collect(),
    };
    let body = toml::to_string(&managed).expect("managed file serialization");
    format!(
        "# Managed by `mosskeys-witness sync` — do not edit.\n\
         # Feed: {feed_url}\n\
         # Manual [[log]] stanzas in witness.toml take precedence over duplicate origins here.\n\
         \n{body}"
    )
}

/// Write `contents` to `path` atomically: a temp file in the same directory,
/// fsynced, then renamed over the target (same-filesystem rename is atomic).
/// A crash can leave the temp file behind, never a half-written target.
fn write_atomic(path: &Path, contents: &str) -> Result<(), SyncError> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("discovered_logs.toml")
    ));
    let result = (|| -> std::io::Result<()> {
        let mut file = File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| SyncError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Cache the validator for the next run. A `200` without an `ETag` header
/// *removes* the cache: keeping a stale validator would invite `304`s for a
/// body we no longer hold. Write failures only cost a full refetch next run,
/// so they warn instead of failing the sync.
fn save_etag(path: &Path, etag: Option<&str>) {
    match etag {
        Some(etag) => {
            if let Err(e) = std::fs::write(path, format!("{etag}\n")) {
                eprintln!(
                    "mosskeys-witness sync: could not cache the feed ETag to {} ({e}); \
                     the next sync re-fetches in full",
                    path.display()
                );
            }
        }
        None => match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "mosskeys-witness sync: could not remove stale ETag cache {} ({e})",
                path.display()
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metamorphic_log::note::VerifierKey;

    /// A valid vkey line for `origin` (Ed25519 0x01), tests only.
    fn vkey(origin: &str) -> String {
        let (_seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
        VerifierKey::new_ed25519(origin, &pk).unwrap().encode()
    }

    fn feed_json(entries: &[(&str, &str, &str)]) -> String {
        let logs: Vec<serde_json::Value> = entries
            .iter()
            .map(|(origin, hybrid, ed25519)| {
                serde_json::json!({
                    "origin": origin,
                    "vkeys": { "hybrid": hybrid, "ed25519": ed25519 },
                })
            })
            .collect();
        serde_json::json!({ "logs": logs }).to_string()
    }

    #[test]
    fn parse_feed_validates_and_preserves_order() {
        let o1 = "example.com/log-one";
        let o2 = "example.com/log-two";
        let body = feed_json(&[(o1, &vkey(o1), &vkey(o1)), (o2, &vkey(o2), &vkey(o2))]);
        let logs = parse_feed(&body).unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].origin, o1);
        assert_eq!(logs[1].origin, o2);
        assert_eq!(logs[0].vkeys.len(), 2);
    }

    #[test]
    fn parse_feed_rejects_malformed_json() {
        assert!(matches!(
            parse_feed("not json"),
            Err(SyncError::FeedJson(_))
        ));
        // Missing vkeys object: shape change, fail closed.
        assert!(matches!(
            parse_feed(r#"{"logs":[{"origin":"example.com/l"}]}"#),
            Err(SyncError::FeedJson(_))
        ));
    }

    #[test]
    fn parse_feed_rejects_empty_feed() {
        assert!(matches!(
            parse_feed(r#"{"logs":[]}"#),
            Err(SyncError::EmptyFeed)
        ));
    }

    #[test]
    fn parse_feed_rejects_duplicate_origins() {
        let o = "example.com/log";
        let body = feed_json(&[(o, &vkey(o), &vkey(o)), (o, &vkey(o), &vkey(o))]);
        assert!(matches!(
            parse_feed(&body),
            Err(SyncError::FeedEntry(ConfigError::DuplicateOrigin(_)))
        ));
    }

    #[test]
    fn parse_feed_rejects_bad_vkey_with_same_rules_as_config() {
        let o = "example.com/log";
        let body = feed_json(&[(o, "not-a-vkey", &vkey(o))]);
        assert!(matches!(
            parse_feed(&body),
            Err(SyncError::FeedEntry(ConfigError::BadVkey { .. }))
        ));
    }

    #[test]
    fn parse_feed_rejects_empty_origin() {
        let body = feed_json(&[("", &vkey("x"), &vkey("x"))]);
        assert!(matches!(
            parse_feed(&body),
            Err(SyncError::FeedEntry(ConfigError::EmptyOrigin))
        ));
    }

    #[test]
    fn render_managed_is_deterministic_and_round_trips() {
        let o = "example.com/log";
        let body = feed_json(&[(o, &vkey(o), &vkey(o))]);
        let logs = parse_feed(&body).unwrap();
        let first = render_managed(&logs, DEFAULT_FEED_URL);
        let second = render_managed(&logs, DEFAULT_FEED_URL);
        assert_eq!(first, second, "rendering must be byte-stable");
        assert!(first.starts_with("# Managed by `mosskeys-witness sync`"));
        assert!(first.contains("[[log]]"));
        assert!(first.contains(&format!("origin = \"{o}\"")));
    }
}
