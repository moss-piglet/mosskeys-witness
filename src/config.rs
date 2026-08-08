//! Operator configuration (TOML) and its startup validation.
//!
//! The config is deliberately a plain `(origin, vkey)` allowlist in the same
//! spirit as the files omniwitness/sigsum operators already maintain, so one
//! log fleet can be multi-homed across witness implementations without
//! translation tooling (threat model T8: unknown origins are `404` **by
//! construction** — there is no wildcard and no way to cosign for a log that
//! is not listed here).
//!
//! Everything in this module fails closed (invariant I4): a config that does
//! not parse, has unknown fields, duplicates an origin, or references an
//! unparsable vkey is a fatal startup error, never a warning.
//!
//! ## The managed file
//!
//! Besides manual `[[log]]` stanzas, the effective allowlist includes the
//! **managed file** [`MANAGED_FILE_NAME`] next to the state file, written
//! atomically by `mosskeys-witness sync` from the log-discovery feed. It is
//! loaded whenever present — no opt-in section required — so a cron'd
//! `sync` (exit 10 = restart) picks up new origins on its own. When the optional
//! `[discovery]` section is present, `run` additionally polls the feed
//! in-process on an interval and hot-swaps the allowlist with no restart at
//! all (see [`crate::discovery`]). Precedence rules:
//!
//! - A manual `[[log]]` stanza always wins over a managed entry for the same
//!   origin (the managed entry is skipped, with a warning).
//! - Origins that vanish from the feed vanish from the managed file — but
//!   their cosignature state is never deleted.
//! - The managed file is validated with the *same* fail-closed rules as the
//!   manual config; a malformed managed file is fatal.
//!
//! ## Format
//!
//! ```toml
//! # Witness identity (must match the name the seed files were minted for).
//! name = "witness.example/w1"
//!
//! # Socket the HTTP service binds (submission + monitoring prefixes share
//! # this one listener, GI-04).
//! listen = "0.0.0.0:8080"
//!
//! # Append-only state file (exclusive-locked, fsynced; see src/store.rs).
//! state_file = "/var/lib/mosskeys-witness/state.jsonl"
//!
//! # The two independently minted cosigner seeds (mode 0600, see `keygen`).
//! [keys]
//! ed25519_seed = "/etc/mosskeys-witness/keys/ed25519.seed"
//! mldsa44_seed = "/etc/mosskeys-witness/keys/mldsa44.seed"
//!
//! # Optional: keep the origin allowlist current from the log-discovery
//! # feed. With the section present, `run` polls the feed itself and
//! # hot-swaps the allowlist — no restarts, no cron.
//! # [discovery]
//! # feed_url = "https://mosskeys.com/api/witness/logs"
//! # interval_secs = 300
//!
//! # One [[log]] stanza per cosigned origin. Duplicate origins are fatal.
//! [[log]]
//! origin = "example.com/behind-the-sofa"
//! vkeys = ["example.com/behind-the-sofa+1a2b3c4d+AVS9..."]
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use metamorphic_log::note::VerifierKey;
use serde::Deserialize;

use crate::keygen::{self, KeygenError};

/// File name of the managed allowlist that `mosskeys-witness sync` maintains
/// as a sibling of the state file (see the module docs).
pub const MANAGED_FILE_NAME: &str = "discovered_logs.toml";

/// Default discovery-feed poll interval when `[discovery]` sets no
/// `interval_secs` (5 minutes: a new origin is cosigned within one interval,
/// and ETag-conditional polls cost a 304 in between).
pub const DEFAULT_INTERVAL_SECS: u64 = 300;

/// The managed allowlist path for a given state file: a sibling of it, so it
/// lives on the same volume and survives the same backups.
pub fn managed_file_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(MANAGED_FILE_NAME)
}

/// A fully validated runtime configuration (see module docs for the format).
#[derive(Debug)]
pub struct Config {
    /// Witness key name, embedded in every cosignature and vkey.
    pub name: String,
    /// Address the single HTTP listener binds.
    pub listen: SocketAddr,
    /// Path of the append-only state file.
    pub state_file: PathBuf,
    /// Seed file for the `0x04` Ed25519 cosigner.
    pub ed25519_seed: PathBuf,
    /// Seed file for the `0x06` ML-DSA-44 cosigner.
    pub mldsa44_seed: PathBuf,
    /// The cosigning allowlist: manual `[[log]]` stanzas plus the managed
    /// file's entries (manual wins on duplicate origins), in config order.
    pub logs: Vec<LogConfig>,
    /// The manual `[[log]]` stanzas only (the subset of `logs` that did not
    /// come from the managed file). The discovery poller re-applies "manual
    /// wins" precedence over every refreshed feed set when hot-swapping.
    pub manual_logs: Vec<LogConfig>,
    /// The `[discovery]` section when present: its presence alone switches
    /// `run` from merge-at-startup-only to in-process polling + hot-reload
    /// (see [`crate::discovery`]). `None` keeps the cron-`sync` workflow.
    pub discovery: Option<DiscoveryConfig>,
}

/// The optional `[discovery]` section: log-discovery feed settings. Consulted
/// by `mosskeys-witness sync` (feed URL) and, when the section is present at
/// all, by `run`'s in-process poller (feed URL + interval).
#[derive(Debug, Default)]
pub struct DiscoveryConfig {
    /// Feed URL override (default: `https://mosskeys.com/api/witness/logs`).
    pub feed_url: Option<String>,
    /// Poll interval override (default: [`DEFAULT_INTERVAL_SECS`]).
    pub interval_secs: Option<u64>,
}

impl DiscoveryConfig {
    /// The poll interval as a duration, applying the default.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS))
    }
}

/// One cosigned log: its origin line and the log public keys the witness
/// trusts checkpoints from (at least one).
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub origin: String,
    pub vkeys: Vec<VerifierKey>,
}

/// Configuration failures; every variant is fatal at startup (I4).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("config file {} is not valid TOML: {source}", .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    #[error("invalid witness name: {0}")]
    InvalidName(#[from] KeygenError),

    #[error("invalid listen address {0:?}: expected host:port (e.g. \"0.0.0.0:8080\")")]
    Listen(String),

    #[error("the ed25519_seed and mldsa44_seed paths are the same file ({}); the two cosigner identities must be independently minted key files (threat model T2)", .0.display())]
    SameSeedFile(PathBuf),

    #[error(
        "duplicate [[log]] origin {0:?}; each origin may appear exactly once (fail closed, I4)"
    )]
    DuplicateOrigin(String),

    #[error("[[log]] with empty origin; the origin is the checkpoint's first line")]
    EmptyOrigin,

    #[error("[[log]] {origin:?} has no vkeys; at least one trusted log key is required")]
    NoVkeys { origin: String },

    #[error("[[log]] {origin:?} vkey {vkey:?} does not parse: {reason}")]
    BadVkey {
        origin: String,
        vkey: String,
        reason: String,
    },

    #[error("[discovery] feed_url {0:?} is not an http(s) URL")]
    FeedUrl(String),

    #[error(
        "[discovery] interval_secs must be at least 1 (got 0); a zero interval would \
         hammer the feed in a hot loop"
    )]
    DiscoveryIntervalZero,

    #[error("cannot read managed log file {}: {source}", .path.display())]
    ManagedIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "managed log file {} is not valid TOML: {source}; it is written by \
         `mosskeys-witness sync` — repair by re-running sync or remove the file",
        .path.display()
    )]
    ManagedParse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
}

/// The raw TOML shape. `deny_unknown_fields` turns typos into fatal errors
/// instead of silently ignored settings (T8).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    name: String,
    listen: String,
    state_file: PathBuf,
    keys: RawKeys,
    #[serde(rename = "log", default)]
    logs: Vec<RawLog>,
    /// `Option`, not `#[serde(default)]`: the section's *presence* is the
    /// switch that turns on `run`'s in-process poller, so an absent section
    /// (`None`) and a present-but-empty one (`Some(default)`) must differ.
    discovery: Option<RawDiscovery>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeys {
    ed25519_seed: PathBuf,
    mldsa44_seed: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiscovery {
    feed_url: Option<String>,
    interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLog {
    origin: String,
    #[serde(default)]
    vkeys: Vec<String>,
}

/// The raw shape of the managed file: only `[[log]]` stanzas, written by
/// `mosskeys-witness sync`. Same `deny_unknown_fields` posture as the config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManaged {
    #[serde(rename = "log", default)]
    logs: Vec<RawLog>,
}

/// Load and validate the config at `path`, merging the managed file when
/// present. See the module docs for every check performed; any failure is a
/// fatal [`ConfigError`].
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(e),
    })?;
    validate(raw)
}

/// Validate one `(origin, vkeys)` entry into its runtime form. This is THE
/// fail-closed rule for allowlist entries, applied identically to manual
/// `[[log]]` stanzas, managed-file entries, and (in `crate::sync`) entries
/// fetched from the discovery feed — no new trust in malformed input,
/// wherever it came from.
pub fn validate_log_entry(origin: String, vkeys: Vec<String>) -> Result<LogConfig, ConfigError> {
    if origin.is_empty() {
        return Err(ConfigError::EmptyOrigin);
    }
    if vkeys.is_empty() {
        return Err(ConfigError::NoVkeys { origin });
    }
    let mut parsed = Vec::with_capacity(vkeys.len());
    for vkey in &vkeys {
        parsed.push(VerifierKey::parse(vkey).map_err(|e| ConfigError::BadVkey {
            origin: origin.clone(),
            vkey: vkey.clone(),
            reason: e.to_string(),
        })?);
    }
    Ok(LogConfig {
        origin,
        vkeys: parsed,
    })
}

/// Validate a parsed config into its runtime form (split out for tests).
fn validate(raw: RawConfig) -> Result<Config, ConfigError> {
    keygen::validate_name(&raw.name).map_err(ConfigError::InvalidName)?;

    let listen: SocketAddr = raw
        .listen
        .parse()
        .map_err(|_| ConfigError::Listen(raw.listen.clone()))?;

    if raw.keys.ed25519_seed == raw.keys.mldsa44_seed {
        return Err(ConfigError::SameSeedFile(raw.keys.ed25519_seed));
    }

    if let Some(discovery) = &raw.discovery {
        if let Some(feed_url) = &discovery.feed_url {
            if !(feed_url.starts_with("https://") || feed_url.starts_with("http://")) {
                return Err(ConfigError::FeedUrl(feed_url.clone()));
            }
        }
        if discovery.interval_secs == Some(0) {
            return Err(ConfigError::DiscoveryIntervalZero);
        }
    }

    let mut seen = HashSet::with_capacity(raw.logs.len());
    let mut manual_logs = Vec::with_capacity(raw.logs.len());
    for raw_log in raw.logs {
        if !seen.insert(raw_log.origin.clone()) {
            return Err(ConfigError::DuplicateOrigin(raw_log.origin));
        }
        manual_logs.push(validate_log_entry(raw_log.origin, raw_log.vkeys)?);
    }

    // Merge the managed file (written by `mosskeys-witness sync`) when
    // present: same validation, manual stanzas win on duplicate origins.
    let mut logs = manual_logs.clone();
    let managed_path = managed_file_path(&raw.state_file);
    if let Some(managed) = load_managed_entries(&managed_path)? {
        for log in managed {
            if seen.contains(&log.origin) {
                eprintln!(
                    "mosskeys-witness: managed entry {:?} skipped — a manual [[log]] stanza \
                     for this origin takes precedence",
                    log.origin
                );
                continue;
            }
            seen.insert(log.origin.clone());
            logs.push(log);
        }
    }

    Ok(Config {
        name: raw.name,
        listen,
        state_file: raw.state_file,
        ed25519_seed: raw.keys.ed25519_seed,
        mldsa44_seed: raw.keys.mldsa44_seed,
        logs,
        manual_logs,
        discovery: raw.discovery.map(|d| DiscoveryConfig {
            feed_url: d.feed_url,
            interval_secs: d.interval_secs,
        }),
    })
}

/// Read, parse, and validate the managed file at `path`: the same
/// fail-closed rules as manual stanzas, including duplicate-origin rejection
/// within the file (I4). `Ok(None)` when absent — the common case before the
/// first `sync`. Shared by config loading and `sync`'s change check.
pub fn load_managed_entries(path: &Path) -> Result<Option<Vec<LogConfig>>, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError::ManagedIo {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    let raw: RawManaged = toml::from_str(&text).map_err(|e| ConfigError::ManagedParse {
        path: path.to_path_buf(),
        source: Box::new(e),
    })?;
    let mut seen = HashSet::with_capacity(raw.logs.len());
    let mut logs = Vec::with_capacity(raw.logs.len());
    for raw_log in raw.logs {
        if !seen.insert(raw_log.origin.clone()) {
            return Err(ConfigError::DuplicateOrigin(raw_log.origin));
        }
        logs.push(validate_log_entry(raw_log.origin, raw_log.vkeys)?);
    }
    Ok(Some(logs))
}
