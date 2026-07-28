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
//! # One [[log]] stanza per cosigned origin. Duplicate origins are fatal.
//! [[log]]
//! origin = "example.com/behind-the-sofa"
//! vkeys = ["example.com/behind-the-sofa+1a2b3c4d+AVS9..."]
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use metamorphic_log::note::VerifierKey;
use serde::Deserialize;

use crate::keygen::{self, KeygenError};

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
    /// The cosigning allowlist, in config order.
    pub logs: Vec<LogConfig>,
}

/// One cosigned log: its origin line and the log public keys the witness
/// trusts checkpoints from (at least one).
#[derive(Debug)]
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
        source: toml::de::Error,
    },

    #[error("invalid witness name: {0}")]
    InvalidName(#[from] KeygenError),

    #[error("invalid listen address {0:?}: expected host:port (e.g. \"0.0.0.0:8080\")")]
    Listen(String),

    #[error("the ed25519_seed and mldsa44_seed paths are the same file ({}); the two cosigner identities must be independently minted key files (threat model T2)", .0.display())]
    SameSeedFile(PathBuf),

    #[error(
        "no [[log]] stanzas configured; a witness with an empty allowlist would 404 every submission (threat model T8)"
    )]
    NoLogs,

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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeys {
    ed25519_seed: PathBuf,
    mldsa44_seed: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLog {
    origin: String,
    #[serde(default)]
    vkeys: Vec<String>,
}

/// Load and validate the config at `path`. See the module docs for every
/// check performed; any failure is a fatal [`ConfigError`].
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: e,
    })?;
    validate(raw)
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

    if raw.logs.is_empty() {
        return Err(ConfigError::NoLogs);
    }
    let mut seen = HashSet::with_capacity(raw.logs.len());
    let mut logs = Vec::with_capacity(raw.logs.len());
    for raw_log in raw.logs {
        if raw_log.origin.is_empty() {
            return Err(ConfigError::EmptyOrigin);
        }
        if !seen.insert(raw_log.origin.clone()) {
            return Err(ConfigError::DuplicateOrigin(raw_log.origin));
        }
        if raw_log.vkeys.is_empty() {
            return Err(ConfigError::NoVkeys {
                origin: raw_log.origin,
            });
        }
        let mut vkeys = Vec::with_capacity(raw_log.vkeys.len());
        for vkey in &raw_log.vkeys {
            vkeys.push(VerifierKey::parse(vkey).map_err(|e| ConfigError::BadVkey {
                origin: raw_log.origin.clone(),
                vkey: vkey.clone(),
                reason: e.to_string(),
            })?);
        }
        logs.push(LogConfig {
            origin: raw_log.origin,
            vkeys,
        });
    }

    Ok(Config {
        name: raw.name,
        listen,
        state_file: raw.state_file,
        ed25519_seed: raw.keys.ed25519_seed,
        mldsa44_seed: raw.keys.mldsa44_seed,
        logs,
    })
}
