//! Witness cosigner key generation.
//!
//! A mosskeys-witness identity is **two independently minted keypairs**
//! (threat model T2): an Ed25519 pair whose cosignatures interop with today's
//! deployed tooling (vkey signature type `0x04`), and an ML-DSA-44 pair for
//! post-quantum cosignatures (type `0x06`, the tlog-witness spec's recommended
//! type). The pairs share no seed material, so compromise of one file does not
//! imply compromise of the other identity.
//!
//! The secret seeds are written as individual `0600` files that
//! [`generate`] refuses to overwrite (fail closed, T2/T8). Only the public
//! verifier keys (vkeys, in the C2SP signed-note encoding) are ever printed —
//! those are what log operators and witness registries (including a mosskeys
//! deployment's) need in order to trust this witness's cosignatures.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::note::VerifierKey;
use zeroize::Zeroizing;

/// One cosigner suite the witness signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `0x04` — C2SP tlog-cosignature v1 Ed25519 (classical interop).
    Ed25519,
    /// `0x06` — C2SP tlog-cosignature v1 ML-DSA-44 (post-quantum).
    MlDsa44,
}

impl Suite {
    /// All suites the witness dual-signs with, in output order.
    pub const ALL: [Suite; 2] = [Suite::Ed25519, Suite::MlDsa44];

    /// Lowercase tag used in seed filenames and file headers.
    pub fn tag(self) -> &'static str {
        match self {
            Suite::Ed25519 => "ed25519",
            Suite::MlDsa44 => "mldsa44",
        }
    }

    /// The C2SP cosignature type byte, for display.
    pub fn type_byte(self) -> u8 {
        match self {
            Suite::Ed25519 => 0x04,
            Suite::MlDsa44 => 0x06,
        }
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Suite::Ed25519 => write!(f, "Ed25519 (0x04)"),
            Suite::MlDsa44 => write!(f, "ML-DSA-44 (0x06)"),
        }
    }
}

/// One freshly generated cosigner keypair: the public vkey line to hand to
/// log operators, and the path of the `0600` seed file to keep secret.
#[derive(Debug)]
pub struct GeneratedKey {
    pub suite: Suite,
    pub vkey: String,
    pub seed_file: PathBuf,
}

/// The complete witness identity: one [`GeneratedKey`] per [`Suite::ALL`].
#[derive(Debug)]
pub struct Identity {
    pub name: String,
    pub keys: Vec<GeneratedKey>,
}

/// Keygen failures. All variants fail closed: nothing is cosigned, and any
/// already-written seed file from this run is left untouched on disk for the
/// operator to inspect or remove (never silently overwritten later).
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error(
        "invalid witness name {0:?}: must be non-empty and contain no whitespace or '+' \
         (a schema-less URL like `witness.example/w1`, per the tlog-cosignature spec)"
    )]
    InvalidName(String),

    #[error("seed file {} already exists; refusing to overwrite key material (move it aside or choose a fresh --out-dir)", .0.display())]
    SeedFileExists(PathBuf),

    #[error("I/O error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to derive vkey for {0}: {1}")]
    Vkey(Suite, String),

    #[error(
        "seed file {} is accessible by group/others (mode {mode:04o}); key files must be \
         owner-only — run `chmod 600 {}` (threat model T2)",
        .path.display(),
        .path.display()
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error(
        "seed file {} was minted for witness {found:?}, but the configured witness name is \
         {want:?}; refusing to cosign with a mismatched identity (threat model T8)",
        .path.display()
    )]
    NameMismatch {
        path: PathBuf,
        want: String,
        found: String,
    },

    #[error(
        "seed file {} carries a vkey comment that does not match the key derived from its \
         seed (file corrupt or hand-edited); refusing to start (fail closed, I4)",
        .0.display()
    )]
    VkeyMismatch(PathBuf),
}

/// Validate a witness key name with the same rule metamorphic-log's signer
/// enforces (non-empty, no whitespace, no `+`), surfacing a friendlier error
/// at keygen time rather than a signing failure at runtime.
pub fn validate_name(name: &str) -> Result<(), KeygenError> {
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c == '+') {
        return Err(KeygenError::InvalidName(name.to_string()));
    }
    Ok(())
}

/// Generate both cosigner keypairs for witness `name` and write their secret
/// seeds into `out_dir` as `<suite>.seed` files (mode `0600`, never
/// overwritten). Returns the public identity (vkeys + file paths).
pub fn generate(name: &str, out_dir: &Path) -> Result<Identity, KeygenError> {
    validate_name(name)?;

    // Pre-flight: fail before minting anything if any target file exists, so a
    // partial identity (one suite written, the other refused) can never occur.
    for suite in Suite::ALL {
        let path = seed_path(out_dir, suite);
        if path.exists() {
            return Err(KeygenError::SeedFileExists(path));
        }
    }

    if !out_dir.exists() {
        fs::create_dir_all(out_dir).map_err(|e| KeygenError::Io {
            path: out_dir.to_path_buf(),
            source: e,
        })?;
        // A directory we created holds key material: tighten it to the owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(out_dir, fs::Permissions::from_mode(0o700));
        }
    }

    let mut keys = Vec::with_capacity(Suite::ALL.len());
    for suite in Suite::ALL {
        keys.push(generate_one(name, suite, out_dir)?);
    }
    Ok(Identity {
        name: name.to_string(),
        keys,
    })
}

/// The seed file path for a suite within an output directory.
pub fn seed_path(out_dir: &Path, suite: Suite) -> PathBuf {
    out_dir.join(format!("{}.seed", suite.tag()))
}

/// Mint one keypair, write its seed file `0600`, and derive its vkey.
fn generate_one(name: &str, suite: Suite, out_dir: &Path) -> Result<GeneratedKey, KeygenError> {
    // Both generators return (seed, public key); seeds are 32 bytes. The seed
    // is wrapped for zeroization the moment this function returns.
    let (seed, public_key): (Zeroizing<[u8; 32]>, Vec<u8>) = match suite {
        Suite::Ed25519 => {
            let (seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
            (Zeroizing::new(seed), pk.to_vec())
        }
        Suite::MlDsa44 => {
            let (seed, pk) = metamorphic_crypto::ml_dsa_44_generate_keypair();
            (Zeroizing::new(seed), pk)
        }
    };

    let vkey = match suite {
        Suite::Ed25519 => VerifierKey::new_cosignature_ed25519(name, &public_key),
        Suite::MlDsa44 => VerifierKey::new_cosignature_mldsa44(name, &public_key),
    }
    .map_err(|e| KeygenError::Vkey(suite, e.to_string()))?
    .encode();

    let path = seed_path(out_dir, suite);
    write_seed_file(&path, name, suite, &vkey, &seed)?;

    Ok(GeneratedKey {
        suite,
        vkey,
        seed_file: path,
    })
}

/// Write one seed file: a commented, greppable text format whose single
/// non-comment line is the base64-encoded 32-byte seed. Created `0600` with
/// `create_new` so an existing file is never truncated.
fn write_seed_file(
    path: &Path,
    name: &str,
    suite: Suite,
    vkey: &str,
    seed: &[u8; 32],
) -> Result<(), KeygenError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KeygenError::SeedFileExists(path.to_path_buf())
        } else {
            KeygenError::Io {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    let body = format!(
        "# mosskeys-witness secret seed — keep this file secret (mode 0600)\n\
         # suite: {suite} cosigner\n\
         # witness name: {name}\n\
         # vkey: {vkey}\n\
         {seed}\n",
        suite = suite,
        name = name,
        vkey = vkey,
        seed = B64.encode(seed),
    );
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| KeygenError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Parse a seed file written by [`write_seed_file`]: the first non-empty,
/// non-comment line base64-decodes to the 32-byte seed. Everything else —
/// including the embedded vkey comment — is informational and ignored, so the
/// runtime signer always derives identity from the seed itself.
pub fn read_seed_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, KeygenError> {
    let text = fs::read_to_string(path).map_err(|e| KeygenError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    seed_from_text(&text, path)
}

/// Extract the seed line from seed-file text (shared by [`read_seed_file`]
/// and [`load_seed`]).
fn seed_from_text(text: &str, path: &Path) -> Result<Zeroizing<[u8; 32]>, KeygenError> {
    let invalid = |reason: &str| KeygenError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, reason.to_string()),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let raw = B64
            .decode(line)
            .map_err(|_| invalid("seed line is not valid base64"))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| invalid("seed must decode to exactly 32 bytes"))?;
        return Ok(Zeroizing::new(seed));
    }
    Err(invalid("no seed line found"))
}

/// A cosigner key loaded at startup: the secret seed (zeroized on drop) and
/// the public vkey derived from it (printed in the startup banner so the
/// operator can eyeball it against what was registered).
#[derive(Debug)]
pub struct LoadedKey {
    pub suite: Suite,
    pub seed: Zeroizing<[u8; 32]>,
    pub vkey: String,
}

/// Load one cosigner seed for the running witness, enforcing the startup
/// hard-checks from the threat model (T2/T8, invariant I4):
///
/// 1. the file is owner-only (`mode & 0o077 == 0` on Unix) — a group- or
///    world-readable key file is a fatal error, not a warning;
/// 2. the seed parses (same format as [`read_seed_file`]);
/// 3. if the file carries `# witness name:` / `# vkey:` comments (everything
///    [`generate`] writes does), they must match the configured witness name
///    and the vkey derived from the seed — a mismatch means the operator
///    pointed the config at the wrong or corrupted file, and cosigning with
///    it would silently serve the wrong identity.
///
/// The public half is always derived from the seed itself; the comments are
/// only ever a cross-check, never a source of truth.
pub fn load_seed(path: &Path, suite: Suite, name: &str) -> Result<LoadedKey, KeygenError> {
    validate_name(name)?;
    check_owner_only(path)?;

    let text = fs::read_to_string(path).map_err(|e| KeygenError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let seed = seed_from_text(&text, path)?;

    let vkey = match suite {
        Suite::Ed25519 => {
            let pk = metamorphic_crypto::ed25519_public_key(&*seed)
                .map_err(|e| KeygenError::Vkey(suite, e.to_string()))?;
            VerifierKey::new_cosignature_ed25519(name, &pk)
        }
        Suite::MlDsa44 => {
            let pk = metamorphic_crypto::ml_dsa_44_public_key(&*seed)
                .map_err(|e| KeygenError::Vkey(suite, e.to_string()))?;
            VerifierKey::new_cosignature_mldsa44(name, &pk)
        }
    }
    .map_err(|e| KeygenError::Vkey(suite, e.to_string()))?
    .encode();

    for line in text.lines() {
        if let Some(found) = line.strip_prefix("# witness name: ") {
            if found != name {
                return Err(KeygenError::NameMismatch {
                    path: path.to_path_buf(),
                    want: name.to_string(),
                    found: found.to_string(),
                });
            }
        } else if let Some(found) = line.strip_prefix("# vkey: ") {
            if found != vkey {
                return Err(KeygenError::VkeyMismatch(path.to_path_buf()));
            }
        }
    }

    Ok(LoadedKey { suite, seed, vkey })
}

/// Refuse group/world-accessible key files (T2). A no-op on non-Unix
/// platforms, where the ACL model differs; the file is still read only by
/// the service account there.
#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), KeygenError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .map_err(|e| KeygenError::Io {
            path: path.to_path_buf(),
            source: e,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeygenError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), KeygenError> {
    Ok(())
}
