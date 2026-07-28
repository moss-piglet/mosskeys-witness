//! Atomic per-log state store (conformance rows SM-01…SM-05, threat model
//! T1/T3).
//!
//! The witness's anti-split-view guarantee *is* the integrity of this store:
//! for each log origin we keep exactly one record — the latest checkpoint we
//! verified and cosigned, together with the full cosigned note (so the
//! monitoring prefix can serve it, MP-03). Two rules make the guarantee hold:
//!
//! - **Atomic check-and-update** (SM-02): the "does the submitted old size
//!   match our latest?" check and the state update happen under a single
//!   writer lock. The decision logic is supplied by the caller as a closure
//!   ([`Store::update`]), so no request path can interleave a check and a
//!   write (the spec's worked race example).
//!
//! - **Persist-before-respond** (SM-01): an update is only visible to the
//!   caller after the record has been appended to the state file *and*
//!   `fsync`ed. A crash between persist and respond is safe: the client
//!   retries, receives `409 Conflict` with the now-current size, and rebases
//!   (SM-05).
//!
//! ## File format
//!
//! One JSON object per line (append-only, human-inspectable), each carrying a
//! SHA-256 checksum of its payload:
//!
//! ```json
//! {"v":1,"origin":"example.com/log","size":42,"root":"…base64…","note":"…full cosigned note…","sha256":"…hex…"}
//! ```
//!
//! Replay at startup is last-record-wins per origin. A trailing record that
//! fails to parse or checksum is treated as a **torn tail** from a crash
//! mid-append: it is truncated (with a log warning) and replay continues —
//! appends are only ever torn at the end. Corruption anywhere else fails
//! closed (I4): the witness refuses to start rather than risk cosigning on
//! rolled-back state.
//!
//! The store takes an exclusive OS file lock at open; a second witness
//! instance on the same state file fails fast instead of silently racing
//! (T8).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

/// The durable record for one log: the latest checkpoint this witness
/// verified and cosigned, plus the cosigned note for monitoring serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogState {
    /// The log's origin line (checkpoint line 1, no trailing newline).
    pub origin: String,
    /// Tree size of the cosigned checkpoint.
    pub size: u64,
    /// Merkle root hash of the cosigned checkpoint (32 bytes).
    pub root: [u8; 32],
    /// The full cosigned note: the checkpoint text followed by every
    /// signature line the witness returned (log signature(s) + our
    /// cosignature(s)), exactly as served on the monitoring prefix.
    pub note: String,
}

/// The serialized on-disk form of a [`LogState`], with its checksum.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    v: u8,
    origin: String,
    size: u64,
    /// base64 (standard alphabet) of the 32-byte root hash.
    root: String,
    note: String,
    /// hex SHA-256 over the canonical payload (see [`checksum`]).
    sha256: String,
}

impl Record {
    const VERSION: u8 = 1;

    fn from_state(state: &LogState) -> Self {
        let root = B64.encode(state.root);
        let payload = canonical_payload(&state.origin, state.size, &root, &state.note);
        Record {
            v: Self::VERSION,
            origin: state.origin.clone(),
            size: state.size,
            root,
            note: state.note.clone(),
            sha256: hex(&metamorphic_crypto::hash::sha256(payload.as_bytes())),
        }
    }

    /// Validate checksum + structural invariants, then decode into a state.
    fn into_state(self) -> Result<LogState, String> {
        if self.v != Self::VERSION {
            return Err(format!("unsupported record version {}", self.v));
        }
        let payload = canonical_payload(&self.origin, self.size, &self.root, &self.note);
        let want = hex(&metamorphic_crypto::hash::sha256(payload.as_bytes()));
        if self.sha256 != want {
            return Err("checksum mismatch".to_string());
        }
        let root: [u8; 32] = B64
            .decode(&self.root)
            .map_err(|e| format!("root is not valid base64: {e}"))?
            .try_into()
            .map_err(|_| "root must decode to exactly 32 bytes".to_string())?;
        if self.origin.is_empty() {
            return Err("origin is empty".to_string());
        }
        Ok(LogState {
            origin: self.origin,
            size: self.size,
            root,
            note: self.note,
        })
    }
}

/// The exact byte string the checksum commits to: version, origin, size,
/// root, and note, newline-separated and unambiguous (origin and root are
/// single-line by construction).
fn canonical_payload(origin: &str, size: u64, root_b64: &str, note: &str) -> String {
    format!("v1\n{origin}\n{size}\n{root_b64}\n{note}")
}

/// Lowercase hex encode (no external hex crate needed).
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Store-level failures (map to a `500` on the wire, or abort startup).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state file {} is locked by another mosskeys-witness instance", .0.display())]
    Locked(PathBuf),

    #[error(
        "state file {} is corrupt at record {record}: {reason}; refusing to start \
         (fail closed — repair or remove the file)",
        .path.display()
    )]
    Corrupt {
        path: PathBuf,
        record: u64,
        reason: String,
    },

    #[error("I/O error on state file {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// The outcome of a [`Store::update`] check closure.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError<E> {
    /// The check closure rejected the update (a protocol-level rejection such
    /// as 409/422 — nothing was written).
    #[error("{0}")]
    Rejected(E),
    /// Persistence failed mid-update (the record may not be durable).
    #[error("{0}")]
    Store(#[from] StoreError),
}

/// The atomic per-log state store.
pub struct Store {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

struct Inner {
    /// The append handle, positioned at EOF. Also the lock handle: the
    /// exclusive lock is held for the store's lifetime.
    file: File,
    /// Latest state per origin (the replayed truth).
    states: HashMap<String, LogState>,
}

impl Store {
    /// Open (creating if necessary) the state file at `path`, take the
    /// exclusive instance lock, and replay it. See the module docs for the
    /// torn-tail and corruption policies.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let existed = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| StoreError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        // Freshly created state files hold cosigning evidence: owner-only.
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        file.try_lock_exclusive()
            .map_err(|_| StoreError::Locked(path.to_path_buf()))?;

        let (states, needs_newline) = replay(path, &file)?;
        let mut inner = Inner { file, states };
        if needs_newline {
            // The final record was complete but lacked its terminating '\n'
            // (e.g. a hand-edited file); repair framing before appending so
            // the next record cannot fuse onto it.
            inner
                .file
                .write_all(b"\n")
                .and_then(|()| inner.file.sync_all())
                .map_err(|e| StoreError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?;
        }
        Ok(Store {
            path: path.to_path_buf(),
            inner: Mutex::new(inner),
        })
    }

    /// The latest cosigned state for `origin`, if any (cloned; notes are a
    /// few KiB). Used by the monitoring prefix and by tests.
    pub fn latest(&self, origin: &str) -> Option<LogState> {
        self.lock().states.get(origin).cloned()
    }

    /// The latest cosigned state for the log whose **origin hash** (lowercase
    /// hex SHA-256 of the origin, per the monitoring-prefix spec) is
    /// `origin_hash_hex`. The number of logs per witness is small, so a scan
    /// is both simple and fast enough.
    pub fn latest_by_origin_hash(&self, origin_hash_hex: &str) -> Option<LogState> {
        self.lock()
            .states
            .values()
            .find(|s| {
                hex(&metamorphic_crypto::hash::sha256(s.origin.as_bytes())) == origin_hash_hex
            })
            .cloned()
    }

    /// Number of logs with cosigned state (diagnostics/tests).
    pub fn len(&self) -> usize {
        self.lock().states.len()
    }

    /// Whether the store has no cosigned state (diagnostics/tests).
    pub fn is_empty(&self) -> bool {
        self.lock().states.is_empty()
    }

    /// Atomically run `check` against the current state for `origin` and, if
    /// it approves, persist the new record and return its payload.
    ///
    /// `check` receives the latest state (or `None` for a never-cosigned log)
    /// and returns `(new_state, payload)`. The entire check-and-update —
    /// read, closure, append, `fsync` — happens under the writer lock, so no
    /// two requests can interleave (SM-02). The payload is only handed back
    /// after the record is durable (SM-01): the caller then builds the HTTP
    /// response from it.
    pub fn update<T, E>(
        &self,
        origin: &str,
        check: impl FnOnce(Option<&LogState>) -> Result<(LogState, T), E>,
    ) -> Result<T, UpdateError<E>> {
        let mut inner = self.lock();
        let current = inner.states.get(origin);
        let (new_state, payload) = check(current).map_err(UpdateError::Rejected)?;
        debug_assert_eq!(new_state.origin, origin, "check must not move origins");

        inner
            .append(&new_state, &self.path)
            .map_err(UpdateError::Store)?;
        inner.states.insert(origin.to_string(), new_state);
        Ok(payload)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Inner {
    /// Append one record and fsync (SM-01). On failure the in-memory map is
    /// untouched, so a later retry sees the pre-write state.
    fn append(&mut self, state: &LogState, path: &Path) -> Result<(), StoreError> {
        let record = Record::from_state(state);
        let mut line = serde_json::to_string(&record).map_err(|e| StoreError::Corrupt {
            path: path.to_path_buf(),
            record: 0,
            reason: format!("serialization failed: {e}"),
        })?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| StoreError::Io {
                path: path.to_path_buf(),
                source: e,
            })
    }
}

/// Replay the state file into the per-origin map, applying the torn-tail and
/// fail-closed corruption policies described in the module docs. The boolean
/// is `true` when the last good record lacked a trailing newline (framing
/// repair needed before the next append).
fn replay(path: &Path, file: &File) -> Result<(HashMap<String, LogState>, bool), StoreError> {
    let mut states = HashMap::new();
    let mut reader = BufReader::new(file);
    let mut offset: u64 = 0;
    let mut record_no: u64 = 0;
    let mut needs_newline = false;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| StoreError::Io {
                path: path.to_path_buf(),
                source: e,
            })
            .map(|n| n as u64)?;
        if read == 0 {
            break; // clean EOF
        }
        record_no += 1;

        let parsed: Result<Record, _> = serde_json::from_str(line.trim_end());
        let outcome = parsed
            .map_err(|e| e.to_string())
            .and_then(Record::into_state);

        match outcome {
            Ok(state) => {
                states.insert(state.origin.clone(), state);
                offset += read;
                needs_newline = !line.ends_with('\n');
            }
            Err(reason) => {
                // Distinguish a torn tail (this is the final byte range of the
                // file: nothing readable follows) from mid-file corruption.
                let mut probe = String::new();
                let more = reader.read_line(&mut probe).map_err(|e| StoreError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?;
                if more == 0 {
                    // Torn tail: truncate back to the last good boundary. The
                    // checkpoint this record carried was never acknowledged
                    // (fsync precedes response), so dropping it cannot roll
                    // back a cosigned state the client believes exists — the
                    // client will simply retry (SM-05).
                    let file_mut = reader.get_mut();
                    file_mut.set_len(offset).map_err(|e| StoreError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                    file_mut
                        .seek(SeekFrom::Start(offset))
                        .map_err(|e| StoreError::Io {
                            path: path.to_path_buf(),
                            source: e,
                        })?;
                    file_mut.sync_all().map_err(|e| StoreError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                    eprintln!(
                        "mosskeys-witness: truncated torn tail record {record_no} in {} \
                         ({reason}); continuing from last durable state",
                        path.display()
                    );
                    break;
                }
                return Err(StoreError::Corrupt {
                    path: path.to_path_buf(),
                    record: record_no,
                    reason,
                });
            }
        }
    }
    Ok((states, needs_newline))
}

#[cfg(test)]
mod tests;
