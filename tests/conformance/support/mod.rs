//! Shared fixtures for the conformance suite: an in-process witness router
//! over a tempdir, a live `mosskeys-witness run` subprocess, and a minimal
//! blocking HTTP/1.1 client for the socket-level rows.
//!
//! The fixtures mirror the patterns established in `tests/witness.rs`,
//! `tests/server.rs`, and `tests/monitoring.rs`.
//!
//! Not every section uses every helper — the toolbox is shared, so helpers
//! may be unused in any one section module.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{self, Signature, SignedNote, VerifierKey};
use mosskeys_witness::config;
use mosskeys_witness::keygen::{self, Suite};
use mosskeys_witness::server;
use mosskeys_witness::witness::Witness;
use tempfile::TempDir;
use tower::ServiceExt as _;

pub const WITNESS_NAME: &str = "witness.example/test";
pub const LOG_ORIGIN: &str = "example.com/behind-the-sofa";

/// A throwaway log identity (Ed25519 0x01) that produces signed checkpoints.
pub struct TestLog {
    pub origin: String,
    pub seed: [u8; 32],
}

impl TestLog {
    pub fn new(origin: &str) -> Self {
        let (seed, _pk) = metamorphic_crypto::ed25519_generate_keypair();
        TestLog {
            origin: origin.to_string(),
            seed,
        }
    }

    pub fn vkey(&self) -> String {
        let pk = metamorphic_crypto::ed25519_public_key(&self.seed).unwrap();
        VerifierKey::new_ed25519(&self.origin, &pk)
            .unwrap()
            .encode()
    }

    pub fn checkpoint_text(&self, tree: &MerkleTree, size: u64) -> String {
        format!(
            "{}\n{size}\n{}\n",
            self.origin,
            B64.encode(tree.root_at(size))
        )
    }

    pub fn sign(&self, text: &str) -> Signature {
        note::sign_ed25519(text, &self.origin, &self.seed).unwrap()
    }

    /// A complete signed-note checkpoint over `tree`'s first `size` leaves.
    pub fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        let text = self.checkpoint_text(tree, size);
        SignedNote::new(text.clone(), vec![self.sign(&text)])
            .unwrap()
            .marshal()
    }
}

/// A witness router over a tempdir, plus every handle the assertions need
/// (log identity, witness vkeys, state/config paths).
pub struct HttpFixture {
    pub app: axum::Router,
    pub log: TestLog,
    /// The witness cosigner vkeys (0x04 / 0x06), as printed at keygen time.
    pub ed_vkey: String,
    pub ml_vkey: String,
    pub config_path: PathBuf,
    pub state_file: PathBuf,
    pub keys_dir: PathBuf,
    dir: TempDir, // kept alive for the fixture's lifetime
}

impl HttpFixture {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let log = TestLog::new(LOG_ORIGIN);

        let keys_dir = dir.path().join("keys");
        let identity = keygen::generate(WITNESS_NAME, &keys_dir).unwrap();
        let vkey_of = |suite: Suite| {
            identity
                .keys
                .iter()
                .find(|k| k.suite == suite)
                .unwrap()
                .vkey
                .clone()
        };

        let state_file = dir.path().join("state.jsonl");
        let config_path = dir.path().join("witness.toml");
        fs::write(
            &config_path,
            format!(
                r#"
name = "{WITNESS_NAME}"
listen = "127.0.0.1:0"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"

[[log]]
origin = "{LOG_ORIGIN}"
vkeys = ["{}"]
"#,
                state_file.display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
                log.vkey(),
            ),
        )
        .unwrap();

        let witness = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
        HttpFixture {
            app: server::router(witness),
            log,
            ed_vkey: vkey_of(Suite::Ed25519),
            ml_vkey: vkey_of(Suite::MlDsa44),
            config_path,
            state_file,
            keys_dir,
            dir,
        }
    }

    /// Rebuild the witness over the same config/state, replaying the store.
    /// The store lock is exclusive, so the running router is dropped first —
    /// this is the test analogue of a crash and restart (SM-05).
    pub fn restart(self) -> Self {
        let HttpFixture {
            app,
            log,
            ed_vkey,
            ml_vkey,
            config_path,
            state_file,
            keys_dir,
            dir,
        } = self;
        drop(app); // releases Arc<Witness> → Store → the fs2 lock
        let witness = Witness::from_config(&config::load(&config_path).unwrap()).unwrap();
        HttpFixture {
            app: server::router(witness),
            log,
            ed_vkey,
            ml_vkey,
            config_path,
            state_file,
            keys_dir,
            dir,
        }
    }

    pub fn ed_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ed_vkey).unwrap()
    }

    pub fn ml_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.ml_vkey).unwrap()
    }

    pub fn log_vkey(&self) -> VerifierKey {
        VerifierKey::parse(&self.log.vkey()).unwrap()
    }

    /// Both raw 32-byte cosigner seeds, read back from the key files (the
    /// I3 egress-scrub needles).
    pub fn seeds(&self) -> [[u8; 32]; 2] {
        let ed = keygen::read_seed_file(&self.keys_dir.join("ed25519.seed")).unwrap();
        let ml = keygen::read_seed_file(&self.keys_dir.join("mldsa44.seed")).unwrap();
        [*ed, *ml]
    }

    /// Every record in the state JSONL, in file order (empty before the
    /// first accepted checkpoint — `Store::open` creates the file).
    pub fn state_records(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(&self.state_file)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The persisted `LogState.note` for `origin` (last record wins, as at
    /// replay) — exactly the bytes the monitoring prefix must serve (MP-03).
    pub fn stored_note(&self, origin: &str) -> Option<String> {
        self.state_records()
            .iter()
            .rev()
            .find(|record| record["origin"] == origin)
            .map(|record| record["note"].as_str().unwrap().to_string())
    }

    pub fn monitoring_path(origin: &str) -> String {
        format!("/{}/checkpoint", origin_hash(origin))
    }
}

/// Build a request body: `old <old_size>`, proof lines, empty line, note.
pub fn request_body(old_size: u64, proof: &[[u8; 32]], note: &str) -> String {
    let mut body = format!("old {old_size}\n");
    for hash in proof {
        body.push_str(&B64.encode(hash));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(note);
    body
}

/// Flip one bit in the LAST signature line's blob, keeping the key name and
/// key id intact (ST-03's "trusted key, bad signature" shape).
pub fn tamper_last_signature(note: &str) -> String {
    let mut lines: Vec<String> = note.lines().map(str::to_string).collect();
    let sig_line = lines.pop().unwrap();
    let (prefix, blob64) = sig_line.rsplit_once(' ').unwrap();
    let mut blob = B64.decode(blob64).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    lines.push(format!("{prefix} {}", B64.encode(blob)));
    format!("{}\n", lines.join("\n"))
}

/// A tree whose leaves are `leaf-0 … leaf-{n-1}` (the workhorse).
pub fn tree_with_numbered_leaves(n: u64) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for i in 0..n {
        tree.push(format!("leaf-{i}").as_bytes());
    }
    tree
}

/// A DIFFERENT n-leaf history (fork attempts) — leaves `fork-0 …`.
pub fn forked_tree(n: u64) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for i in 0..n {
        tree.push(format!("fork-{i}").as_bytes());
    }
    tree
}

/// Lowercase hex (no external hex crate needed).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// MP-02: lowercase hex of SHA-256 over the origin (no trailing newline).
pub fn origin_hash(origin: &str) -> String {
    hex(&metamorphic_crypto::hash::sha256(origin.as_bytes()))
}

pub fn post(path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .body(body.into())
        .unwrap()
}

pub fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

pub fn method(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

/// POST a body to `/add-checkpoint` through the full layer stack.
pub async fn submit(app: &axum::Router, body: impl Into<Body>) -> axum::response::Response {
    app.clone()
        .oneshot(post("/add-checkpoint", body))
        .await
        .unwrap()
}

pub async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

pub async fn body_string(response: axum::response::Response) -> String {
    String::from_utf8(body_bytes(response).await).unwrap()
}

/// Cosign `note` through the full stack, asserting the 200.
pub async fn cosign_ok(
    app: &axum::Router,
    old_size: u64,
    proof: &[[u8; 32]],
    note: &str,
) -> String {
    let response = submit(app, request_body(old_size, proof, note)).await;
    assert_eq!(response.status(), 200);
    body_string(response).await
}

/// The monitoring body for `origin` through the full stack (must be 200).
pub async fn monitoring_body(app: &axum::Router, origin: &str) -> Vec<u8> {
    let response = app
        .clone()
        .oneshot(get(&HttpFixture::monitoring_path(origin)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    body_bytes(response).await
}

// ---------------------------------------------------------------------------
// Subprocess harness: the real binary over loopback TCP.
// ---------------------------------------------------------------------------

/// A live `mosskeys-witness run` subprocess over a tempdir, for the rows
/// `Router::oneshot` cannot reach (GI-03 keep-alive, ST-11 stderr evidence,
/// the I3 startup banner).
pub struct WitnessProcess {
    child: Child,
    pub port: u16,
    pub log: TestLog,
    pub ed_vkey: String,
    pub ml_vkey: String,
    pub state_file: PathBuf,
    pub keys_dir: PathBuf,
    dir: TempDir,
}

impl WitnessProcess {
    pub fn spawn() -> Self {
        let dir = TempDir::new().unwrap();
        let log = TestLog::new(LOG_ORIGIN);

        let keys_dir = dir.path().join("keys");
        let identity = keygen::generate(WITNESS_NAME, &keys_dir).unwrap();
        let vkey_of = |suite: Suite| {
            identity
                .keys
                .iter()
                .find(|k| k.suite == suite)
                .unwrap()
                .vkey
                .clone()
        };

        let state_file = dir.path().join("state.jsonl");
        let port = free_port();
        let config_path = dir.path().join("witness.toml");
        fs::write(
            &config_path,
            format!(
                r#"
name = "{WITNESS_NAME}"
listen = "127.0.0.1:{port}"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"

[[log]]
origin = "{LOG_ORIGIN}"
vkeys = ["{}"]
"#,
                state_file.display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
                log.vkey(),
            ),
        )
        .unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_mosskeys-witness"))
            .args(["run", "--config"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        // Wait for the listener, or surface a startup failure (I4 paths
        // exit non-zero before binding).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("witness exited before listening: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "witness did not start listening within 10s"
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        WitnessProcess {
            child,
            port,
            log,
            ed_vkey: vkey_of(Suite::Ed25519),
            ml_vkey: vkey_of(Suite::MlDsa44),
            state_file,
            keys_dir,
            dir,
        }
    }

    /// Both raw 32-byte cosigner seeds (the I3 scrub needles).
    pub fn seeds(&self) -> [[u8; 32]; 2] {
        let ed = keygen::read_seed_file(&self.keys_dir.join("ed25519.seed")).unwrap();
        let ml = keygen::read_seed_file(&self.keys_dir.join("mldsa44.seed")).unwrap();
        [*ed, *ml]
    }

    /// Kill the process and return everything it ever wrote to stderr.
    pub fn into_stderr(self) -> String {
        let mut child = self.child;
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        String::from_utf8(output.stderr).unwrap()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------
// A minimal blocking HTTP/1.1 client (keep-alive capable: the caller owns
// the stream and may send sequential requests on one connection — GI-03).
// ---------------------------------------------------------------------------

pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// One blocking HTTP/1.1 exchange. Responses are read by Content-Length
/// (hyper sets it for every fixed body this service produces).
pub fn raw_request(stream: &mut TcpStream, method: &str, path: &str, body: &[u8]) -> RawResponse {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();

    // The clone shares the socket; responses are consumed exactly to their
    // Content-Length and requests are never pipelined, so the per-request
    // BufReader can never over-read a following response.
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("malformed status line: {status_line:?}"))
        .parse()
        .unwrap();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .expect("hyper sets a Content-Length on these responses");
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();

    RawResponse {
        status,
        headers,
        body,
    }
}
