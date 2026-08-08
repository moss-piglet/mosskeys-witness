//! Integration tests for `mosskeys-witness sync`: feed fixtures (200 / 304 /
//! malformed / bad vkey / duplicates), managed-file round trips, removal
//! semantics, and the exit-code contract (0 unchanged / 10 updated / 1 error)
//! exercised against the real binary.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use metamorphic_log::note::VerifierKey;
use mosskeys_witness::config;
use mosskeys_witness::sync::{self, SyncError, SyncOutcome};

/// A valid vkey line for `origin` (Ed25519 0x01), fixtures only.
fn vkey(origin: &str) -> String {
    let (_seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
    VerifierKey::new_ed25519(origin, &pk).unwrap().encode()
}

/// The feed body shape: `{logs: [{origin, vkeys: {hybrid, ed25519}}]}`.
fn feed_body(entries: &[(&str, &str, &str)]) -> String {
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

/// A one-request HTTP/1.1 server on a loopback ephemeral port; the captured
/// request head is readable via `request()`.
struct FeedServer {
    url: String,
    request_rx: mpsc::Receiver<String>,
}

impl FeedServer {
    /// The request head (everything up to the blank line), for assertions on
    /// `If-None-Match` and friends.
    fn request(&self) -> String {
        self.request_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("server received a request")
    }
}

/// Serve exactly one response: `status` line, optional `etag` header, `body`.
fn serve_once(status: &str, etag: Option<&str>, body: &str) -> FeedServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let (status, body) = (status.to_string(), body.to_string());
    let etag = etag.map(str::to_string);
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
        let mut response = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        );
        if let Some(etag) = &etag {
            response.push_str(&format!("etag: {etag}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(&body);
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });
    FeedServer {
        url: format!("http://{addr}/api/witness/logs"),
        request_rx: rx,
    }
}

/// A witness directory: config, state file location, managed/etag paths.
struct Fixture {
    dir: tempfile::TempDir,
    config_path: PathBuf,
}

impl Fixture {
    /// A config with zero manual [[log]] stanzas (fully managed witness) and
    /// everything under a fresh tempdir. `extra` is appended verbatim (e.g. a
    /// [discovery] section or manual stanzas).
    fn new(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("witness.toml");
        let text = format!(
            r#"
name = "witness.example/w1"
listen = "127.0.0.1:8787"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"

{extra}
"#,
            dir.path().join("state.jsonl").display(),
            dir.path().join("keys/ed25519.seed").display(),
            dir.path().join("keys/mldsa44.seed").display(),
        );
        fs::write(&config_path, &text).unwrap();
        Fixture { dir, config_path }
    }

    fn managed_path(&self) -> PathBuf {
        self.dir.path().join(config::MANAGED_FILE_NAME)
    }

    fn etag_path(&self) -> PathBuf {
        self.dir.path().join(sync::ETAG_FILE_NAME)
    }

    fn sync(&self, feed_url: Option<&str>) -> Result<SyncOutcome, SyncError> {
        sync::sync(&self.config_path, feed_url, true)
    }

    /// The effective allowlist the running witness would see.
    fn load_logs(&self) -> Vec<config::LogConfig> {
        config::load(&self.config_path).unwrap().logs
    }
}

const ORIGIN_ONE: &str = "example.com/log-one";
const ORIGIN_TWO: &str = "example.com/log-two";

fn two_log_feed() -> String {
    feed_body(&[
        (ORIGIN_ONE, &vkey(ORIGIN_ONE), &vkey(ORIGIN_ONE)),
        (ORIGIN_TWO, &vkey(ORIGIN_TWO), &vkey(ORIGIN_TWO)),
    ])
}

#[test]
fn sync_200_writes_managed_file_and_caches_etag() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"etag-v1\""), &two_log_feed());

    let outcome = fixture.sync(Some(&server.url)).unwrap();
    assert_eq!(outcome, SyncOutcome::Updated);

    // The request was unconditional (nothing cached yet) and asked for JSON.
    let request = server.request();
    assert!(!request.contains("If-None-Match"), "got:\n{request}");
    assert!(
        request.contains("accept: application/json"),
        "got:\n{request}"
    );

    // Managed file: header comment + both origins, and it round-trips through
    // the same config load the running witness performs (zero manual stanzas).
    let managed = fs::read_to_string(fixture.managed_path()).unwrap();
    assert!(
        managed.starts_with("# Managed by `mosskeys-witness sync`"),
        "{managed}"
    );
    assert!(managed.contains(ORIGIN_ONE), "{managed}");
    assert!(managed.contains(ORIGIN_TWO), "{managed}");
    let logs = fixture.load_logs();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].origin, ORIGIN_ONE);
    assert_eq!(logs[0].vkeys.len(), 2);
    assert_eq!(logs[1].origin, ORIGIN_TWO);

    assert_eq!(
        fs::read_to_string(fixture.etag_path()).unwrap().trim(),
        "\"etag-v1\""
    );
}

#[test]
fn sync_304_is_unchanged_and_sends_if_none_match() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"etag-v1\""), &two_log_feed());
    assert_eq!(
        fixture.sync(Some(&server.url)).unwrap(),
        SyncOutcome::Updated
    );
    let before = fs::read_to_string(fixture.managed_path()).unwrap();

    let server = serve_once("304 Not Modified", Some("\"etag-v1\""), "");
    let outcome = fixture.sync(Some(&server.url)).unwrap();
    assert_eq!(outcome, SyncOutcome::Unchanged);
    assert_eq!(
        fs::read_to_string(fixture.managed_path()).unwrap(),
        before,
        "a 304 must not touch the managed file"
    );
    assert!(
        server.request().contains("if-none-match: \"etag-v1\""),
        "the cached validator must go out as If-None-Match"
    );
}

#[test]
fn sync_200_with_identical_set_is_unchanged_but_recaches_etag() {
    let fixture = Fixture::new("");
    let body = two_log_feed();
    let server = serve_once("200 OK", Some("\"etag-v1\""), &body);
    assert_eq!(
        fixture.sync(Some(&server.url)).unwrap(),
        SyncOutcome::Updated
    );

    // The feed re-serves the same set under a new ETag (e.g. a deploy
    // reshuffled validators): no rewrite, no restart-worthy 10, but the new
    // validator is cached. (The second server listens on a different port, so
    // the on-disk `# Feed:` provenance line would differ if the comparison
    // were byte-based — the allowlist entries are what count.)
    let before = fs::read_to_string(fixture.managed_path()).unwrap();
    let server = serve_once("200 OK", Some("\"etag-v2\""), &body);
    let outcome = fixture.sync(Some(&server.url)).unwrap();
    assert_eq!(outcome, SyncOutcome::Unchanged);
    assert_eq!(
        fs::read_to_string(fixture.managed_path()).unwrap(),
        before,
        "same entries must not rewrite the managed file"
    );
    assert_eq!(
        fs::read_to_string(fixture.etag_path()).unwrap().trim(),
        "\"etag-v2\""
    );
}

#[test]
fn sync_corrupt_managed_file_fails_closed() {
    // A managed file that does not parse is an operator-visible incident, not
    // something sync silently overwrites (same posture as config load, I4).
    let fixture = Fixture::new("");
    fs::write(fixture.managed_path(), "not toml = [").unwrap();
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Config(config::ConfigError::ManagedParse { .. })
        ),
        "got {err:?}"
    );
}

#[test]
fn sync_without_managed_file_sends_no_stale_validator() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"etag-v1\""), &two_log_feed());
    assert_eq!(
        fixture.sync(Some(&server.url)).unwrap(),
        SyncOutcome::Updated
    );

    // The managed file is lost (operator deleted it, fresh volume): the
    // cached ETag must NOT condition the request, or a 304 would never
    // restore the allowlist.
    fs::remove_file(fixture.managed_path()).unwrap();
    let server = serve_once("200 OK", Some("\"etag-v1\""), &two_log_feed());
    let outcome = fixture.sync(Some(&server.url)).unwrap();
    assert_eq!(outcome, SyncOutcome::Updated);
    assert!(
        !server.request().contains("If-None-Match"),
        "no validator without the file it validated"
    );
    assert!(fixture.managed_path().exists());
}

#[test]
fn sync_malformed_json_is_an_error_and_writes_nothing() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"e\""), "this is not json");
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(matches!(err, SyncError::FeedJson(_)), "got {err:?}");
    assert!(!fixture.managed_path().exists());
}

#[test]
fn sync_bad_vkey_is_an_error_and_writes_nothing() {
    let fixture = Fixture::new("");
    let body = feed_body(&[(ORIGIN_ONE, "not-a-vkey", &vkey(ORIGIN_ONE))]);
    let server = serve_once("200 OK", Some("\"e\""), &body);
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::FeedEntry(config::ConfigError::BadVkey { .. })
        ),
        "got {err:?}"
    );
    assert!(!fixture.managed_path().exists());
}

#[test]
fn sync_duplicate_origin_in_feed_is_an_error() {
    let fixture = Fixture::new("");
    let body = feed_body(&[
        (ORIGIN_ONE, &vkey(ORIGIN_ONE), &vkey(ORIGIN_ONE)),
        (ORIGIN_ONE, &vkey(ORIGIN_ONE), &vkey(ORIGIN_ONE)),
    ]);
    let server = serve_once("200 OK", Some("\"e\""), &body);
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::FeedEntry(config::ConfigError::DuplicateOrigin(_))
        ),
        "got {err:?}"
    );
    assert!(!fixture.managed_path().exists());
}

#[test]
fn sync_empty_feed_is_refused() {
    // Fail closed: an empty feed must never empty the allowlist (T8).
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"e\""), r#"{"logs":[]}"#);
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(matches!(err, SyncError::EmptyFeed), "got {err:?}");
    assert!(!fixture.managed_path().exists());
}

#[test]
fn sync_unexpected_status_is_an_error() {
    let fixture = Fixture::new("");
    let server = serve_once("500 Internal Server Error", None, "boom");
    let err = fixture.sync(Some(&server.url)).unwrap_err();
    assert!(matches!(err, SyncError::Status(500)), "got {err:?}");
    assert!(!fixture.managed_path().exists());
}

#[test]
fn sync_unreachable_feed_is_an_error() {
    let fixture = Fixture::new("");
    // Bind then immediately drop: nothing listens on the port.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = fixture
        .sync(Some(&format!("http://127.0.0.1:{port}/api/witness/logs")))
        .unwrap_err();
    assert!(matches!(err, SyncError::Http(_)), "got {err:?}");
}

#[test]
fn sync_drops_origins_removed_from_the_feed() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    assert_eq!(
        fixture.sync(Some(&server.url)).unwrap(),
        SyncOutcome::Updated
    );
    assert_eq!(fixture.load_logs().len(), 2);

    // The feed now lists only ORIGIN_TWO: ORIGIN_ONE leaves the managed file
    // (its cosignature state, if any, is the store's business and is never
    // touched here).
    let body = feed_body(&[(ORIGIN_TWO, &vkey(ORIGIN_TWO), &vkey(ORIGIN_TWO))]);
    let server = serve_once("200 OK", Some("\"v2\""), &body);
    assert_eq!(
        fixture.sync(Some(&server.url)).unwrap(),
        SyncOutcome::Updated
    );
    let logs = fixture.load_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].origin, ORIGIN_TWO);
}

#[test]
fn sync_uses_discovery_feed_url_from_config_when_no_flag() {
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let fixture = Fixture::new(&format!("[discovery]\nfeed_url = \"{}\"\n", server.url));
    // No --feed-url: the config's [discovery] feed_url is the source.
    assert_eq!(fixture.sync(None).unwrap(), SyncOutcome::Updated);
    assert_eq!(fixture.load_logs().len(), 2);
}

#[test]
fn sync_flag_overrides_config_feed_url() {
    let config_server = serve_once("200 OK", Some("\"v1\""), r#"{"logs":[]}"#);
    let flag_server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let fixture = Fixture::new(&format!(
        "[discovery]\nfeed_url = \"{}\"\n",
        config_server.url
    ));
    // The flag points elsewhere; the config's feed is never contacted.
    assert_eq!(
        fixture.sync(Some(&flag_server.url)).unwrap(),
        SyncOutcome::Updated
    );
    assert_eq!(fixture.load_logs().len(), 2);
}

// --- Exit-code contract, exercised against the real binary ---

/// Run the compiled binary's `sync` and return (exit code, stdout, stderr).
fn run_sync_bin(config: &Path, extra_args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_mosskeys-witness"))
        .arg("sync")
        .arg("--config")
        .arg(config)
        .args(extra_args)
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn exit_code_contract() {
    let fixture = Fixture::new("");

    // 10: the managed file changed (certbot pattern: gate the restart on 10).
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let (code, _, _) = run_sync_bin(
        &fixture.config_path,
        &["--feed-url", &server.url, "--quiet"],
    );
    assert_eq!(code, Some(10));

    // 0: feed not modified.
    let server = serve_once("304 Not Modified", Some("\"v1\""), "");
    let (code, _, _) = run_sync_bin(
        &fixture.config_path,
        &["--feed-url", &server.url, "--quiet"],
    );
    assert_eq!(code, Some(0));

    // 1: error (feed down).
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("http://127.0.0.1:{port}/api/witness/logs");
    let (code, _, stderr) = run_sync_bin(&fixture.config_path, &["--feed-url", &url, "--quiet"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("error:"), "errors still print: {stderr}");
}

#[test]
fn quiet_suppresses_non_error_output() {
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let url = server.url.clone();

    let (code, stdout, _) = run_sync_bin(&fixture.config_path, &["--feed-url", &url]);
    assert_eq!(code, Some(10));
    assert!(stdout.contains("2 logs written"), "got: {stdout:?}");

    // Fresh fixture for the quiet variant.
    let fixture = Fixture::new("");
    let server = serve_once("200 OK", Some("\"v1\""), &two_log_feed());
    let (code, stdout, _) = run_sync_bin(
        &fixture.config_path,
        &["--feed-url", &server.url, "--quiet"],
    );
    assert_eq!(code, Some(10));
    assert!(stdout.is_empty(), "--quiet printed: {stdout:?}");
}
