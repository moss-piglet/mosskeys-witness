//! Integration tests for `[discovery]` in-process auto-sync + hot-reload:
//! allowlist hot-swaps mid-run (new origin cosigned / removed origin 404s /
//! vkey rotation / manual stanzas win / cosignature state untouched), the
//! poll primitive against a mock feed (200 / 304 / invalid / down), the
//! interval loop sequencing (200 → 304 → changed 200), and boot with a
//! managed file present.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{SignedNote, VerifierKey};
use mosskeys_witness::config::{self, LogConfig};
use mosskeys_witness::discovery;
use mosskeys_witness::keygen;
use mosskeys_witness::sync::{self, FeedTarget};
use mosskeys_witness::witness::{Reject, Witness, WitnessError};
use tempfile::TempDir;

const WITNESS_NAME: &str = "witness.example/discovery";

/// A throwaway log identity (Ed25519 0x01) that produces signed checkpoints.
struct TestLog {
    origin: String,
    seed: [u8; 32],
}

impl TestLog {
    fn new(origin: &str) -> Self {
        let (seed, _pk) = metamorphic_crypto::ed25519_generate_keypair();
        TestLog {
            origin: origin.to_string(),
            seed,
        }
    }

    fn vkey(&self) -> String {
        let pk = metamorphic_crypto::ed25519_public_key(&self.seed).unwrap();
        VerifierKey::new_ed25519(&self.origin, &pk)
            .unwrap()
            .encode()
    }

    /// A signed-note checkpoint over `tree`'s first `size` leaves.
    fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        let text = format!(
            "{}\n{size}\n{}\n",
            self.origin,
            B64.encode(tree.root_at(size))
        );
        let sig = metamorphic_log::note::sign_ed25519(&text, &self.origin, &self.seed).unwrap();
        SignedNote::new(text, vec![sig]).unwrap().marshal()
    }

    /// A complete `old 0` request for a one-leaf checkpoint — the canonical
    /// "is this origin cosigned?" probe.
    fn size_one_request(&self) -> String {
        let mut tree = MerkleTree::new();
        tree.push(b"leaf");
        format!("old 0\n\n{}", self.checkpoint_note(&tree, 1))
    }
}

/// A well-formed request body: `old <old_size>`, the given proof lines, an
/// empty line, then the signed checkpoint note.
fn request_body(old_size: u64, proof: &[[u8; 32]], note: &str) -> String {
    let mut body = format!("old {old_size}\n");
    for hash in proof {
        body.push_str(&B64.encode(hash));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(note);
    body
}

/// Is `log` in the witness's effective allowlist right now? (Any outcome but
/// UnknownOrigin means yes: 200, or 409 once the probe itself has cosigned.)
fn cosigns(witness: &Witness, log: &TestLog) -> bool {
    !matches!(
        witness.add_checkpoint(&log.size_one_request()),
        Err(WitnessError::Rejected(Reject::UnknownOrigin))
    )
}

/// Feed-validated entries for a direct [`Witness::apply_managed_entries`].
fn managed_entries(logs: &[&TestLog]) -> Vec<LogConfig> {
    logs.iter()
        .map(|log| config::validate_log_entry(log.origin.clone(), vec![log.vkey()]).unwrap())
        .collect()
}

/// Managed-file TOML content, as `mosskeys-witness sync` would render it.
fn managed_toml(logs: &[&TestLog]) -> String {
    let mut out = String::from("# Managed by `mosskeys-witness sync` — do not edit.\n\n");
    for log in logs {
        out.push_str(&format!(
            "[[log]]\norigin = \"{}\"\nvkeys = [\"{}\"]\n\n",
            log.origin,
            log.vkey()
        ));
    }
    out
}

/// The feed body shape: `{logs: [{origin, vkeys: {hybrid, ed25519}}]}`.
fn feed_body(logs: &[&TestLog]) -> String {
    let entries: Vec<serde_json::Value> = logs
        .iter()
        .map(|log| {
            serde_json::json!({
                "origin": log.origin,
                "vkeys": { "hybrid": log.vkey(), "ed25519": log.vkey() },
            })
        })
        .collect();
    serde_json::json!({ "logs": entries }).to_string()
}

/// A witness over a tempdir: minted seeds, config built from the given manual
/// stanzas, and optionally a managed file in place before boot.
struct Fixture {
    witness: Arc<Witness>,
    dir: TempDir, // kept alive for the fixture's lifetime (declared last: dropped last)
}

impl Fixture {
    fn new(manual: &[&TestLog], managed: Option<String>) -> Self {
        let dir = TempDir::new().unwrap();
        let keys_dir = dir.path().join("keys");
        keygen::generate(WITNESS_NAME, &keys_dir).unwrap();

        let mut stanzas = String::new();
        for log in manual {
            stanzas.push_str(&format!(
                "[[log]]\norigin = \"{}\"\nvkeys = [\"{}\"]\n",
                log.origin,
                log.vkey()
            ));
        }
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

{stanzas}
"#,
                state_file.display(),
                keys_dir.join("ed25519.seed").display(),
                keys_dir.join("mldsa44.seed").display(),
            ),
        )
        .unwrap();
        if let Some(managed) = managed {
            fs::write(config::managed_file_path(&state_file), managed).unwrap();
        }

        let witness = Arc::new(Witness::from_config(&config::load(&config_path).unwrap()).unwrap());
        Fixture { witness, dir }
    }

    /// A sync target pointing at `url`, with the managed file and ETag cache
    /// in this fixture's state directory.
    fn feed_target(&self, url: &str) -> FeedTarget {
        FeedTarget {
            feed_url: url.to_string(),
            managed_path: self.dir.path().join(config::MANAGED_FILE_NAME),
            etag_path: self.dir.path().join(sync::ETAG_FILE_NAME),
        }
    }
}

// --- Hot-swap semantics (Witness::apply_managed_entries) ---

#[test]
fn hot_swap_adds_a_new_origin_mid_run() {
    let manual = TestLog::new("example.com/manual");
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[&manual], None);

    // Before the swap: 404 by construction (T8).
    assert!(!cosigns(&fx.witness, &discovered));

    let update = fx
        .witness
        .apply_managed_entries(managed_entries(&[&discovered]));
    assert_eq!(update.total, 2);
    assert_eq!(update.added, vec!["example.com/discovered".to_string()]);
    assert!(update.removed.is_empty() && update.rotated.is_empty());

    // Mid-run, no restart: the new origin is cosigned (dual lines), the
    // manual one is undisturbed.
    let response = fx
        .witness
        .add_checkpoint(&discovered.size_one_request())
        .unwrap();
    assert_eq!(response.lines().count(), 2, "dual cosignature");
    assert!(cosigns(&fx.witness, &manual));
}

#[test]
fn hot_swap_removes_an_origin_dropped_from_the_feed() {
    let manual = TestLog::new("example.com/manual");
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[&manual], None);
    fx.witness
        .apply_managed_entries(managed_entries(&[&discovered]));
    assert!(cosigns(&fx.witness, &discovered));

    // The feed drops the origin: the next swap removes it (an empty managed
    // set is reachable here only via this primitive — a real feed serving
    // zero logs is rejected fail-closed upstream).
    let update = fx.witness.apply_managed_entries(vec![]);
    assert_eq!(update.total, 1);
    assert_eq!(update.removed, vec!["example.com/discovered".to_string()]);

    assert!(!cosigns(&fx.witness, &discovered));
    assert!(cosigns(&fx.witness, &manual), "manual origins survive");
}

#[test]
fn hot_swap_applies_a_vkey_rotation() {
    let before = TestLog::new("example.com/rotating");
    let after = TestLog::new("example.com/rotating"); // same origin, new key
    let fx = Fixture::new(&[], Some(managed_toml(&[&before])));

    // Cosigned at size 1 under the pre-rotation key.
    let mut tree = MerkleTree::new();
    for leaf in [b"leaf-0".as_slice(), b"leaf-1"] {
        tree.push(leaf);
    }
    fx.witness
        .add_checkpoint(&format!("old 0\n\n{}", before.checkpoint_note(&tree, 1)))
        .unwrap();

    let update = fx.witness.apply_managed_entries(managed_entries(&[&after]));
    assert_eq!(update.rotated, vec!["example.com/rotating".to_string()]);
    assert!(update.added.is_empty() && update.removed.is_empty());

    // The old key is no longer trusted (403), the rotated key is — and the
    // cosigned state carried straight across the swap (old size 1, proof,
    // size 2 → 200).
    let proof = tree.consistency_proof(1, 2);
    let stale = request_body(1, &proof, &before.checkpoint_note(&tree, 2));
    assert!(matches!(
        fx.witness.add_checkpoint(&stale),
        Err(WitnessError::Rejected(Reject::NoTrustedSignature))
    ));
    let rotated = request_body(1, &proof, &after.checkpoint_note(&tree, 2));
    assert!(fx.witness.add_checkpoint(&rotated).is_ok());
}

#[test]
fn hot_swap_lets_manual_stanzas_win_over_the_feed() {
    let manual = TestLog::new("example.com/pinned");
    let feed_version = TestLog::new("example.com/pinned"); // same origin, other key
    let fx = Fixture::new(&[&manual], None);

    let update = fx
        .witness
        .apply_managed_entries(managed_entries(&[&feed_version]));
    assert_eq!(update.total, 1, "the feed entry is shadowed by the stanza");
    assert!(update.added.is_empty() && update.rotated.is_empty());

    // Only the pinned manual key is trusted.
    assert!(matches!(
        fx.witness.add_checkpoint(&feed_version.size_one_request()),
        Err(WitnessError::Rejected(Reject::NoTrustedSignature))
    ));
    assert!(
        fx.witness
            .add_checkpoint(&manual.size_one_request())
            .is_ok()
    );
}

#[test]
fn hot_swap_never_touches_cosignature_state() {
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[], Some(managed_toml(&[&discovered])));

    // Cosign size 1, then watch the origin leave and return.
    let mut tree = MerkleTree::new();
    for leaf in [b"leaf-0".as_slice(), b"leaf-1"] {
        tree.push(leaf);
    }
    fx.witness
        .add_checkpoint(&format!(
            "old 0\n\n{}",
            discovered.checkpoint_note(&tree, 1)
        ))
        .unwrap();
    fx.witness.apply_managed_entries(vec![]);
    assert!(!cosigns(&fx.witness, &discovered));
    fx.witness
        .apply_managed_entries(managed_entries(&[&discovered]));

    // The store was never involved in the swaps: the witness still holds
    // size 1, so a replayed `old 0` is a 409 carrying that size, and the
    // honest continuation (old 1 + proof) chains on to size 2.
    let replay = request_body(0, &[], &discovered.checkpoint_note(&tree, 2));
    assert!(matches!(
        fx.witness.add_checkpoint(&replay),
        Err(WitnessError::Rejected(Reject::SizeConflict(1)))
    ));
    let proof = tree.consistency_proof(1, 2);
    let next = request_body(1, &proof, &discovered.checkpoint_note(&tree, 2));
    assert!(fx.witness.add_checkpoint(&next).is_ok());
}

#[test]
fn boot_with_a_managed_file_present_cosigns_it_immediately() {
    // The deployment flip: a redeploy finds the managed file on the volume
    // and serves it from the first request, before any poll runs.
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[], Some(managed_toml(&[&discovered])));
    assert_eq!(fx.witness.log_count(), 1);
    assert!(cosigns(&fx.witness, &discovered));
}

// --- The poll primitive against a mock feed ---

/// An HTTP/1.1 mock feed on a loopback ephemeral port. Every request head is
/// readable via `request()` (async: the single-threaded test runtime must
/// keep driving the poller while we wait for it).
struct FeedServer {
    url: String,
    request_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl FeedServer {
    /// The next request head (everything up to the blank line), for
    /// assertions on `If-None-Match` and friends.
    async fn request(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(10), self.request_rx.recv())
            .await
            .expect("server received a request")
            .expect("server channel open")
    }
}

/// Read one request head (up to the blank line) off a freshly accepted
/// stream and hand it to the channel.
fn read_head(stream: &mut std::net::TcpStream, tx: &tokio::sync::mpsc::UnboundedSender<String>) {
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
}

fn response_bytes(status: &str, etag: Option<&str>, body: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    if let Some(etag) = etag {
        response.push_str(&format!("etag: {etag}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    response.into_bytes()
}

/// Serve exactly one response: `status` line, optional `etag` header, `body`.
/// (Same shape as tests/sync.rs's `serve_once`.)
fn serve_once(status: &str, etag: Option<&str>, body: &str) -> FeedServer {
    serve_sequence(vec![(status, etag, body.to_string())])
}

/// Serve the scripted responses in order, one per request, then keep
/// answering the last one (the poll loop's later ticks stay cheap instead of
/// hanging on an unlistened port). Every request head goes to the channel.
fn serve_sequence(script: Vec<(&str, Option<&str>, String)>) -> FeedServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    // Render the responses eagerly so the thread owns only 'static bytes.
    let responses: Vec<Vec<u8>> = script
        .iter()
        .map(|(status, etag, body)| response_bytes(status, *etag, body))
        .collect();
    thread::spawn(move || {
        let mut responses = responses.into_iter();
        let mut last: Option<Vec<u8>> = None;
        loop {
            let response = match responses.next() {
                Some(bytes) => {
                    last = Some(bytes.clone());
                    bytes
                }
                None => match &last {
                    Some(bytes) => bytes.clone(),
                    None => return,
                },
            };
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            read_head(&mut stream, &tx);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    FeedServer {
        url: format!("http://{addr}/api/witness/logs"),
        request_rx: rx,
    }
}

/// A port nothing listens on (bind, read the address, drop).
fn dead_url() -> String {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}/api/witness/logs")
}

/// Assert `condition` within a generous deadline (poll processing is
/// observed through witness state, so synchronization is by polling).
async fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "condition not met within the deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn poll_once_applies_a_changed_feed() {
    let manual = TestLog::new("example.com/manual");
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[&manual], None);

    let mut server = serve_once("200 OK", Some("\"v1\""), &feed_body(&[&discovered]));
    let target = fx.feed_target(&server.url);
    discovery::poll_once(&fx.witness, &target).await;

    // The swap landed: the new origin cosigns, the manual one is untouched,
    // and the managed file + ETag cache persist the update for the next boot.
    assert!(
        !server.request().await.contains("If-None-Match"),
        "nothing cached yet, the first poll is unconditional"
    );
    assert!(cosigns(&fx.witness, &discovered));
    assert!(cosigns(&fx.witness, &manual));
    assert_eq!(fx.witness.log_count(), 2);
    let managed = fs::read_to_string(&target.managed_path).unwrap();
    assert!(managed.contains("example.com/discovered"), "{managed}");
    assert_eq!(
        fs::read_to_string(&target.etag_path).unwrap().trim(),
        "\"v1\""
    );
}

#[tokio::test]
async fn poll_once_304_keeps_the_current_set() {
    let manual = TestLog::new("example.com/manual");
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[&manual], None);

    // One mock URL serving 200 then 304: the poll primitive is driven twice.
    let mut server = serve_sequence(vec![
        ("200 OK", Some("\"v1\""), feed_body(&[&discovered])),
        ("304 Not Modified", None, String::new()),
    ]);
    let target = fx.feed_target(&server.url);

    discovery::poll_once(&fx.witness, &target).await;
    server.request().await;
    assert_eq!(fx.witness.log_count(), 2);
    let managed_before = fs::read_to_string(&target.managed_path).unwrap();

    discovery::poll_once(&fx.witness, &target).await;
    let head = server.request().await;
    assert!(
        head.contains("if-none-match: \"v1\""),
        "the cached validator must condition the poll: {head}"
    );
    assert_eq!(fx.witness.log_count(), 2, "a 304 changes nothing");
    assert!(cosigns(&fx.witness, &discovered));
    assert_eq!(
        fs::read_to_string(&target.managed_path).unwrap(),
        managed_before,
        "a 304 must not touch the managed file"
    );
}

#[tokio::test]
async fn poll_once_keeps_the_stale_set_when_the_feed_is_down() {
    let manual = TestLog::new("example.com/manual");
    let fx = Fixture::new(&[&manual], None);

    let target = fx.feed_target(&dead_url());
    discovery::poll_once(&fx.witness, &target).await;

    assert_eq!(fx.witness.log_count(), 1);
    assert!(cosigns(&fx.witness, &manual), "serving continues");
    assert!(!target.managed_path.exists(), "nothing was written");
}

#[tokio::test]
async fn poll_once_keeps_the_stale_set_on_an_invalid_feed() {
    let manual = TestLog::new("example.com/manual");
    let discovered = TestLog::new("example.com/discovered");
    let fx = Fixture::new(&[&manual], None);

    // Malformed JSON, an empty feed, and a bad vkey are all rejected the
    // same way: logged, nothing written, the last known set keeps serving.
    for body in [
        "this is not json".to_string(),
        r#"{"logs":[]}"#.to_string(),
        feed_body_invalid_vkey(&discovered),
    ] {
        let server = serve_once("200 OK", Some("\"v\""), &body);
        let target = fx.feed_target(&server.url);
        discovery::poll_once(&fx.witness, &target).await;
        assert_eq!(fx.witness.log_count(), 1, "body {body:?} must be rejected");
        assert!(cosigns(&fx.witness, &manual));
        assert!(!target.managed_path.exists());
    }
}

/// A feed body whose hybrid vkey does not parse (fail-closed validation is
/// the same rule as config load).
fn feed_body_invalid_vkey(log: &TestLog) -> String {
    serde_json::json!({
        "logs": [{
            "origin": log.origin,
            "vkeys": { "hybrid": "not-a-vkey", "ed25519": log.vkey() },
        }]
    })
    .to_string()
}

#[tokio::test]
async fn interval_loop_applies_updates_without_a_restart() {
    let manual = TestLog::new("example.com/manual");
    let one = TestLog::new("example.com/one");
    let two = TestLog::new("example.com/two");
    let fx = Fixture::new(&[&manual], None);

    let mut server = serve_sequence(vec![
        ("200 OK", Some("\"v1\""), feed_body(&[&one])),
        ("304 Not Modified", None, String::new()),
        ("200 OK", Some("\"v2\""), feed_body(&[&one, &two])),
    ]);
    let target = fx.feed_target(&server.url);
    let handle = discovery::spawn(fx.witness.clone(), target, Duration::from_millis(25));

    // Poll 1 fires immediately (boot is never blocked on the feed): an
    // unconditional GET, then the new origin is cosigned mid-run.
    let head1 = server.request().await;
    assert!(
        !head1.contains("If-None-Match"),
        "nothing cached yet: {head1}"
    );
    let w = fx.witness.clone();
    let first = String::from("example.com/one");
    eventually(move || {
        let probe = TestLog::new(&first);
        cosigns(&w, &probe) && w.log_count() == 2
    })
    .await;

    // Poll 2 is a 304 (the request proves poll 1's ETag was cached; the
    // sequential loop means this head only arrives after poll 2 finished,
    // having changed nothing).
    let head2 = server.request().await;
    assert!(
        head2.contains("if-none-match: \"v1\""),
        "cached validator sent: {head2}"
    );

    // Poll 3 revalidates under the same validator, gets the changed set, and
    // applies it — still with no restart and no operator action.
    let head3 = server.request().await;
    assert!(head3.contains("if-none-match: \"v1\""), "{head3}");
    let w = fx.witness.clone();
    eventually(move || {
        let probe = TestLog::new("example.com/two");
        cosigns(&w, &probe) && w.log_count() == 3
    })
    .await;

    assert!(
        cosigns(&fx.witness, &manual),
        "manual origin served throughout"
    );
    let managed = fs::read_to_string(fx.dir.path().join(config::MANAGED_FILE_NAME)).unwrap();
    assert!(managed.contains("example.com/two"), "{managed}");
    handle.abort();
}
