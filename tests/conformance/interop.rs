//! §8 interop live tests (docs/spec-conformance.md): omniwitness and sigsum.
//!
//! GATED: these tests need a Go toolchain and module downloads, so they run
//! only when `MOSSKEYS_WITNESS_INTEROP=1` is set. One-time setup and the
//! full explanation of what each row proves live in docs/interop.md.
//!
//! Each test drives the REAL binary: it submits a checkpoint over loopback
//! TCP, fetches the cosigned note from the monitoring prefix, and hands the
//! exact served bytes to the external verifier (scripts/interop/) — the
//! omniwitness row via golang.org/x/mod/sumdb/note (the note library
//! omniwitness is built on), the sigsum row via sigsum-go's pkg/checkpoint.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

use crate::support::{
    HttpFixture, LOG_ORIGIN, WitnessProcess, connect, raw_request, request_body,
    tree_with_numbered_leaves,
};

fn interop_enabled() -> bool {
    std::env::var("MOSSKEYS_WITNESS_INTEROP").as_deref() == Ok("1")
}

fn skip(row: &str) {
    eprintln!(
        "skipping §8 {row} live test: set MOSSKEYS_WITNESS_INTEROP=1 after the one-time setup in \
         docs/interop.md"
    );
}

#[test]
fn interop_omniwitness_xmod_note_verifies_our_0x04_cosignature() {
    // covers §8 omniwitness row (when enabled): our served checkpoint + the
    // 0x04 line verify through golang.org/x/mod/sumdb/note with a
    // cosignature/v1 verifier — the omniwitness verification construction.
    if !interop_enabled() {
        return skip("omniwitness");
    }
    let artifacts = produce_witnessed_checkpoint();
    run_go_verifier("omniwitness", &artifacts);
}

#[test]
fn interop_sigsum_go_verifies_our_0x04_cosignature() {
    // covers §8 sigsum row (when enabled): sigsum-go's pkg/checkpoint parses
    // the checkpoint, verifies the log signature, and verifies our 0x04
    // cosignature via VerifyCosignatureByKey; its NewWitnessKeyId agrees
    // with our vkey's key id (CS-08).
    if !interop_enabled() {
        return skip("sigsum");
    }
    let artifacts = produce_witnessed_checkpoint();
    run_go_verifier("sigsum", &artifacts);
}

/// The exact artifacts an external verifier needs: the served cosigned note
/// (checkpoint text + log signature + both witness cosignature lines) plus
/// the two vkeys.
struct Artifacts {
    note_path: PathBuf,
    witness_vkey: String,
    log_vkey: String,
    #[allow(dead_code)]
    dir: TempDir, // kept alive until the verifier has run
}

/// Submit a checkpoint to the real binary and fetch the monitoring note.
fn produce_witnessed_checkpoint() -> Artifacts {
    let proc = WitnessProcess::spawn();
    let mut stream = connect(proc.port);

    let tree = tree_with_numbered_leaves(3);
    let body = request_body(0, &[], &proc.log.checkpoint_note(&tree, 3));
    let submitted = raw_request(&mut stream, "POST", "/add-checkpoint", body.as_bytes());
    assert_eq!(submitted.status, 200);

    let served = raw_request(
        &mut stream,
        "GET",
        &HttpFixture::monitoring_path(LOG_ORIGIN),
        &[],
    );
    assert_eq!(served.status, 200);

    let dir = TempDir::new().unwrap();
    let note_path = dir.path().join("witnessed-checkpoint.txt");
    std::fs::write(&note_path, &served.body).unwrap();

    let witness_vkey = proc.ed_vkey.clone();
    let log_vkey = proc.log.vkey();
    let _ = proc.into_stderr();

    Artifacts {
        note_path,
        witness_vkey,
        log_vkey,
        dir,
    }
}

/// `go run ./<which>` the verifier in scripts/interop/ against the
/// artifacts. Fails with setup guidance when the toolchain or the resolved
/// modules are missing (docs/interop.md).
fn run_go_verifier(which: &str, artifacts: &Artifacts) {
    let interop_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/interop");
    assert!(
        interop_dir.join("go.sum").exists(),
        "Go modules not resolved — one-time setup: `cd scripts/interop && go mod tidy` \
         (see docs/interop.md)"
    );
    let output = Command::new("go")
        .args(["run", &format!("./{which}")])
        .arg(&artifacts.note_path)
        .arg(&artifacts.witness_vkey)
        .arg(&artifacts.log_vkey)
        .current_dir(&interop_dir)
        .output()
        .expect("failed to execute `go` — install a Go toolchain (see docs/interop.md)");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the {which} verifier rejected our cosignature:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("OK:"),
        "the {which} verifier did not report success:\nstdout: {stdout}\nstderr: {stderr}"
    );
    eprintln!("§8 {which}: {}", stdout.trim());
}
