//! Unit tests for the add-checkpoint request parser (AC-01…AC-06).
//! Each test cites the conformance row it covers (docs/spec-conformance.md).

use super::*;

use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{Signature, SignedNote};

/// A throwaway log identity for building signed checkpoints.
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

    /// A signed-note checkpoint over `tree`'s first `size` leaves.
    fn checkpoint_note(&self, tree: &MerkleTree, size: u64) -> String {
        self.sign(&checkpoint_text(&self.origin, tree, size))
    }

    fn sign(&self, text: &str) -> String {
        let sig = metamorphic_log::note::sign_ed25519(text, &self.origin, &self.seed).unwrap();
        SignedNote::new(text.to_string(), vec![sig])
            .unwrap()
            .marshal()
    }
}

fn checkpoint_text(origin: &str, tree: &MerkleTree, size: u64) -> String {
    format!("{origin}\n{size}\n{}\n", B64.encode(tree.root_at(size)))
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

fn parse_ok(body: &str) -> ParsedRequest {
    parse_request(body).unwrap_or_else(|r| panic!("should parse, got {r:?}: {body:?}"))
}

fn parse_err(body: &str) -> Reject {
    parse_request(body).unwrap_err()
}

#[test]
fn parses_a_minimal_valid_request() {
    // covers AC-01, AC-02, AC-03, AC-06
    let log = TestLog::new("example.com/log");
    let mut tree = MerkleTree::new();
    for i in 0..3u64 {
        tree.push(format!("leaf-{i}").as_bytes());
    }
    let note = log.checkpoint_note(&tree, 3);

    let req = parse_ok(&request_body(0, &[], &note));
    assert_eq!(req.old_size, 0);
    assert!(req.proof.is_empty());
    assert_eq!(req.checkpoint.origin(), "example.com/log");
    assert_eq!(req.checkpoint.size(), 3);
    assert_eq!(req.checkpoint.root_hash(), &tree.root_at(3));
    assert_eq!(req.note.signatures().len(), 1);
}

#[test]
fn parses_proof_lines() {
    // covers AC-04: each proof line is one base64 hash, decoded in order.
    let log = TestLog::new("example.com/log");
    let mut tree = MerkleTree::new();
    for i in 0..5u64 {
        tree.push(format!("leaf-{i}").as_bytes());
    }
    let proof = tree.consistency_proof(3, 5);
    let note = log.checkpoint_note(&tree, 5);

    let req = parse_ok(&request_body(3, &proof, &note));
    assert_eq!(req.old_size, 3);
    assert_eq!(
        req.proof,
        proof.iter().map(|h| h.to_vec()).collect::<Vec<_>>()
    );
}

#[test]
fn rejects_missing_trailing_newline() {
    // covers AC-02: every line — including the last — terminates in U+000A.
    let log = TestLog::new("example.com/log");
    let tree = MerkleTree::new();
    let note = log.checkpoint_note(&tree, 0);
    let mut body = request_body(0, &[], &note);
    body.pop(); // strip the final newline
    assert_eq!(
        parse_err(&body),
        Reject::Malformed("body is not newline-terminated")
    );
    assert_eq!(
        parse_err(""),
        Reject::Malformed("body is not newline-terminated")
    );
}

#[test]
fn rejects_malformed_old_size_lines() {
    // covers AC-03
    let log = TestLog::new("example.com/log");
    let tree = MerkleTree::new();
    let note = log.checkpoint_note(&tree, 0);
    // "<old-size line>" + "\n" (ends the line) + "\n" (empty separator) + note.
    let good_tail = format!("\n\n{note}");

    for (line, why) in [
        ("old", "no size"),
        ("old\t0", "tab is not 0x20"),
        ("old  0", "double space"),
        ("old ", "empty digits"),
        ("old 01", "leading zero"),
        ("old 0x10", "not decimal"),
        ("old -1", "negative"),
        ("old 18446744073709551616", "u64 overflow"),
        ("old 1.0", "not an integer"),
        ("old 1 ", "trailing space"),
    ] {
        let body = format!("{line}{good_tail}");
        assert!(
            matches!(parse_err(&body), Reject::Malformed(_)),
            "{why}: {line:?} should be 400"
        );
    }

    // "0" itself is the one allowed zero-padded-free zero; u64::MAX is fine.
    assert_eq!(parse_ok(&format!("old 0{good_tail}")).old_size, 0);
}

#[test]
fn rejects_bad_proof_lines() {
    // covers AC-04
    let log = TestLog::new("example.com/log");
    let mut tree = MerkleTree::new();
    tree.push(b"leaf");
    let note = log.checkpoint_note(&tree, 1);

    // Not base64 at all.
    let body = format!("old 0\n!!!not-base64!!!\n\n{note}");
    assert_eq!(
        parse_err(&body),
        Reject::Malformed("consistency-proof line is not valid base64")
    );

    // Valid base64 but not a 32-byte hash.
    let short = B64.encode([7u8; 16]);
    let body = format!("old 0\n{short}\n\n{note}");
    assert_eq!(
        parse_err(&body),
        Reject::Malformed("consistency-proof line must decode to a 32-byte hash")
    );
}

#[test]
fn rejects_more_than_63_proof_lines() {
    // covers AC-05
    let log = TestLog::new("example.com/log");
    let tree = MerkleTree::new();
    let note = log.checkpoint_note(&tree, 0);

    let proof63 = vec![[1u8; 32]; 63];
    let req = parse_ok(&request_body(0, &proof63, &note));
    assert_eq!(req.proof.len(), 63);

    let proof64 = vec![[1u8; 32]; 64];
    assert_eq!(
        parse_err(&request_body(0, &proof64, &note)),
        Reject::Malformed("more than 63 consistency-proof lines")
    );
}

#[test]
fn rejects_missing_separator_or_checkpoint() {
    // covers AC-01: the empty line and the checkpoint are required.
    assert_eq!(
        parse_err("old 0\n"),
        Reject::Malformed("missing empty line before the checkpoint")
    );
    assert_eq!(
        parse_err("old 0\n\n"),
        Reject::Malformed("missing checkpoint")
    );

    // Proof-looking lines that never terminate in a separator.
    let body = format!("old 0\n{}\n", B64.encode([1u8; 32]));
    assert_eq!(
        parse_err(&body),
        Reject::Malformed("missing empty line before the checkpoint")
    );
}

#[test]
fn rejects_a_structurally_bad_note() {
    // covers AC-01/AC-06: the checkpoint must be a well-formed signed note.
    // No signature block at all.
    let body = "old 0\n\nexample.com/log\n1\nAARpcm88QZxj7jR9izc5sCygNRvIk0Ym2MCPmtKGxBk=\n";
    assert_eq!(
        parse_err(body),
        Reject::Malformed("checkpoint is not a well-formed signed note")
    );

    // Signature line missing the — prefix.
    let body = "old 0\n\nexample.com/log\n1\nAARpcm88QZxj7jR9izc5sCygNRvIk0Ym2MCPmtKGxBk=\n\nnot-a-sig-line\n";
    assert_eq!(
        parse_err(body),
        Reject::Malformed("checkpoint is not a well-formed signed note")
    );
}

#[test]
fn rejects_a_bad_checkpoint_body() {
    // covers AC-01: the note text must parse as a checkpoint (origin, size,
    // 32-byte root). Here the root is not valid base64.
    let log = TestLog::new("example.com/log");
    let text = "example.com/log\n1\n!!!not-base64!!!\n";
    let note = log.sign(text);
    let body = format!("old 0\n\n{note}");
    assert_eq!(
        parse_err(&body),
        Reject::Malformed("checkpoint body is malformed")
    );
}

#[test]
fn parses_multiple_signatures_including_unknown_keys() {
    // covers AC-06 (+ ST-04 groundwork: unknown signatures parse fine and
    // are carried along for the verifier to ignore).
    let log = TestLog::new("example.com/log");
    let stranger = TestLog::new("stranger.example/other");
    let mut tree = MerkleTree::new();
    tree.push(b"leaf");

    let text = checkpoint_text("example.com/log", &tree, 1);
    let sigs: Vec<Signature> = [&log, &stranger]
        .iter()
        .map(|l| metamorphic_log::note::sign_ed25519(&text, &l.origin, &l.seed).unwrap())
        .collect();
    let note = SignedNote::new(text, sigs).unwrap().marshal();

    let req = parse_ok(&format!("old 0\n\n{note}"));
    assert_eq!(req.note.signatures().len(), 2);
    assert_eq!(req.note.signatures()[1].name(), "stranger.example/other");
}
