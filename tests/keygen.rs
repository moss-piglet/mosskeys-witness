//! Integration tests for the keygen tooling (task 3).
//!
//! These prove the file ↔ vkey correspondence that log operators rely on:
//! the public vkey printed at keygen time is exactly the key the runtime
//! signer will derive from the seed file (conformance rows CS-08/CS-09).

use std::fs;

use metamorphic_log::note::{SignatureType, VerifierKey};
use mosskeys_witness::keygen::{self, KeygenError, Suite};

#[test]
fn generates_both_suites_with_matching_vkeys() {
    let dir = tempfile::tempdir().unwrap();
    let identity = keygen::generate("witness.example/w1", dir.path()).unwrap();

    assert_eq!(identity.name, "witness.example/w1");
    assert_eq!(identity.keys.len(), 2);

    for key in &identity.keys {
        // The vkey parses back with the right name and signature type.
        let parsed = VerifierKey::parse(&key.vkey).unwrap();
        assert_eq!(parsed.name(), "witness.example/w1");
        let want_type = match key.suite {
            Suite::Ed25519 => SignatureType::CosignatureV1Ed25519,
            Suite::MlDsa44 => SignatureType::CosignatureV1MlDsa44,
        };
        assert_eq!(parsed.signature_type(), want_type);

        // The seed file exists, decodes to 32 bytes, and — critically — the
        // public key derived from the seed matches the public key in the vkey
        // (so what you register is what the witness will sign with).
        assert!(key.seed_file.is_file());
        let seed = keygen::read_seed_file(&key.seed_file).unwrap();
        let derived: Vec<u8> = match key.suite {
            Suite::Ed25519 => metamorphic_crypto::ed25519_public_key(&*seed)
                .unwrap()
                .to_vec(),
            Suite::MlDsa44 => metamorphic_crypto::ml_dsa_44_public_key(&*seed).unwrap(),
        };
        assert_eq!(derived, parsed.public_key());
    }
}

#[test]
fn seed_files_are_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let identity = keygen::generate("witness.example/w1", dir.path()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for key in &identity.keys {
            let mode = fs::metadata(&key.seed_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{:?} permissions", key.seed_file);
        }
    }
}

#[test]
fn refuses_to_overwrite_existing_seed_files() {
    let dir = tempfile::tempdir().unwrap();
    keygen::generate("witness.example/w1", dir.path()).unwrap();

    // A second run must fail closed and leave the first identity untouched.
    let err = keygen::generate("witness.example/w1", dir.path()).unwrap_err();
    assert!(matches!(err, KeygenError::SeedFileExists(_)));

    // ... and the original seed files are byte-identical afterwards.
    let first = fs::read(dir.path().join("ed25519.seed")).unwrap();
    let _ = keygen::generate("witness.example/w1", dir.path());
    let second = fs::read(dir.path().join("ed25519.seed")).unwrap();
    assert_eq!(first, second);
}

#[test]
fn rejects_invalid_names() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["", "has space", "has\ttab", "has+plus"] {
        let err = keygen::generate(bad, dir.path()).unwrap_err();
        assert!(matches!(err, KeygenError::InvalidName(_)), "name {bad:?}");
    }
    // No files were minted for the invalid attempts.
    assert!(!dir.path().join("ed25519.seed").exists());
    assert!(!dir.path().join("mldsa44.seed").exists());
}

#[test]
fn read_seed_file_ignores_comments_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let identity = keygen::generate("witness.example/w1", dir.path()).unwrap();
    let key = &identity.keys[0];

    let text = fs::read_to_string(&key.seed_file).unwrap();
    assert!(text.contains("# witness name: witness.example/w1"));
    assert!(text.contains(&key.vkey));

    let seed = keygen::read_seed_file(&key.seed_file).unwrap();
    assert_eq!(seed.len(), 32);
}
