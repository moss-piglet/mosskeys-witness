//! Integration tests for config loading and the startup hard-checks
//! (threat model T2/T8, invariant I4 — task 5).

use std::fs;

use metamorphic_log::note::VerifierKey;
use mosskeys_witness::config::{self, ConfigError};

/// A minimal valid config for one log; returns the TOML text.
fn valid_config(log_origin: &str, log_vkey: &str) -> String {
    format!(
        r#"
name = "witness.example/w1"
listen = "127.0.0.1:8080"
state_file = "/tmp/mosskeys-witness-test/state.jsonl"

[keys]
ed25519_seed = "/tmp/mosskeys-witness-test/keys/ed25519.seed"
mldsa44_seed = "/tmp/mosskeys-witness-test/keys/mldsa44.seed"

[[log]]
origin = "{log_origin}"
vkeys = ["{log_vkey}"]
"#
    )
}

/// Mint a throwaway log identity (Ed25519 0x01) and return its vkey line.
fn log_vkey(origin: &str) -> String {
    let (_seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
    VerifierKey::new_ed25519(origin, &pk).unwrap().encode()
}

fn load_str(text: &str) -> Result<config::Config, ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.toml");
    fs::write(&path, text).unwrap();
    config::load(&path)
}

#[test]
fn valid_config_loads() {
    let origin = "example.com/behind-the-sofa";
    let vkey = log_vkey(origin);
    let cfg = load_str(&valid_config(origin, &vkey)).unwrap();

    assert_eq!(cfg.name, "witness.example/w1");
    assert_eq!(cfg.listen.port(), 8080);
    assert_eq!(cfg.logs.len(), 1);
    assert_eq!(cfg.logs[0].origin, origin);
    assert_eq!(cfg.logs[0].vkeys.len(), 1);
    assert_eq!(cfg.logs[0].vkeys[0].name(), origin);
}

#[test]
fn duplicate_origins_are_fatal() {
    // T8/I4: two stanzas for one origin must not silently merge.
    let origin = "example.com/behind-the-sofa";
    let vkey = log_vkey(origin);
    let text = format!(
        "{}\n[[log]]\norigin = \"{origin}\"\nvkeys = [\"{vkey}\"]\n",
        valid_config(origin, &vkey)
    );
    let err = load_str(&text).unwrap_err();
    assert!(
        matches!(err, ConfigError::DuplicateOrigin(_)),
        "got {err:?}"
    );
}

#[test]
fn empty_log_list_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin)).replace(
        "[[log]]\norigin = \"example.com/behind-the-sofa\"",
        "[[__disabled__]]\norigin = \"example.com/behind-the-sofa\"",
    );
    // The [[log]] stanza was renamed away, leaving zero logs; the stray
    // top-level key trips deny_unknown_fields first, so assert either fatal.
    assert!(load_str(&text).is_err());

    // And the clean empty-allowlist case:
    let text = valid_config(origin, &log_vkey(origin))
        .split("[[log]]")
        .next()
        .unwrap()
        .to_string();
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::NoLogs), "got {err:?}");
}

#[test]
fn unknown_fields_are_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin)).replace(
        "state_file =",
        "statefile =", // typo must not be silently ignored (T8)
    );
    assert!(matches!(
        load_str(&text).unwrap_err(),
        ConfigError::Parse { .. }
    ));
}

#[test]
fn unparsable_vkey_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, "not-a-vkey");
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::BadVkey { .. }), "got {err:?}");
}

#[test]
fn log_without_vkeys_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin)).replace(
        "vkeys = [\"",
        "vkeys_backup = [\"", // unknown field → fatal parse error
    );
    assert!(load_str(&text).is_err());

    // Explicitly empty vkeys list:
    let vkey = log_vkey(origin);
    let text = valid_config(origin, &vkey).replace(&format!("vkeys = [\"{vkey}\"]"), "vkeys = []");
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::NoVkeys { .. }), "got {err:?}");
}

#[test]
fn same_seed_file_for_both_suites_is_fatal() {
    // T2: the two cosigner identities must be independently minted files.
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin)).replace(
        "\"/tmp/mosskeys-witness-test/keys/mldsa44.seed\"",
        "\"/tmp/mosskeys-witness-test/keys/ed25519.seed\"",
    );
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::SameSeedFile(_)), "got {err:?}");
}

#[test]
fn bad_listen_address_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin))
        .replace("listen = \"127.0.0.1:8080\"", "listen = \"not-an-address\"");
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::Listen(_)), "got {err:?}");
}

#[test]
fn invalid_witness_name_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin))
        .replace("name = \"witness.example/w1\"", "name = \"has space\"");
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidName(_)), "got {err:?}");
}
