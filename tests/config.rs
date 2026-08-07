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
fn empty_log_list_loads_but_witness_construction_is_fatal() {
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin)).replace(
        "[[log]]\norigin = \"example.com/behind-the-sofa\"",
        "[[__disabled__]]\norigin = \"example.com/behind-the-sofa\"",
    );
    // The [[log]] stanza was renamed away, leaving zero logs; the stray
    // top-level key trips deny_unknown_fields first, so assert either fatal.
    assert!(load_str(&text).is_err());

    // The clean empty-allowlist case: the config itself loads (a fully
    // managed witness has zero manual stanzas before its first sync), but
    // building a witness from it is fatal (T8) — and needs no key files.
    let text = valid_config(origin, &log_vkey(origin))
        .split("[[log]]")
        .next()
        .unwrap()
        .to_string();
    let config = load_str(&text).unwrap();
    assert!(config.logs.is_empty());
    let err = mosskeys_witness::witness::Witness::from_config(&config).unwrap_err();
    assert!(
        matches!(err, mosskeys_witness::witness::StartupError::NoLogs),
        "got {err:?}"
    );
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

// --- Managed file (discovered_logs.toml) merge semantics ---

/// A config + its directory, so tests can place a managed file next to the
/// state file. Zero manual [[log]] stanzas unless `extra` adds some.
fn fixture_with_managed(extra_config: &str, managed: Option<&str>) -> config::Config {
    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("state.jsonl");
    let text = format!(
        r#"
name = "witness.example/w1"
listen = "127.0.0.1:8787"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"

{extra_config}
"#,
        state_file.display(),
        dir.path().join("keys/ed25519.seed").display(),
        dir.path().join("keys/mldsa44.seed").display(),
    );
    let config_path = dir.path().join("witness.toml");
    fs::write(&config_path, &text).unwrap();
    if let Some(managed) = managed {
        fs::write(config::managed_file_path(&state_file), managed).unwrap();
    }
    // The tempdir can drop after this call: load reads everything eagerly.
    config::load(&config_path).unwrap()
}

fn managed_toml(entries: &[(&str, &str)]) -> String {
    let mut out = String::from("# Managed by `mosskeys-witness sync` — do not edit.\n\n");
    for (origin, vkey) in entries {
        out.push_str(&format!(
            "[[log]]\norigin = \"{origin}\"\nvkeys = [\"{vkey}\"]\n\n"
        ));
    }
    out
}

#[test]
fn managed_file_is_merged_into_the_allowlist() {
    let origin = "example.com/managed";
    let config = fixture_with_managed("", Some(&managed_toml(&[(origin, &log_vkey(origin))])));
    assert_eq!(config.logs.len(), 1);
    assert_eq!(config.logs[0].origin, origin);
}

#[test]
fn manual_stanza_wins_over_managed_on_duplicate_origin() {
    let origin = "example.com/shared";
    let manual_vkey = log_vkey(origin);
    let managed_vkey = log_vkey(origin); // a DIFFERENT key for the same origin
    let manual = format!("[[log]]\norigin = \"{origin}\"\nvkeys = [\"{manual_vkey}\"]\n");
    let config = fixture_with_managed(&manual, Some(&managed_toml(&[(origin, &managed_vkey)])));
    assert_eq!(config.logs.len(), 1, "manual wins, managed entry skipped");
    assert_eq!(config.logs[0].vkeys[0].encode(), manual_vkey);
}

#[test]
fn malformed_managed_file_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("state.jsonl");
    let text = format!(
        r#"
name = "witness.example/w1"
listen = "127.0.0.1:8787"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"
"#,
        state_file.display(),
        dir.path().join("keys/ed25519.seed").display(),
        dir.path().join("keys/mldsa44.seed").display(),
    );
    let config_path = dir.path().join("witness.toml");
    fs::write(&config_path, &text).unwrap();
    fs::write(
        config::managed_file_path(&state_file),
        "this is not toml = [",
    )
    .unwrap();
    let err = config::load(&config_path).unwrap_err();
    assert!(
        matches!(err, ConfigError::ManagedParse { .. }),
        "got {err:?}"
    );
}

#[test]
fn duplicate_origin_within_managed_file_is_fatal() {
    let origin = "example.com/dup";
    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("state.jsonl");
    let text = format!(
        r#"
name = "witness.example/w1"
listen = "127.0.0.1:8787"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"
"#,
        state_file.display(),
        dir.path().join("keys/ed25519.seed").display(),
        dir.path().join("keys/mldsa44.seed").display(),
    );
    let config_path = dir.path().join("witness.toml");
    fs::write(&config_path, &text).unwrap();
    fs::write(
        config::managed_file_path(&state_file),
        managed_toml(&[(origin, &log_vkey(origin)), (origin, &log_vkey(origin))]),
    )
    .unwrap();
    let err = config::load(&config_path).unwrap_err();
    assert!(
        matches!(err, ConfigError::DuplicateOrigin(_)),
        "got {err:?}"
    );
}

#[test]
fn managed_entry_with_bad_vkey_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("state.jsonl");
    let text = format!(
        r#"
name = "witness.example/w1"
listen = "127.0.0.1:8787"
state_file = "{}"

[keys]
ed25519_seed = "{}"
mldsa44_seed = "{}"
"#,
        state_file.display(),
        dir.path().join("keys/ed25519.seed").display(),
        dir.path().join("keys/mldsa44.seed").display(),
    );
    let config_path = dir.path().join("witness.toml");
    fs::write(&config_path, &text).unwrap();
    fs::write(
        config::managed_file_path(&state_file),
        managed_toml(&[("example.com/bad", "not-a-vkey")]),
    )
    .unwrap();
    let err = config::load(&config_path).unwrap_err();
    assert!(matches!(err, ConfigError::BadVkey { .. }), "got {err:?}");
}

#[test]
fn discovery_section_is_optional_and_validated() {
    // No [discovery] at all: fine, sync would use the default feed URL.
    let config = fixture_with_managed("", None);
    assert!(config.discovery.feed_url.is_none());

    // A non-http(s) feed URL is a fatal typo, not a silent ignore (T8).
    let origin = "example.com/behind-the-sofa";
    let text = valid_config(origin, &log_vkey(origin))
        + "\n[discovery]\nfeed_url = \"ftp://example.com/feed\"\n";
    let err = load_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::FeedUrl(_)), "got {err:?}");
}
