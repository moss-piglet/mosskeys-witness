# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-08-08

### Fixed

- **C2SP prefix conformance:** the HTTP API is now served under the path
  component of the configured witness `name` (e.g. `witness.example/mosskeys`
  serves under `/mosskeys`), so a registered submission prefix of
  `https://<name>` reaches `add-checkpoint` instead of 404ing at the router.
  The API keeps answering at the listener root too, so root-registered
  prefixes already in the wild — and host-only names, where the prefix IS the
  root — are unaffected. Both mounts are the same handlers over the same
  state: identical status taxonomy, method strictness, and T4 hardening, with
  the effective prefixes printed in the startup banner. A name whose path
  component is not a plain static URL path (empty segments, or the router's
  `{`/`}`/`*` syntax characters) is now a fatal config error (fail closed,
  I4) instead of a silently unreachable API.

## [0.4.1] - 2026-08-07

### Fixed

- The one-shot `sync` cron recipe now gates the witness restart on exit 10
  (the shipped `&&` form restarted on unchanged, never on updated), with the
  missing cron.d user field added. Ships `packaging/systemd/` oneshot+timer
  units; same wiring fixed in `sync --help`, `config.example.toml`, and the
  module docs.

## [0.4.0] - 2026-08-07

### Added

- `[discovery]` in-process auto-sync: when the section is present, `run`
  polls the log-discovery feed itself (ETag-conditional, first poll at boot
  without blocking startup) and hot-swaps the in-memory origin allowlist —
  no restarts, no cron. Poll failures are logged and non-fatal; the last
  known set keeps serving.

## [0.3.0] - 2026-08-07

### Added

- One-shot `mosskeys-witness sync` subcommand maintaining the managed
  `discovered_logs.toml` allowlist next to the state file (certbot-style
  exit contract: 0 unchanged / 10 updated / 1 error), for cron- or
  systemd-timer-driven allowlist updates.

## [0.2.0] - 2026-07-29

### Added

- One-line install script and container quickstart docs (GHCR image,
  bind-mount layout, non-root uid notes).

## [0.1.0] - 2026-07-29

Initial release: a post-quantum-native C2SP tlog-witness that dual-signs
every accepted checkpoint with Ed25519 (`0x04`) and ML-DSA-44 (`0x06`)
cosignatures, built on the audited `metamorphic-log` crate.
