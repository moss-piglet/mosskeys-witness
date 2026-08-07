#!/usr/bin/env bash
# Decouple the crate from its sibling working tree so a CI / release build
# resolves `metamorphic-log` from crates.io instead of `../metamorphic-log`.
#
# During local co-development the `Cargo.toml` pins that crate to the sibling
# checkout via `path = "..."`, so `Cargo.lock` records it as a source-less
# (local) package. That path cannot exist on a CI runner or influence a
# published release, so this script rewrites both files in place:
#
#   Cargo.toml
#     1. drop the `path = "..."` key from the metamorphic-log dependency
#        (leaving the crates.io `version` requirement intact), and
#
#   Cargo.lock
#     2. delete the source-less metamorphic-log package entry so it gets
#        re-added FROM crates.io (with a registry source + checksum) by
#        `cargo fetch`. Only this entry is touched; every other dependency
#        (including metamorphic-crypto, which is a pure crates.io dependency
#        here) stays pinned exactly as committed, which is what keeps the
#        `--locked` build honest.
#
# The published dep is already on crates.io at the pinned version
# (metamorphic-log 0.5.0). After this script, run `cargo fetch` once to re-add
# the entry, then build/publish with `--locked`.
#
# Idempotent: safe to run twice (the second run is a no-op).
set -euo pipefail

manifest="${1:-Cargo.toml}"
lockfile="${2:-Cargo.lock}"

python3 - "$manifest" "$lockfile" <<'PY'
import re, sys

manifest, lockfile = sys.argv[1], sys.argv[2]

# --- Cargo.toml ---
src = open(manifest, encoding="utf-8").read()

# 1. Strip `, path = "../metamorphic-log"` from the dependency line, keeping
#    the crates.io version requirement.
src = re.sub(
    r'(metamorphic-log\s*=\s*\{[^}]*?),\s*path\s*=\s*"\.\./metamorphic-log"',
    r'\1',
    src,
)

open(manifest, "w", encoding="utf-8").write(src)
print(f"decoupled {manifest} from the sibling working tree")

# --- Cargo.lock ---
try:
    lock = open(lockfile, encoding="utf-8").read()
except FileNotFoundError:
    print(f"no {lockfile}; skipping lock cleanup")
    raise SystemExit(0)

lock = re.sub(
    r'\[\[package\]\]\nname = "metamorphic-log"\n.*?(?=\n\[\[package\]\]|\Z)',
    "",
    lock,
    flags=re.S,
)

open(lockfile, "w", encoding="utf-8").write(lock)
print(f"removed metamorphic-log entry from {lockfile} (cargo fetch re-adds from crates.io)")
PY

echo "--- resulting metamorphic-log dependency state ---"
grep -nE 'metamorphic-log' "$manifest" || true
