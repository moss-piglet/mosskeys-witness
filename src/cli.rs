//! Command-line surface (clap derive), styled to match the mosskeys-cli bar.

use std::path::PathBuf;

use clap::builder::styling::{Color, RgbColor, Style, Styles};
use clap::{Args, Parser, Subcommand};

/// Brand-aligned help styles, mirroring mosskeys-cli: section headers and
/// usage in emerald, commands/flags in bright emerald, placeholders in cyber
/// cyan. clap only paints these on a TTY and honours `NO_COLOR`.
const fn help_styles() -> Styles {
    const BRAND: Color = Color::Rgb(RgbColor(52, 211, 153)); // emerald-400
    const BRAND_LIGHT: Color = Color::Rgb(RgbColor(110, 231, 183)); // emerald-300
    const CYBER: Color = Color::Rgb(RgbColor(34, 211, 238)); // cyan-400
    const DANGER: Color = Color::Rgb(RgbColor(252, 165, 165)); // red-300

    Styles::styled()
        .header(Style::new().bold().underline().fg_color(Some(BRAND)))
        .usage(Style::new().bold().underline().fg_color(Some(BRAND)))
        .literal(Style::new().bold().fg_color(Some(BRAND_LIGHT)))
        .placeholder(Style::new().fg_color(Some(CYBER)))
        .valid(Style::new().fg_color(Some(BRAND_LIGHT)))
        .invalid(Style::new().bold().fg_color(Some(DANGER)))
        .error(Style::new().bold().fg_color(Some(DANGER)))
}

/// mosskeys-witness — a post-quantum-native C2SP tlog-witness.
#[derive(Debug, Parser)]
#[command(
    name = "mosskeys-witness",
    version,
    about = "cosign transparency-log checkpoints with Ed25519 (0x04) + ML-DSA-44 (0x06)",
    long_about = "mosskeys-witness is a C2SP tlog-witness: it verifies transparency-log \
checkpoints for consistency and cosigns them. Every accepted checkpoint is dual-signed — \
an Ed25519 (0x04) cosignature for interop with today's tooling, and an ML-DSA-44 (0x06) \
cosignature, the post-quantum type the tlog-witness spec recommends. Run a subcommand \
with --help for its full options.",
    next_line_help = true,
    max_term_width = 100,
    styles = help_styles()
)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout (implies no colour).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mint the witness's two cosigner keypairs (Ed25519 + ML-DSA-44).
    Keygen(KeygenArgs),
    /// Run the witness HTTP service (submission + monitoring prefixes).
    Run(RunArgs),
    /// Sync the managed origin allowlist from the log-discovery feed (one-shot, cron-friendly).
    Sync(SyncArgs),
}

/// `mosskeys-witness keygen` — generate both cosigner keypairs locally.
///
/// Keys are generated entirely on this machine via the audited
/// metamorphic-crypto core; nothing touches the network. The secret seeds are
/// written to `--out-dir` as `0600` files that are never overwritten; only the
/// public vkeys are printed, ready to register with every log this witness
/// will cosign (e.g. a mosskeys deployment's witness registry).
#[derive(Debug, Args)]
#[command(after_long_help = "EXAMPLES:\n\
    \x20   # Mint both cosigner keypairs for a witness identity\n\
    \x20   mosskeys-witness keygen --name witness.example/w1 --out-dir ./keys\n\
    \n\
    \x20   # Then, on each log you cosign, register BOTH printed vkeys. On a\n\
    \x20   # mosskeys deployment the registry accepts the 0x06 ML-DSA-44 vkey\n\
    \x20   # alongside the classical 0x04 one.\n\
    \n\
    OUTPUT:\n\
    \x20   Two seed files (KEEP SECRET, mode 0600):\n\
    \x20     <out-dir>/ed25519.seed   — Ed25519 (0x04) cosigner seed\n\
    \x20     <out-dir>/mldsa44.seed   — ML-DSA-44 (0x06) cosigner seed\n\
    \x20   Two vkey lines on stdout (PUBLIC, safe to share):\n\
    \x20     the signed-note verifier keys for both cosigners.")]
pub struct KeygenArgs {
    /// Witness key name — a schema-less URL identifying this cosigner
    /// (e.g. witness.example/w1). Embedded in every cosignature and vkey.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Directory to write the two `0600` seed files into
    /// (created `0700` if missing; existing seed files are never overwritten).
    #[arg(long, short = 'o', value_name = "DIR")]
    pub out_dir: PathBuf,
}

/// `mosskeys-witness run` — start the witness HTTP service.
///
/// Loads the TOML config, applies every startup hard-check (owner-only seed
/// files whose derived vkeys match the configured witness name, duplicate
/// origins fatal, state file exclusive-locked and replayed), then serves
/// `POST /add-checkpoint` — and the monitoring prefix — on one listener
/// until SIGINT/SIGTERM. Any check failure is fatal (fail closed, I4).
#[derive(Debug, Args)]
#[command(after_long_help = "EXAMPLES:\n\
    \x20   # Mint the identity, then write a config (see config.example.toml)\n\
    \x20   mosskeys-witness keygen --name witness.example/w1 --out-dir ./keys\n\
    \x20   mosskeys-witness run --config ./witness.toml\n\
    \n\
    \x20   # Submit a checkpoint from a log (what the service answers):\n\
    \x20   curl -X POST --data-binary @request.txt http://127.0.0.1:8080/add-checkpoint\n\
    \n\
    CONFIG:\n\
    \x20   The config is a plain (origin, vkey) allowlist like omniwitness/sigsum\n\
    \x20   operators already maintain — unknown origins are 404 by construction.\n\
    \x20   See config.example.toml for the annotated template.")]
pub struct RunArgs {
    /// Path to the TOML config file (witness name, seed paths, listen
    /// address, state file, and the [[log]] origin+vkey allowlist).
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: PathBuf,
}

/// `mosskeys-witness sync` — refresh the managed origin allowlist from the
/// log-discovery feed, one-shot (the certbot-renew pattern).
///
/// Fetches the feed ETag-conditionally (a 304 costs nothing), validates every
/// entry with the same fail-closed rules as config load, and writes the
/// result atomically to `discovered_logs.toml` next to the state file.
/// `run` merges that file at startup whenever present — manual [[log]]
/// stanzas win on duplicate origins — so a cron pair keeps the allowlist
/// current without hand-edits. (With a [discovery] section in the config,
/// `run` instead polls the feed itself on an interval and hot-reloads the
/// allowlist in-process — no cron, no restarts.) The configured feed is the
/// vetting boundary for managed entries; pin an origin's keys with a manual
/// stanza if you want them frozen.
#[derive(Debug, Args)]
#[command(after_long_help = "EXIT CODES:\n\
    \x20   0   origin set unchanged (feed not modified, or same set on disk)\n\
    \x20   10  managed file updated — restart the witness to apply\n\
    \x20   1   error (feed unreachable, invalid feed, unwritable state dir)\n\
    \n\
    EXAMPLES:\n\
    \x20   # One-shot: fetch the feed and write the managed allowlist\n\
    \x20   mosskeys-witness sync --config ./witness.toml\n\
    \n\
    \x20   # Cron, certbot-style: restart only when the set changed\n\
    \x20   */15 * * * * mosskeys-witness sync --quiet --config /etc/mosskeys-witness/witness.toml \\\n\
    \x20       && systemctl restart mosskeys-witness\n\
    \n\
    \x20   # Point at a different deployment's feed (or set [discovery] feed_url)\n\
    \x20   mosskeys-witness sync --config ./witness.toml --feed-url https://example.com/api/witness/logs")]
pub struct SyncArgs {
    /// Path to the TOML config file. Locates the state file (the managed
    /// `discovered_logs.toml` and the ETag cache live next to it) and the
    /// optional [discovery] feed_url.
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: PathBuf,

    /// Override the discovery feed URL (default:
    /// https://mosskeys.com/api/witness/logs, or the config's
    /// [discovery] feed_url).
    #[arg(long, value_name = "URL")]
    pub feed_url: Option<String>,

    /// Suppress non-error output (for cron).
    #[arg(long, short = 'q')]
    pub quiet: bool,
}
