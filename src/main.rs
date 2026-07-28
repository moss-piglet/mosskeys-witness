#![forbid(unsafe_code)]
//! Binary entry point for `mosskeys-witness`.

mod cli;

use std::process::ExitCode;

use clap::Parser as _;
use cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => run_keygen(&args, cli.json),
    }
}

fn run_keygen(args: &cli::KeygenArgs, json: bool) -> ExitCode {
    match mosskeys_witness::keygen::generate(&args.name, &args.out_dir) {
        Ok(identity) => {
            if json {
                let keys: Vec<serde_json::Value> = identity
                    .keys
                    .iter()
                    .map(|k| {
                        serde_json::json!({
                            "suite": k.suite.tag(),
                            "type": format!("0x{:02x}", k.suite.type_byte()),
                            "vkey": k.vkey,
                            "seed_file": k.seed_file,
                        })
                    })
                    .collect();
                let out = serde_json::json!({
                    "name": identity.name,
                    "keys": keys,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).expect("JSON serialization")
                );
            } else {
                println!("Witness identity minted for {}\n", identity.name);
                for key in &identity.keys {
                    println!("{} vkey (public — register with logs):", key.suite);
                    println!("  {}", key.vkey);
                    println!(
                        "  seed file (secret, mode 0600): {}",
                        key.seed_file.display()
                    );
                    println!();
                }
                println!(
                    "Register BOTH vkeys with every log this witness cosigns, then keep the\n\
                     seed files safe — they are the only copy of your witness identity."
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
