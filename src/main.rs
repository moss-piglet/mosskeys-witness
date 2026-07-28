#![forbid(unsafe_code)]
//! Binary entry point for `mosskeys-witness`.
//!
//! The real CLI (keygen / run / config handling) lands with the keygen task;
//! this stub keeps the scaffold buildable and CI green in the meantime.

fn main() {
    eprintln!(
        "mosskeys-witness {} (scaffold — CLI not yet implemented)",
        env!("CARGO_PKG_VERSION")
    );
}
