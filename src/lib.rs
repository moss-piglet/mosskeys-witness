#![forbid(unsafe_code)]
//! # mosskeys-witness
//!
//! A post-quantum-native [C2SP tlog-witness](https://c2sp.org/tlog-witness):
//! an HTTP service that verifies transparency-log checkpoints for consistency
//! and returns cosignatures over them.
//!
//! Every accepted checkpoint is **dual-signed** from two independently minted
//! keypairs:
//!
//! - a `0x04` Ed25519 cosignature for interop with today's deployed tooling
//!   (omniwitness, sigsum-compatible verifiers), and
//! - a `0x06` ML-DSA-44 cosignature — the post-quantum type the tlog-witness
//!   spec recommends and no other shipping witness produces.
//!
//! All checkpoint, note, Merkle-proof, and cosignature handling is delegated
//! to the audited [`metamorphic-log`] crate; this crate adds the wire
//! protocol, the atomic per-log state store, and key management. The design
//! invariants are in `docs/spec-conformance.md` and `docs/threat-model.md`.

pub mod keygen;

#[cfg(test)]
mod tests {
    /// Smoke test: the metamorphic-log cosignature vkey surface this witness
    /// is built on (0x04 / 0x06 encoders) is reachable and round-trips.
    #[test]
    fn cosignature_vkeys_round_trip() {
        let ed = metamorphic_log::note::VerifierKey::new_cosignature_ed25519(
            "witness.example/w1",
            &[7u8; 32],
        )
        .expect("0x04 vkey");
        let ml = metamorphic_log::note::VerifierKey::new_cosignature_mldsa44(
            "witness.example/w1",
            &[9u8; 1312],
        )
        .expect("0x06 vkey");

        for vkey in [ed, ml] {
            let encoded = vkey.encode();
            let parsed =
                metamorphic_log::note::VerifierKey::parse(&encoded).expect("vkey re-parse");
            assert_eq!(parsed.name(), vkey.name());
            assert_eq!(parsed.key_id(), vkey.key_id());
            assert_eq!(parsed.signature_type(), vkey.signature_type());
            assert_eq!(parsed.public_key(), vkey.public_key());
        }
    }
}
