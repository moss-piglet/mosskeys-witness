//! §4 add-checkpoint — cosignature production (CS-01…CS-10). The returned
//! lines are parsed and checked against the tlog-cosignature preimages:
//! through metamorphic-log's `SignedNote::verify` (the same verifier a
//! monitor runs), through its message constructors with metamorphic-crypto's
//! primitive verifiers (positive AND negative known-answer checks), and
//! against hand-assembled struct layouts where the spec fixes the bytes.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{self, Signature, SignatureType, SignedNote, VerifierKey};

use crate::support::{
    HttpFixture, LOG_ORIGIN, WITNESS_NAME, hex, request_body, submit, tree_with_numbered_leaves,
};

/// One dual-signed checkpoint and its parsed response pieces.
struct Cosigned {
    body: String,
    checkpoint_text: String,
    ed_sig: Signature,
    ml_sig: Signature,
    size: u64,
    root: [u8; 32],
}

/// Submit `tree`@`size` (old 0, no proof) and dissect the 200 response.
async fn cosign_at(fx: &HttpFixture, tree: &MerkleTree, size: u64) -> Cosigned {
    let response = submit(
        &fx.app,
        request_body(0, &[], &fx.log.checkpoint_note(tree, size)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = crate::support::body_string(response).await;

    let checkpoint_text = fx.log.checkpoint_text(tree, size);
    let combined = format!("{checkpoint_text}\n{body}");
    let parsed = SignedNote::parse(&combined).unwrap();
    let ed_vkey = fx.ed_vkey();
    let ml_vkey = fx.ml_vkey();
    let find = |vkey: &VerifierKey| {
        parsed
            .signatures()
            .iter()
            .find(|s| s.name() == WITNESS_NAME && s.key_id() == vkey.key_id())
            .expect("a cosignature from each witness key")
            .clone()
    };
    Cosigned {
        body,
        checkpoint_text,
        ed_sig: find(&ed_vkey),
        ml_sig: find(&ml_vkey),
        size,
        root: tree.root_at(size),
    }
}

/// The `u64 timestamp` prefix of a cosignature's `timestamped_signature`
/// blob (CS-05).
fn timestamp_of(sig: &Signature) -> u64 {
    u64::from_be_bytes(sig.signature()[..8].try_into().unwrap())
}

#[tokio::test]
async fn cs_01_cs_02_cs_10_dual_cosignatures_verify_through_metamorphic_log() {
    // covers CS-01 (the response signatures are tlog-cosignatures from the
    // witness key(s) on the checkpoint), CS-02 (an ML-DSA-44 cosignature is
    // produced), CS-10 (BOTH a 0x04 and a 0x06, from separately minted
    // keypairs — stricter than the spec baseline).
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let r = cosign_at(&fx, &tree, 3).await;

    // Exactly two lines (ST-12), one per witness key.
    assert_eq!(r.body.lines().count(), 2);

    // The keygen-produced vkeys are one 0x04 and one 0x06, independently
    // minted (distinct key ids, distinct key material).
    let ed_vkey = fx.ed_vkey();
    let ml_vkey = fx.ml_vkey();
    assert_eq!(
        ed_vkey.signature_type(),
        SignatureType::CosignatureV1Ed25519
    );
    assert_eq!(
        ml_vkey.signature_type(),
        SignatureType::CosignatureV1MlDsa44
    );
    assert_ne!(ed_vkey.key_id(), ml_vkey.key_id());
    assert_ne!(ed_vkey.public_key(), ml_vkey.public_key());

    // Both cosignatures verify through metamorphic-log's SignedNote::verify
    // — the same code path a monitor or registry runs.
    let combined = format!("{}\n{}", r.checkpoint_text, r.body);
    let note = SignedNote::parse(&combined).unwrap();
    let verified = note.verify(&[ed_vkey.clone(), ml_vkey.clone()]).unwrap();
    assert_eq!(verified.len(), 2);
    for vkey in [&ed_vkey, &ml_vkey] {
        assert!(
            verified
                .iter()
                .any(|s| s.name() == vkey.name() && s.key_id() == vkey.key_id()),
            "cosignature for {:?} must verify",
            vkey.signature_type()
        );
    }
}

#[tokio::test]
async fn cs_04_cs_05_one_nonzero_big_endian_timestamp_per_response() {
    // covers CS-04 (timestamp MUST NOT be zero) and CS-05 (POSIX seconds,
    // ≤ 2^63−1, big-endian in the `timestamped_signature` blob). Both
    // cosignatures in one response carry the SAME timestamp.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
    let r = cosign_at(&fx, &tree, 3).await;
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;

    let ed_ts = timestamp_of(&r.ed_sig);
    let ml_ts = timestamp_of(&r.ml_sig);
    assert!(ed_ts > 0, "CS-04: nonzero");
    assert!(ml_ts > 0, "CS-04: nonzero");
    assert_eq!(
        ed_ts, ml_ts,
        "one timestamp per response, both cosignatures"
    );
    assert!(ed_ts <= i64::MAX as u64, "CS-05: ≤ 2^63−1");

    // CS-05 endianness: read big-endian the blob's first 8 bytes are the
    // current POSIX time (a little-endian read would land ~2^56, billions
    // of years outside this window).
    assert!(
        (before..=after).contains(&ed_ts),
        "big-endian POSIX seconds within the request window"
    );
}

#[tokio::test]
async fn cs_06_the_ed25519_signed_message_is_the_spec_preimage() {
    // covers CS-06: the 0x04 signed message is `cosignature/v1\n` +
    // `time <decimal>\n` + the whole note body (incl. its final newline,
    // excl. signature lines). Asserted as an exact known-answer string and
    // through metamorphic-crypto's verifier, positive and negative.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let r = cosign_at(&fx, &tree, 3).await;

    let ts = timestamp_of(&r.ed_sig);
    let pk = fx.ed_vkey().public_key().to_vec();
    let sig = &r.ed_sig.signature()[8..];

    // Known-answer: the preimage is byte-exact the spec's construction.
    let message = note::cosignature_v1_message(&r.checkpoint_text, ts);
    assert_eq!(
        message,
        format!("cosignature/v1\ntime {ts}\n{}", r.checkpoint_text)
    );
    assert!(metamorphic_crypto::ed25519_verify(pk.as_slice(), message.as_bytes(), sig).unwrap());

    // Negatives: any other timestamp or body fails to verify.
    let wrong_ts = note::cosignature_v1_message(&r.checkpoint_text, ts + 1);
    assert!(
        !metamorphic_crypto::ed25519_verify(pk.as_slice(), wrong_ts.as_bytes(), sig)
            .unwrap_or(false)
    );
    let other_text = fx.log.checkpoint_text(&tree, 2);
    let wrong_text = note::cosignature_v1_message(&other_text, ts);
    assert!(
        !metamorphic_crypto::ed25519_verify(pk.as_slice(), wrong_text.as_bytes(), sig)
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn cs_07_and_cs_03_the_mldsa44_message_is_the_whole_tree_struct() {
    // covers CS-07 (the 0x06 signed message is the spec's cosigned_message
    // struct: label "subtree/v1\n\0", cosigner name, timestamp, log origin,
    // start, end, root hash) and CS-03 (whole-tree: start == 0, end ==
    // checkpoint size — every other range MUST fail to verify).
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let r = cosign_at(&fx, &tree, 3).await;

    let ts = timestamp_of(&r.ml_sig);
    let pk = fx.ml_vkey().public_key().to_vec();
    let sig = &r.ml_sig.signature()[8..];

    // Known-answer: hand-assemble the struct per the spec and compare with
    // metamorphic-log's constructor byte-for-byte.
    let mut want = Vec::new();
    want.extend_from_slice(b"subtree/v1\n\0");
    want.push(WITNESS_NAME.len() as u8);
    want.extend_from_slice(WITNESS_NAME.as_bytes());
    want.extend_from_slice(&ts.to_be_bytes());
    want.push(LOG_ORIGIN.len() as u8);
    want.extend_from_slice(LOG_ORIGIN.as_bytes());
    want.extend_from_slice(&0u64.to_be_bytes()); // start
    want.extend_from_slice(&r.size.to_be_bytes()); // end
    want.extend_from_slice(&r.root);
    let message =
        note::cosignature_v1_mldsa44_message(WITNESS_NAME, ts, LOG_ORIGIN, 0, r.size, &r.root)
            .unwrap();
    assert_eq!(message, want, "CS-07 struct layout");

    assert!(metamorphic_crypto::ml_dsa_44_verify(pk.as_slice(), &message, sig).unwrap());

    // CS-03: the cosignature commits to exactly (0, checkpoint size) — any
    // other subtree range fails to verify.
    for (start, end) in [(1, r.size), (0, r.size - 1), (0, r.size + 1), (0, 0)] {
        let m =
            note::cosignature_v1_mldsa44_message(WITNESS_NAME, ts, LOG_ORIGIN, start, end, &r.root)
                .unwrap();
        assert!(
            !metamorphic_crypto::ml_dsa_44_verify(pk.as_slice(), &m, sig).unwrap_or(false),
            "subtree range ({start}, {end}) must not verify"
        );
    }

    // CS-07 field binding: wrong origin, wrong root, wrong timestamp all fail.
    let wrong_origin = note::cosignature_v1_mldsa44_message(
        WITNESS_NAME,
        ts,
        "example.com/other",
        0,
        r.size,
        &r.root,
    )
    .unwrap();
    assert!(
        !metamorphic_crypto::ml_dsa_44_verify(pk.as_slice(), &wrong_origin, sig).unwrap_or(false)
    );
    let wrong_root =
        note::cosignature_v1_mldsa44_message(WITNESS_NAME, ts, LOG_ORIGIN, 0, r.size, &[9u8; 32])
            .unwrap();
    assert!(
        !metamorphic_crypto::ml_dsa_44_verify(pk.as_slice(), &wrong_root, sig).unwrap_or(false)
    );
    let wrong_ts =
        note::cosignature_v1_mldsa44_message(WITNESS_NAME, ts + 1, LOG_ORIGIN, 0, r.size, &r.root)
            .unwrap();
    assert!(!metamorphic_crypto::ml_dsa_44_verify(pk.as_slice(), &wrong_ts, sig).unwrap_or(false));
}

#[tokio::test]
async fn cs_08_key_ids_match_the_spec_formula_as_known_answers() {
    // covers CS-08: key id = SHA-256(name ‖ "\n" ‖ 0x04 ‖ 32-byte pk)[:4]
    // for Ed25519, SHA-256(name ‖ "\n" ‖ 0x06 ‖ 1312-byte pk)[:4] for
    // ML-DSA-44 — computed here from first principles and checked against
    // both the keygen-produced vkeys and the returned signature lines.
    let fx = HttpFixture::new();
    let tree = tree_with_numbered_leaves(3);
    let r = cosign_at(&fx, &tree, 3).await;

    for (vkey, type_byte, pk_len) in [(fx.ed_vkey(), 0x04u8, 32), (fx.ml_vkey(), 0x06u8, 1312)] {
        assert_eq!(vkey.public_key().len(), pk_len);
        let mut preimage = vkey.name().as_bytes().to_vec();
        preimage.push(b'\n');
        preimage.push(type_byte);
        preimage.extend_from_slice(vkey.public_key());
        let digest = metamorphic_crypto::hash::sha256(&preimage);
        let key_id = u32::from_be_bytes(digest[..4].try_into().unwrap());
        assert_eq!(
            key_id,
            vkey.key_id(),
            "CS-08 known-answer for type {type_byte:#04x}"
        );
    }

    // The signature lines carry exactly these (name, key id) pairs.
    assert_eq!(r.ed_sig.name(), WITNESS_NAME);
    assert_eq!(r.ed_sig.key_id(), fx.ed_vkey().key_id());
    assert_eq!(r.ml_sig.name(), WITNESS_NAME);
    assert_eq!(r.ml_sig.key_id(), fx.ml_vkey().key_id());
}

#[tokio::test]
async fn cs_09_vkey_encodings_are_type_byte_plus_public_key() {
    // covers CS-09: the 0x04 vkey encodes `0x04 ‖ 32-byte pk`, the 0x06 vkey
    // `0x06 ‖ 1312-byte pk` — checked against the keygen-produced strings,
    // which must round-trip byte-exactly through parse/encode.
    let fx = HttpFixture::new();

    for (encoded, type_byte, total_len) in [
        (fx.ed_vkey.clone(), 0x04u8, 33usize),
        (fx.ml_vkey.clone(), 0x06u8, 1313usize),
    ] {
        let (name, rest) = encoded.split_once('+').unwrap();
        let (id_hex, key_b64) = rest.split_once('+').unwrap();
        assert_eq!(name, WITNESS_NAME);

        let raw = B64.decode(key_b64).unwrap();
        assert_eq!(raw.len(), total_len, "type byte + public key length");
        assert_eq!(raw[0], type_byte);

        let vkey = VerifierKey::parse(&encoded).unwrap();
        assert_eq!(&raw[1..], vkey.public_key());
        assert_eq!(id_hex, hex(&vkey.key_id().to_be_bytes()));
        assert_eq!(
            vkey.encode(),
            encoded,
            "the keygen-printed vkey is the canonical encoding"
        );
    }
}
