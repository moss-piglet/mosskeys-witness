//! Unit + concurrency tests for the atomic state store (SM-01…SM-05, T1/T3/T8).

use std::io::Write as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use super::*;

fn state(origin: &str, size: u64, root_byte: u8) -> LogState {
    LogState {
        origin: origin.to_string(),
        size,
        root: [root_byte; 32],
        note: format!(
            "{origin}\n{size}\n{}\n\n— {origin} c2ln\n",
            B64.encode([root_byte; 32])
        ),
    }
}

/// A check closure that approves only when the current size matches
/// `expect` — the shape of the real witness's old-size check (ST-06).
fn cas(
    expect: u64,
    new: LogState,
) -> impl FnOnce(Option<&LogState>) -> Result<(LogState, u64), &'static str> {
    move |current| {
        let cur = current.map_or(0, |c| c.size);
        if cur != expect {
            return Err("size mismatch");
        }
        Ok((new, cur))
    }
}

#[test]
fn persist_and_reopen_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    {
        let store = Store::open(&path).unwrap();
        assert!(store.is_empty());
        let prev = store
            .update("example.com/log", cas(0, state("example.com/log", 42, 7)))
            .unwrap();
        assert_eq!(prev, 0);
        assert_eq!(store.len(), 1);
    } // lock released on drop

    let store = Store::open(&path).unwrap();
    let got = store.latest("example.com/log").unwrap();
    assert_eq!(got, state("example.com/log", 42, 7));
}

#[test]
fn rejected_update_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let store = Store::open(&path).unwrap();
    store
        .update("example.com/log", cas(0, state("example.com/log", 42, 7)))
        .unwrap();

    let before = std::fs::read(&path).unwrap();
    let err = store
        .update("example.com/log", cas(0, state("example.com/log", 43, 8)))
        .unwrap_err();
    assert!(matches!(err, UpdateError::Rejected("size mismatch")));

    // Neither in-memory state nor the file changed.
    assert_eq!(store.latest("example.com/log").unwrap().size, 42);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn torn_tail_is_truncated_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let good_len;
    {
        let store = Store::open(&path).unwrap();
        store
            .update("example.com/log", cas(0, state("example.com/log", 42, 7)))
            .unwrap();
        good_len = std::fs::metadata(&path).unwrap().len();
    }

    // Simulate a crash mid-append: half a record at EOF.
    let mut f = OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(b"{\"v\":1,\"origin\":\"example.com/log\",\"si")
        .unwrap();
    drop(f);

    let store = Store::open(&path).unwrap();
    assert_eq!(store.latest("example.com/log").unwrap().size, 42);
    // The garbage was truncated back to the last durable boundary...
    assert_eq!(std::fs::metadata(&path).unwrap().len(), good_len);
    // ...and the store accepts new appends afterwards (SM-05).
    store
        .update("example.com/log", cas(42, state("example.com/log", 43, 8)))
        .unwrap();
    drop(store);

    let store = Store::open(&path).unwrap();
    assert_eq!(store.latest("example.com/log").unwrap().size, 43);
}

#[test]
fn mid_file_corruption_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    {
        let store = Store::open(&path).unwrap();
        store
            .update("example.com/log", cas(0, state("example.com/log", 42, 7)))
            .unwrap();
        store
            .update("example.com/log", cas(42, state("example.com/log", 43, 8)))
            .unwrap();
    }

    // Flip a byte in the FIRST record (mid-file), then append nothing.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[20] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();

    let err = Store::open(&path).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt { record: 1, .. }));
}

#[test]
fn unterminated_final_record_is_reframed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let st = state("example.com/log", 42, 7);
    let record = Record::from_state(&st);
    // Hand-write a record WITHOUT its trailing newline.
    std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();

    {
        let store = Store::open(&path).unwrap();
        assert_eq!(store.latest("example.com/log").unwrap().size, 42);
        store
            .update("example.com/log", cas(42, state("example.com/log", 43, 8)))
            .unwrap();
    }

    // Replay must see both records cleanly (no fused lines).
    let store = Store::open(&path).unwrap();
    assert_eq!(store.latest("example.com/log").unwrap().size, 43);
}

#[test]
fn second_instance_lock_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let store = Store::open(&path).unwrap();
    let err = Store::open(&path).unwrap_err();
    assert!(matches!(err, StoreError::Locked(_)));
    drop(store);
}

#[test]
fn concurrent_cas_updates_form_a_single_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let store = Arc::new(Store::open(&path).unwrap());
    let successes = Arc::new(AtomicU64::new(0));

    // 16 threads each run a CAS loop bumping the SAME origin's size by one
    // per success: exactly the interleaving the spec's race example warns
    // about. The store's atomic check-and-update must serialize them.
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let store = Arc::clone(&store);
            let successes = Arc::clone(&successes);
            std::thread::spawn(move || {
                for _ in 0..25 {
                    loop {
                        let cur = store.latest("example.com/log").map_or(0, |s| s.size);
                        let next = state("example.com/log", cur + 1, (cur % 250) as u8 + 1);
                        match store.update("example.com/log", cas(cur, next)) {
                            Ok(_) => {
                                successes.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Err(UpdateError::Rejected(_)) => continue, // lost the race; re-read
                            Err(UpdateError::Store(e)) => panic!("store error: {e}"),
                        }
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }

    assert_eq!(successes.load(Ordering::SeqCst), 400);
    assert_eq!(store.latest("example.com/log").unwrap().size, 400);
    drop(store);

    // And the durable file replays to exactly that state.
    let store = Store::open(&path).unwrap();
    assert_eq!(store.latest("example.com/log").unwrap().size, 400);
}

#[test]
fn disjoint_origins_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let store = Store::open(&path).unwrap();
    store
        .update("a.example/log", cas(0, state("a.example/log", 10, 1)))
        .unwrap();
    store
        .update("b.example/log", cas(0, state("b.example/log", 20, 2)))
        .unwrap();

    assert_eq!(store.len(), 2);
    assert_eq!(store.latest("a.example/log").unwrap().size, 10);
    assert_eq!(store.latest("b.example/log").unwrap().size, 20);
}

#[test]
fn latest_by_origin_hash_matches_lowercase_sha256_hex() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("witness.state");

    let store = Store::open(&path).unwrap();
    store
        .update("example.com/log", cas(0, state("example.com/log", 42, 7)))
        .unwrap();

    let hash = hex(&metamorphic_crypto::hash::sha256(b"example.com/log"));
    let got = store.latest_by_origin_hash(&hash).unwrap();
    assert_eq!(got.size, 42);

    assert!(store.latest_by_origin_hash(&hash.to_uppercase()).is_none());
    assert!(store.latest_by_origin_hash(&hex(&[0u8; 32])).is_none());
}
