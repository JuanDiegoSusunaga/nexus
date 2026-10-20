use nexus_core::checkpoint::{CheckpointStore, decode, encode};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/checkpoint-tests")
        .join(format!("{}-{}-{}", std::process::id(), nexus_core::Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap(); path
}

#[test]
fn only_one_writer_opens_a_store_and_partial_files_do_not_publish_a_new_generation() {
    let path = directory(); let mut store = CheckpointStore::create(&path).unwrap();
    store.commit(b"committed").unwrap();
    assert!(CheckpointStore::open(&path).is_err());
    std::fs::write(path.join(".checkpoint-00000000000000000002-interrupted.pending"), b"partial").unwrap();
    drop(store);
    let mut reopened = CheckpointStore::open(&path).unwrap();
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.read_latest().unwrap(), b"committed");
    reopened.commit(b"next committed").unwrap();
    assert_eq!(reopened.generation(), 2);
    assert_eq!(reopened.read_latest().unwrap(), b"next committed");
}

#[test]
fn corrupt_latest_checkpoint_is_rejected_instead_of_silently_restoring_an_older_nonce() {
    for case in 0..5 {
        let path = directory(); let mut store = CheckpointStore::create(&path).unwrap();
        store.commit(b"older state").unwrap(); store.commit(b"latest state").unwrap(); drop(store);
        let latest = path.join("checkpoint-00000000000000000002.bin");
        let mut bytes = std::fs::read(&latest).unwrap();
        match case {
            0 => bytes[0] ^= 1,
            1 => { bytes.pop(); },
            2 => bytes.push(0),
            3 => bytes[8] = 1,
            _ => bytes[56] ^= 1,
        }
        std::fs::write(&latest, bytes).unwrap();
        let store = CheckpointStore::open(&path).unwrap();
        assert!(store.read_latest().is_err(), "case {case}");
        assert_eq!(store.generation(), 2);
    }
}

#[test]
fn checkpoint_codec_rejects_trailing_bytes_and_unrepresentable_collection_lengths() {
    let mut bytes = encode(&vec![1u8, 2, 3]).unwrap(); bytes.push(0);
    assert!(decode::<Vec<u8>>(&bytes).is_err());
    assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes()).is_err());
}
