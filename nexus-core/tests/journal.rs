//! Fallos de disco, integridad, exclusión y recuperación del diario incremental.
use nexus_core::{journal::{JournalStore, MAX_RECORD_BYTES}, NexusError};
use std::{fs, io::Write, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/journal-tests")
        .join(format!("{}-{stamp}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir_all(&path).unwrap(); path
}
fn sample() -> PathBuf {
    let path = directory();
    let mut journal = JournalStore::create(&path).unwrap();
    for bytes in [b"genesis".as_slice(), b"voto", b"decision"] { journal.commit(bytes).unwrap(); }
    path
}

#[test]
fn exclusive_writer_streamed_recovery_and_append_preserve_all_records() {
    let path = directory();
    let mut writer = JournalStore::create(&path).unwrap();
    writer.commit(b"genesis").unwrap();
    assert!(JournalStore::create(&path).is_err());
    assert!(JournalStore::open(&path, |_, _| Ok(())).is_err());
    drop(writer);
    let mut seen = Vec::new();
    let mut writer = JournalStore::open(&path, |sequence, bytes| {
        seen.push((sequence, bytes.to_vec())); Ok(())
    }).unwrap();
    assert_eq!(seen, vec![(1, b"genesis".to_vec())]);
    assert!(JournalStore::create(&path).is_err());
    writer.commit(b"voto").unwrap();
    drop(writer);
    let mut seen = Vec::new();
    let writer = JournalStore::open(&path, |sequence, bytes| {
        seen.push((sequence, bytes.to_vec())); Ok(())
    }).unwrap();
    assert_eq!(writer.sequence(), 2);
    assert_eq!(seen[1], (2, b"voto".to_vec()));
}

#[test]
fn corruption_truncation_missing_middle_and_spliced_records_fail_closed() {
    for variant in 0..4 {
        let path = sample();
        let second = path.join(JournalStore::record_name(2));
        let third = path.join(JournalStore::record_name(3));
        match variant {
            0 => {
                let mut bytes = fs::read(&third).unwrap();
                let last = bytes.len() - 1; bytes[last] ^= 1;
                fs::write(&third, bytes).unwrap();
            }
            1 => { fs::OpenOptions::new().write(true).open(&third).unwrap().set_len(30).unwrap(); }
            2 => { fs::rename(&second, path.join("removed-middle")).unwrap(); }
            _ => {
                let other = directory();
                let mut writer = JournalStore::create(&other).unwrap();
                writer.commit(b"other-genesis").unwrap(); writer.commit(b"voto").unwrap();
                writer.commit(b"decision").unwrap(); drop(writer);
                fs::copy(other.join(JournalStore::record_name(3)), &third).unwrap();
            }
        }
        assert!(JournalStore::open(&path, |_, _| Ok(())).is_err(), "variante {variant}");
        assert!(third.exists());
    }
}

#[test]
fn failed_publication_keeps_sequence_and_allows_retry() {
    let path = sample();
    let mut writer = JournalStore::open(&path, |_, _| Ok(())).unwrap();
    let obstruction = path.join(JournalStore::record_name(4));
    fs::create_dir(&obstruction).unwrap();
    assert!(writer.commit(b"siguiente").is_err());
    assert_eq!(writer.sequence(), 3);
    fs::remove_dir(obstruction).unwrap();
    writer.commit(b"siguiente").unwrap();
    assert_eq!(writer.sequence(), 4);
}

#[test]
fn empty_oversized_legacy_and_malformed_records_are_rejected() {
    let path = directory();
    let mut writer = JournalStore::create(&path).unwrap();
    assert!(writer.commit(&[]).is_err());
    assert!(writer.commit(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    assert_eq!(writer.sequence(), 0);
    drop(writer);
    assert!(JournalStore::open(&path, |_, _| Ok(())).is_err());
    fs::write(path.join("checkpoint-00000000000000000001.bin"), b"old").unwrap();
    assert!(JournalStore::exists(&path).unwrap());
    assert!(JournalStore::create(&path).is_err());
    assert!(JournalStore::open(&path, |_, _| Ok(())).is_err());
    let malformed = directory();
    fs::write(malformed.join("event-1.bin"), b"bad").unwrap();
    assert!(JournalStore::exists(&malformed).unwrap());
    assert!(JournalStore::create(&malformed).is_err());
}

#[test]
fn visitor_failure_does_not_rewrite_or_discard_the_committed_history() {
    let path = sample();
    let last = path.join(JournalStore::record_name(3));
    let original = fs::read(&last).unwrap();
    assert!(JournalStore::open(&path, |_, _| Err(NexusError::StateError("rechazo semántico".into()))).is_err());
    assert_eq!(fs::read(&last).unwrap(), original);
    assert_eq!(JournalStore::open(&path, |_, _| Ok(())).unwrap().sequence(), 3);
}

#[test]
fn aggregate_history_exceeds_64_mib_without_an_oversized_record() {
    let path = directory();
    let payload = vec![0x5a; 7_500_000];
    let mut writer = JournalStore::create(&path).unwrap();
    for _ in 0..10 { writer.commit(&payload).unwrap(); }
    drop(writer);
    let mut total = 0;
    let writer = JournalStore::open(&path, |_, bytes| {
        assert_eq!(bytes, payload.as_slice()); total += bytes.len(); Ok(())
    }).unwrap();
    assert_eq!(writer.sequence(), 10);
    assert!(total > 64 * 1024 * 1024);
}

#[test]
fn abrupt_exit_with_partial_temporary_preserves_every_committed_record() {
    const CHILD: &str = "NEXUS_JOURNAL_PARTIAL_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = Path::new(&path);
        let _writer = JournalStore::open(path, |_, _| Ok(())).unwrap();
        let mut partial = fs::File::create(path.join(".event-00000000000000000004-interrupted.pending")).unwrap();
        partial.write_all(b"NXSJNL02 incomplete").unwrap(); partial.sync_all().unwrap();
        std::process::exit(0);
    }
    let path = sample();
    let before = fs::read(path.join(JournalStore::record_name(3))).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "abrupt_exit_with_partial_temporary_preserves_every_committed_record", "--nocapture"])
        .env(CHILD, &path);
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let result = command.output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let mut writer = JournalStore::open(&path, |_, _| Ok(())).unwrap();
    assert_eq!(writer.sequence(), 3);
    assert_eq!(fs::read(path.join(JournalStore::record_name(3))).unwrap(), before);
    writer.commit(b"siguiente").unwrap();
}
