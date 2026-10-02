use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    FileSync,
    Publish,
    Unlink,
    ParentSync,
}

#[derive(Default)]
struct FaultOperations {
    failures: Vec<Step>,
    calls: Vec<Step>,
    temporary: Option<PathBuf>,
}

impl FaultOperations {
    fn before(&mut self, step: Step) -> std::io::Result<()> {
        self.calls.push(step);
        if self.failures.contains(&step) {
            return Err(std::io::Error::other(format!("injected {step:?} failure")));
        }
        Ok(())
    }
}

impl PrivateArtifactOperations for FaultOperations {
    fn sync_file(&mut self, file: &File) -> std::io::Result<()> {
        self.before(Step::FileSync)?;
        file.sync_all()
    }

    fn publish(&mut self, temporary: &Path, destination: &Path) -> std::io::Result<()> {
        self.temporary = Some(temporary.to_owned());
        self.before(Step::Publish)?;
        publish_without_overwrite(temporary, destination)
    }

    fn unlink_temporary(&mut self, temporary: &Path) -> std::io::Result<()> {
        self.before(Step::Unlink)?;
        fs::remove_file(temporary)
    }

    fn sync_parent(&mut self, parent: &Path) -> std::io::Result<()> {
        self.before(Step::ParentSync)?;
        sync_parent_directory(parent)
    }
}

fn payload() -> serde_json::Value {
    serde_json::json!({ "credential": "synthetic-only" })
}

const EXPECTED_BYTES: &[u8] = b"{\n  \"credential\": \"synthetic-only\"\n}\n";

fn assert_private_bytes(path: &Path) {
    assert_eq!(fs::read(path).expect("artifact bytes"), EXPECTED_BYTES);
    assert_eq!(
        fs::metadata(path)
            .expect("artifact metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600,
    );
}

fn assert_prepublication_failure(failure: Step, expected_calls: &[Step]) {
    let directory = tempfile::tempdir().expect("private directory");
    let destination = directory.path().join("artifact.json");
    let mut operations = FaultOperations {
        failures: vec![failure],
        ..FaultOperations::default()
    };

    let result = write_private_json_with_operations(&destination, &payload(), &mut operations);

    assert!(
        matches!(result, Err(WalletError::Io(error)) if error.to_string().contains("injected"))
    );
    assert_eq!(operations.calls, expected_calls);
    assert!(!destination.exists(), "no destination was published");
    assert_eq!(
        fs::read_dir(directory.path()).expect("directory").count(),
        0
    );
}

#[test]
fn file_sync_failure_never_publishes_and_removes_the_temporary() {
    assert_prepublication_failure(Step::FileSync, &[Step::FileSync]);
}

#[test]
fn publication_failure_never_commits_and_removes_the_temporary() {
    assert_prepublication_failure(Step::Publish, &[Step::FileSync, Step::Publish]);
}

#[test]
fn successful_publication_preserves_bytes_permissions_and_operation_order() {
    let directory = tempfile::tempdir().expect("private directory");
    let destination = directory.path().join("artifact.json");
    let mut operations = FaultOperations::default();

    write_private_json_with_operations(&destination, &payload(), &mut operations)
        .expect("publish artifact");

    assert_eq!(
        operations.calls,
        [
            Step::FileSync,
            Step::Publish,
            Step::Unlink,
            Step::ParentSync
        ],
    );
    assert_private_bytes(&destination);
    assert_eq!(fs::metadata(&destination).expect("metadata").nlink(), 1);
    assert_eq!(
        fs::read_dir(directory.path()).expect("directory").count(),
        1
    );
    assert_eq!(
        read_private_json::<serde_json::Value>(&destination).expect("read"),
        payload()
    );
}

#[test]
fn existing_destination_is_not_overwritten_even_after_syncing_a_new_temporary() {
    let directory = tempfile::tempdir().expect("private directory");
    let destination = directory.path().join("artifact.json");
    write_private_json(&destination, &payload()).expect("original artifact");
    let mut operations = FaultOperations::default();

    let result = write_private_json_with_operations(
        &destination,
        &serde_json::json!({ "credential": "replacement" }),
        &mut operations,
    );

    assert!(
        matches!(result, Err(WalletError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(operations.calls, [Step::FileSync, Step::Publish]);
    assert_private_bytes(&destination);
    assert_eq!(
        fs::read_dir(directory.path()).expect("directory").count(),
        1
    );
}

fn assert_committed_failure(unlink_fails: bool, parent_sync_fails: bool) {
    let directory = tempfile::tempdir().expect("private directory");
    let destination = directory.path().join("artifact.json");
    let mut operations = FaultOperations::default();
    if unlink_fails {
        operations.failures.push(Step::Unlink);
    }
    if parent_sync_fails {
        operations.failures.push(Step::ParentSync);
    }

    let error = write_private_json_with_operations(&destination, &payload(), &mut operations)
        .expect_err("injected post-publication failure");

    // In particular, unlink failure must never short-circuit the parent fsync.
    assert_eq!(
        operations.calls,
        [
            Step::FileSync,
            Step::Publish,
            Step::Unlink,
            Step::ParentSync
        ],
    );
    assert!(error.to_string().contains("destination was committed"));
    match (unlink_fails, parent_sync_fails, &error) {
        (true, false, WalletError::DestinationCommittedTempUnlink(cause)) => {
            assert!(cause.to_string().contains("injected Unlink"));
            assert!(error.to_string().contains("parent directory synced"));
        }
        (false, true, WalletError::DestinationCommittedParentSync(cause)) => {
            assert!(cause.to_string().contains("injected ParentSync"));
        }
        (
            true,
            true,
            WalletError::DestinationCommittedTempUnlinkAndParentSync {
                unlink,
                parent_sync,
            },
        ) => {
            assert!(unlink.to_string().contains("injected Unlink"));
            assert!(parent_sync.to_string().contains("injected ParentSync"));
            assert!(error.to_string().contains("durability is uncertain"));
        }
        _ => panic!("incorrect committed-destination error: {error}"),
    }
    assert_private_bytes(&destination);
    let temporary = operations.temporary.expect("publication path");
    if unlink_fails {
        let destination_metadata = fs::metadata(&destination).expect("destination metadata");
        let temporary_metadata = fs::metadata(&temporary).expect("leftover temporary metadata");
        assert_eq!(destination_metadata.dev(), temporary_metadata.dev());
        assert_eq!(destination_metadata.ino(), temporary_metadata.ino());
        assert_eq!(destination_metadata.nlink(), 2);
        assert_private_bytes(&temporary);
        assert!(matches!(
            read_private_json::<serde_json::Value>(&destination),
            Err(WalletError::InvalidArtifact(message)) if message.contains("hardlinks")
        ));
        fs::remove_file(&temporary).expect("explicit leftover-link cleanup");
    } else {
        assert!(!temporary.exists());
    }
    assert_eq!(fs::metadata(&destination).expect("metadata").nlink(), 1);
    assert_eq!(
        read_private_json::<serde_json::Value>(&destination).expect("read after cleanup"),
        payload()
    );

    let retry = write_private_json(&destination, &serde_json::json!({ "replacement": true }));
    assert!(
        matches!(retry, Err(WalletError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_private_bytes(&destination);
    assert_eq!(
        fs::read_dir(directory.path()).expect("directory").count(),
        1
    );
}

#[test]
fn unlink_failure_reports_committed_destination_and_still_syncs_parent() {
    assert_committed_failure(true, false);
}

#[test]
fn parent_sync_failure_reports_committed_destination_after_temporary_cleanup() {
    assert_committed_failure(false, true);
}

#[test]
fn unlink_and_parent_sync_failure_preserve_both_causes_and_the_leftover_link() {
    assert_committed_failure(true, true);
}
