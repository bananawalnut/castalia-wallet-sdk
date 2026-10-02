use castalia_wallet_sdk::{KeyCeremony, LocalVault, RecoveryKit, WalletError};
use std::fs;

const OVERSIZED_ARTIFACT_BYTES: usize = 64 * 1024 + 1;

#[test]
fn ceremony_keeps_both_private_keys_live_for_immediate_signing() {
    let output = KeyCeremony::create(b"correct horse battery staple").expect("ceremony");
    let message = b"castalia key ceremony demo";

    let signature = output.signer.sign(message).expect("hybrid signature");

    output
        .signer
        .public_anchor()
        .verify(message, &signature)
        .expect("both signature halves verify");
}

#[test]
fn local_vault_unlock_reconstructs_the_registered_public_anchor() {
    let password = b"vault password with adequate entropy";
    let output = KeyCeremony::create(password).expect("ceremony");
    let expected = output.signer.public_anchor().clone();

    let unlocked = output.local_vault.unlock(password).expect("vault unlock");

    assert_eq!(unlocked.public_anchor(), &expected);
    assert!(matches!(
        output.local_vault.unlock(b"wrong password"),
        Err(WalletError::DecryptionFailed)
    ));
}

#[test]
fn recovery_requires_both_mnemonic_and_password() {
    let password = b"recovery password with adequate entropy";
    let output = KeyCeremony::create(password).expect("ceremony");
    let other = KeyCeremony::create(password).expect("second ceremony");
    let expected = output.signer.public_anchor().clone();

    let recovered = output
        .recovery_kit
        .recover(output.mnemonic.phrase(), password)
        .expect("recovery");

    assert_eq!(recovered.public_anchor(), &expected);
    assert!(matches!(
        output
            .recovery_kit
            .recover(output.mnemonic.phrase(), b"wrong password"),
        Err(WalletError::DecryptionFailed)
    ));
    assert!(matches!(
        output
            .recovery_kit
            .recover(other.mnemonic.phrase(), password),
        Err(WalletError::DecryptionFailed)
    ));
}

#[test]
fn persisted_artifacts_contain_no_plaintext_seed_password_or_mnemonic() {
    let password = b"marker-password-that-must-not-appear";
    let output = KeyCeremony::create(password).expect("ceremony");

    let vault_json = serde_json::to_string(&output.local_vault).expect("serialize vault");
    let recovery_json = serde_json::to_string(&output.recovery_kit).expect("serialize recovery");

    for encoded in [&vault_json, &recovery_json] {
        assert!(!encoded.contains("marker-password-that-must-not-appear"));
        assert!(!encoded.contains(output.mnemonic.phrase()));
        assert!(
            !encoded.contains("seed"),
            "secret-shaped field names stay absent"
        );
    }
}

#[cfg(unix)]
#[test]
fn private_artifacts_are_written_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let output = KeyCeremony::create(b"file permission password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("wallet.vault.json");
    let recovery_path = dir.path().join("wallet.recovery.json");

    output
        .local_vault
        .write_private(&vault_path)
        .expect("vault write");
    output
        .recovery_kit
        .write_private(&recovery_path)
        .expect("recovery write");

    assert_eq!(
        std::fs::metadata(vault_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(recovery_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn private_writes_do_not_overwrite_or_leave_temporary_artifacts() {
    let output = KeyCeremony::create(b"no overwrite password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("wallet.vault.json");
    let recovery_path = dir.path().join("wallet.recovery.json");
    let original = b"existing destination must survive";
    fs::write(&vault_path, original).expect("existing vault destination");
    fs::write(&recovery_path, original).expect("existing recovery destination");

    assert!(matches!(
        output.local_vault.write_private(&vault_path),
        Err(WalletError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert!(matches!(
        output.recovery_kit.write_private(&recovery_path),
        Err(WalletError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(&vault_path).expect("read vault"), original);
    assert_eq!(fs::read(&recovery_path).expect("read recovery"), original);

    let entries = fs::read_dir(dir.path())
        .expect("read tempdir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(entries.len(), 2, "failed writes must clean up temp files");
    assert!(entries.iter().any(|entry| entry.path() == vault_path));
    assert!(entries.iter().any(|entry| entry.path() == recovery_path));
}

#[test]
fn persisted_private_artifacts_round_trip_without_temporary_files() {
    let password = b"persisted round trip password";
    let output = KeyCeremony::create(password).expect("ceremony");
    let expected = output.signer.public_anchor();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("wallet.vault.json");
    let recovery_path = dir.path().join("wallet.recovery.json");

    output
        .local_vault
        .write_private(&vault_path)
        .expect("vault write");
    output
        .recovery_kit
        .write_private(&recovery_path)
        .expect("recovery write");

    let vault = LocalVault::read(&vault_path).expect("vault read");
    let recovery = RecoveryKit::read(&recovery_path).expect("recovery read");
    assert_eq!(
        vault
            .unlock(password)
            .expect("vault unlock")
            .public_anchor(),
        expected
    );
    assert_eq!(
        recovery
            .recover(output.mnemonic.phrase(), password)
            .expect("recovery")
            .public_anchor(),
        expected
    );

    let paths = fs::read_dir(dir.path())
        .expect("read tempdir")
        .map(|entry| entry.expect("directory entry").path())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2, "successful writes remove temp files");
    assert!(paths.contains(&vault_path));
    assert!(paths.contains(&recovery_path));
}

#[cfg(unix)]
#[test]
fn private_reads_reject_symlinks_before_parsing() {
    use std::os::unix::fs::symlink;

    let output = KeyCeremony::create(b"symlink rejection password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("wallet.vault.json");
    let vault_link = dir.path().join("wallet.vault.link.json");
    let recovery = dir.path().join("wallet.recovery.json");
    let recovery_link = dir.path().join("wallet.recovery.link.json");
    output
        .local_vault
        .write_private(&vault)
        .expect("vault write");
    output
        .recovery_kit
        .write_private(&recovery)
        .expect("recovery write");
    symlink(&vault, &vault_link).expect("vault symlink");
    symlink(&recovery, &recovery_link).expect("recovery symlink");

    assert!(matches!(
        LocalVault::read(vault_link),
        Err(WalletError::InvalidArtifact(message)) if message.contains("symlink")
    ));
    assert!(matches!(
        RecoveryKit::read(recovery_link),
        Err(WalletError::InvalidArtifact(message)) if message.contains("symlink")
    ));
}

#[test]
fn private_reads_reject_non_regular_files_before_parsing() {
    let dir = tempfile::tempdir().expect("tempdir");

    assert!(matches!(
        LocalVault::read(dir.path()),
        Err(WalletError::InvalidArtifact(message)) if message.contains("regular file")
    ));
    assert!(matches!(
        RecoveryKit::read(dir.path()),
        Err(WalletError::InvalidArtifact(message)) if message.contains("regular file")
    ));
}

#[test]
fn private_reads_reject_oversized_artifacts_before_json_parsing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("oversized.vault.json");
    let recovery = dir.path().join("oversized.recovery.json");
    let oversized = vec![b' '; OVERSIZED_ARTIFACT_BYTES];
    fs::write(&vault, &oversized).expect("oversized vault");
    fs::write(&recovery, &oversized).expect("oversized recovery");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).expect("vault mode");
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).expect("recovery mode");
    }

    assert!(matches!(
        LocalVault::read(vault),
        Err(WalletError::InvalidArtifact(message)) if message.contains("too large")
    ));
    assert!(matches!(
        RecoveryKit::read(recovery),
        Err(WalletError::InvalidArtifact(message)) if message.contains("too large")
    ));
}

#[cfg(unix)]
#[test]
fn private_reads_reject_group_or_world_access() {
    use std::os::unix::fs::PermissionsExt;

    let output = KeyCeremony::create(b"read permission password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("wallet.vault.json");
    let recovery = dir.path().join("wallet.recovery.json");
    output
        .local_vault
        .write_private(&vault)
        .expect("vault write");
    output
        .recovery_kit
        .write_private(&recovery)
        .expect("recovery write");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o640)).expect("vault mode");
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o602)).expect("recovery mode");

    assert!(matches!(
        LocalVault::read(vault),
        Err(WalletError::InvalidArtifact(message)) if message.contains("permissions")
    ));
    assert!(matches!(
        RecoveryKit::read(recovery),
        Err(WalletError::InvalidArtifact(message)) if message.contains("permissions")
    ));
}

#[cfg(unix)]
#[test]
fn private_reads_reject_hardlinked_artifacts() {
    let output = KeyCeremony::create(b"hardlink rejection password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("wallet.vault.json");
    let vault_alias = dir.path().join("wallet.vault.alias.json");
    output
        .local_vault
        .write_private(&vault)
        .expect("vault write");
    fs::hard_link(&vault, &vault_alias).expect("vault hardlink");

    assert!(matches!(
        LocalVault::read(vault),
        Err(WalletError::InvalidArtifact(message)) if message.contains("hardlink")
    ));
}

#[cfg(unix)]
#[test]
fn private_reads_reject_special_permission_bits() {
    use std::os::unix::fs::PermissionsExt;

    let output = KeyCeremony::create(b"special mode rejection password").expect("ceremony");
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("wallet.vault.json");
    output
        .local_vault
        .write_private(&vault)
        .expect("vault write");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o4600)).expect("setuid mode");

    assert!(matches!(
        LocalVault::read(vault),
        Err(WalletError::InvalidArtifact(message)) if message.contains("permissions")
    ));
}

#[cfg(unix)]
#[test]
fn private_writes_require_an_existing_trusted_parent_directory() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let output = KeyCeremony::create(b"trusted parent password").expect("ceremony");
    let root = tempfile::tempdir().expect("tempdir");

    let missing_parent = root.path().join("missing");
    let missing_path = missing_parent.join("wallet.vault.json");
    assert!(matches!(
        output.local_vault.write_private(&missing_path),
        Err(WalletError::InvalidArtifact(message)) if message.contains("parent")
    ));
    assert!(!missing_parent.exists(), "write must not create parents");

    let insecure_parent = root.path().join("insecure");
    fs::create_dir(&insecure_parent).expect("insecure parent");
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o777))
        .expect("insecure parent mode");
    assert!(matches!(
        output
            .local_vault
            .write_private(insecure_parent.join("wallet.vault.json")),
        Err(WalletError::InvalidArtifact(message)) if message.contains("parent")
    ));

    let trusted_parent = root.path().join("trusted");
    let symlink_parent = root.path().join("linked");
    fs::create_dir(&trusted_parent).expect("trusted parent");
    fs::set_permissions(&trusted_parent, fs::Permissions::from_mode(0o700))
        .expect("trusted parent mode");
    symlink(&trusted_parent, &symlink_parent).expect("parent symlink");
    assert!(matches!(
        output
            .local_vault
            .write_private(symlink_parent.join("wallet.vault.json")),
        Err(WalletError::InvalidArtifact(message)) if message.contains("parent")
    ));
    assert!(!trusted_parent.join("wallet.vault.json").exists());
}

#[cfg(unix)]
#[test]
fn private_writes_force_exact_mode_under_restrictive_umask() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    const CHILD_ENV: &str = "CASTALIA_RESTRICTIVE_UMASK_CHILD";
    const DIRECTORY_ENV: &str = "CASTALIA_RESTRICTIVE_UMASK_DIRECTORY";
    if std::env::var_os(CHILD_ENV).is_some() {
        let output = KeyCeremony::create(b"restrictive umask password").expect("ceremony");
        let directory = std::env::var_os(DIRECTORY_ENV).expect("pre-created directory");
        let vault = std::path::PathBuf::from(directory).join("wallet.vault.json");
        output
            .local_vault
            .write_private(&vault)
            .expect("vault write under restrictive umask");
        assert_eq!(
            fs::metadata(vault)
                .expect("vault metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        return;
    }

    let dir = tempfile::tempdir().expect("parent-created tempdir");
    let executable = std::env::current_exe().expect("current test executable");
    let status = Command::new("sh")
        .args([
            "-c",
            "umask 777; exec \"$1\" --exact private_writes_force_exact_mode_under_restrictive_umask --nocapture",
            "sh",
        ])
        .arg(executable)
        .env(CHILD_ENV, "1")
        .env(DIRECTORY_ENV, dir.path())
        .status()
        .expect("restrictive-umask child");
    assert!(status.success(), "restrictive-umask child failed");
}

#[test]
fn committed_write_errors_explicitly_state_that_the_destination_was_committed() {
    let unlink = WalletError::DestinationCommittedTempUnlink(std::io::Error::other("unlink"));
    let fsync = WalletError::DestinationCommittedParentSync(std::io::Error::other("fsync"));
    let both = WalletError::DestinationCommittedTempUnlinkAndParentSync {
        unlink: std::io::Error::other("unlink"),
        parent_sync: std::io::Error::other("fsync"),
    };

    assert!(unlink.to_string().contains("destination was committed"));
    assert!(unlink.to_string().contains("temporary"));
    assert!(unlink.to_string().contains("synced"));
    assert!(fsync.to_string().contains("destination was committed"));
    assert!(fsync.to_string().contains("parent"));
    assert!(both.to_string().contains("destination was committed"));
    assert!(both.to_string().contains("durability is uncertain"));
    assert!(both.to_string().contains("unlink"));
    assert!(both.to_string().contains("fsync"));
}
