use castalia_wallet_sdk::{KeyCeremony, WalletError};

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
