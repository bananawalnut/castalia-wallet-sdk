use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_sdk::{KeyCeremony, LocalVault, RecoveryKit, WalletError};
use zeroize::{Zeroize, Zeroizing};

const DEMO_MESSAGE: &[u8] = b"castalia-key-ceremony-v1 self-test";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), WalletError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("create") => {
            let (vault, recovery) = parse_create_paths(args.collect())?;
            create(vault, recovery)
        }
        Some("unlock") => {
            let path = required_path(args.next(), "unlock requires a local-vault path")?;
            reject_extra_args(args)?;
            unlock(path)
        }
        Some("recover") => {
            let recovery = required_path(args.next(), "recover requires a recovery-kit path")?;
            let vault = required_path(args.next(), "recover requires a new local-vault path")?;
            reject_extra_args(args)?;
            recover(recovery, vault)
        }
        Some("self-test") => {
            reject_extra_args(args)?;
            self_test()
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(WalletError::InvalidArtifact(format!(
            "unknown command {other:?}; run with --help"
        ))),
    }
}

fn create(vault_path: PathBuf, recovery_path: PathBuf) -> Result<(), WalletError> {
    preflight_new(&vault_path)?;
    preflight_new(&recovery_path)?;

    let password = prompt_new_password("Local/recovery password")?;
    let output = KeyCeremony::create(password.as_bytes())?;
    verify_signer(&output.signer)?;

    output.local_vault.write_private(&vault_path)?;
    if let Err(error) = output.recovery_kit.write_private(&recovery_path) {
        let _ = fs::remove_file(&vault_path);
        return Err(error);
    }

    println!("Castalia Member Key ceremony complete.");
    print_anchor(output.signer.public_anchor());
    println!("Local vault: {}", vault_path.display());
    println!("Recovery kit: {}", recovery_path.display());
    println!();
    println!("RECOVERY PHRASE — displayed once; keep it offline and separate from the kit:");
    println!("{}", output.mnemonic.phrase());
    println!();
    println!(
        "Both expanded private keys remain available in signer memory until this process exits."
    );
    Ok(())
}

fn unlock(vault_path: PathBuf) -> Result<(), WalletError> {
    let vault = LocalVault::read(vault_path)?;
    let mut password = Zeroizing::new(
        rpassword::prompt_password("Local vault password: ").map_err(WalletError::Io)?,
    );
    let signer = vault.unlock(password.as_bytes())?;
    password.zeroize();
    verify_signer(&signer)?;
    println!("Local vault unlocked and hybrid signer verified.");
    print_anchor(signer.public_anchor());
    Ok(())
}

fn recover(recovery_path: PathBuf, vault_path: PathBuf) -> Result<(), WalletError> {
    preflight_new(&vault_path)?;
    let kit = RecoveryKit::read(recovery_path)?;
    let mut mnemonic = Zeroizing::new(
        rpassword::prompt_password("24-word recovery phrase (hidden): ")
            .map_err(WalletError::Io)?,
    );
    let mut recovery_password =
        Zeroizing::new(rpassword::prompt_password("Recovery password: ").map_err(WalletError::Io)?);
    let new_password = prompt_new_password("New local-vault password")?;

    let (signer, vault) = kit.recover_to_local_vault(
        mnemonic.as_str(),
        recovery_password.as_bytes(),
        new_password.as_bytes(),
    )?;
    mnemonic.zeroize();
    recovery_password.zeroize();
    verify_signer(&signer)?;
    vault.write_private(&vault_path)?;

    println!("Recovery succeeded; a new local vault was written.");
    print_anchor(signer.public_anchor());
    println!("Local vault: {}", vault_path.display());
    Ok(())
}

fn self_test() -> Result<(), WalletError> {
    let mut password_bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *password_bytes)
        .map_err(|error| WalletError::Randomness(error.to_string()))?;

    let output = KeyCeremony::create(&*password_bytes)?;
    let expected = output.signer.public_anchor().clone();
    verify_signer(&output.signer)?;

    let unlocked = output.local_vault.unlock(&*password_bytes)?;
    verify_signer(&unlocked)?;
    if unlocked.public_anchor() != &expected {
        return Err(WalletError::VerificationFailed(
            "local unlock changed the public anchor",
        ));
    }

    let recovered = output
        .recovery_kit
        .recover(output.mnemonic.phrase(), &*password_bytes)?;
    verify_signer(&recovered)?;
    if recovered.public_anchor() != &expected {
        return Err(WalletError::VerificationFailed(
            "recovery changed the public anchor",
        ));
    }

    println!("SELF-TEST PASS");
    println!("  fresh hybrid signing: pass");
    println!("  password vault unlock: pass");
    println!("  mnemonic + password recovery: pass");
    print_anchor(&expected);
    Ok(())
}

fn verify_signer(signer: &castalia_wallet_sdk::HybridSigner) -> Result<(), WalletError> {
    let signature = signer.sign(DEMO_MESSAGE)?;
    signer.public_anchor().verify(DEMO_MESSAGE, &signature)
}

fn print_anchor(anchor: &castalia_wallet_sdk::HybridPublicAnchor) {
    println!("Member Key ID: {}", hex(&anchor.key_id));
    println!(
        "Ed25519 public key: {}",
        URL_SAFE_NO_PAD.encode(anchor.ed25519)
    );
    println!(
        "ML-DSA-65 public key: {} bytes; digest {}",
        anchor.ml_dsa_65.len(),
        hex(blake3::hash(&anchor.ml_dsa_65).as_bytes())
    );
}

fn parse_create_paths(args: Vec<String>) -> Result<(PathBuf, PathBuf), WalletError> {
    let mut vault = PathBuf::from("castalia-member.vault.json");
    let mut recovery = PathBuf::from("castalia-member.recovery.json");
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--vault" => {
                index += 1;
                vault = required_path(args.get(index).cloned(), "--vault requires a path")?;
            }
            "--recovery-kit" => {
                index += 1;
                recovery =
                    required_path(args.get(index).cloned(), "--recovery-kit requires a path")?;
            }
            other => {
                return Err(WalletError::InvalidArtifact(format!(
                    "unknown create option {other:?}"
                )));
            }
        }
        index += 1;
    }
    if vault == recovery {
        return Err(WalletError::InvalidArtifact(
            "vault and recovery-kit paths must differ".into(),
        ));
    }
    Ok((vault, recovery))
}

fn prompt_new_password(label: &str) -> Result<Zeroizing<String>, WalletError> {
    let mut first = Zeroizing::new(
        rpassword::prompt_password(format!("{label} (minimum 12 bytes): "))
            .map_err(WalletError::Io)?,
    );
    let mut second = Zeroizing::new(
        rpassword::prompt_password(format!("Confirm {label}: ")).map_err(WalletError::Io)?,
    );
    if first.as_str() != second.as_str() {
        first.zeroize();
        second.zeroize();
        return Err(WalletError::InvalidArtifact(
            "passwords do not match".into(),
        ));
    }
    second.zeroize();
    if first.len() < 12 {
        first.zeroize();
        return Err(WalletError::WeakPassword);
    }
    Ok(first)
}

fn preflight_new(path: &Path) -> Result<(), WalletError> {
    if path.exists() {
        return Err(WalletError::InvalidArtifact(format!(
            "refusing to overwrite {}",
            path.display()
        )));
    }
    Ok(())
}

fn required_path(value: Option<String>, message: &str) -> Result<PathBuf, WalletError> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| WalletError::InvalidArtifact(message.into()))
}

fn reject_extra_args(mut args: impl Iterator<Item = String>) -> Result<(), WalletError> {
    if let Some(extra) = args.next() {
        return Err(WalletError::InvalidArtifact(format!(
            "unexpected argument {extra:?}"
        )));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn print_help() {
    println!(
        "castalia-key-ceremony\n\n\
         USAGE:\n\
           castalia-key-ceremony create [--vault PATH] [--recovery-kit PATH]\n\
           castalia-key-ceremony unlock <VAULT_PATH>\n\
           castalia-key-ceremony recover <RECOVERY_KIT_PATH> <NEW_VAULT_PATH>\n\
           castalia-key-ceremony self-test\n\n\
         The CLI performs no registration and makes no network requests. Passwords and the\n\
         recovery phrase are read through hidden prompts. Existing artifacts are never overwritten."
    );
}
