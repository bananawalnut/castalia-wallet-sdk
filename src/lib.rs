//! Local Castalia Member Key ceremony primitives.
//!
//! A ceremony derives an Ed25519 and ML-DSA-65 keypair from one 32-byte secret,
//! keeps both expanded private keys in [`HybridSigner`] memory, and stores only
//! encrypted copies of the reconstruction secret. No registration or network
//! behavior lives in this crate.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u8 = 1;
const LOCAL_KIND: &str = "castalia-local-vault-v1";
const RECOVERY_KIND: &str = "castalia-recovery-kit-v1";
const HYBRID_CONTEXT: &[u8] = b"castalia-member-key-v1";
const MIN_PASSWORD_BYTES: usize = 12;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SECRET_LEN: usize = 32;
const KDF_OUTPUT_LEN: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

/// Errors returned by wallet ceremony, signing, persistence, and recovery.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("password must contain at least {MIN_PASSWORD_BYTES} bytes")]
    WeakPassword,
    #[error("operating-system randomness failed: {0}")]
    Randomness(String),
    #[error("key operation failed: {0}")]
    KeyOperation(String),
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid recovery phrase")]
    InvalidMnemonic,
    #[error("invalid protected artifact: {0}")]
    InvalidArtifact(String),
    #[error("hybrid signature verification failed: {0}")]
    VerificationFailed(&'static str),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Public Ed25519 + ML-DSA-65 anchor associated with a Member Key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicAnchor {
    pub ed25519: [u8; 32],
    pub ml_dsa_65: Vec<u8>,
    pub key_id: [u8; 32],
}

impl HybridPublicAnchor {
    /// Verify both halves of a signature against the same domain-separated message.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<(), WalletError> {
        if self.ml_dsa_65.len() != ml_dsa_65::PK_LEN {
            return Err(WalletError::InvalidArtifact(
                "ML-DSA-65 public key has the wrong length".into(),
            ));
        }
        if signature.ml_dsa_65.len() != ml_dsa_65::SIG_LEN {
            return Err(WalletError::VerificationFailed(
                "ML-DSA-65 signature has the wrong length",
            ));
        }
        if anchor_id(&self.ed25519, &self.ml_dsa_65) != self.key_id {
            return Err(WalletError::VerificationFailed(
                "public anchor identifier mismatch",
            ));
        }

        let digest = signing_digest(message);
        let ed_key = VerifyingKey::from_bytes(&self.ed25519)
            .map_err(|_| WalletError::VerificationFailed("invalid Ed25519 public key"))?;
        let ed_signature = Ed25519Signature::from_bytes(&signature.ed25519);
        ed_key
            .verify_strict(&digest, &ed_signature)
            .map_err(|_| WalletError::VerificationFailed("Ed25519 signature mismatch"))?;

        let ml_bytes: [u8; ml_dsa_65::PK_LEN] = self
            .ml_dsa_65
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::InvalidArtifact("invalid ML-DSA-65 public key".into()))?;
        let ml_key = ml_dsa_65::PublicKey::try_from_bytes(ml_bytes)
            .map_err(|_| WalletError::InvalidArtifact("invalid ML-DSA-65 public key".into()))?;
        let ml_signature: [u8; ml_dsa_65::SIG_LEN] = signature
            .ml_dsa_65
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::VerificationFailed("invalid ML-DSA-65 signature"))?;
        if !ml_key.verify(&digest, &ml_signature, HYBRID_CONTEXT) {
            return Err(WalletError::VerificationFailed(
                "ML-DSA-65 signature mismatch",
            ));
        }

        Ok(())
    }
}

/// A signature that is valid only when both algorithm halves verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519: [u8; 64],
    pub ml_dsa_65: Vec<u8>,
}

/// An unlocked signer. Both expanded private keys remain live until this value is dropped.
pub struct HybridSigner {
    ed25519: SigningKey,
    ml_dsa_65: ml_dsa_65::PrivateKey,
    public_anchor: HybridPublicAnchor,
}

impl HybridSigner {
    fn from_secret(secret: &[u8; SECRET_LEN]) -> Self {
        let ed25519 = SigningKey::from_bytes(secret);
        let (ml_public, ml_dsa_65) = ml_dsa_65::KG::keygen_from_seed(secret);
        let ed_public = ed25519.verifying_key().to_bytes();
        let ml_public = ml_public.into_bytes().to_vec();
        let public_anchor = HybridPublicAnchor {
            ed25519: ed_public,
            key_id: anchor_id(&ed_public, &ml_public),
            ml_dsa_65: ml_public,
        };
        Self {
            ed25519,
            ml_dsa_65,
            public_anchor,
        }
    }

    pub fn public_anchor(&self) -> &HybridPublicAnchor {
        &self.public_anchor
    }

    /// Sign with the already-expanded Ed25519 and ML-DSA-65 private keys.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature, WalletError> {
        let digest = signing_digest(message);
        let ed25519 = self.ed25519.sign(&digest).to_bytes();
        let ml_dsa_65 = self
            .ml_dsa_65
            .try_sign(&digest, HYBRID_CONTEXT)
            .map_err(|error| WalletError::KeyOperation(error.into()))?
            .to_vec();
        Ok(HybridSignature { ed25519, ml_dsa_65 })
    }
}

/// A mnemonic encoding an independent recovery secret, not the Member Key secret.
pub struct RecoveryMnemonic(Zeroizing<String>);

impl RecoveryMnemonic {
    pub fn phrase(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KdfProfile {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl Default for KdfProfile {
    fn default() -> Self {
        Self {
            algorithm: "argon2id-v19".into(),
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            lanes: ARGON2_LANES,
        }
    }
}

impl KdfProfile {
    fn validate(&self) -> Result<(), WalletError> {
        if self.algorithm != "argon2id-v19"
            || self.memory_kib != ARGON2_MEMORY_KIB
            || self.iterations != ARGON2_ITERATIONS
            || self.lanes != ARGON2_LANES
        {
            return Err(WalletError::InvalidArtifact(
                "unsupported key-derivation profile".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtectedEnvelope {
    version: u8,
    kind: String,
    kdf: KdfProfile,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    anchor_id: [u8; 32],
}

/// Password-unlocked local persistence for the 32-byte reconstruction secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalVault {
    protected: ProtectedEnvelope,
}

impl LocalVault {
    pub fn unlock(&self, password: &[u8]) -> Result<HybridSigner, WalletError> {
        validate_password(password)?;
        let secret = self.protected.open(password, &[])?;
        signer_from_opened_secret(secret, self.protected.anchor_id)
    }

    pub fn write_private(&self, path: impl AsRef<Path>) -> Result<(), WalletError> {
        write_private_json(path.as_ref(), self)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        read_private_json(path.as_ref())
    }
}

/// Offline recovery artifact requiring both the independent mnemonic and password.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryKit {
    protected: ProtectedEnvelope,
}

impl RecoveryKit {
    pub fn recover(&self, mnemonic: &str, password: &[u8]) -> Result<HybridSigner, WalletError> {
        let recovery_secret = parse_recovery_secret(mnemonic)?;
        validate_password(password)?;
        let secret = self.protected.open(password, &recovery_secret)?;
        signer_from_opened_secret(secret, self.protected.anchor_id)
    }

    /// Recover and immediately rewrap the secret into a new password-only local vault.
    pub fn recover_to_local_vault(
        &self,
        mnemonic: &str,
        recovery_password: &[u8],
        new_local_password: &[u8],
    ) -> Result<(HybridSigner, LocalVault), WalletError> {
        let recovery_secret = parse_recovery_secret(mnemonic)?;
        validate_password(recovery_password)?;
        validate_password(new_local_password)?;
        let secret = self.protected.open(recovery_password, &recovery_secret)?;
        let signer = HybridSigner::from_secret(&secret);
        if signer.public_anchor.key_id != self.protected.anchor_id {
            return Err(WalletError::DecryptionFailed);
        }
        let protected = ProtectedEnvelope::seal(
            LOCAL_KIND,
            &secret,
            new_local_password,
            &[],
            signer.public_anchor.key_id,
        )?;
        Ok((signer, LocalVault { protected }))
    }

    pub fn write_private(&self, path: impl AsRef<Path>) -> Result<(), WalletError> {
        write_private_json(path.as_ref(), self)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        read_private_json(path.as_ref())
    }
}

/// Result of a fresh ceremony. The signer is already unlocked and retains both private keys.
pub struct CeremonyOutput {
    pub signer: HybridSigner,
    pub local_vault: LocalVault,
    pub recovery_kit: RecoveryKit,
    pub mnemonic: RecoveryMnemonic,
}

pub struct KeyCeremony;

impl KeyCeremony {
    /// Create a fresh Member Key and both protected persistence artifacts.
    pub fn create(password: &[u8]) -> Result<CeremonyOutput, WalletError> {
        validate_password(password)?;

        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        let mut recovery_secret = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(&mut *secret)
            .map_err(|error| WalletError::Randomness(error.to_string()))?;
        getrandom::fill(&mut *recovery_secret)
            .map_err(|error| WalletError::Randomness(error.to_string()))?;

        let mnemonic =
            Mnemonic::from_entropy(&*recovery_secret).map_err(|_| WalletError::InvalidMnemonic)?;
        let signer = HybridSigner::from_secret(&secret);
        let anchor_id = signer.public_anchor.key_id;

        let local_vault = LocalVault {
            protected: ProtectedEnvelope::seal(LOCAL_KIND, &secret, password, &[], anchor_id)?,
        };
        let recovery_kit = RecoveryKit {
            protected: ProtectedEnvelope::seal(
                RECOVERY_KIND,
                &secret,
                password,
                &*recovery_secret,
                anchor_id,
            )?,
        };

        Ok(CeremonyOutput {
            signer,
            local_vault,
            recovery_kit,
            mnemonic: RecoveryMnemonic(Zeroizing::new(mnemonic.to_string())),
        })
    }
}

impl ProtectedEnvelope {
    fn seal(
        kind: &str,
        secret: &[u8; SECRET_LEN],
        password: &[u8],
        extra_secret: &[u8],
        anchor_id: [u8; 32],
    ) -> Result<Self, WalletError> {
        let mut salt = vec![0u8; SALT_LEN];
        let mut nonce = vec![0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|error| WalletError::Randomness(error.to_string()))?;
        getrandom::fill(&mut nonce).map_err(|error| WalletError::Randomness(error.to_string()))?;

        let key = derive_wrapping_key(password, extra_secret, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WalletError::EncryptionFailed)?;
        let aad = envelope_aad(kind, &anchor_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| WalletError::EncryptionFailed)?;

        Ok(Self {
            version: FORMAT_VERSION,
            kind: kind.into(),
            kdf: KdfProfile::default(),
            salt,
            nonce,
            ciphertext,
            anchor_id,
        })
    }

    fn open(
        &self,
        password: &[u8],
        extra_secret: &[u8],
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>, WalletError> {
        self.validate()?;
        let key = derive_wrapping_key(password, extra_secret, &self.salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WalletError::DecryptionFailed)?;
        let aad = envelope_aad(&self.kind, &self.anchor_id);
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| WalletError::DecryptionFailed)?,
        );
        if plaintext.len() != SECRET_LEN {
            return Err(WalletError::DecryptionFailed);
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(secret)
    }

    fn validate(&self) -> Result<(), WalletError> {
        if self.version != FORMAT_VERSION {
            return Err(WalletError::InvalidArtifact("unsupported version".into()));
        }
        if self.kind != LOCAL_KIND && self.kind != RECOVERY_KIND {
            return Err(WalletError::InvalidArtifact("unknown artifact kind".into()));
        }
        self.kdf.validate()?;
        if self.salt.len() != SALT_LEN
            || self.nonce.len() != NONCE_LEN
            || self.ciphertext.len() != SECRET_LEN + 16
        {
            return Err(WalletError::InvalidArtifact(
                "protected field has the wrong length".into(),
            ));
        }
        Ok(())
    }
}

fn signer_from_opened_secret(
    secret: Zeroizing<[u8; SECRET_LEN]>,
    expected_anchor_id: [u8; 32],
) -> Result<HybridSigner, WalletError> {
    let signer = HybridSigner::from_secret(&secret);
    if signer.public_anchor.key_id != expected_anchor_id {
        return Err(WalletError::DecryptionFailed);
    }
    Ok(signer)
}

fn parse_recovery_secret(mnemonic: &str) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    if entropy.len() != SECRET_LEN {
        return Err(WalletError::InvalidMnemonic);
    }
    Ok(entropy)
}

fn validate_password(password: &[u8]) -> Result<(), WalletError> {
    if password.len() < MIN_PASSWORD_BYTES {
        return Err(WalletError::WeakPassword);
    }
    Ok(())
}

fn derive_wrapping_key(
    password: &[u8],
    extra_secret: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KDF_OUTPUT_LEN]>, WalletError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(KDF_OUTPUT_LEN),
    )
    .map_err(|_| WalletError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut input = Zeroizing::new(Vec::with_capacity(
        HYBRID_CONTEXT.len() + 8 + extra_secret.len() + password.len(),
    ));
    input.extend_from_slice(HYBRID_CONTEXT);
    input.extend_from_slice(&(extra_secret.len() as u32).to_le_bytes());
    input.extend_from_slice(extra_secret);
    input.extend_from_slice(&(password.len() as u32).to_le_bytes());
    input.extend_from_slice(password);

    let mut output = Zeroizing::new([0u8; KDF_OUTPUT_LEN]);
    argon2
        .hash_password_into(&input, salt, &mut *output)
        .map_err(|_| WalletError::KeyDerivation)?;
    Ok(output)
}

fn anchor_id(ed25519: &[u8; 32], ml_dsa_65: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("castalia.member-key.anchor.v1");
    hasher.update(ed25519);
    hasher.update(&(ml_dsa_65.len() as u64).to_le_bytes());
    hasher.update(ml_dsa_65);
    *hasher.finalize().as_bytes()
}

fn signing_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("castalia.member-key.signature.v1");
    hasher.update(&(message.len() as u64).to_le_bytes());
    hasher.update(message);
    *hasher.finalize().as_bytes()
}

fn envelope_aad(kind: &str, anchor_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(kind.len() + 1 + anchor_id.len());
    aad.extend_from_slice(kind.as_bytes());
    aad.push(FORMAT_VERSION);
    aad.extend_from_slice(anchor_id);
    aad
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), WalletError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let bytes = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_private_json<T: DeserializeOwned>(path: &Path) -> Result<T, WalletError> {
    let bytes = Zeroizing::new(fs::read(path)?);
    Ok(serde_json::from_slice(&bytes)?)
}
