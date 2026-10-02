# Castalia Wallet SDK

Local, registration-free primitives for a Castalia Member Key ceremony.

> [!WARNING]
> This is experimental cryptographic software. It has not received an independent security audit and is not yet approved for production Member Keys. See [SECURITY.md](SECURITY.md).

The ceremony generates one 32-byte secret from OS randomness and deterministically expands it into an Ed25519 keypair and an ML-DSA-65 keypair. Both expanded private keys remain in `HybridSigner` memory for normal signing. The reconstruction secret is separately wrapped into:

- a password-only local vault for routine restart/unlock;
- a recovery kit requiring both an independent 24-word mnemonic and the password.

The mnemonic encodes an independent recovery secret. It does not encode the Member Key secret directly. Artifacts are published without overwriting an existing destination and use exact owner-only `0600` permissions on supported Unix platforms. The parent directory must already exist and must not be group- or world-writable. Reads reject symlinks, hardlinks, nonregular files and artifacts larger than 64 KiB. Every path ancestor must remain trusted during the operation; the API does not pin the complete ancestor chain. Errors beginning with `destination was committed` mean publication succeeded but cleanup or directory synchronization failed: inspect the existing destination before retrying. If temporary-link removal failed, the destination still has a second hardlink and private reads reject it until that specific leftover link is removed. A parent synchronization error leaves durability uncertain even when the destination is readable.

This repository does not register Member Keys, create Dregg cells, register Dregg nodes, or make network requests.

## CLI

```sh
cargo +1.96.0 run --locked --bin castalia-key-ceremony -- self-test
cargo +1.96.0 run --locked --bin castalia-key-ceremony -- create \
  --vault ./castalia-member.vault.json \
  --recovery-kit ./castalia-member.recovery.json
cargo +1.96.0 run --locked --bin castalia-key-ceremony -- unlock ./castalia-member.vault.json
cargo +1.96.0 run --locked --bin castalia-key-ceremony -- recover \
  ./castalia-member.recovery.json \
  ./restored-member.vault.json
```

`create`, `unlock`, and `recover` use hidden terminal prompts. `create` displays the recovery phrase once after both protected artifacts have been written successfully.

## Security boundary

- Private keys and plaintext reconstruction material are never serialized.
- XChaCha20-Poly1305 authenticates protected artifacts.
- Argon2id uses 64 MiB, three iterations, and one lane.
- The public anchor identifier and artifact type/version are authenticated as associated data.
- Hybrid signatures verify Ed25519 and ML-DSA-65 over one domain-separated BLAKE3 message digest.
- The implementation uses the RustCrypto-adjacent `fips204` crate directly. It does not yet route ML-DSA through Dregg's Lean-verified runtime bridge; parity with the exact production Dregg primitive remains a release gate.

## Verification

```sh
cargo +1.96.0 fmt --check
cargo +1.96.0 test --all-targets --locked
cargo +1.96.0 clippy --all-targets --locked -- -D warnings
cargo +1.96.0 run --locked --bin castalia-key-ceremony -- self-test
```

## License

Licensed under either Apache License 2.0 or the MIT License, at your option.
