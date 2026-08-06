# Castalia Wallet SDK

Local, registration-free primitives for a Castalia Member Key ceremony.

> [!WARNING]
> This is experimental cryptographic software. It has not received an independent security audit and is not yet approved for production Member Keys. See [SECURITY.md](SECURITY.md).

The ceremony generates one 32-byte secret from OS randomness and deterministically expands it into an Ed25519 keypair and an ML-DSA-65 keypair. Both expanded private keys remain in `HybridSigner` memory for normal signing. The reconstruction secret is separately wrapped into:

- a password-only local vault for routine restart/unlock;
- a recovery kit requiring both an independent 24-word mnemonic and the password.

The mnemonic encodes an independent recovery secret. It does not encode the Member Key secret directly. Artifacts are created with owner-only permissions on Unix and are never overwritten.

This repository does not register Member Keys, create Dregg cells, register Dregg nodes, or make network requests.

## CLI

```sh
cargo run --bin castalia-key-ceremony -- self-test
cargo run --bin castalia-key-ceremony -- create \
  --vault ./castalia-member.vault.json \
  --recovery-kit ./castalia-member.recovery.json
cargo run --bin castalia-key-ceremony -- unlock ./castalia-member.vault.json
cargo run --bin castalia-key-ceremony -- recover \
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
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --bin castalia-key-ceremony -- self-test
```

## License

Licensed under either Apache License 2.0 or the MIT License, at your option.
