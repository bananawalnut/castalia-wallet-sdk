# Custody file hardening reconciliation

Base: `998032f723ffa93287b87109446f56472da17605`. The filesystem helpers and their tests are selectively retained from the uncommitted `feat/castalia-wallet-dregg-adapter` source captured on 2026-10-02.

Signing, identity derivation, v1 encodings, dependencies and CLI signing self-tests remain those of main. Both experimental Dregg adapters are preserved separately and are not dependencies of this change.

Security boundary: direct-parent validation assumes trusted, nonreplaceable path ancestors. Full descriptor-relative ancestor traversal and independent custody audit remain outside this change. Reads fail closed on unsupported platforms.

Validation on 2026-10-02 with Rust 1.96.0: locked offline all-target tests passed (16 integration cases), locked offline Clippy passed with warnings denied, formatting passed, and the original CLI signing/unlock/recovery self-test passed. Tests cover private-mode enforcement, no overwrite, temporary cleanup, persisted identity/recovery round trips, unsafe filesystem entries and explicit post-publication error messages. Cargo manifests, lockfile and CLI are unchanged.

Linux CI initially exposed a test-fixture assumption: checking a top-level temp directory exercises rejection of its world-writable `/tmp` parent before file-type rejection. The fixture now nests the non-file inside a trusted private parent, preserving both production checks. Runtime code and signing/recovery fixtures are unchanged.

## Publication failure-path follow-up

The private writer now takes an internal operations implementation. Public callers
always receive the real filesystem implementation; tests inject operation failures
without environment variables, public hooks, changed schemas or new dependencies.
The same writer still creates real private temporary files, serializes the same
bytes, and publishes with a real no-overwrite hardlink before cleanup and directory
synchronization.

Seven focused cases cover file-sync failure, publication failure, successful
publication, an existing destination, temporary-unlink failure, parent-sync failure,
and both post-publication failures together. They assert operation order, exact
bytes and permissions, truthful committed-destination errors, temporary cleanup and
that a surviving second hardlink prevents private reads until explicit cleanup.
The original signing, identity and recovery fixtures remain unchanged.

CI now selects Rust 1.96.0 explicitly, uses immutable action commits, and requires
`--locked` for Clippy, tests and the original CLI ceremony self-test. The lockfile
and dependency manifest remain unchanged. Linux CI for this follow-up is pending
publication. Local validation on macOS/aarch64 passed on 2026-10-02:

- `rustc 1.96.0 (ac68faa20 2026-05-25)` and `cargo 1.96.0 (30a34c682 2026-05-25)`.
- `cargo +1.96.0 fmt --check`.
- `cargo +1.96.0 test --all-targets --locked --offline`: 7 publication cases plus all 16 original integration cases passed.
- `cargo +1.96.0 clippy --all-targets --locked --offline -- -D warnings`.
- `cargo +1.96.0 run --locked --offline --quiet --bin castalia-key-ceremony -- self-test`: hybrid signing, password unlock and mnemonic/password recovery passed.
- Locked/offline Cargo metadata resolves 100 packages, with only this SDK as a local package and no Dregg package or sibling checkout.
- Unchanged `Cargo.lock` SHA-256: `5417c8a69cf2e3b0c9f74473b388ced3be6538b50377f5f0fb6da637f11a7def`.
- Local debug CLI test artifact SHA-256: `126ab3e1b30aaae8b8172be87116949f8eb8e20c0b482cbcc2c2057c5a01f0d5`. This is test evidence, not a release artifact or cross-platform reproducibility claim.

The starting candidate was `3ca07222a996c20c19e7854007b23f8b1d47bc1b`.
No signing/recovery format migration, public API change or independent custody
qualification is implied by these failure-injection tests.
