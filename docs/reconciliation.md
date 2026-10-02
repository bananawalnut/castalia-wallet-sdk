# Custody file hardening reconciliation

Base: `998032f723ffa93287b87109446f56472da17605`. The filesystem helpers and their tests are selectively retained from the uncommitted `feat/castalia-wallet-dregg-adapter` source captured on 2026-10-02.

Signing, identity derivation, v1 encodings, dependencies and CLI signing self-tests remain those of main. Both experimental Dregg adapters are preserved separately and are not dependencies of this change.

Security boundary: direct-parent validation assumes trusted, nonreplaceable path ancestors. Full descriptor-relative ancestor traversal and independent custody audit remain outside this change. Reads fail closed on unsupported platforms.

Validation on 2026-10-02 with Rust 1.96.0: locked offline all-target tests passed (16 integration cases), locked offline Clippy passed with warnings denied, formatting passed, and the original CLI signing/unlock/recovery self-test passed. Tests cover private-mode enforcement, no overwrite, temporary cleanup, persisted identity/recovery round trips, unsafe filesystem entries and explicit post-publication error messages. Cargo manifests, lockfile and CLI are unchanged.
