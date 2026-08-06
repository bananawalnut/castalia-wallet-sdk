# Security Policy

## Current status

Castalia Wallet SDK is experimental cryptographic software. It has not received an independent security audit and is not yet approved for protecting production Member Keys.

The current ML-DSA implementation uses the `fips204` Rust crate directly. Routing through, and exact compatibility testing against, Dregg's production verified ML-DSA implementation remains a release gate.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability that could expose private key material or bypass hybrid verification. Contact the repository owner privately through GitHub before publishing details.

Include the affected revision, reproduction steps, expected impact, and whether any secret material may have been exposed. Never include real seeds, mnemonics, passwords, private keys, or protected production artifacts.
