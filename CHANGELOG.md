# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Fixed

- Validate and durably publish private artifacts without overwriting destinations — prevent unsafe filesystem entries, partial writes and ambiguous post-publication errors while preserving v1 custody and signing formats.

- Make the non-regular-file regression fixture independent of the host temp-directory permissions, so Linux exercises the intended rejection without weakening trusted-parent validation.

- Pin CI to the tested Rust 1.96.0 toolchain and locked dependency resolution — prevent future stable releases or Clippy from silently changing the validated dependency set.

### Added

- Exercise private-file durability failures through the real publication path — verify committed-destination errors, cleanup, parent synchronization, hardlink read refusal and no-overwrite behavior using deterministic private test operations.
