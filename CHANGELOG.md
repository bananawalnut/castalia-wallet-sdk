# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Fixed

- Validate and durably publish private artifacts without overwriting destinations — prevent unsafe filesystem entries, partial writes and ambiguous post-publication errors while preserving v1 custody and signing formats.
