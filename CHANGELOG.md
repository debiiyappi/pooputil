# Changelog

All notable changes documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [Semantic Versioning](https://semver.org/)

## [Unreleased]

### Added
- `--password` now optional: interactive `getpass` prompt,
  with double-entry confirmation on encrypt
- `POOPUTIL_PASSWORD` environment variable fallback
- Built-in deflate compression inside the `.poop` container —
  no intermediate plaintext zip (single-file and folder modes)
- Encrypted manifest in folder containers (paths, sizes, mtimes, modes)
- KDF parameters written to the container header
- `SECURITY.md`

### Changed
- Scrypt cost raised to `n=2^17` (128 MiB)
- Version now single-sourced; `pooputil --version` added

### Security
- Zip-bomb extraction guards: total size, per-entry size,
  entry-count and compression-ratio caps
- Header now authenticates KDF params and compression method

## [0.1.0] - 2026-08-04

### Fixed
- Broken imports from v0.0.1

## [0.0.2] - unreleased

### Fixed
- Broken imports from v0.0.1

## [0.0.1] - initial release

### Added
- AES-256-GCM encryption, Scrypt KDF, CLI, GUI, Python API
