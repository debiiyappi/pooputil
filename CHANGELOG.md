# Changelog

All notable changes to pooputil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Raised `MAX_COMPRESSION_RATIO` threshold from `1000:1` to `1040:1` to eliminate false-positive zip bomb rejections on highly compressible data (e.g., zero-filled files) approaching Deflate's theoretical maximum ratio of `1032:1`.
- Corrected byte accounting in `_PlainReader.feed_entry()` to subtract unconsumed trailing bytes (`decompressor.unused_data`) from `consumed` upon hitting `decompressor.eof`.

## [2.0.0]

### Added
- v2 container format:
  - KDF parameters (log2 N, r, p) and compression method stored in the
    plaintext header, bound by GCM AAD
  - built-in raw DEFLATE streaming inside the GCM ciphertext — no
    intermediate plaintext ZIP is ever written to disk
  - encrypted manifest in folder containers (relative path, size, mtime,
    mode), restored on decrypt
- `--password` is now optional: interactive `getpass` prompt with
  double-entry confirmation when encrypting
- `POOPUTIL_PASSWORD` environment variable as a password fallback
- Extraction defenses: entry-count cap (10 000), total-size cap (8 GiB),
  per-entry compression-ratio cap, manifest path validation
- `SECURITY.md` with supported versions and vulnerability reporting

### Changed
- Scrypt cost raised from n=2^14 to n=2^17 (r=8, p=1) for new containers
- KDF now uses `hashlib.scrypt` (explicit `maxmem`) instead of the
  `cryptography` wrapper
- v1 containers remain decryptable via a legacy path (read-only)
- Encryption/decryption now streams one file at a time with bounded memory

### Fixed
- CLI: dead duplicate `parser.parse_args()` / `args.password.encode()`
  lines removed so the interactive password prompt actually runs
- Folder encryption no longer silently overwrites a sibling `.zip` file

## [1.0.0]

### Fixed
- Broken imports from v0.0.1; package structure moved under `src/`

### Added
- AES-256-GCM encryption with Scrypt key derivation
- Custom `.poop` container format
- CLI, desktop GUI and Python API
- Secure overwrite-based deletion of originals
