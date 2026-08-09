# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-08-09

### Changed
- none.

### Removed
- **Core:** Removed zip bomb protection guards (including `MAX_ENTRIES`, `MAX_EXTRACT_SIZE`, and `MAX_COMPRESSION_RATIO` limits) from the decryption and extraction pipeline. These checks were buggy and occasionally prevented legitimate files from being restored.
