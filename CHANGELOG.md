# SECURITY.md

# Security Policy

## Supported Versions

| Version | Supported          | Security Updates |
| 1.x     | :white_check_mark: | Full support     |
| < 0.0.3 | :x:                | Unsupported      |

---

## Security Guarantees & Threat Model

`pooputil` is designed for single-pass, authenticated stream encryption of files and directory archives.

### Cryptographic Standards
- **Authenticated Encryption**: AES-256-GCM. Header metadata (version, container type, compression mode, KDF parameters, salt, and IV) is bound to the payload via Additional Authenticated Data (AAD).
- **Key Derivation Function (KDF)**: `scrypt` with default parameters `N=2^17` (131,072), `r=8`, `p=1`, `maxmem=512MB`. Each container generates a fresh 16-byte random salt and 12-byte IV using system entropy (`os.urandom`).
- **Disk & Memory Safety**: Payload compression (raw DEFLATE) occurs directly inside the GCM ciphertext stream. No unencrypted intermediate ZIP archives touch disk during folder operations.
- **Secure File Destruction**: Original files are overwritten with null bytes (`0x00`), flushed to disk (`fsync`), and unlinked.

---

## Extraction Safety & DoS Defenses

To prevent extraction path traversal, directory escape, and resource exhaustion attacks (e.g., zip bombs), extraction enforces hard boundaries:

| Defense Parameter | Boundary | Behavior on Violation |
| :--- | :--- | :--- |
| **Max Extraction Volume** | `8 GiB` | Triggers `InvalidPoopFile` if cumulative output exceeds limit |
| **Max Entry Count** | `10,000` entries | Rejects archives exceeding total file threshold |
| **Max Compression Ratio** | `1040:1` | Prevents zip-bomb expansion (tuned safely above Deflate's `1032:1` limit) |
| **Max Manifest Size** | `16 MiB` | Rejects oversized folder metadata headers |
| **Path Traversal Protection** | Active | Rejects relative paths containing `..`, absolute root paths, or symlinks |
| **System Directory Safety** | Active | Refuses operations on system/protected OS roots (`/etc`, `/usr`, `C:\Windows`, etc.) |

---

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately rather than opening a public issue.

1. **Email**: Contact `debiiyapp@gmail.com` with the subject line `[SECURITY] pooputil vulnerability`.
2. **Details**: Include a proof of concept, step-by-step reproduction steps, and affected version(s).
3. **Response Timeline**: You will receive an initial response within 48 hours. Fixes will be developed privately and released as a minor patch version alongside an advisory.
