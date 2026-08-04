# Security Policy

## Supported Versions

| Version        | Container | Supported          |
| -------------- | --------- | ------------------ |
| 0.1.1          | v2        | :white_check_mark: |
| 0.1.x          | v1        | :warning: read-only decryption only |
| < 0.1          | -         | :x:                |

## Reporting a Vulnerability

Do NOT open a public issue for security vulnerabilities.

Report privately to **debiiyapp@gmail.com** with:

- Description and impact
- Steps to reproduce (PoC preferred)
- Affected versions
- Suggested fix (optional)

Expected response time: i am alone and a solo devs here the expected is random.

## Container Format (v2)

Plaintext header

Everything else — manifest, file contents — is inside the
AES-256-GCM stream and indistinguishable from random bytes.

- Encryption: AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)
- Key derivation: Scrypt n=2^17 r=8 p=1 (128 MiB), params stored
  in the header and covered by AAD; v1 containers use n=2^14
- Compression: raw DEFLATE, streamed inside the GCM ciphertext
- Integrity: GCM tag binds the full plaintext header + payload

## Security Model

- Confidentiality: payload and metadata (names, sizes, mtimes)
  are encrypted; an attacker with only `.poop` containers learns
  nothing but header fields.
- Integrity: any modification or truncation fails tag
  verification before decrypted data is finalized.
- Assumed attacker: offline, with full access to `.poop`
  containers.

## Extraction Defenses

- Path traversal entries rejected (manifest validation)
- Symlinks refused on both encrypt and decrypt
- Caps: total 8 GiB, 10 000 entries, per-entry compression
  ratio 1000:1 — extraction aborts and cleans up on violation

## Explicitly Out of Scope

- Secure deletion guarantees on SSDs / wear-leveling filesystems
- Attacks requiring code execution with the user's privileges
- Physical attacks (cold boot, memory dumping)
- Side channels on password entry (keyloggers, shoulder surfing)

## Notes

- The password is the only secret. Losing it means permanent
  data loss; there is no backdoor and no recovery mechanism.
- `decrypt_target` removes the `.poop` container after a
  successful decryption — keep backups if you want to decrypt
  the same container twice.
