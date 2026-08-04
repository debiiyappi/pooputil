# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

Do NOT open a public issue for security vulnerabilities.
Report privately to **debiiyapp@gmail.com** with:

- Description and impact
- Steps to reproduce (PoC preferred)
- Affected versions
- Suggested fix (optional)

Expect a confirmation within 48 hours and a status update
within 7 days. We will coordinate disclosure timing with you.

## Security Model

- Confidentiality: AES-256-GCM (payload, authenticated)
- Key derivation: Scrypt, params stored in the container header
- Integrity: GCM tag bound to the full plaintext header via AAD
- Assumed attacker: offline, with access to `.poop` containers

## Explicitly Out of Scope

- Secure deletion behavior on SSDs / wear-leveling filesystems
- Attacks requiring code execution with the user's privileges
- Physical attacks (cold boot, memory dumping)
