# .poop Container Format — v1

## Layout

| Offset | Length | Field |
|-------:|-------:|-------|
| 0      | 4      | Magic `"POOP"` |
| 4      | 1      | Format version `0x01` |
| 5      | 1      | Payload type: `0x00` = file, `0x01` = folder (ZIP) |
| 6      | 16     | scrypt salt |
| 22     | 12     | AES-256-GCM nonce (IV) |
| 34     | 16     | GCM authentication tag |
| 50     | …      | AES-256-GCM ciphertext, streamed in 64 KiB chunks |

Header is 50 bytes total.

## Key derivation

scrypt(N=2^14, r=8, p=1, length=32), salt = header bytes 6..21.

## Authentication

AAD = MAGIC ‖ VERSION ‖ TYPE ‖ SALT ‖ IV (all 34 bytes before the tag).
The tag is written at offset 34 after encryption; on decrypt it must validate
before any plaintext is published (via atomic temp file + rename).

## Versioning rules

- Byte 4 is the version discriminator. Unknown versions are rejected with
  `InvalidPoopFile`, never guessed at.
- New features must append fields or add a new version; v1 files must stay
  decryptable.
