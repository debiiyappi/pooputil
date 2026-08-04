# pooputil v2 Container Format — Specification

This document describes the on-disk format of `.poop` containers as
produced by pooputil >= 0.2.0, and the v1 format it can still read.

Status: **normative** for v2. Version 1 layout is documented for
compatibility, read-only.

## 1. Notation

- All multi-byte integers are little-endian.
- All fields are fixed-size unless stated otherwise.
- `||` means concatenation.
- "Covered by AAD" means the bytes are bound into GCM additional
  authenticated data; they are authenticated but **not** encrypted.

## 2. Threat model

Assumed attacker: offline, in possession of one or more `.poop`
containers, without the password. They must learn nothing about file
contents, names, sizes, or mtimes, and must be unable to modify a
container without detection.

Out of scope: code execution as the user, physical attacks, keyloggers,
SSD wear-leveling effects on secure deletion.

## 3. Cipher and KDF

| Component | Value |
| --- | --- |
| Cipher | AES-256-GCM |
| Key length | 32 bytes (derived) |
| Nonce (IV) | 12 bytes, fresh random per container |
| Tag | 16 bytes (128-bit) |
| KDF | scrypt, `N=2^17, r=8, p=1`, `dklen=32` |
| Salt | 16 bytes, fresh random per container |
| KDF memory | 128 MiB (implementation uses `maxmem=512 MiB`) |

The KDF parameters are **stored in the container header** (section 4),
so they can be tuned in future versions without breaking old files.

## 4. Header

### 4.1 v2 header (54 bytes total)

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 4 | MAGIC | ASCII `POOP` |
| 4 | 1 | VERSION | `0x02` |
| 5 | 1 | TYPE | `0x00` = file, `0x01` = folder |
| 6 | 1 | COMPRESS | `0x01` = raw DEFLATE |
| 7 | 1 | LOG_N | `log2(N)` of scrypt, e.g. `17` |
| 8 | 1 | R | scrypt `r`, e.g. `8` |
| 9 | 1 | P | scrypt `p`, e.g. `1` |
| 10 | 16 | SALT | KDF salt |
| 26 | 12 | IV | GCM nonce |
| 38 | 16 | TAG | GCM tag (written at finalize) |
| 54 | - | end | ciphertext starts here |

The first 38 bytes (MAGIC .. IV) form the GCM AAD. The tag at offset 38
authenticates AAD + all ciphertext.

The `COMPRESS` byte is validated by the reader; unknown values are
rejected. The `TYPE` byte is duplicated by the manifest structure and
re-checked after decryption.

### 4.2 v1 header (50 bytes total, read-only)

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 4 | MAGIC | ASCII `POOP` |
| 4 | 1 | VERSION | `0x01` |
| 5 | 1 | TYPE | `0x00` file / `0x01` folder |
| 6 | 16 | SALT | KDF salt |
| 22 | 12 | IV | GCM nonce |
| 34 | 16 | TAG | GCM tag |
| 50 | - | end | ciphertext starts here |

v1 KDF params are implicit: `N=2^14, r=8, p=1`. v1 payload is
uncompressed ciphertext. v1 folders contain a plaintext ZIP encrypted
in one GCM stream; v2 can decrypt and extract them via a legacy path.

## 5. Payload — file container (`TYPE = 0x00`)

offset 54: ciphertext( raw_deflate( file_bytes ) )





- One single raw DEFLATE stream (zlib `wbits = -15`), level 6,
  covering the entire file, streamed directly into the GCM encryptor.
- The stream runs to end-of-file; the deflate end marker terminates it.
- Memory use is bounded: a fixed 64 KiB chunk is compressed and
  encrypted per iteration, no full-file buffering.

## 6. Payload — folder container (`TYPE = 0x01`)

offset 54: ciphertext( u32 LE manifest_length || manifest_bytes (UTF-8 JSON) || raw_deflate( entry[0].bytes ) || raw_deflate( entry[1].bytes ) || ... )

- One GCM stream for the whole container. The manifest is encrypted
  like everything else — names, sizes and mtimes never appear in
  plaintext.
- Each entry is a **self-terminating** raw DEFLATE stream. The reader
  detects the boundary via the decompressor's EOF; any leftover
  plaintext bytes belong to the next entry.

Field	Type	Meaning
name	string	POSIX-style relative path (/ separators)
size	int	uncompressed size in bytes
mtime_ns	int	os.stat().st_mtime_ns of the source
mode	int	permission bits (st_mode & 0o777)
Order of entries = order of streams in the payload. Readers MUST validate the manifest before writing any file (section 8).

7. Key schedule



key = scrypt(password, salt, N=2^LOG_N, r=R, p=P, dklen=32)
LOG_N, R, P come from the header (v2) or are fixed for v1. The same derived key is used only for this one container (fresh salt + IV per container), so no nonce-reuse risk exists across files.

8. Extraction defenses (mandatory)


Check	Limit
Manifest size	16 MiB
Entry count	10 000
Total uncompressed size	8 GiB
Per-entry compression ratio	1000:1
Path traversal (.., absolute paths)	rejected
Symlinks	rejected on encrypt and decrypt
Ratio is computed as declared_size / consumed_plaintext for the entry's deflate stream and checked while extracting. On ANY failure — including GCM tag mismatch at finalize — the partially extracted directory is deleted and the error surfaces as InvalidPoopFile.

9. Versioning and compatibility


Container	pooputil >= 0.2.0	pooputil < 0.2.0
v1	decrypt (read-only)	yes
v2	read/write	no (Unsupported .poop version)
Rules for future changes:

Unknown VERSION → reject with a clear error, never guess.
Unknown COMPRESS → reject (a zstd/lzma code can be added later as new method bytes; old files keep decrypting).
Never re-derive KDF params from code constants; read them from the header.
10. Secure deletion
encrypt_target overwrites the original (single pass, 64 KiB chunks) then removes it; folders are walked bottom-up.
decrypt_target overwrites and removes the .poop container after a successful decryption. Decryption therefore consumes the container — keep a copy if you need it twice.
These guarantees are best-effort on SSDs (wear leveling) and journaled filesystems; see README.
11. Reference implementation notes
Encrypt: zlib.compressobj(level=6, wbits=-15) feeding encryptor.update(), tag patched into the header slot after finalize(), then fsync + atomic os.replace.
Decrypt: lazy _PlainReader that decrypts 64 KiB chunks on demand, one decompressobj(wbits=-15) per entry.
All temp files are created with O_EXCL | O_NOFOLLOW, mode 0600.
Raw DEFLATE (wbits=-15) is used deliberately: no zlib/gzip wrapper bytes, so the container stays self-describing and the framing is defined solely by this spec.



