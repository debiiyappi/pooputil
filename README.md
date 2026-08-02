# 💩 pooputil

> Ever heard of ransomware?
>
> One of the first things it usually does is scan your drive for common file extensions.
>
> ```
> .docx .xlsx .pptx
> .pdf  .jpg  .png
> .zip  .sql  .db
> ```
>
> Your files are predictable.
>
> `pooputil` changes that.

`pooputil` is a small open-source file encryption utility that compresses your files into encrypted **.poop** containers.

Instead of just hiding files somewhere, pooputil compresses them, encrypts them using **AES-256-GCM**, derives keys using **Scrypt**, and can optionally overwrite the original file after encryption.

Whether you're storing backups, documents or just wanna archive stuff safely, pooputil gives you a Python API, CLI and a simple desktop GUI.

> **v0.0.2**
>
> Fixed the broken imports from v0.0.1. Everything should work properly now.

Licensed under **GPLv3**. Fork it, improve it or build your own project on top of it.

---

# Features

- AES-256-GCM authenticated encryption
- Scrypt password derivation
- Compress before encrypting
- Custom `.poop` container format
- Python API
- CLI
- Desktop GUI
- Optional overwrite-based deletion
- Backend separated from GUI

---

# Why `.poop`?

A lot of malware targets common file extensions.

```
.docx
.xlsx
.pdf
.jpg
.png
.zip
```

Those are easy to recognize.

pooputil stores encrypted data inside `.poop` containers instead.

Will this stop malware?

Probably not.

If malware wants to encrypt every file on your disk it'll happily encrypt `.poop` too.

The idea here isn't to beat ransomware, it's to make your actual file contents unreadable without the password while also giving you a funny file extension.

---

# Architecture

pooputil is split into modules kinda like Arduino.

```
GUI
 │
 ▼
pooputil.core
 ▲
 │
CLI
 │
 ▼
Python API
```

The GUI is just a frontend.

Most of the work happens inside `pooputil.core`, so you can import it directly into your own scripts without dragging GUI stuff along.

---

# Crypto

| Component | Algorithm |
|-----------|-----------|
| Encryption | AES-256-GCM |
| KDF | Scrypt |
| Salt | 16 bytes |
| Nonce | 12 bytes |
| Authentication | GCM Tag |

I use the `cryptography` library instead of trying to implement crypto myself.

---

# Secure deletion

After encryption pooputil can overwrite the original file before deleting it.

Keep in mind secure deletion depends on your filesystem and storage device. SSDs especially don't always behave the same because of wear leveling.

---

# Installation

```bash
pip install pooputil
```

---

# Usage

## GUI

```bash
pooputil-gui
```

or

```bash
python -m pooputil
```

---

## CLI

Encrypt

```bash
pooputil-cli --encrypt "/path/to/data" --password "SuperSecretKey99"
```

Decrypt

```bash
pooputil-cli --decrypt "/path/to/data.poop" --password "SuperSecretKey99"
```

---

# Python API

```python
from pooputil import core

password = b"SuperSecretPassword"
target = "./important.docx"

if core.is_safe_path(target):
    core.encrypt_target(target, password)
else:
    print("Unsafe path.")
```

Decrypt

```python
from pooputil import core

restored = core.decrypt_target(
    "./important.docx.poop",
    b"SuperSecretPassword"
)

print(restored)
```

---

# Disclaimer

This project is meant for legitimate encryption and backup purposes.

Also...

Don't forget your password.

I can't magically decrypt your `.poop` if you lose it.

---

# License

GPLv3.
