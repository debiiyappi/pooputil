"""  Copyright (C) 2026 debiiyappi <debiiyapp@gmail.com>
  This file is the core of pooputil.
  pooputil is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version. """

import os
import shutil
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"POOP"
VERSION = b"\x01"
TYPE_FILE = b"\x00"
TYPE_FOLDER = b"\x01"

SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
TAG_OFFSET = len(MAGIC) + len(VERSION) + 1 + SALT_LEN + IV_LEN
HEADER_SIZE = TAG_OFFSET + TAG_LEN
CHUNK_SIZE = 64 * 1024
MAX_EXTRACT_SIZE = 8 * 1024 ** 3


class InvalidPoopFile(Exception):
    pass


def get_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
    return kdf.derive(password)


def is_safe_path(target_path: str) -> bool:
    path = Path(target_path).resolve()

    if path == path.anchor:
        return False

    if os.name == "nt":
        protected = [
            Path(os.environ.get("SystemRoot", r"C:\Windows")),
            Path(r"C:\Program Files"),
            Path(r"C:\Program Files (x86)"),
            Path(os.environ.get("ProgramData", r"C:\ProgramData")),
        ]
    else:
        protected = [
            Path("/"), Path("/bin"), Path("/boot"), Path("/dev"), Path("/etc"),
            Path("/lib"), Path("/lib64"), Path("/proc"), Path("/root"),
            Path("/run"), Path("/sbin"), Path("/sys"), Path("/usr"),
            Path("/var"), Path("/opt"), Path("/srv"), Path("/mnt"), Path("/media"),
            Path("/System"), Path("/Library"), Path("/private"),
        ]

    return not any(path == p or p in path.parents for p in protected)


def _open_read_nofollow(path: str):
    if os.path.islink(path):
        raise ValueError("Refusing to operate on symbolic links.")

    st_before = os.stat(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        st_fd = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if (st_fd.st_dev, st_fd.st_ino) != (st_before.st_dev, st_before.st_ino):
        os.close(fd)
        raise ValueError("File changed while it was being opened (TOCTOU); aborting.")
    return fd


def secure_delete(filepath: str) -> None:
    if os.path.islink(filepath):
        os.unlink(filepath)
        return
    if not os.path.lexists(filepath):
        return
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            remaining = file_size
            while remaining > 0:
                f.write(os.urandom(min(CHUNK_SIZE, remaining)))
                remaining -= CHUNK_SIZE
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass


def secure_rmtree(dirpath: str) -> None:
    if os.path.islink(dirpath):
        raise ValueError("Refusing to operate on symbolic links.")
    for root, dirs, files in os.walk(dirpath, topdown=False):
        for name in files:
            p = os.path.join(root, name)
            if os.path.islink(p):
                os.unlink(p)
            else:
                secure_delete(p)
        for name in dirs:
            p = os.path.join(root, name)
            if os.path.islink(p):
                os.unlink(p)
            else:
                os.rmdir(p)
    os.rmdir(dirpath)


def process_encryption(source_path: str, output_path: str,
                       password: bytes, file_type: bytes = TYPE_FILE) -> None:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = get_key(password, salt)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv),
                       backend=default_backend()).encryptor()
    header = MAGIC + VERSION + file_type + salt + iv
    encryptor.authenticate_additional_data(header)

    temp_path = output_path + ".tmp"
    try:
        fd = _open_read_nofollow(source_path)
        with os.fdopen(fd, "rb") as f_in, open(temp_path, "wb") as f_out:
            f_out.write(header + b"\x00" * TAG_LEN)
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
            encryptor.finalize()
            f_out.seek(TAG_OFFSET)
            f_out.write(encryptor.tag)
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(temp_path, output_path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def process_decryption(source_path: str, output_path: str, password: bytes) -> bytes:
    with os.fdopen(_open_read_nofollow(source_path), "rb") as f_in:
        magic = f_in.read(len(MAGIC))
        if magic != MAGIC:
            raise InvalidPoopFile("Not a .poop file (bad magic).")
        version = f_in.read(len(VERSION))
        if version != VERSION:
            raise InvalidPoopFile(f"Unsupported .poop version: {version!r}")
        file_type = f_in.read(1)
        if file_type not in (TYPE_FILE, TYPE_FOLDER):
            raise InvalidPoopFile(f"Unknown payload type: {file_type!r}")
        salt = f_in.read(SALT_LEN)
        iv = f_in.read(IV_LEN)
        tag = f_in.read(TAG_LEN)
        if len(salt) < SALT_LEN or len(iv) < IV_LEN or len(tag) < TAG_LEN:
            raise InvalidPoopFile("File is truncated or not a valid .poop file.")

        key = get_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag),
                           backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(MAGIC + VERSION + file_type + salt + iv)

        temp_path = output_path + ".tmp"
        try:
            with open(temp_path, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                try:
                    decryptor.finalize()
                except InvalidTag:
                    raise InvalidPoopFile("Wrong password or corrupted file.") from None
                f_out.flush()
                os.fsync(f_out.fileno())
            os.replace(temp_path, output_path)
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise
    return file_type


def _extract_zip(zip_path: str, dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    dest_root = Path(dest_dir).resolve()
    total = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                target = (dest_root / info.filename).resolve()
                if target != dest_root and dest_root not in target.parents:
                    raise InvalidPoopFile(
                        f"Archive entry escapes extraction dir: {info.filename!r}")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise InvalidPoopFile(f"Archive contains a symlink: {info.filename!r}")
                if info.file_size > MAX_EXTRACT_SIZE or total + info.file_size > MAX_EXTRACT_SIZE:
                    raise InvalidPoopFile("Archive too large to extract safely (zip bomb?).")
                total += info.file_size
                zf.extract(info, dest_dir)
    except zipfile.BadZipFile as exc:
        raise InvalidPoopFile("Decrypted payload is not a valid ZIP archive.") from exc


def encrypt_target(target_path: str, password: bytes) -> str:
    target_path = target_path.rstrip(os.sep + (os.altsep or "")) or target_path

    if not os.path.lexists(target_path):
        raise FileNotFoundError(f"No such file or directory: {target_path}")
    if os.path.islink(target_path):
        raise ValueError("Refusing to operate on symbolic links.")
    if not is_safe_path(target_path):
        raise ValueError(f"Refusing to encrypt unsafe path: {target_path}")

    is_folder = os.path.isdir(target_path)
    if is_folder:
        zip_path = shutil.make_archive(target_path, "zip", target_path)
        file_to_encrypt, file_type = zip_path, TYPE_FOLDER
    else:
        zip_path, file_to_encrypt, file_type = None, target_path, TYPE_FILE

    output_filepath = target_path + ".poop"
    try:
        process_encryption(file_to_encrypt, output_filepath, password, file_type)
    finally:
        if zip_path is not None and os.path.exists(zip_path):
            secure_delete(zip_path)

    if is_folder:
        secure_rmtree(target_path)
    else:
        secure_delete(target_path)
    return output_filepath


def decrypt_target(filepath: str, password: bytes) -> str:
    if not filepath.endswith(".poop"):
        raise InvalidPoopFile("Input must have a .poop extension.")
    if os.path.islink(filepath):
        raise ValueError("Refusing to operate on symbolic links.")
    if os.path.isdir(filepath):
        raise InvalidPoopFile("Input is a directory, not a .poop file.")
    if not is_safe_path(filepath):
        raise ValueError(f"Refusing to decrypt unsafe path: {filepath}")

    output_filepath = filepath[:-len(".poop")]
    file_type = process_decryption(filepath, output_filepath, password)

    try:
        if file_type == TYPE_FOLDER:
            if not output_filepath.endswith(".zip"):
                raise InvalidPoopFile("Folder payload did not decrypt to a .zip file.")
            extract_dir = output_filepath[:-len(".zip")]
            _extract_zip(output_filepath, extract_dir)
            secure_delete(output_filepath)
            return extract_dir
        return output_filepath
    finally:
        secure_delete(filepath)
