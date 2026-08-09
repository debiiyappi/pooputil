"""
Copyright (C) 2026 debiiyappi <debiiyapp@gmail.com>

Licensed under the GNU General Public License, Version 3 (GPLv3).
You are free to copy, modify, and redistribute this software under
the terms of the license.
"""

import hashlib
import json
import os
import shutil
import stat
import struct
import zipfile
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"POOP"
VERSION_V1 = 1
VERSION_V2 = 2
TYPE_FILE = 0
TYPE_FOLDER = 1
COMPRESS_RAW_DEFLATE = 1

SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
V1_HEADER = len(MAGIC) + 1 + 1 + SALT_LEN + IV_LEN
V2_HEADER = len(MAGIC) + 1 + 1 + 1 + 3 + SALT_LEN + IV_LEN
V2_TAG_OFFSET = V2_HEADER

KDF_LOG_N = 17
KDF_R = 8
KDF_P = 1
LEGACY_PARAMS = (14, 8, 1)

CHUNK_SIZE = 64 * 1024
COMPRESS_LEVEL = 6


class InvalidPoopFile(Exception):
    pass


def get_key(password: bytes, salt: bytes,
            log_n: int = KDF_LOG_N, r: int = KDF_R, p: int = KDF_P) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=1 << log_n, r=r, p=p,
                          maxmem=512 * 1024 * 1024, dklen=32)


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
            Path("/var"), Path("/tmp"), Path("/opt"),
        ]
    for p in protected:
        if path == p or p in path.parents:
            return False
    return True


def _open_read_nofollow(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


def _open_exclusive_temp(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, 0o600)


def _read_exact(f_in, n, what):
    data = f_in.read(n)
    if len(data) != n:
        raise InvalidPoopFile(f"File truncated reading {what}.")
    return data


def secure_delete(path: str) -> None:
    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as f:
            remaining = size
            while remaining:
                n = min(CHUNK_SIZE, remaining)
                f.write(b"\x00" * n)
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def secure_rmtree(path: str) -> None:
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            secure_delete(os.path.join(root, name))
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass


def _build_header_v2(file_type, salt, iv, log_n, r, p):
    return (MAGIC + bytes([VERSION_V2, file_type, COMPRESS_RAW_DEFLATE,
                           log_n, r, p]) + salt + iv)


def _read_header(f_in):
    magic = _read_exact(f_in, 4, "magic")
    if magic != MAGIC:
        raise InvalidPoopFile("Not a .poop file (bad magic).")
    version = _read_exact(f_in, 1, "version")[0]
    if version == VERSION_V1:
        head = _read_exact(f_in, V1_HEADER - 5, "header")
        aad = magic + bytes([version]) + head
        tag = _read_exact(f_in, TAG_LEN, "tag")
        return (version, head[0], LEGACY_PARAMS,
                head[1:17], head[17:29], tag, aad)
    if version == VERSION_V2:
        head = _read_exact(f_in, V2_HEADER - 5, "header")
        aad = magic + bytes([version]) + head
        if head[1] != COMPRESS_RAW_DEFLATE:
            raise InvalidPoopFile(f"Unsupported compression method: {head[1]}")
        params = (head[2], head[3], head[4])
        tag = _read_exact(f_in, TAG_LEN, "tag")
        return (version, head[0], params,
                head[5:21], head[21:33], tag, aad)
    raise InvalidPoopFile(f"Unsupported .poop version: {version!r}")


def _peek_header(path):
    with os.fdopen(_open_read_nofollow(path), "rb") as f:
        magic = _read_exact(f, 4, "magic")
        if magic != MAGIC:
            raise InvalidPoopFile("Not a .poop file (bad magic).")
        version = _read_exact(f, 1, "version")[0]
        file_type = _read_exact(f, 1, "type")[0]
        return version, file_type


def _stream_deflate_encrypt(f_in, f_out, encryptor):
    comp = zlib.compressobj(level=COMPRESS_LEVEL, wbits=-15)
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if not chunk:
            break
        out = comp.compress(chunk)
        if out:
            f_out.write(encryptor.update(out))
    out = comp.flush()
    if out:
        f_out.write(encryptor.update(out))


def _process_encryption_file(source_path, output_path, password,
                             log_n=KDF_LOG_N, r=KDF_R, p=KDF_P):
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    header = _build_header_v2(TYPE_FILE, salt, iv, log_n, r, p)
    key = get_key(password, salt, log_n, r, p)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(header)
    temp_path = output_path + ".tmp"
    created = False
    try:
        fd = _open_exclusive_temp(temp_path)
        created = True
        with os.fdopen(fd, "wb") as f_out:
            f_out.write(header + b"\x00" * TAG_LEN)
            with os.fdopen(_open_read_nofollow(source_path), "rb") as f_in:
                _stream_deflate_encrypt(f_in, f_out, encryptor)
            encryptor.finalize()
            f_out.seek(V2_TAG_OFFSET)
            f_out.write(encryptor.tag)
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(temp_path, output_path)
    except Exception:
        if created:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise


def _folder_entries(root):
    base = Path(root).resolve()
    entries = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                continue
            rel = str(p.relative_to(base)).replace(os.sep, "/")
            entries.append({"name": rel, "size": st.st_size,
                            "mtime_ns": st.st_mtime_ns,
                            "mode": st.st_mode & 0o777})
    return entries


def _process_encryption_folder(dir_path, output_path, password,
                               log_n=KDF_LOG_N, r=KDF_R, p=KDF_P):
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    header = _build_header_v2(TYPE_FOLDER, salt, iv, log_n, r, p)
    key = get_key(password, salt, log_n, r, p)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(header)
    entries = _folder_entries(dir_path)
    manifest = json.dumps(entries, separators=(",", ":")).encode()
    temp_path = output_path + ".tmp"
    created = False
    try:
        fd = _open_exclusive_temp(temp_path)
        created = True
        base = Path(dir_path).resolve()
        with os.fdopen(fd, "wb") as f_out:
            f_out.write(header + b"\x00" * TAG_LEN)
            f_out.write(encryptor.update(struct.pack("<I", len(manifest))))
            f_out.write(encryptor.update(manifest))
            for entry in entries:
                src = base.joinpath(*entry["name"].split("/"))
                comp = zlib.compressobj(level=COMPRESS_LEVEL, wbits=-15)
                with open(src, "rb") as f_in:
                    while True:
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        out = comp.compress(chunk)
                        if out:
                            f_out.write(encryptor.update(out))
                out = comp.flush()
                if out:
                    f_out.write(encryptor.update(out))
            encryptor.finalize()
            f_out.seek(V2_TAG_OFFSET)
            f_out.write(encryptor.tag)
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(temp_path, output_path)
    except Exception:
        if created:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise


class _PlainReader:
    def __init__(self, f_in, decryptor):
        self.f_in = f_in
        self.decryptor = decryptor
        self.pending = b""

    def read(self, n):
        while len(self.pending) < n:
            chunk = self.f_in.read(CHUNK_SIZE)
            if not chunk:
                return self.pending[:n] or None
            self.pending += self.decryptor.update(chunk)
        out, self.pending = self.pending[:n], self.pending[n:]
        return out

    def read_exact(self, n, what):
        out = self.read(n)
        if out is None or len(out) < n:
            raise InvalidPoopFile(f"File truncated reading {what}.")
        return out

    def feed_entry(self, decompressor, f_out):
        consumed = 0
        while True:
            if self.pending:
                consumed += len(self.pending)
                out = decompressor.decompress(self.pending)
                self.pending = decompressor.unused_data
                if out:
                    f_out.write(out)
            if decompressor.eof:
                return consumed - len(self.pending)
            chunk = self.f_in.read(CHUNK_SIZE)
            if not chunk:
                raise InvalidPoopFile("File truncated inside compressed entry.")
            self.pending += self.decryptor.update(chunk)


def _validate_manifest(manifest, dest_root):
    if not isinstance(manifest, list):
        raise InvalidPoopFile("Manifest is not a list.")
    for entry in manifest:
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise InvalidPoopFile("Manifest entry missing name.")
        if any(part in ("..", "", ".") for part in Path(name).parts):
            raise InvalidPoopFile(f"Unsafe manifest path: {name!r}")
        target = (dest_root / name).resolve()
        if target != dest_root and dest_root not in target.parents:
            raise InvalidPoopFile(f"Entry escapes extraction dir: {name!r}")
        size = entry.get("size", 0)
        if not isinstance(size, int) or size < 0:
            raise InvalidPoopFile(f"Bad size in manifest for {name!r}")


def _process_decryption_file(source_path, output_path, password):
    with os.fdopen(_open_read_nofollow(source_path), "rb") as f_in:
        version, file_type, params, salt, iv, tag, aad = _read_header(f_in)
        if file_type != TYPE_FILE:
            raise InvalidPoopFile("Container type changed between header and payload.")
        key = get_key(password, salt, *params)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(aad)
        temp = output_path + ".tmp"
        created = False
        try:
            fd = _open_exclusive_temp(temp)
            created = True
            with os.fdopen(fd, "wb") as f_out:
                if version == VERSION_V1:
                    while True:
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                    try:
                        decryptor.finalize()
                    except InvalidTag:
                        raise InvalidPoopFile(
                            "Wrong password or corrupted file.") from None
                else:
                    reader = _PlainReader(f_in, decryptor)
                    d = zlib.decompressobj(wbits=-15)
                    reader.feed_entry(d, f_out)
                    while True:
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                    try:
                        decryptor.finalize()
                    except InvalidTag:
                        raise InvalidPoopFile(
                            "Wrong password or corrupted file.") from None
                f_out.flush()
                os.fsync(f_out.fileno())
            os.replace(temp, output_path)
        except Exception:
            if created:
                try:
                    os.remove(temp)
                except OSError:
                    pass
            raise


def _legacy_extract_zip(zip_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    dest_root = Path(dest_dir).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            target = (dest_root / info.filename).resolve()
            if target != dest_root and dest_root not in target.parents:
                raise InvalidPoopFile(
                    f"Archive entry escapes extraction dir: {info.filename!r}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise InvalidPoopFile("Archive contains a symlink.")
            zf.extract(info, dest_dir)


def _process_decryption_legacy_folder(source_path, dest_dir, password):
    zip_path = dest_dir.rstrip(os.sep) + ".legacy.zip"
    with os.fdopen(_open_read_nofollow(source_path), "rb") as f_in:
        version, file_type, params, salt, iv, tag, aad = _read_header(f_in)
        key = get_key(password, salt, *params)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(aad)
        temp = zip_path + ".tmp"
        created = False
        try:
            fd = _open_exclusive_temp(temp)
            created = True
            with os.fdopen(fd, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                try:
                    decryptor.finalize()
                except InvalidTag:
                    raise InvalidPoopFile(
                        "Wrong password or corrupted file.") from None
                f_out.flush()
                os.fsync(f_out.fileno())
            os.replace(temp, zip_path)
        except Exception:
            if created:
                try:
                    os.remove(temp)
                except OSError:
                    pass
            raise
    try:
        _legacy_extract_zip(zip_path, dest_dir)
    finally:
        secure_delete(zip_path)


def _process_decryption_folder(source_path, dest_dir, password):
    version, file_type = _peek_header(source_path)
    if file_type != TYPE_FOLDER:
        raise InvalidPoopFile("Container is not a folder container.")
    if version == VERSION_V1:
        _process_decryption_legacy_folder(source_path, dest_dir, password)
        return

    with os.fdopen(_open_read_nofollow(source_path), "rb") as f_in:
        version, file_type, params, salt, iv, tag, aad = _read_header(f_in)
        key = get_key(password, salt, *params)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(aad)
        reader = _PlainReader(f_in, decryptor)
        manifest_len = struct.unpack("<I", reader.read_exact(4, "manifest length"))[0]
        manifest = json.loads(reader.read_exact(manifest_len, "manifest"))
        dest_root = Path(dest_dir).resolve()
        _validate_manifest(manifest, dest_root)
        os.makedirs(dest_dir, exist_ok=True)
        try:
            for entry in manifest:
                target = dest_root.joinpath(*entry["name"].split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                d = zlib.decompressobj(wbits=-15)
                with open(target, "wb") as f_out:
                    reader.feed_entry(d, f_out)
                if "mtime_ns" in entry:
                    os.utime(target, ns=(entry["mtime_ns"], entry["mtime_ns"]))
                if "mode" in entry:
                    try:
                        os.chmod(target, entry["mode"] & 0o777)
                    except OSError:
                        pass
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                decryptor.update(chunk)
            try:
                decryptor.finalize()
            except InvalidTag:
                raise InvalidPoopFile("Wrong password or corrupted file.") from None
        except Exception:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise


def encrypt_target(target_path: str, password: bytes, force: bool = False) -> str:
    target_path = target_path.rstrip(os.sep + (os.altsep or "")) or target_path
    if not os.path.lexists(target_path):
        raise FileNotFoundError(f"No such file or directory: {target_path}")
    if os.path.islink(target_path):
        raise ValueError("Refusing to operate on symbolic links.")
    if not is_safe_path(target_path):
        raise ValueError(f"Refusing to encrypt unsafe path: {target_path}")

    output_filepath = target_path + ".poop"
    if os.path.lexists(output_filepath) and not force:
        raise FileExistsError(
            f"Refusing to overwrite existing file: {output_filepath} "
            "(pass force=True to overwrite it)")

    if os.path.isdir(target_path):
        _process_encryption_folder(target_path, output_filepath, password)
        secure_rmtree(target_path)
    else:
        _process_encryption_file(target_path, output_filepath, password)
        secure_delete(target_path)
    return output_filepath


def decrypt_target(filepath: str, password: bytes, force: bool = False) -> str:
    if not filepath.endswith(".poop"):
        raise InvalidPoopFile("Input must have a .poop extension.")
    if os.path.islink(filepath):
        raise ValueError("Refusing to operate on symbolic links.")
    if os.path.isdir(filepath):
        raise InvalidPoopFile("Input is a directory, not a .poop file.")
    if not is_safe_path(filepath):
        raise ValueError(f"Refusing to decrypt unsafe path: {filepath}")

    output_filepath = filepath[:-len(".poop")]
    if os.path.lexists(output_filepath) and not force:
        raise FileExistsError(
            f"Refusing to overwrite existing file: {output_filepath} "
            "(pass force=True to overwrite it)")

    version, file_type = _peek_header(filepath)
    if file_type == TYPE_FOLDER:
        _process_decryption_folder(filepath, output_filepath, password)
    else:
        _process_decryption_file(filepath, output_filepath, password)
    secure_delete(filepath)
    return output_filepath
