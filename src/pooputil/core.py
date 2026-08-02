"""  Copyright (C) 2026 debiiyappi <debiiyapp@gmail.com>
  This file is part of pooputil.
  pooputil is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by """

import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

def secure_delete(filepath: str) -> None:
    if not os.path.exists(filepath):
        return
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            chunk_size = 64 * 1024
            for _ in range(0, file_size, chunk_size):
                f.write(os.urandom(min(chunk_size, file_size - f.tell())))
    except Exception:
        pass
    finally:
        os.remove(filepath)

def secure_rmtree(dirpath: str) -> None:
    for root, dirs, files in os.walk(dirpath, topdown=False):
        for name in files:
            secure_delete(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(dirpath)

def get_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password)

def is_safe_path(target_path: str) -> bool:
    path = os.path.abspath(target_path).lower()
    if os.path.ismount(path) or path == os.path.abspath(os.sep):
        return False
    home_dir = os.path.expanduser("~").lower()
    unsafe_paths = [
        'c:\\windows', 'c:/windows', 'c:\\windows\\system32', 'c:/windows/system32',
        'c:\\program files', 'c:/program files', 'c:\\program files (x86)', 'c:/program files (x86)',
        home_dir, os.path.join(home_dir, 'documents').lower(), os.path.join(home_dir, 'videos').lower(),
        os.path.join(home_dir, 'pictures').lower(), os.path.join(home_dir, 'music').lower(),
        os.path.join(home_dir, 'desktop').lower(), os.path.join(home_dir, 'downloads').lower()
    ]
    unsafe_paths = [os.path.normpath(p) for p in unsafe_paths]
    if os.path.normpath(path) in unsafe_paths:
        return False
    return True

def process_encryption(source_path: str, output_path: str, password: bytes) -> None:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = get_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(source_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(salt)
        f_out.write(iv)
        f_out.write(b'\x00' * 16)
        while True:
            chunk = f_in.read(64 * 1024)
            if not chunk:
                break
            f_out.write(encryptor.update(chunk))
        encryptor.finalize()
        tag = encryptor.tag
        f_out.seek(28)
        f_out.write(tag)

def process_decryption(source_path: str, output_path: str, password: bytes) -> None:
    with open(source_path, "rb") as f_in:
        salt = f_in.read(16)
        iv = f_in.read(12)
        tag = f_in.read(16)
        if len(salt) < 16 or len(iv) < 12 or len(tag) < 16:
            raise ValueError("File is corrupted or not a valid .poop file.")
        key = get_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        with open(output_path, "wb") as f_out:
            while True:
                chunk = f_in.read(64 * 1024)
                if not chunk:
                    break
                f_out.write(decryptor.update(chunk))
            decryptor.finalize()

def encrypt_target(target_path: str, password: bytes) -> str:
    is_folder = os.path.isdir(target_path)
    if is_folder:
        zip_path = shutil.make_archive(target_path, 'zip', target_path)
        file_to_encrypt = zip_path
    else:
        file_to_encrypt = target_path

    output_filepath = target_path + ".poop"
    process_encryption(file_to_encrypt, output_filepath, password)

    if is_folder:
        secure_delete(zip_path)
        secure_rmtree(target_path)
    else:
        secure_delete(target_path)
    return output_filepath

def decrypt_target(filepath: str, password: bytes) -> str:
    output_filepath = filepath[:-5]
    process_decryption(filepath, output_filepath, password)
    secure_delete(filepath)

    if output_filepath.endswith(".zip"):
        extract_dir = output_filepath[:-4]
        shutil.unpack_archive(output_filepath, extract_dir)
        secure_delete(output_filepath)
        return extract_dir
    return output_filepath
