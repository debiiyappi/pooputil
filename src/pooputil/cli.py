"""
Copyright (C) 2026 debiiyappi <debiiyapp@gmail.com>

pooputil CLI — thin frontend over pooputil.core.

Licensed under the GNU General Public License, Version 3 (GPLv3).
You are free to copy, modify, and redistribute this software under
the terms of the license.
"""

import argparse
import getpass
import os
import sys

from pooputil import core


def _resolve_password(args) -> bytes:
    if args.password:
        return args.password.encode()
    if os.environ.get("POOPUTIL_PASSWORD"):
        return os.environ["POOPUTIL_PASSWORD"].encode()
    pw = getpass.getpass("Secret password: ")
    if args.encrypt:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return pw.encode()


def main():
    parser = argparse.ArgumentParser(description="Pooputil CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="Target path to encrypt.")
    group.add_argument("-d", "--decrypt", help="Target .poop file to decrypt.")
    parser.add_argument("-p", "--password", help="Password (optional; prompts if omitted).")
    args = parser.parse_args()

    password_bytes = _resolve_password(args)

    if args.encrypt:
        target = args.encrypt
        if not os.path.exists(target):
            print(f"Error: Target path '{target}' does not exist.")
            sys.exit(1)
        if not core.is_safe_path(target):
            print("Error: Operation rejected. Target falls within protected OS paths.")
            sys.exit(1)

        print(f"Archiving and securing: {target}...")
        try:
            output = core.encrypt_target(target, password_bytes)
            print(f"Success! Output: {output}")
        except Exception as e:
            print(f"Failure: {str(e)}")
            sys.exit(1)

    elif args.decrypt:
        target = args.decrypt
        if not os.path.exists(target) or not target.endswith(".poop"):
            print("Error: Target file must exist and feature a valid '.poop' extension.")
            sys.exit(1)

        print(f"Extracting and verifying payload integrity: {target}...")
        try:
            output = core.decrypt_target(target, password_bytes)
            print(f"Success! Restored to: {output}")
        except Exception as e:
            print(f"Decryption Failure: Incorrect password or corrupted data. Details: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()
