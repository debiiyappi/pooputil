import sys
import argparse
import os
import core

def main():
    parser = argparse.ArgumentParser(description="Pooputil CLI - Core Hardware Cryptographic Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="Target path of the file/folder to encrypt.")
    group.add_argument("-d", "--decrypt", help="Target path of the .poop file to decrypt.")
    parser.add_argument("-p", "--password", required=True, help="Secret password string.")

    args = parser.parse_args()
    password_bytes = args.password.encode()

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
