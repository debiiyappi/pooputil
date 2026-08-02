# 💩 pooputil

Industrial-grade, memory-hard cryptographic engine and toolkit utilizing the `.poop` file extension
Other apps just hide your data. `pooputil` compresses your files, encrypts them to `.poop` containers, and then literally shreds the original files off your drive so forensic recovery tools find absolutely nothing. It is a clean, absolute wipe. My bad about the broken module imports in v0.0.1, everything flows perfectly now in v0.0.2!

Licensed under the copyleft **GNU GPLv3**. Take the source code, fork it, and build your own toolkit on top of it

---

## 🛠️ Infrastructure Core Design
`pooputil` is structured like Arduino. The foundational backend logic (**pooputil core**) is completely separated from the graphical user interface. You can import the core logic programmatically into your own automation pipelines without loading any bulk GUI dependencies.

*   **Encryption Pipeline:** AES-256-GCM (Authenticated Encryption with Associated Data). It doesnt just encrypt; it mathematically guarantees your data hasnt been tampered with.
*   **Key Derivation Function (KDF):** Scrypt. A highly specialized, memory-hard algorithm specifically engineered to resist hardware-accelerated GPU/ASIC brute-force cracking rigs.
*   **Data Sanitization:** Algorithmic zero-and-random-fill secure shredding matrix. The original file is obliterated before standard deletion.

---

## Installation

Install the compiled library binaries straight from PyPI using any system terminal pathway:


pip install pooputil


---

##  Operation

### 1. Launching the Graphical Toolkit (GUI)
If you want to use the standard desktop UI workspace panel with simple mouse clicks, execute the graphical macro shortcut:


pooputil-gui

*(Alternatively, run `python -m pooputil` to launch the exact same layout window.)*

### 2. Utilizing the CLI Engine (Command Line Interface)
Perfect for headless servers, backup tasks, cron jobs, or executing tasks inside scripting setups.

*   **To Compress, Secure, and Shred a File/Folder:**
   
    pooputil-cli --encrypt "/path/to/classified_assets" --password "SuperSecretKey99"
    
*   **To Flush and Restore from a `.poop` Payload Container:**
    
    pooputil-cli --decrypt "/path/to/classified_assets.poop" --password "SuperSecretKey99"
  

---

##  Developer Implementation API (Importing the Core)
If you are another software engineer looking to harness the heavy-lifting capabilities of the `pooputil` ecosystem inside your custom scripts, tap directly into our exposed library endpoints:


from pooputil import core

secret_password = b"PremiumDevPass123"
target_item = "./confidential_payroll.csv"

# Verify path bounds to prevent bricking system directories
if core.is_safe_path(target_item):
    print("Path verified. Commencing data digestion...")
    

else:
    print("Operation rejected! Target path falls inside restricted system pathways.")


To reconstruct a `.poop` payload container back to its raw file or unpacked folder state:

from pooputil import core

restored_path = core.decrypt_target("./confidential_payroll.csv.poop", b"PremiumDevPass123")
print(f"Data verification passed. Restored to: {restored_path}")
