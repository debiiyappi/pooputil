import os
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.exceptions import InvalidTag
from pooputil import core

class PooputilToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pooputil Toolkit GUI")
        self.root.geometry("550x280")
        self.root.configure(padx=20, pady=20)
        
        tk.Label(root, text="Password (Secret Key):", font=("Helvetica", 10, "bold")).pack(anchor="w")
        self.password_entry = tk.Entry(root, show="*", width=50, font=("Helvetica", 10))
        self.password_entry.pack(fill="x", pady=(0, 15))
        
        tk.Label(root, text="Select File or Folder to Encrypt/Decrypt:", font=("Helvetica", 10, "bold")).pack(anchor="w")
        file_frame = tk.Frame(root)
        file_frame.pack(fill="x", pady=(0, 15))
        
        self.path_entry = tk.Entry(file_frame, font=("Helvetica", 10))
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.browse_file_btn = tk.Button(file_frame, text="📄 File", command=self.browse_file)
        self.browse_file_btn.pack(side="left", padx=(0, 5))
        
        self.browse_folder_btn = tk.Button(file_frame, text="📁 Folder", command=self.browse_folder)
        self.browse_folder_btn.pack(side="right")
        
        btn_frame = tk.Frame(root)
        btn_frame.pack(fill="x", pady=(10, 0))
        
        self.encrypt_btn = tk.Button(btn_frame, text=" Encrypt to .poop", command=self.encrypt, bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"))
        self.encrypt_btn.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        self.decrypt_btn = tk.Button(btn_frame, text=" Decrypt from .poop", command=self.decrypt, bg="#f44336", fg="white", font=("Helvetica", 10, "bold"))
        self.decrypt_btn.pack(side="right", expand=True, fill="x", padx=(5, 0))

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, filepath)

    def browse_folder(self):
        folderpath = filedialog.askdirectory()
        if folderpath:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folderpath)

    def encrypt(self):
        password = self.password_entry.get().encode()
        target_path = self.path_entry.get().strip()
        
        if not password or not target_path:
            messagebox.showwarning("Whopsie!", "Please provide a password and target.")
            return
        if not os.path.exists(target_path):
            messagebox.showerror("Whopsie!", "File/Folder does not exist.")
            return
        if not core.is_safe_path(target_path):
            messagebox.showerror("Whopsie!", "Encrypting user/system directories is blocked.")
            return
            
        try:
            output_filepath = core.encrypt_target(target_path, password)
            messagebox.showinfo("Success", f"Encrypted and securely shredded original!\nSaved as:\n{output_filepath}")
        except Exception as e:
            messagebox.showerror("Whopsie!", f"An error occurred: {str(e)}")

    def decrypt(self):
        password = self.password_entry.get().encode()
        filepath = self.path_entry.get().strip()
        
        if not password or not filepath:
            messagebox.showwarning("Whopsie!", "Please provide a password and a file.")
            return
        if not os.path.exists(filepath) or not filepath.endswith(".poop"):
            messagebox.showwarning("Whopsie!", "Please select a valid .poop file.")
            return
            
        output_filepath = filepath[:-5]
        try:
            final_output = core.decrypt_target(filepath, password)
            messagebox.showinfo("Success", f"Decrypted successfully!\nRestored to:\n{final_output}")
        except InvalidTag:
            if os.path.exists(output_filepath):
                os.remove(output_filepath)
            messagebox.showerror("Whopsie!", "Decryption failed! Incorrect password or data tampering detected.")
        except Exception as e:
            if os.path.exists(output_filepath):
                os.remove(output_filepath)
            messagebox.showerror("Whopsie!", f"An error occurred: {str(e)}")

def main():
    root = tk.Tk()
    app = PooputilToolkitApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
