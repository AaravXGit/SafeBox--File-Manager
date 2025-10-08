# gui.py
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import account
from filemanager import add_file, list_files, open_file, delete_file
from utils import ensure_vault, TEMP_DIR
import os, shutil

ensure_vault()

class SafeBoxApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cosmo")  # modern theme
        self.title("SafeBox – Secure File Manager")
        self.geometry("900x600")
        self.resizable(True, True)
        self.key = None
        self.appstyle = ttk.Style()
        self.appstyle.configure("TButton", font=("Segoe UI", 11), padding=6)
        self.create_login_frame()

    def clear(self):
        for child in self.winfo_children():
            child.destroy()

    # ---------------- LOGIN FRAME ----------------
    def create_login_frame(self):
        self.clear()
        frame = ttk.Frame(self, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="🔒 SafeBox Login / Register", font=("Segoe UI", 18, "bold")).pack(pady=20)
        ttk.Label(frame, text="Username", font=("Segoe UI", 12)).pack(anchor="w")
        self.username_entry = ttk.Entry(frame, font=("Segoe UI", 12), width=30)
        self.username_entry.pack(pady=5)

        ttk.Label(frame, text="Password", font=("Segoe UI", 12)).pack(anchor="w")
        self.password_entry = ttk.Entry(frame, font=("Segoe UI", 12), show="*", width=30)
        self.password_entry.pack(pady=5)

        btns = ttk.Frame(frame)
        btns.pack(pady=20)
        ttk.Button(btns, text="Login", bootstyle=SUCCESS, command=self.do_login).pack(side="left", padx=10)
        ttk.Button(btns, text="Register", bootstyle=INFO, command=self.do_register).pack(side="left", padx=10)
        ttk.Button(btns, text="Forgot Password", command=self.reset_vault).pack(side="left", padx=10)

    # ---------------- MAIN FRAME ----------------
    def create_main_frame(self):
        self.clear()

        header = ttk.Frame(self, padding=10)
        header.pack(fill=X)
        ttk.Label(header, text="🗂️ Your Encrypted Vault", font=("Segoe UI", 16, "bold")).pack(side=LEFT)
        ttk.Button(header, text="Logout", bootstyle=DANGER, command=self.logout).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Refresh", bootstyle=SECONDARY, command=self.populate_list).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Add File", bootstyle=SUCCESS, command=self.add_file_dialog).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Show Vault", command=self.open_vault_folder).pack(side=RIGHT, padx=5)

        # Treeview
        self.tree = ttk.Treeview(self, columns=("orig", "added"), show="headings", bootstyle=INFO)
        self.tree.heading("orig", text="Original Name")
        self.tree.heading("added", text="Added At")
        self.tree.column("orig", width=400)
        self.tree.column("added", width=300)
        self.tree.pack(fill=BOTH, expand=True, padx=20, pady=20)
        self.tree.bind("<Double-1>", self.open_selected)

        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill=X)
        ttk.Button(bottom, text="Open", bootstyle=PRIMARY, command=self.open_selected).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Delete", bootstyle=WARNING, command=self.delete_selected).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Clean Temp", bootstyle=SECONDARY, command=self.clean_temp).pack(side=RIGHT, padx=5)

        self.populate_list()

    # ---------------- ACTIONS ----------------
    def do_register(self):
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        if not username or not pwd:
            messagebox.showerror("Error", "Enter both username and password.")
            return
        try:
            key = account.create_user(username, pwd)
            self.key = key
            messagebox.showinfo("Success", "User registered successfully!")
            self.create_main_frame()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_login(self):
        pwd = self.password_entry.get().strip()
        if not pwd:
            messagebox.showerror("Error", "Enter password.")
            return
        key = account.verify_user(pwd)
        if key is None:
            messagebox.showerror("Error", "No user found. Please register first.")
            return
        self.key = key
        messagebox.showinfo("Success", "Logged in successfully!")
        self.create_main_frame()

    def populate_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        try:
            files = list_files(self.key)
            for masked, orig, added in files:
                self.tree.insert("", "end", iid=masked, values=(orig, added))
        except Exception as e:
            messagebox.showerror("Error", f"Could not list files: {e}")

    def add_file_dialog(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            add_file(self.key, path)
            messagebox.showinfo("Added", "File added to vault (encrypted).")
            self.populate_list()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def get_selected(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def open_selected(self, event=None):
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning("Select", "Select a file first.")
            return
        try:
            filepath = open_file(self.key, selected)
            messagebox.showinfo("Opened", f"File opened: {filepath}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_selected(self):
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning("Select", "Select a file first.")
            return
        if not messagebox.askyesno("Confirm", "Delete this file from vault?"):
            return
        try:
            delete_file(self.key, selected)
            messagebox.showinfo("Deleted", "File deleted successfully.")
            self.populate_list()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clean_temp(self):
        try:
            if TEMP_DIR.exists():
                for p in TEMP_DIR.iterdir():
                    if p.is_file():
                        p.unlink()
                    else:
                        shutil.rmtree(p, ignore_errors=True)
                messagebox.showinfo("Cleaned", "Temporary files cleaned.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_vault_folder(self):
        import os, subprocess, sys
        from utils import VAULT_DIR
        path = str(VAULT_DIR)
        if os.name == "nt":
            os.startfile(path)

    def reset_vault(self):
        import shutil
        from utils import VAULT_DIR
        from tkinter import messagebox

        if not VAULT_DIR.exists():
            messagebox.showinfo("Info", "No existing vault to reset")
            return
        confirm = messagebox.askyesno("Confirm Reset", "This will permanently delete your existing vault and all files.\nDo you want to continue?")
        
        if confirm:
            try:
                shutil.rmtree(VAULT_DIR, ignore_errors=True)
                messagebox.showinfo("Reset Successful", "Vault deleted. You can now register a new account")
                self.create_login_frame()
            except Exception as e:
                messagebox.showerror("Error", f"Could not reset vault: {e}")
                
    def logout(self):
        self.key = None
        self.create_login_frame()


if __name__ == "__main__":
    app = SafeBoxApp()
    app.mainloop()

