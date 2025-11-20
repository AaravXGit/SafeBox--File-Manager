# gui.py
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import account
from filemanager import add_file, list_files, open_file, delete_file
from utils import ensure_vault, TEMP_DIR
import os, shutil
import tkinter as tk
from PIL import Image, ImageDraw, ImageFont
from stegano import lsb
from tkinter import filedialog, messagebox
from filemanager import add_file
import os
import re
from tkinter import messagebox

ensure_vault()

class SafeBoxApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cosmo")  # modern theme
        self.title("SafeBox – Secure File Manager")
        self.geometry("900x600")
        self.resizable(True, True)
        self.key = None
        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 11), padding=6)

        self.create_login_frame()
        # --- AUTO LOCK FEATURE ---
        self.bind_all("<Any-KeyPress>", self.reset_timer)
        self.bind_all("<Any-Button>", self.reset_timer)
        self.reset_timer()


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
        ttk.Button(btns, text="Forgot Password?", bootstyle=WARNING, command=self.reset_vault).pack(side="left", padx=10)
        ttk.Button(btns, text="Recover using Key", command=self.recover_with_key).pack(side="left", padx=10)


    # ---------------- MAIN FRAME ----------------
    def create_main_frame(self):
        self.clear()

        header = ttk.Frame(self, padding=10)
        header.pack(fill=X)
        ttk.Label(header, text="💼 Your Encrypted Vault", font=("Segoe UI SemiBold", 18, "bold")).pack(side=LEFT)
        ttk.Button(header, text="Logout", bootstyle=DANGER, command=self.logout).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Refresh", bootstyle=SECONDARY, command=self.populate_list).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Add File", bootstyle=SUCCESS, command=self.add_file_dialog).pack(side=RIGHT, padx=5)
        ttk.Button(header, text="Show Vault", command=self.open_vault_folder).pack(side="left", padx=5)
        view_btn = ttk.Button(header, text="📜 View Logs", command=self.show_logs)
        view_btn.pack(pady=10)



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
        ttk.Button(bottom, text="Save & Re-encrypt", bootstyle=SUCCESS, command=self.save_selected).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Delete", bootstyle=WARNING, command=self.delete_selected).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Clean Temp", bootstyle=SECONDARY, command=self.clean_temp).pack(side=RIGHT, padx=5)
        ttk.Button(bottom, text="Embed", bootstyle=INFO, command=self.stego_watermark).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Verify", bootstyle=WARNING, command=self.verify_stego_watermark).pack(side=RIGHT, padx=5)



        self.populate_list()

    # ---------------- ACTIONS ----------------
    def do_register(self):
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        if not username or not pwd:
            messagebox.showerror("Error", "Enter both username and password.")
            return
        try:
            key, recovery_key = account.create_user(username, pwd)
            self.key = key


            import base64, os, hashlib
            recovery_key = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8")

            cfg = account.load_config()
            cfg["user"]["recovery_key"] = recovery_key
            cfg["user"]["recovery_key_hash"] = hashlib.sha256(recovery_key.encode()).hexdigest()
            account.save_config(cfg)
            # after recovery_key = ...
            from account import save_recovery_key_to_config
            save_recovery_key_to_config(recovery_key)



            # Create popup window (keeps open until user closes)
            popup = tk.Toplevel(self)
            popup.title("Your Recovery Key")
            popup.geometry("420x300")
            popup.configure(bg="#f4f4f4")

            ttk.Label(
            popup,
            text="🔐 Save This Recovery Key Safely!",
            font=("Segoe UI SemiBold", 13, "bold"),
            background="#f4f4f4"
            ).pack(pady=10)

            box = ttk.Entry(popup, font=("Consolas", 11), width=45)
            box.insert(0, recovery_key)
            box.config(state="readonly")
            box.pack(pady=5)

            # Copy key button
            def copy_key():
                popup.clipboard_clear()
                popup.clipboard_append(recovery_key)
                popup.update()
            
                ttk.Label(
                popup,
                text="✅ Copied to clipboard!",
                background="#f4f4f4",
                foreground="green"
                ).pack(pady=5)

            ttk.Button(popup, text="Copy Key", bootstyle=INFO, command=copy_key).pack(pady=8)

            ttk.Label(
            popup,
            text="Make sure to store it somewhere safe.",
            background="#f4f4f4",
            font=("Segoe UI", 9, "italic")
            ).pack(pady=5)

            # When popup closed → show message & open main vault
                    # When popup closed → show message & open main vault
            def on_close():
                try:
                    popup.destroy()
                except:
                    pass
            # success message and open vault
                messagebox.showinfo("Success", "User registered successfully!")
                self.create_main_frame()

        # Instead of protocol (which sometimes fails in ttkbootstrap)
        # add an explicit "Continue" button
            ttk.Button(
            popup,
            text="Continue",
            bootstyle=SUCCESS,
            command=on_close
            ).pack(pady=10)
            
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

    def save_selected(self):
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning("Select", "Select a file first.")
            return
        try:
            from filemanager import save_and_reencrypt
            save_and_reencrypt(self.key, selected)
            messagebox.showinfo("Saved", "File changes saved and re-encrypted.")
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

    def logout(self):
        self.key = None
        self.create_login_frame()
    
    def open_vault_folder(self):
        import os
        import subprocess
        import sys
        from utils import VAULT_DIR

        path = str(VAULT_DIR)

        if os.name == "nt":  # Windows
            os.startfile(path)
        elif sys.platform == "darwin":  # macOS
            subprocess.Popen(["open", path])
        else:  # Linux
            subprocess.Popen(["xdg-open", path])

    def show_logs(self):
        from tkinter import messagebox
        from logger import read_logs
        import tkinter as tk

        logs = read_logs(self.key)
        if not logs or logs == ["No logs found."]:
            messagebox.showinfo("Logs", "No logs found.")
            return

    # Create log window
        log_win = tk.Toplevel(self)
        log_win.title("Activity Logs")
        log_win.geometry("650x450")

    # Heading
        tk.Label(
        log_win,
        text="Activity Logs",
        font=("Segoe UI Semibold", 16),
        pady=10
    ).pack()

    # Scrollable text box
        frame = tk.Frame(log_win)
        frame.pack(expand=True, fill="both", padx=15, pady=10)

        txt = tk.Text(
        frame,
        wrap="word",
        font=("Consolas", 10),
        bg="#ffffff",
        fg="#1f2937",
        relief="flat"
    )
        txt.pack(side="left", expand=True, fill="both")

        scroll = tk.Scrollbar(frame, command=txt.yview)
        scroll.pack(side="right", fill="y")
        txt.config(yscrollcommand=scroll.set)

    # Add cleanly formatted logs
        for log in logs:
            txt.insert("end", log.strip() + "\n\n")

        txt.config(state="disabled")


    def reset_vault(self):
        import shutil
        from utils import VAULT_DIR, ensure_vault
        from tkinter import messagebox

        if not VAULT_DIR.exists():
            messagebox.showinfo("Info", "No existing vault found.")
            return

        confirm = messagebox.askyesno(
        "Confirm Reset",
        "This will delete your encrypted vault and all files.\nDo you want to continue?"
    )
        if confirm:
            try:
            # delete old vault
                shutil.rmtree(VAULT_DIR, ignore_errors=True)

            # recreate a fresh empty vault folder
                ensure_vault()

                messagebox.showinfo("Reset Successful", "Vault deleted. You can now register a new account.")
                self.create_login_frame()
            except Exception as e:
                messagebox.showerror("Error", f"Could not reset vault: {e}")

    def recover_with_key(self):
        from tkinter import simpledialog, messagebox
        from account import reset_password_with_recovery_key

        recovery_key = simpledialog.askstring("Recover", "Enter your recovery key:", show="*")
        if not recovery_key:
            return

        new_pwd = simpledialog.askstring("New Password", "Enter new password:", show="*")
        if not new_pwd:
            messagebox.showwarning("Input", "Password cannot be empty.")
            return

        try:
            reset_password_with_recovery_key(recovery_key, new_pwd)
            messagebox.showinfo("Success", "Password reset successfully! You can now log in with your new password.")
        except Exception as e:
            messagebox.showerror("Error", str(e))


    # ---------------- AUTO LOCK FEATURE ----------------
    def reset_timer(self, event=None):
        """Reset idle timer on any user activity"""
        if hasattr(self, 'idle_after'):
            self.after_cancel(self.idle_after)
        self.idle_after = self.after(20000, self.lock_vault)  # 1 minutes = 60000 ms

    def lock_vault(self):
        """Auto lock the vault after inactivity"""
        from tkinter import messagebox
        messagebox.showinfo("Privacy Lock", "Vault auto-locked due to inactivity.")
        self.key = None
        self.create_login_frame()


    def stego_watermark(self):
        # 1️⃣ Ask user to select file
        path = filedialog.askopenfilename(title="Select image or text file")
        if not path:
            return

        ext = path.split(".")[-1].lower()
        processed_path = path  # will update if watermark/stego applied

        try:
            if ext in ["png","jpg","jpeg"]:
                img = Image.open(path).convert("RGBA")
                W, H = img.size

                # Transparent layer
                txt_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
                draw = ImageDraw.Draw(txt_layer)

                watermark_text = "©MyVault"

                # Auto font size
                font_size = int(min(W, H) / 7)

                try:
                    font = ImageFont.truetype("arial.ttf", font_size)
                except:
                    font = ImageFont.load_default()

                color = (255, 255, 255, 140)  # more visible

                # Text size
                bbox = font.getbbox(watermark_text)
                text_w = bbox[2] - bbox[0]
                text_h = bbox[3] - bbox[1]

                # CENTER position
                x = (W - text_w) // 2
                y = (H - text_h) // 2

                draw.text((x, y), watermark_text, font=font, fill=color)

                # Diagonal rotate
                rotated = txt_layer.rotate(30, expand=1)

                # Crop back to original size
                rot_W, rot_H = rotated.size
                left = (rot_W - W) // 2
                top = (rot_H - H) // 2
                right = left + W
                bottom = top + H

                rotated_cropped = rotated.crop((left, top, right, bottom))

                # Merge
                watermarked = Image.alpha_composite(img, rotated_cropped)

                wm_path = path + "_wm.png"
                watermarked.save(wm_path)
                processed_path = wm_path


                # 3️⃣ Steganography (hidden message)
                secret_message = "HiddenOwnershipInfo"
                stego_path = path + "_stego.png"
                lsb.hide(processed_path, secret_message).save(stego_path)
                processed_path = stego_path

            elif ext == "txt":
                with open(path, "a", encoding="utf-8") as f:
                    f.write("\n©MyVault\nHiddenOwnershipInfo")
                processed_path = path
            else:
                messagebox.showwarning("Unsupported", "Only image (png/jpg/jpeg) or text files supported.")
                return

            # 4️⃣ Encrypt and add to vault
            add_file(self.key, processed_path)
            messagebox.showinfo("Success", "File processed with watermark/stego and added to vault!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to process file: {e}")



    def verify_stego_watermark(self):
        path = filedialog.askopenfilename(title="Select file to check")
        if not path:
            return

        ext = path.split(".")[-1].lower()

        try:
            if ext in ["png", "jpg", "jpeg"]:
                # Extract hidden message using steganography
                hidden = lsb.reveal(path)
                if hidden:
                    messagebox.showinfo("Stego Found ✅", f"Hidden Message:\n\n{hidden}")
                else:
                    messagebox.showwarning("No Hidden Text", "No steganography detected in image.")

            elif ext == "txt":
                # Search for watermark + hidden markers
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()

                watermark = "©MyVault"
                hidden_pattern = r"HiddenOwnershipInfo"

                found_watermark = watermark in text
                found_hidden = re.search(hidden_pattern, text) is not None

                result = []
                if found_watermark:
                    result.append("✅ Watermark detected.")
                if found_hidden:
                    result.append("✅ Hidden Ownership text detected.")

                if not result:
                    result = ["No hidden signature found."]

                messagebox.showinfo("Text Verification", "\n".join(result))

            else:
                messagebox.showwarning("Unsupported", "Only image or text files can be verified.")

        except Exception as e:
            messagebox.showerror("Error", f"Could not verify hidden text.\n\n{e}")



if __name__ == "__main__":
    app = SafeBoxApp()
    app.mainloop()
