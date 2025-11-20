# utils.py
import os
import json
import pathlib
import uuid
import tempfile
from datetime import datetime
from zipfile import ZipFile

HOME = pathlib.Path.home()
VAULT_DIR = HOME / ".safe_vault"
CONFIG_FILE = VAULT_DIR / "config.json"
METADATA_FILE = VAULT_DIR / "metadata.json.enc"  # encrypted
LOG_FILE = VAULT_DIR / "actions.log.enc"  # encrypted log
TEMP_DIR = VAULT_DIR / ".temp"

def ensure_vault():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    # config.json left for account module to initialize

def mask_filename(original_name: str) -> str:
    return str(uuid.uuid4())

def human_time():
    return datetime.utcnow().isoformat() + "Z"

def compress_file_to_bytes(file_path: str) -> bytes:
    # create a zip in memory (temp file) containing the file at root
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    try:
        with ZipFile(temp_zip.name, 'w') as zf:
            zf.write(file_path, arcname=os.path.basename(file_path))
        with open(temp_zip.name, "rb") as f:
            data = f.read()
        return data
    finally:
        try:
            os.unlink(temp_zip.name)
        except Exception:
            pass

def ensure_config_exists():
    ensure_vault()
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w") as f:
            json.dump({}, f)


# --- Ask user for encryption/decryption key ---
import tkinter as tk
from tkinter import simpledialog

def ask_key(prompt="Enter key:"):
    root = tk.Tk()
    root.withdraw()  # hide main window
    key = simpledialog.askstring("Security", prompt, show="*")
    root.destroy()
    return key


def compression_stats(file_path, compressed_data):
    import os
    original_size = os.path.getsize(file_path)
    compressed_size = len(compressed_data)
    saved = ((original_size - compressed_size) / original_size) * 100 if original_size != 0 else 0

    return {
        "original_size": original_size,
        "compressed_size": compressed_size,
        "saved_percent": round(saved, 2)
    }
