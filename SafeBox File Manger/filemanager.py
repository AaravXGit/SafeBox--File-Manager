# filemanager.py
import os
from utils import VAULT_DIR, ensure_vault, mask_filename, METADATA_FILE, TEMP_DIR, compress_file_to_bytes, TEMP_DIR
from encryption import encrypt_bytes, decrypt_bytes
import json
from pathlib import Path
import shutil
from logger import append_log
from utils import compression_stats
from tkinter import messagebox



ensure_vault()

def _read_metadata(key: bytes):
    if not METADATA_FILE.exists():
        return {}
    data = decrypt_bytes(key, METADATA_FILE.read_bytes())
    return json.loads(data.decode("utf-8"))

def _write_metadata(key: bytes, metadata: dict):
    raw = json.dumps(metadata, indent=2).encode("utf-8")
    enc = encrypt_bytes(key, raw)
    with open(METADATA_FILE, "wb") as f:
        f.write(enc)

def add_file(key: bytes, src_path: str):
    src_path = str(src_path)

    from utils import ask_key
    from encryption import derive_key, generate_salt
    import base64

    # ask user for encryption key
    user_key = ask_key("Enter encryption key for this file:")
    if not user_key:
        raise Exception("No key provided.")

    # generate salt and derive key from user input
    salt = generate_salt()
    derived_key = derive_key(user_key, salt)

    if not os.path.exists(src_path):
        raise FileNotFoundError(src_path)
    compressed = compress_file_to_bytes(src_path)
    stats = compression_stats(src_path, compressed)
    messagebox.showinfo("Compression Stats",
    f"Original: {stats['original_size']} bytes\n"
    f"Compressed: {stats['compressed_size']} bytes\n"
    f"Saved: {stats['saved_percent']}%"
    )

    masked = mask_filename(os.path.basename(src_path))
    out_path = VAULT_DIR / masked
    enc = encrypt_bytes(derived_key, compressed)

    with open(out_path, "wb") as f:
        f.write(enc)
    metadata = _read_metadata(key)
    
    metadata[masked] = {
    "original_name": os.path.basename(src_path),
    "added_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    "size": len(compressed),
    "salt": base64.b64encode(salt).decode()
}

    _write_metadata(key, metadata)
    append_log(key, {"action": "add", "file": os.path.basename(src_path)})

def list_files(key: bytes):
    metadata = _read_metadata(key)
    # return list of (masked, original_name)
    return [(m, metadata[m]["original_name"], metadata[m]["added_at"]) for m in metadata]

def open_file(key: bytes, masked_name: str):
    from utils import ask_key
    from encryption import derive_key
    import base64

     # ask user for the key used during encryption
    user_key = ask_key("Enter key to decrypt this file:")
    if not user_key:
        raise Exception("No key provided.")

    # read the metadata to get the salt used when encrypting this file
    metadata = _read_metadata(key)
    salt_b64 = metadata[masked_name].get("salt")
    if not salt_b64:
        raise Exception("Salt not found for this file.")

    # convert the stored salt back to bytes and derive the AES key
    salt = base64.b64decode(salt_b64)
    derived_key = derive_key(user_key, salt)


    vault_path = VAULT_DIR / masked_name
    if not vault_path.exists():
        raise FileNotFoundError(masked_name)
        
    data = decrypt_bytes(derived_key, vault_path.read_bytes())

    # write to temp file as a zip, then extract to temp dir and open the file
    temp_zip = TEMP_DIR / f"{masked_name}.zip"
    with open(temp_zip, "wb") as f:
        f.write(data)
    # extract
    extract_dir = TEMP_DIR / masked_name
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    import zipfile
    with zipfile.ZipFile(temp_zip, "r") as zf:
        zf.extractall(extract_dir)
    # open first file found
    files = list(extract_dir.glob("*"))
    if not files:
        raise FileNotFoundError("No files inside zip")
    file_to_open = str(files[0])
    # platform open
    if os.name == "nt":
        os.startfile(file_to_open)
    else:
        import subprocess, sys
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.Popen([opener, file_to_open])
    append_log(key, {"action": "open", "file": masked_name})
    return file_to_open

def delete_file(key: bytes, masked_name: str):
    vault_path = VAULT_DIR / masked_name
    if vault_path.exists():
        vault_path.unlink()
    metadata = _read_metadata(key)
    if masked_name in metadata:
        orig = metadata[masked_name]["original_name"]
        del metadata[masked_name]
        _write_metadata(key, metadata)
        append_log(key, {"action": "delete", "file": orig})


def save_and_reencrypt(key: bytes, masked_name: str):
    import difflib, base64
    from encryption import derive_key, encrypt_bytes, decrypt_bytes
    from utils import TEMP_DIR, VAULT_DIR
    from logger import log_edit_action

    vault_path = VAULT_DIR / masked_name
    temp_dir = TEMP_DIR / masked_name
    if not vault_path.exists():
        raise FileNotFoundError("Encrypted vault file not found.")
    if not temp_dir.exists():
        raise FileNotFoundError("Edited temp file not found.")

    # --- Load metadata to get the salt ---
    from utils import METADATA_FILE
    import json
    metadata_raw = decrypt_bytes(key, METADATA_FILE.read_bytes())
    metadata = json.loads(metadata_raw.decode("utf-8"))
    entry = metadata.get(masked_name)
    if not entry:
        raise Exception("Metadata entry not found.")
    salt = base64.b64decode(entry["salt"])

    from utils import ask_key
    user_key = ask_key("Enter same encryption key used for this file:")
    if not user_key:
        raise Exception("No key provided.")
    derived_key = derive_key(user_key, salt)

    # --- Read the original (old) decrypted text for diff ---
    import tempfile, zipfile, os
    old_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    old_zip.write(decrypt_bytes(derived_key, vault_path.read_bytes()))
    old_zip.close()

    old_text = ""
    with zipfile.ZipFile(old_zip.name, "r") as zf:
        for name in zf.namelist():
            with zf.open(name) as f:
                old_text = f.read().decode(errors="ignore")

    os.unlink(old_zip.name)

    # --- Read the new edited text ---
    new_file = list(temp_dir.glob("*.txt"))
    if not new_file:
        raise Exception("Edited temp .txt file not found.")
    new_text = new_file[0].read_text(errors="ignore")

    # --- Compare old vs new ---
    diff = list(difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(), lineterm=""
    ))

    added_lines = [line for line in diff if line.startswith("+") and not line.startswith("+++")]
    removed_lines = [line for line in diff if line.startswith("-") and not line.startswith("---")]

    if not added_lines and not removed_lines:
        msg = "No content changes detected."
    else:
        msg = f"Changes detected. {len(added_lines)} added, {len(removed_lines)} removed."

    # --- Recompress new file and re-encrypt ---
    from utils import compress_file_to_bytes
    compressed = compress_file_to_bytes(str(new_file[0]))
    enc = encrypt_bytes(derived_key, compressed)
    with open(vault_path, "wb") as f:
        f.write(enc)

    # --- Log the change ---
    log_edit_action(key, entry["original_name"], msg, {
        "added": added_lines,
        "removed": removed_lines
    })

