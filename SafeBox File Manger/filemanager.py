# filemanager.py
import os
from utils import VAULT_DIR, ensure_vault, mask_filename, METADATA_FILE, TEMP_DIR, compress_file_to_bytes, TEMP_DIR
from encryption import encrypt_bytes, decrypt_bytes
import json
from pathlib import Path
import shutil
from logger import append_log

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
    if not os.path.exists(src_path):
        raise FileNotFoundError(src_path)
    compressed = compress_file_to_bytes(src_path)
    masked = mask_filename(os.path.basename(src_path))
    out_path = VAULT_DIR / masked
    enc = encrypt_bytes(key, compressed)
    with open(out_path, "wb") as f:
        f.write(enc)
    metadata = _read_metadata(key)
    metadata[masked] = {
        "original_name": os.path.basename(src_path),
        "added_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "size": len(compressed)
    }
    _write_metadata(key, metadata)
    append_log(key, {"action": "add", "file": os.path.basename(src_path)})

def list_files(key: bytes):
    metadata = _read_metadata(key)
    # return list of (masked, original_name)
    return [(m, metadata[m]["original_name"], metadata[m]["added_at"]) for m in metadata]

def open_file(key: bytes, masked_name: str):
    vault_path = VAULT_DIR / masked_name
    if not vault_path.exists():
        raise FileNotFoundError(masked_name)
    data = decrypt_bytes(key, vault_path.read_bytes())
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
