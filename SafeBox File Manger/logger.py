# logger.py
import json
from utils import LOG_FILE, ensure_vault, human_time
from encryption import encrypt_bytes, decrypt_bytes
import os

ensure_vault()

def append_log(key: bytes, entry: dict):
    # read existing (if any), append entry and write encrypted
    logs = []
    if LOG_FILE.exists():
        try:
            data = decrypt_bytes(key, LOG_FILE.read_bytes())
            logs = json.loads(data.decode("utf-8"))
        except Exception:
            logs = []
    entry["_time"] = human_time()
    logs.append(entry)
    raw = json.dumps(logs, indent=2).encode("utf-8")
    enc = encrypt_bytes(key, raw)
    with open(LOG_FILE, "wb") as f:
        f.write(enc)
