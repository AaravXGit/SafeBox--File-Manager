#logger.py
import json
from utils import LOG_FILE, ensure_vault, human_time
from encryption import encrypt_bytes, decrypt_bytes

ensure_vault()

def append_log(key: bytes, entry: dict):
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

def read_logs(key: bytes):
    if not LOG_FILE.exists():
        return ["No logs found."]
    try:
        data = decrypt_bytes(key, LOG_FILE.read_bytes())
        text = data.decode("utf-8")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return lines if lines else ["No log entries yet."]
    except Exception as e:
        return [f"Error reading logs: {e}"]

def log_edit_action(key: bytes, filename: str, message: str = "File edited", details: dict = None):
    logs = []
    if LOG_FILE.exists():
        try:
            data = decrypt_bytes(key, LOG_FILE.read_bytes())
            logs = json.loads(data.decode("utf-8"))
        except Exception:
            logs = []
    entry = {
        "action": "edit",
        "file": filename,
        "details": message,
        "_time": human_time()
    }
    if details:
        entry["changes"] = details
    logs.append(entry)
    enc = encrypt_bytes(key, json.dumps(logs, indent=2).encode())
    with open(LOG_FILE, "wb") as f:
        f.write(enc)
