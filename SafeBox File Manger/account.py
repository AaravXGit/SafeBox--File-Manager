# account.py
import json
from pathlib import Path
from encryption import derive_key, generate_salt
from utils import CONFIG_FILE, ensure_config_exists
import base64
import os

ensure_config_exists()

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def create_user(username: str, password: str):
    cfg = load_config()
    if "user" in cfg:
        raise ValueError("User already exists")
    salt = generate_salt()
    key = derive_key(password, salt)
    # Save salt as base64 and store username
    cfg["user"] = {"username": username, "salt": base64.b64encode(salt).decode("utf-8")}
    save_config(cfg)
    # Return derived key so caller can continue
    return key

def verify_user(password: str):
    cfg = load_config()
    if "user" not in cfg:
        return None
    salt = base64.b64decode(cfg["user"]["salt"].encode("utf-8"))
    key = derive_key(password, salt)
    return key

def user_exists():
    cfg = load_config()
    return "user" in cfg
