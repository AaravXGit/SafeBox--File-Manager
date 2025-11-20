# account.py 
import json 
import os
import base64
import hashlib
from pathlib import Path
from encryption import derive_key, generate_salt
from utils import CONFIG_FILE, ensure_config_exists, ensure_vault

# Ensure config file exists
ensure_config_exists()


# ---------------- BASIC USER FUNCTIONS ----------------

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def create_user(username: str, password: str):
    """
    Creates a new user, derives encryption key, and also generates recovery key.
    """
    cfg = load_config()
    if "user" in cfg:
        raise ValueError("User already exists")

    # Generate salt + key
    salt = generate_salt()
    key = derive_key(password, salt)

    # Generate recovery key
    recovery_key = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8")
    recovery_hash = hashlib.sha256(recovery_key.encode()).hexdigest()

    # Save all details together
    cfg["user"] = {
        "username": username,
        "salt": base64.b64encode(salt).decode("utf-8"),
    }
    cfg["recovery_key_hash"] = recovery_hash

    save_config(cfg)

    # Return derived key + recovery key so GUI can show to user
    return key, recovery_key


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


# ---------------- RECOVERY SYSTEM ----------------

import hashlib, base64, os
from utils import CONFIG_FILE, ensure_vault

def save_recovery_key_to_config(recovery_key: str):
    """Store recovery key hash in config."""
    ensure_vault()
    key_hash = hashlib.sha256(recovery_key.encode()).hexdigest()

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
    else:
        cfg = {}

    if "user" not in cfg:
        raise ValueError("User not found in config.")

    cfg["user"]["recovery_key_hash"] = key_hash
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def reset_password_with_recovery_key(recovery_key: str, new_password: str):
    """Verify recovery key and reset password if correct."""
    if not CONFIG_FILE.exists():
        raise ValueError("Vault not initialized.")

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    user = config.get("user", {})
    stored_hash = user.get("recovery_key_hash")

    if not stored_hash:
        raise ValueError("Recovery key not set for this vault.")

    if hashlib.sha256(recovery_key.encode()).hexdigest() != stored_hash:
        raise ValueError("Invalid recovery key.")

    # Update password (rederive salt + new key)
    from encryption import generate_salt, derive_key
    salt = generate_salt()
    key = derive_key(new_password, salt)
    user["salt"] = base64.b64encode(salt).decode("utf-8")

    config["user"] = user
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


    # Delete all old encrypted files (they can't be decrypted with new key)
    from utils import VAULT_DIR
    import shutil

    if VAULT_DIR.exists():
        for f in VAULT_DIR.iterdir():
            if f.is_file() and f.suffix.endswith(".enc"):
                try:
                    f.unlink()
                except Exception:
                    pass

    return key


