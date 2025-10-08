# encryption.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os
import base64

# Parameters
KEY_LEN = 32  # AES-256
SALT_LEN = 16
PBKDF2_ITERS = 200_000
NONCE_LEN = 12  # recommended for GCM

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode("utf-8"), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def generate_salt() -> bytes:
    return get_random_bytes(SALT_LEN)

def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # store as: nonce + tag + ciphertext
    return nonce + tag + ciphertext

def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:NONCE_LEN]
    tag = blob[NONCE_LEN:NONCE_LEN+16]
    ciphertext = blob[NONCE_LEN+16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# helpers for file io
def encrypt_file_to_path(key: bytes, data: bytes, out_path: str):
    with open(out_path, "wb") as f:
        f.write(encrypt_bytes(key, data))

def decrypt_file_from_path(key: bytes, in_path: str) -> bytes:
    with open(in_path, "rb") as f:
        blob = f.read()
    return decrypt_bytes(key, blob)
