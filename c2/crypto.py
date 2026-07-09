"""Shared crypto helpers for the C2 server.

Uses AES-256-GCM to keep beacon traffic confidential and tamper-resistant.
A per-agent session key is derived from a pre-shared key embedded in the
implant plus a random nonce exchanged at registration time.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets

from Crypto.Cipher import AES  # type: ignore


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(psk: str, nonce: bytes) -> bytes:
    """Derive a 32-byte session key from the pre-shared key and nonce."""
    return hashlib.pbkdf2_hmac("sha256", psk.encode("utf-8"), nonce, 100_000, dklen=32)


def encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt a string, returns b64(nonce || tag || ciphertext)."""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return _b64(nonce + tag + ct)


def decrypt(blob: str, key: bytes) -> str:
    raw = _unb64(blob)
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode("utf-8")


def random_token(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)
