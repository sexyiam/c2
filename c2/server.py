"""Entry point: starts the HTTP listener and the operator CLI together."""
from __future__ import annotations

import logging
import os
import sys
import threading
from typing import TextIO


class _QuietStream:
    """Drop Flask/Werkzeug banner lines that would otherwise stomp the prompt."""

    _DROP_PREFIXES = (" * ",)
    _DROP_SUBSTR = (
        "Running on http",
        "Running on https",
        "Press CTRL+C to quit",
        "development server",
        "Serving Flask app",
        "Debug mode:",
        "WARNING: This is a development server",
    )

    def __init__(self, real: TextIO) -> None:
        self._real = real

    def write(self, s: str) -> int:
        if not s:
            return 0
        for line in s.splitlines(keepends=True):
            stripped = line.lstrip()
            if stripped.startswith(self._DROP_PREFIXES):
                continue
            if any(x in line for x in self._DROP_SUBSTR):
                continue
            self._real.write(line)
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def fileno(self) -> int:
        return self._real.fileno()

    def isatty(self) -> bool:
        return self._real.isatty()

    @property
    def encoding(self):
        return getattr(self._real, "encoding", "utf-8")


class _QuietWerkzeug(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if " - - [" in msg and ('"POST ' in msg or '"GET ' in msg):
            return False
        return True


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    for name in ("werkzeug", "flask.app"):
        lg = logging.getLogger(name)
        lg.setLevel(logging.ERROR)
        lg.addFilter(_QuietWerkzeug())
    logging.getLogger("c2.listener").setLevel(logging.INFO)


def main() -> None:
    from .cli import OperatorCLI
    from .doh import create_doh
    from .listener import create_app
    from .pipe_server import start_pipe_server
    from .stage import stage_bp
    from .state import State

    _configure_logging()
    sys.stderr = _QuietStream(sys.stderr)

    host = os.environ.get("C2_HOST", "127.0.0.1")
    port = int(os.environ.get("C2_PORT", "8443"))
    psk = os.environ.get("C2_PSK", "change-me-shared-key")

    cert = os.environ.get("C2_CERT")
    key = os.environ.get("C2_KEY")
    tls_mode = os.environ.get("C2_TLS", "").lower()
    ssl_context = None
    scheme = "http"
    if cert and key:
        ssl_context = (cert, key)
        scheme = "https"
    elif tls_mode == "adhoc":
        ssl_context = "adhoc"
        scheme = "https"

    state = State()
    app = create_app(state, psk=psk)
    app.register_blueprint(stage_bp)
    doh_app = create_doh(state)
    stop = threading.Event()

    threading.Thread(
        target=lambda: app.run(
            host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context
        ),
        daemon=True,
    ).start()

    doh_port = int(os.environ.get("C2_DOH_PORT", "8053"))
    threading.Thread(
        target=lambda: doh_app.run(
            host=host, port=doh_port, debug=False, use_reloader=False, ssl_context=ssl_context
        ),
        daemon=True,
    ).start()

    pipe_name = os.environ.get("C2_PIPE", "c2_session")
    start_pipe_server(pipe_name, state)

    # Brief pause so bind failures surface before the banner.
    stop.wait(0.2)

    cli = OperatorCLI(state, stop, bind=f"{scheme}://{host}:{port}", psk=psk)
    cli.run()
    stop.set()
    print("stopped.")


if __name__ == "__main__":
    main()
