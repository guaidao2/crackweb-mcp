"""The checkout entry point: no install, one script, a real stdio exchange.

The handshake and the tool list are protocol-level, so they exercise the whole wiring —
path setup, binary resolution, the server, and the encoding of what goes out — without
needing a scan to run.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "server.py"
FAKE = Path(__file__).resolve().parent / "fake_crackweb.py"

EXPECTED_TOOLS = {
    "list_checks",
    "scan",
    "crawl",
    "start_proxy",
    "proxy_status",
    "stop_proxy",
    "start_oob",
    "oob_status",
    "stop_oob",
    "local_jwt",
    "local_hash",
    "ca",
}


class Session:
    """A client that talks the way a client does: one message, then its reply.

    Writing the whole exchange at once and closing stdin lets the server leave before it has
    answered the last request — a race the test has no business being in, and one that made
    the suite fail on exactly one of eight CI jobs.
    """

    def __init__(self, binary: str | None = None, pythonioencoding: str | None = None) -> None:
        env = dict(os.environ)
        env.pop("PYTHONIOENCODING", None)
        if pythonioencoding is not None:
            env["PYTHONIOENCODING"] = pythonioencoding
        self.replies: queue.Queue[bytes] = queue.Queue()
        self.stderr: list[bytes] = []
        self.missing = AssertionError("no reply")
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT), binary or str(FAKE)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        threading.Thread(target=self._pump, args=(self.process.stdout, self.replies), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.process.stderr, None), daemon=True).start()

    def _pump(self, stream: object, into: queue.Queue[bytes] | None) -> None:
        for line in stream:  # type: ignore[union-attr]
            if into is None:
                self.stderr.append(line)
            else:
                into.put(line)

    def stderr_text(self) -> str:
        return b"".join(self.stderr).decode("utf-8", "replace")

    def send(self, message: dict) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def reply(self, wanted: int, timeout: float = 30.0) -> dict:
        """The reply with this id, or a failure that says what the server did say."""
        try:
            while True:
                line = self.replies.get(timeout=timeout)
                text = line.decode("utf-8")  # strict: this is the protocol's encoding
                if not text.lstrip().startswith("{"):
                    continue
                message = json.loads(text)
                if message.get("id") == wanted:
                    return message
        except queue.Empty:
            raise AssertionError(
                f"no reply to {wanted}; exit code {self.process.poll()}, stderr:\n"
                f"{self.stderr_text()[-800:]}"
            )

    def close(self) -> int:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        return self.process.wait(timeout=30)

    def kill_if_running(self) -> None:
        if self.process.poll() is None:
            self.process.kill()


def handshake(session: Session) -> dict:
    """initialize, then tools/list, then hand back the tool list."""
    session.send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }
    )
    initialized = session.reply(1)
    assert initialized["result"]["serverInfo"]["name"] == "crackweb"

    session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    session.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return session.reply(2)["result"]


def test_the_script_answers_the_handshake_and_lists_the_tools() -> None:
    session = Session()
    try:
        result = handshake(session)
        tools = result["tools"]
        assert {tool["name"] for tool in tools} == EXPECTED_TOOLS
        # A description is the contract a client reads, so every tool has one.
        assert all(tool.get("description") for tool in tools)
        assert session.close() == 0
    finally:
        session.kill_if_running()


def test_the_protocol_is_utf8_even_where_the_console_is_not() -> None:
    # Tool descriptions carry characters a legacy code page cannot represent. A stream that
    # encoded them its own way would hand the client a parse error rather than a tool list,
    # so every line is decoded as UTF-8 while the child is told to use another encoding.
    session = Session(pythonioencoding="cp1252")
    try:
        result = handshake(session)
        assert any("—" in tool.get("description", "") for tool in result["tools"])
        assert session.close() == 0
    finally:
        session.kill_if_running()


def test_the_script_says_which_binary_is_missing(tmp_path: Path) -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "not-a-binary")],
        capture_output=True,
        timeout=60,
    )
    assert done.returncode == 2
    stderr = done.stderr.decode("utf-8", "replace")
    assert "not-a-binary" in stderr
    assert "CRACKWEB_BIN" in stderr


def test_the_script_reports_its_version() -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        timeout=60,
    )
    assert done.returncode == 0
    assert done.stdout.decode("utf-8").strip().startswith("crackweb-mcp ")
