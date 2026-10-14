"""The checkout entry point: no install, one script, a real stdio handshake.

The handshake and the tool list are protocol-level, so they exercise the whole wiring —
path setup, binary resolution, the server, and the encoding of what goes out — without
needing a scan to run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
}

HANDSHAKE = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
]


def run_server(binary: str | None = None, pythonioencoding: str | None = None):
    """Speak the handshake and hand back the raw streams.

    Bytes rather than text: stdout has to be UTF-8 whatever the machine's code page is, and
    that is worth asserting instead of decoding leniently.
    """
    env = dict(os.environ)
    env.pop("PYTHONIOENCODING", None)
    if pythonioencoding is not None:
        env["PYTHONIOENCODING"] = pythonioencoding
    body = "\n".join(json.dumps(line) for line in HANDSHAKE) + "\n"
    return subprocess.run(
        [sys.executable, str(SCRIPT), binary or str(FAKE)],
        input=body.encode(),
        capture_output=True,
        env=env,
        timeout=120,
    )


def replies_of(done: subprocess.CompletedProcess[bytes]) -> dict[int, dict]:
    stdout = done.stdout.decode("utf-8")  # strict: this is the protocol's encoding
    return {
        json.loads(line)["id"]: json.loads(line)
        for line in stdout.splitlines()
        if line.strip().startswith("{") and '"id"' in line
    }


def test_the_script_answers_the_handshake_and_lists_the_tools() -> None:
    done = run_server()
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")

    replies = replies_of(done)
    assert 1 in replies and 2 in replies
    assert replies[1]["result"]["serverInfo"]["name"] == "crackweb"
    tools = replies[2]["result"]["tools"]
    assert {tool["name"] for tool in tools} == EXPECTED_TOOLS
    # A description is the contract a client reads, so every tool has one.
    assert all(tool.get("description") for tool in tools)


def test_the_protocol_is_utf8_even_where_the_console_is_not() -> None:
    # Tool descriptions carry characters a legacy code page cannot represent. A stream that
    # encoded them its own way would hand the client a parse error rather than a tool list,
    # so stdout is asserted to be UTF-8 while the child is told to use another encoding.
    done = run_server(pythonioencoding="cp1252")
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")

    replies = replies_of(done)
    assert 2 in replies
    assert any("—" in tool.get("description", "") for tool in replies[2]["result"]["tools"])


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
