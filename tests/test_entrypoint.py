"""The checkout entry point: no install, one script, a real stdio handshake.

The handshake and the tool list are protocol-level, so they exercise the whole wiring —
path setup, binary resolution, the FastMCP server — without needing a scan to run.
"""

from __future__ import annotations

import json
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


def speak(payload_lines: list[dict]) -> subprocess.CompletedProcess[str]:
    """Send JSON-RPC lines and let the server exit when stdin closes."""
    body = "\n".join(json.dumps(line) for line in payload_lines) + "\n"
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(FAKE)],
        input=body,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def test_the_script_answers_the_handshake_and_lists_the_tools() -> None:
    done = speak(
        [
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
    )
    assert done.returncode == 0, done.stderr

    replies = {
        json.loads(line)["id"]: json.loads(line)
        for line in done.stdout.splitlines()
        if line.strip().startswith("{") and '"id"' in line
    }
    assert 1 in replies and 2 in replies
    assert replies[1]["result"]["serverInfo"]["name"] == "crackweb"
    names = {tool["name"] for tool in replies[2]["result"]["tools"]}
    assert names == EXPECTED_TOOLS
    # A description is the contract a client reads, so every tool has one.
    assert all(tool.get("description") for tool in replies[2]["result"]["tools"])


def test_the_script_says_which_binary_is_missing(tmp_path: Path) -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "not-a-binary")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert done.returncode == 2
    assert "not-a-binary" in done.stderr
    assert "CRACKWEB_BIN" in done.stderr


def test_the_script_reports_its_version() -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert done.returncode == 0
    assert done.stdout.strip().startswith("crackweb-mcp ")
