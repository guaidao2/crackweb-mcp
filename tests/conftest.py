"""Fixtures: a stand-in binary that records what it was asked to do, and a registry whose
logs live in the test's own directory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from crackweb_mcp import crackweb
from crackweb_mcp.processes import Registry

FAKE = Path(__file__).parent / "fake_crackweb.py"


@pytest.fixture
def fake_crackweb(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the wrapper at the stand-in, run through this interpreter.

    PREFIX is what makes a .py stand-in work on every platform: the wrapper still starts a
    real process, which is the part worth exercising. FAKE_ARGV_LOG makes the stand-in write
    down every command line it was given, so a test can assert the flags themselves.
    """
    monkeypatch.setenv(crackweb.BINARY_ENV, str(FAKE))
    monkeypatch.setenv("FAKE_ARGV_LOG", str(tmp_path / "argv.log"))
    monkeypatch.setattr(crackweb, "PREFIX", [sys.executable])
    return FAKE


@pytest.fixture
def argv_log(tmp_path: Path):
    """A reader for the command lines the stand-in recorded."""

    def read() -> list[list[str]]:
        path = tmp_path / "argv.log"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    return read


@pytest.fixture
def registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Registry:
    """A registry that writes into the test's own directory and never reaps."""
    monkeypatch.setenv("CRACKWEB_MCP_TMP", str(tmp_path / "runs"))
    made = Registry(idle=0)
    yield made
    made.stop_all()
