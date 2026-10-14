"""Fixtures: a stand-in binary, and a registry whose logs live in the test's tmp dir."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from crackweb_mcp import crackweb
from crackweb_mcp.proxy import Registry

FAKE = Path(__file__).parent / "fake_crackweb.py"


@pytest.fixture
def fake_crackweb(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the wrapper at the stand-in, run through this interpreter.

    PREFIX is what makes a .py stand-in work on every platform: the wrapper still starts
    a real process, which is the part worth exercising.
    """
    monkeypatch.setenv(crackweb.BINARY_ENV, str(FAKE))
    monkeypatch.setattr(crackweb, "PREFIX", [sys.executable])
    return FAKE


@pytest.fixture
def registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Registry:
    """A registry that writes into the test's own directory and never reaps."""
    monkeypatch.setenv("CRACKWEB_MCP_TMP", str(tmp_path / "runs"))
    made = Registry(idle=0)
    yield made
    made.stop_all()
