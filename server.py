#!/usr/bin/env python3
"""Run the crackweb MCP server straight from a checkout, without installing anything.

    python3 server.py /path/to/crackweb

The packaged command (`crackweb-mcp`) is the same server with an entry point installed
around it. This file exists for the machines where installing one is awkward: a
distribution Python that refuses `pip install .` behind PEP 668, a box with no pipx, or
simply a checkout somebody would rather not install from.

The one dependency is the MCP SDK. If it is not importable from the Python you run this
with, the message says how to get it — including the way that does not touch the system
Python at all.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
# A checkout has the package under src/, so the server can be run from here without being
# installed.
sys.path.insert(0, str(REPO / "src"))

USAGE = "usage: python3 server.py <path-to-crackweb> [--binary <path>] [--version]"

INSTALL_HINT = (
    "the MCP SDK is not importable from this Python. Either:\n"
    "  python3 -m pip install --user --break-system-packages mcp\n"
    "or leave the system Python alone and install the packaged command instead:\n"
    "  pipx install git+https://github.com/guaidao2/crackweb-mcp     # then run: crackweb-mcp"
)


def main(argv: list[str]) -> int:
    args = list(argv)
    if args and args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    if args and args[0] in ("-V", "--version"):
        from crackweb_mcp import __version__

        print(f"crackweb-mcp {__version__}")
        return 0

    binary = ""
    while args:
        item = args.pop(0)
        if item == "--binary" and args:
            binary = args.pop(0)
        elif item.startswith("--binary="):
            binary = item.split("=", 1)[1]
        elif not item.startswith("-") and not binary:
            binary = item
        else:
            print(f"server.py: unknown argument {item!r}\n{USAGE}", file=sys.stderr)
            return 2

    if binary:
        os.environ["CRACKWEB_BIN"] = str(Path(binary).expanduser())

    try:
        import mcp  # noqa: F401 - imported to find out whether it is there
    except ImportError:
        print(f"server.py: {INSTALL_HINT}", file=sys.stderr)
        return 2

    from crackweb_mcp import crackweb, server

    # The same UTF-8 the protocol needs, before anything is printed: a path on this machine
    # is not ASCII, and a mangled message is worse than a short one.
    server.force_utf8()

    # Finding the binary now, rather than on the first tool call, turns "forgot the path" into
    # a message at startup instead of a failure in the middle of a session.
    try:
        crackweb.find_binary()
    except crackweb.CrackwebError as exc:
        print(f"server.py: {exc}\n{USAGE}", file=sys.stderr)
        return 2

    return server.main([])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
