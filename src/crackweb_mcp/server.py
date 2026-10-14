"""The MCP surface: six tools over one CLI.

A tool description is the contract a client reads before it calls anything, so the ones
with behaviour worth knowing say it: proxy_status reports that its cursor only moves
when it is called and that calling it often is cheap, and start_proxy says that scope is
not optional. Nothing here asks a client to behave in a particular way — a description
that said "call this every few steps" would be a promise this server cannot keep.

Nothing may be written to stdout: that is the protocol channel. Anything a human might
want to see goes to stderr.
"""

from __future__ import annotations

import os
import signal
import sys

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCP_Server
except ImportError:  # mcp 2.x renamed FastMCP to MCPServer, and kept the same shape
    from mcp.server.mcpserver import MCPServer as MCP_Server

from . import __version__, crackweb, tools
from .proxy import Registry

INSTRUCTIONS = (
    "crackweb is a traffic-driven web DAST scanner. These tools run its CLI. scan and "
    "crawl test a target once and return the report; the proxy tools test traffic you "
    "generate, as you generate it. Findings are confirmed evidence rather than guesses, "
    "so report them as they are, with the evidence beside them. A check marked opt-in in "
    "list_checks runs page scripts or writes to a shared cache: those only run when a "
    "call says enable_unsafe."
)


def build_server(registry: Registry | None = None) -> MCP_Server:
    """Wire the tools onto a server. One registry, so one place proxies live."""
    registry = registry or Registry()
    server = MCP_Server(name="crackweb", instructions=INSTRUCTIONS)

    @server.tool(
        name="list_checks",
        description=(
            "Every check the installed crackweb offers: id, severity, tags, and whether "
            "it is opt-in (opt-in checks run page scripts or write to a cache and are "
            "never selected by \"all\"). Call it before choosing checks for a scan."
        ),
    )
    def list_checks() -> dict:
        return tools.list_checks(registry)

    @server.tool(
        name="scan",
        description=(
            "Test one URL once and return the report's findings, with the exit code and "
            "whatever the CLI said on stderr when something went wrong. For a whole site, "
            "use crawl instead. Long targets: pass timeout_s, or run a proxy and poll it."
        ),
    )
    def scan(
        url: str,
        checks: str | None = None,
        enable_unsafe: bool = False,
        timeout_s: float | None = None,
    ) -> dict:
        return tools.scan(registry, url, checks=checks, enable_unsafe=enable_unsafe, timeout_s=timeout_s)

    @server.tool(
        name="crawl",
        description=(
            "Discover a target's pages and test them: the usual first call against a site. "
            "Returns the findings and the crawl's counts. Pass checks to narrow what runs; "
            "enable_unsafe is required for opt-in checks."
        ),
    )
    def crawl(
        url: str,
        checks: str | None = None,
        enable_unsafe: bool = False,
        timeout_s: float | None = None,
    ) -> dict:
        return tools.crawl(registry, url, checks=checks, enable_unsafe=enable_unsafe, timeout_s=timeout_s)

    @server.tool(
        name="start_proxy",
        description=(
            "Start an intercepting proxy and return its address; point whatever generates "
            "traffic at it (curl -x, a script's proxy setting) and crackweb tests that "
            "traffic as it passes. scope is required and lists the host patterns the proxy "
            "may intercept — anything else is tunnelled untouched. The proxy is stopped "
            "when this server exits, and on its own if left idle."
        ),
    )
    def start_proxy(
        scope: str | list[str],
        listen: str | None = None,
        upstream: str | None = None,
        checks: str | None = None,
        passive_only: bool = False,
        enable_unsafe: bool = False,
    ) -> dict:
        return tools.start_proxy(
            registry,
            scope=scope,
            listen=listen,
            upstream=upstream,
            checks=checks,
            passive_only=passive_only,
            enable_unsafe=enable_unsafe,
        )

    @server.tool(
        name="proxy_status",
        description=(
            "What the proxy has found since your cursor, and whether it is still running. "
            "The cursor is in the reply: pass it back to get only what is new, or omit it "
            "to continue from where the last call left off. Reading moves the cursor, so "
            "calling this often is cheap and never repeats a finding — and every other "
            "tool's result carries how many findings are waiting for you."
        ),
    )
    def proxy_status(proxy_id: str, cursor: int | None = None) -> dict:
        return tools.proxy_status(registry, proxy_id, cursor=cursor)

    @server.tool(
        name="stop_proxy",
        description=(
            "Stop a proxy and return everything it found. Safe to call twice. Set "
            "include_report to also get the full report crackweb wrote on exit (it is much "
            "larger than the findings)."
        ),
    )
    def stop_proxy(proxy_id: str, include_report: bool = False) -> dict:
        return tools.stop_proxy(registry, proxy_id, include_report=include_report)

    return server


def _install_signal_handlers(registry: Registry) -> None:
    """Make the exits that can be handled stop the proxies on the way out."""

    def handler(signum: int, _frame: object) -> None:
        registry.stop_all()
        raise SystemExit(0 if signum in (signal.SIGINT, signal.SIGTERM) else 1)

    for name in ("SIGINT", "SIGTERM"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, handler)
        except (ValueError, OSError):  # not the main thread, or not supported here
            pass


def force_utf8() -> None:
    """Speak UTF-8 whatever the console's code page is.

    MCP is UTF-8 JSON on stdout. A Windows console defaults to a code page that cannot
    represent some of what a tool description says, and a stream that encodes it its own way
    hands the client a parse error instead of a tool list. stderr goes the same way, so that
    a diagnostic is readable rather than mangled.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):  # a stream that cannot be reconfigured
            pass


def main(argv: list[str] | None = None) -> int:
    """Entry point: `crackweb-mcp [--binary PATH]` over stdio."""
    force_utf8()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("--version", "-V"):
        print(f"crackweb-mcp {__version__}")
        return 0
    if args and args[0] == "--binary":
        if len(args) < 2:
            print("--binary needs a path", file=sys.stderr)
            return 2
        os.environ[crackweb.BINARY_ENV] = args[1]
    elif args:
        print(f"unknown argument {args[0]!r}", file=sys.stderr)
        return 2

    try:
        binary = crackweb.find_binary()
    except crackweb.CrackwebError as exc:
        print(f"crackweb-mcp: {exc}", file=sys.stderr)
        return 2

    registry = Registry()
    _install_signal_handlers(registry)
    print(f"crackweb-mcp {__version__} serving {binary} over stdio", file=sys.stderr)
    build_server(registry).run()
    registry.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
