"""The tools, as plain functions.

The MCP layer only names these and describes them; the work lives here so it can be
tested without a protocol in the way.

Every result carries `proxies`: what is running, and how much sits after the caller's
cursor. That is the one place a caller that never asks learns that something was found,
and it costs a read of a file.
"""

from __future__ import annotations

from . import crackweb
from .proxy import Registry


def _with_state(registry: Registry, result: dict) -> dict:
    result["proxies"] = registry.summary()
    return result


def list_checks(registry: Registry) -> dict:
    """Every check the binary knows, with the tags that select them."""
    return _with_state(registry, crackweb.list_checks())


def scan(
    registry: Registry,
    url: str,
    checks: object = None,
    enable_unsafe: bool = False,
    timeout_s: float | None = None,
) -> dict:
    """One target, scanned once, and the findings it produced."""
    return _with_state(
        registry,
        crackweb.one_shot(
            "scan",
            url,
            checks=checks,
            enable_unsafe=enable_unsafe,
            timeout=timeout_s or crackweb.DEFAULT_TIMEOUT,
        ),
    )


def crawl(
    registry: Registry,
    url: str,
    checks: object = None,
    enable_unsafe: bool = False,
    timeout_s: float | None = None,
) -> dict:
    """One target, discovered and then scanned: what a person would run first."""
    return _with_state(
        registry,
        crackweb.one_shot(
            "crawl",
            url,
            checks=checks,
            enable_unsafe=enable_unsafe,
            timeout=timeout_s or crackweb.DEFAULT_TIMEOUT,
        ),
    )


def start_proxy(
    registry: Registry,
    scope: object,
    listen: str | None = None,
    upstream: str | None = None,
    checks: object = None,
    passive_only: bool = False,
    enable_unsafe: bool = False,
) -> dict:
    """Start an intercepting proxy for traffic the caller sends through it."""
    patterns = [scope] if isinstance(scope, str) else list(scope or [])
    proxy = registry.start(
        scope=patterns,
        listen=listen,
        upstream=upstream,
        checks=checks,
        passive_only=passive_only,
        enable_unsafe=enable_unsafe,
    )
    result = {
        "proxy_id": proxy.id,
        "listen": proxy.listen,
        "scope": proxy.scope,
        "running": proxy.running,
        "findings_log": str(proxy.findings_log),
        "report_path": str(proxy.report_path),
        "next_step": (
            f"point the tool that generates traffic at http://{proxy.listen} as its "
            f"HTTP proxy, then ask proxy_status for findings"
        ),
    }
    return _with_state(registry, result)


def proxy_status(registry: Registry, proxy_id: str, cursor: int | None = None) -> dict:
    """Findings confirmed since the cursor, as the proxy runs."""
    return _with_state(registry, registry.status(proxy_id, cursor))


def stop_proxy(registry: Registry, proxy_id: str, include_report: bool = False) -> dict:
    """Stop a proxy and return everything it found."""
    return _with_state(registry, registry.stop(proxy_id, include_report=include_report))
