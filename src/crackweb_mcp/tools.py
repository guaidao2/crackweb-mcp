"""The tools, as plain functions.

The MCP layer only names these and describes them; the work lives here so it can be tested
without a protocol in the way.

Every result carries `processes`: what is running, and how much sits after the caller's
cursor. That is the one place a caller that never asks learns that something arrived, and it
costs a read of a file.
"""

from __future__ import annotations

from . import crackweb
from .crackweb import RequestOptions, Target
from .processes import Registry


def _with_state(registry: Registry, result: dict) -> dict:
    result["processes"] = registry.summary()
    return result


def list_checks(registry: Registry) -> dict:
    """Every check the binary knows, with the tags that select them."""
    return _with_state(registry, crackweb.list_checks())


def scan(
    registry: Registry,
    target: Target,
    options: RequestOptions,
    timeout_s: float | None = None,
) -> dict:
    """One request, tested once, and the findings it produced."""
    return _with_state(
        registry, crackweb.scan(options, target, timeout=timeout_s or crackweb.DEFAULT_TIMEOUT)
    )


def crawl(
    registry: Registry,
    target: Target,
    options: RequestOptions,
    depth: int | None = None,
    engine: str | None = None,
    max_pages: int | None = None,
    scope: object = None,
    api_docs: object = None,
    no_discovery: bool = False,
    allow_state_change: bool = False,
    timeout_s: float | None = None,
) -> dict:
    """A target discovered and then tested: what a person would run first."""
    return _with_state(
        registry,
        crackweb.crawl(
            options,
            target,
            depth=depth,
            engine=engine,
            max_pages=max_pages,
            scope=scope,
            api_docs=api_docs,
            no_discovery=no_discovery,
            allow_state_change=allow_state_change,
            timeout=timeout_s or crackweb.DEFAULT_TIMEOUT,
        ),
    )


def start_proxy(
    registry: Registry,
    scope: object,
    options: RequestOptions,
    listen: str | None = None,
    upstream: str | None = None,
    passive_only: bool = False,
    export_ca: str | None = None,
) -> dict:
    """Start an intercepting proxy for traffic the caller sends through it."""
    patterns = [scope] if isinstance(scope, str) else list(scope or [])
    entry = registry.start_proxy(
        options,
        scope=patterns,
        listen=listen,
        upstream=upstream,
        passive_only=passive_only,
        export_ca=export_ca,
    )
    return _with_state(
        registry,
        {
            "kind": entry.kind,
            "proxy_id": entry.id,
            "listen": entry.listen,
            "scope": entry.scope,
            "running": entry.running,
            "log": str(entry.log),
            "report_path": str(entry.report_path),
            "next_step": (
                f"point the tool that generates traffic at http://{entry.listen} as its "
                f"HTTP proxy, then ask proxy_status for findings"
            ),
        },
    )


def proxy_status(registry: Registry, proxy_id: str, cursor: int | None = None) -> dict:
    """Findings confirmed since the cursor, as the proxy runs."""
    return _with_state(registry, registry.status(proxy_id, cursor))


def stop_proxy(registry: Registry, proxy_id: str, include_report: bool = False) -> dict:
    """Stop the proxy and return everything it found."""
    return _with_state(registry, registry.stop(proxy_id, include_report=include_report))


def start_oob(
    registry: Registry,
    http: str | None = None,
    dns: str | None = None,
    token: str | None = None,
    domain: str | None = None,
) -> dict:
    """Start the out-of-band listener, which collects callbacks from the target."""
    entry = registry.start_oob(http=http, dns=dns, token=token, domain=domain)
    return _with_state(
        registry,
        {
            "kind": entry.kind,
            "oob_id": entry.id,
            "listen": entry.listen,
            "callback_url": registry.status(entry.id)["listening"].get("callback_url", ""),
            "running": entry.running,
            "log": str(entry.log),
            "next_step": (
                "pass these addresses to scan or crawl as oob_http and oob_dns, then ask "
                "oob_status for the callbacks a check provokes"
            ),
        },
    )


def oob_status(registry: Registry, oob_id: str, cursor: int | None = None) -> dict:
    """Callbacks collected since the cursor, as the listener runs."""
    return _with_state(registry, registry.status(oob_id, cursor))


def stop_oob(registry: Registry, oob_id: str) -> dict:
    """Stop the listener and return every callback it collected."""
    return _with_state(registry, registry.stop(oob_id))


def local_jwt(
    registry: Registry,
    token: str,
    secret: str | None = None,
    wordlist: str | None = None,
    forge: bool = False,
    claims: object = None,
) -> dict:
    """Decode a token offline, recover its signing secret, and sign one of its own."""
    return _with_state(
        registry,
        crackweb.local_jwt(token, secret=secret, wordlist=wordlist, forge=forge, claims=claims),
    )


def local_hash(registry: Registry, value: str, wordlist: str | None = None) -> dict:
    """Identify a hash offline and try to recover what it was made from."""
    return _with_state(registry, crackweb.local_hash(value, wordlist=wordlist))


def ca(
    registry: Registry,
    out_dir: str | None = None,
    force: bool = False,
    export: str | None = None,
) -> dict:
    """Load or generate the interception CA, and say what it is."""
    return _with_state(registry, crackweb.ca(out_dir=out_dir, force=force, export=export))
