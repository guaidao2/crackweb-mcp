"""A stand-in for the crackweb CLI.

The wrapper's own behaviour is what these tests are about, so the binary underneath is
replaceable. This one answers the shapes the wrapper calls: --list-checks, a one-shot
scan or crawl that writes a report, and a proxy that prints findings as they are
confirmed and writes its report when it is stopped.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path

def _row(check_id: str, kind: str, severity: str, tags: str, opt_in: bool = False) -> str:
    """One row of --list-checks, in the binary's own fixed-width format."""
    return "  " + " ".join(
        [
            check_id.ljust(28),
            kind.ljust(8),
            severity.ljust(9),
            ("[opt-in]" if opt_in else "").ljust(16),
            tags,
        ]
    )


LIST_CHECKS = "\n".join(
    [
        "checks:",
        _row("access-control-variants", "active", "high", "active,authorization"),
        _row("cache-poisoning", "active", "high", "active,cache,injection", opt_in=True),
        _row("dom-xss", "active", "high", "active,injection,xss", opt_in=True),
        _row("exposed-path", "active", "high", "active,disclosure"),
        _row("passive-security-headers", "passive", "low", "passive,headers"),
        _row("sqli-union", "active", "critical", "active,injection,sql"),
        "",
    ]
)

# Printed in the shapes crackweb uses: severity in brackets, two spaces before the check
# id, four-space indented detail lines, a blank line after each finding.
FINDING_ENV_FILE = """[High] File served that was never meant to be served  exposed-path
    GET http://example.com/swagger.json
    Param: q
    Payload: /swagger.json

"""

FINDING_INJECTION = """[Critical] Value reaches the database  sqli
    POST http://example.com/login
    Payload: ' OR 1=1 -- x

"""


def arg_value(argv: list[str], flag: str) -> str | None:
    """The value of -o/--output and friends, whether it was split or joined."""
    for index, item in enumerate(argv):
        if item == flag and index + 1 < len(argv):
            return argv[index + 1]
        if item.startswith(flag + "="):
            return item.split("=", 1)[1]
    return None


def report_findings(url: str) -> dict:
    return {
        "tool": "crackweb",
        "version": "0.0.0-fake",
        "target": url,
        "requests": 7,
        "endpoints": 3,
        "findings": [
            {
                "check": "exposed-path",
                "severity": "high",
                "confidence": "certain",
                "url": "http://example.com/swagger.json",
                "payload": "/swagger.json",
                "evidence": {"matches": ["the file is reachable by anyone who asks"]},
            }
        ],
    }


def write_report(path: str, url: str) -> None:
    Path(path).write_text(json.dumps(report_findings(url)), encoding="utf-8")


def run_proxy(argv: list[str]) -> int:
    """Print findings as they arrive; write the report when stopped."""
    report_path = arg_value(argv, "-o") or arg_value(argv, "--output") or "report.json"
    scope = [argv[index + 1] for index, item in enumerate(argv) if item == "--scope"]

    def stop(*_args: object) -> None:
        write_report(report_path, "proxy:" + ",".join(scope))
        sys.exit(0)

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is not None:
            try:
                signal.signal(number, stop)
            except (ValueError, OSError):
                pass

    print(FINDING_ENV_FILE, end="", flush=True)
    time.sleep(0.7)
    print(FINDING_INJECTION, end="", flush=True)
    while True:
        time.sleep(0.1)


def main(argv: list[str]) -> int:
    if not argv:
        return 2
    if "--version" in argv or "-V" in argv:
        print("crackweb v0.0.0-fake")
        return 0
    if "--list-checks" in argv:
        print(LIST_CHECKS, end="")
        return 0
    if argv[0] == "proxy" and os.environ.get("FAKE_START_FAIL"):
        print("fake: cannot listen on that address", file=sys.stderr)
        return 1
    if argv[0] in ("scan", "crawl"):
        if os.environ.get("FAKE_FAIL"):
            print("fake: none of the requested checks exist", file=sys.stderr)
            return 2
        url = arg_value(argv, "-u") or arg_value(argv, "--url") or "http://example.com"
        report_path = arg_value(argv, "-o") or arg_value(argv, "--output")
        if report_path:
            write_report(report_path, url)
        print(FINDING_ENV_FILE, end="")
        return 0
    if argv[0] == "proxy":
        return run_proxy(argv)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
