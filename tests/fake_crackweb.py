"""A stand-in for the crackweb CLI.

The wrapper's own behaviour is what these tests are about, so the binary underneath is
replaceable. This one answers every command the wrapper calls, prints what those commands
print, and — when asked — records the argv it was given, so a test can assert the whole
command line rather than a property of it.
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

# Printed in the shapes crackweb uses: severity in brackets, two spaces before the check id,
# four-space indented detail lines, a blank line after each finding.
FINDING_ENV_FILE = """[High] File served that was never meant to be served  exposed-path
    GET http://example.com/swagger.json
    Param: q
    Payload: /swagger.json

"""

FINDING_INJECTION = """[Critical] Value reaches the database  sqli-union
    POST http://example.com/login
    Payload: ' OR 1=1 -- x

"""

# The out-of-band listener's two shapes: the addresses it names on the way up, and one line
# per interaction.
OOB_LISTENING = "out-of-band server listening: http 127.0.0.1:8081, dns 127.0.0.1:5353\n"
OOB_CALLBACK = "14:22:07  HTTP  example.com:54321  /probe?token=abc\n"


def record(argv: list[str]) -> None:
    """Append this command line to the log, when a test asked for one."""
    path = os.environ.get("FAKE_ARGV_LOG", "").strip()
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\n")


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


def write_report(path: str, target: str) -> None:
    Path(path).write_text(json.dumps(report_findings(target)), encoding="utf-8")


def stop_handlers(stop) -> None:  # type: ignore[no-untyped-def]
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, stop)
        except (ValueError, OSError):
            pass


def run_proxy(argv: list[str]) -> int:
    """Print findings as they arrive; write the report when stopped."""
    report_path = arg_value(argv, "-o") or arg_value(argv, "--output") or "report.json"
    scope = [argv[index + 1] for index, item in enumerate(argv) if item == "--scope"]

    def stop(*_args: object) -> None:
        # FAKE_NO_REPORT stands in for a stop that gives the process no chance to write:
        # what Windows does to a proxy that is being stopped.
        if not os.environ.get("FAKE_NO_REPORT"):
            write_report(report_path, "proxy:" + ",".join(scope))
        sys.exit(0)

    stop_handlers(stop)
    print(FINDING_ENV_FILE, end="", flush=True)
    time.sleep(0.7)
    print(FINDING_INJECTION, end="", flush=True)
    while True:
        time.sleep(0.1)


def run_oob(argv: list[str]) -> int:
    """Name the addresses, then collect a callback; stop when asked."""
    http = arg_value(argv, "--http") or "127.0.0.1:8081"
    dns = arg_value(argv, "--dns") or "127.0.0.1:5353"

    def stop(*_args: object) -> None:
        sys.exit(0)

    stop_handlers(stop)
    # The real listener names its addresses on stderr (a note) and prints callbacks on
    # stdout, so the stand-in does the same: the difference is what the wrapper has to cope
    # with, and a stand-in that hid it would test nothing.
    print(f"out-of-band server listening: http {http}, dns {dns}", file=sys.stderr, flush=True)
    print(f"callback URLs look like http://{http}/minted-token (one is minted per injection)\n",
          flush=True)
    time.sleep(0.7)
    print(OOB_CALLBACK, end="", flush=True)
    while True:
        time.sleep(0.1)


def run_local(argv: list[str]) -> int:
    """The offline subjects: a token, or a hash."""
    subject = argv[1] if len(argv) > 1 else ""
    if subject == "jwt":
        print(
            "header:\n"
            '  {"alg": "HS256", "typ": "JWT"}\n'
            "claims:\n"
            '  {"sub": "admin", "role": "admin"}\n'
            "signature: HMAC-SHA256, key recovered: secret\n",
            end="",
        )
        return 0
    if subject == "hash":
        print("algorithm: md5\nplaintext: hunter2\n", end="")
        return 0
    print(f"fake: unknown local subject {subject!r}", file=sys.stderr)
    return 2


def run_ca(argv: list[str]) -> int:
    """The certificate authority block crackweb prints."""
    export = arg_value(argv, "--export")
    print(
        "  Check            crackweb interception CA\n"
        "  Serial           1f2e3d4c\n"
        "  Expires          2036-10-14\n"
        "  SHA-256          11:22:33:44\n"
        "  Certificate      /tmp/ca/ca.crt\n"
        "  Key              /tmp/ca/ca.key\n",
        end="",
    )
    if export:
        print(f"CA certificate exported to {export}")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        return 2
    record(argv)
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
        target = arg_value(argv, "-u") or arg_value(argv, "--url") or "http://example.com"
        report_path = arg_value(argv, "-o") or arg_value(argv, "--output")
        if report_path:
            write_report(report_path, target)
        print(FINDING_ENV_FILE, end="")
        return 0
    if argv[0] == "proxy":
        return run_proxy(argv)
    if argv[0] == "oob":
        return run_oob(argv)
    if argv[0] == "local":
        return run_local(argv)
    if argv[0] == "ca":
        return run_ca(argv)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
