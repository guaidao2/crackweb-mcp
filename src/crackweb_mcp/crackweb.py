"""Running the crackweb CLI: finding the binary, invoking it, reading what it wrote.

Everything here is one of three things — locate the binary, run a subcommand with the
environment the parsing depends on, or turn a report into a dictionary. No behaviour of
crackweb is restated here: the wrapper calls the same commands a person would type.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

BINARY_ENV = "CRACKWEB_BIN"
DEFAULT_TIMEOUT = 900.0
# PREFIX is prepended to every invocation. It exists for two purposes: running crackweb
# through an interpreter (`go run ./cmd/crackweb`), and pointing the wrapper at a stand-in
# binary in tests without teaching the rest of the code that stand-ins exist.
PREFIX: list[str] = []
LIST_CHECKS_ROW = re.compile(r"^  (?P<id>[a-z0-9][a-z0-9-]+)\s{2,}(?P<rest>.*)$")
OPT_IN = "[opt-in]"
# The columns are fixed-width in the binary's own output (`%-28s %-8s %-9s %-16s %s`), but
# an empty one collapses when whitespace is collapsed with it — so the words are read for
# what they are rather than for where they sit. Kind and severity both come from a closed
# vocabulary, which makes that safe.
KINDS = {"active", "passive"}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class CrackwebError(RuntimeError):
    """The CLI could not be run, or could not do what it was asked to do."""


def find_binary() -> str:
    """Where the crackweb binary is: CRACKWEB_BIN, then PATH.

    A wrapper that guesses at a path would be worse than one that says it could not
    find the tool, so a missing binary is an error with the fix in the message.
    """
    override = os.environ.get(BINARY_ENV, "").strip()
    if override:
        path = Path(override).expanduser()
        if not path.exists():
            raise CrackwebError(f"{BINARY_ENV}={override} does not exist")
        return str(path)

    found = shutil.which("crackweb")
    if found:
        return found
    raise CrackwebError(
        f"no crackweb binary found: set {BINARY_ENV} to its path, or put crackweb on PATH"
    )


def environment() -> dict[str, str]:
    """The environment every invocation runs with.

    English and no colour are not preferences here, they are what makes the output
    stable to read: findings are recognised by their severity word, and colour codes
    would have to be stripped from every line.
    """
    env = dict(os.environ)
    env["CRACKWEB_LANG"] = "en"
    env["NO_COLOR"] = "1"
    return env


def run(args: list[str], timeout: float = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run one crackweb invocation to completion."""
    binary = find_binary()
    try:
        return subprocess.run(
            [*PREFIX, binary, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=environment(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CrackwebError(
            f"crackweb {' '.join(args)} did not finish within {timeout:.0f}s"
        ) from exc


def tail(text: str | None, limit: int = 2000) -> str:
    """The end of an output stream, where the reason for a failure is."""
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else "…" + text[-limit:]


def selection_args(checks: object, enable_unsafe: bool) -> list[str]:
    """The flags that decide which checks run.

    Naming a check is not enough for the ones marked opt-in: they need the second flag
    as well, and the wrapper never adds it on its own. A caller that wants a check that
    runs page scripts or writes to a cache has to say so.
    """
    args: list[str] = []
    if checks:
        args += ["--checks", checks if isinstance(checks, str) else ",".join(checks)]
    if enable_unsafe:
        args.append("--enable-unsafe-checks")
    return args


def list_checks(timeout: float = 120.0) -> dict:
    """Every check the binary knows, with the tags that select them."""
    done = run(["scan", "--list-checks"], timeout=timeout)
    checks: list[dict] = []
    unparsed = 0
    for line in done.stdout.splitlines():
        row = LIST_CHECKS_ROW.match(line)
        if not row:
            continue
        words = re.split(r"\s+", row.group("rest").strip())
        kind = next((w for w in words if w.lower() in KINDS), "")
        severity = next((w for w in words if w.lower() in SEVERITIES), "")
        if not kind or not severity:
            unparsed += 1
        opt_in = OPT_IN in words
        consumed = {kind, severity, OPT_IN} | {w for w in words if w.lower() in KINDS}
        tags_word = next((w for w in reversed(words) if w not in consumed), "")
        checks.append(
            {
                "id": row.group("id"),
                "kind": kind.lower(),
                "severity": severity.lower(),
                "opt_in": opt_in,
                "tags": [t for t in tags_word.split(",") if t],
            }
        )
    if not checks:
        raise CrackwebError(f"could not read the check list: {tail(done.stderr or done.stdout)}")
    result: dict = {"checks": checks, "count": len(checks)}
    if unparsed:
        # A column that moved — or output that is not the shape this reads — would otherwise
        # show up as rows with blanks in them and nothing else to say what happened.
        result["warnings"] = [
            f"{unparsed} of {len(checks)} rows carried no kind and severity this parser "
            f"recognises; --list-checks may not be the shape it expects"
        ]
    return result


def one_shot(
    command: str,
    url: str,
    checks: object = None,
    enable_unsafe: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Run scan or crawl once and return the report it wrote.

    -q keeps the console output from being mistaken for the answer, and -o decides
    where the answer goes. The report is the structured result; the exit code and
    whatever the CLI said on stderr are kept so a failure can be explained rather
    than guessed at.
    """
    with tempfile.TemporaryDirectory(prefix="crackweb-mcp-") as workdir:
        report_path = Path(workdir) / "report.json"
        args = [command, "-u", url, "-q", "-o", str(report_path)]
        args += selection_args(checks, enable_unsafe)
        done = run(args, timeout=timeout)

        result: dict = {
            "command": command,
            "url": url,
            "exit_code": done.returncode,
            "stderr": tail(done.stderr),
            "findings": [],
            "summary": {},
        }
        if report_path.exists():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            result["findings"] = report.get("findings", [])
            result["summary"] = {
                key: report[key]
                for key in ("target", "started", "finished", "duration", "requests", "endpoints")
                if key in report
            }
        elif done.returncode != 0:
            raise CrackwebError(
                f"crackweb {command} failed with exit code {done.returncode}: "
                f"{tail(done.stderr) or tail(done.stdout)}"
            )
        result["finding_count"] = len(result["findings"])
        return result
