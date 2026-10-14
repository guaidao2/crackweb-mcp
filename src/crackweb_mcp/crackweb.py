"""Running the crackweb CLI: finding the binary, building its command line, reading results.

Everything here is one of four things — locate the binary, turn an option into the flags the
CLI expects, run a subcommand, or turn its output into a dictionary. The flag names live in
`RequestOptions` and nowhere else, so a flag is spelled once and tested once.

The commands that send traffic share one set of options (the CLI calls them the request
flags); each also has a few of its own, which the functions for them take as keyword
arguments.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

BINARY_ENV = "CRACKWEB_BIN"
DEFAULT_TIMEOUT = 900.0
# PREFIX is prepended to every invocation. It exists for two purposes: running crackweb
# through an interpreter (`go run ./cmd/crackweb`), and pointing the wrapper at a stand-in
# binary in tests without teaching the rest of the code that stand-ins exist.
PREFIX: list[str] = []
LIST_CHECKS_ROW = re.compile(r"^  (?P<id>[a-z0-9][a-z0-9-]+)\s{2,}(?P<rest>.*)$")
OPT_IN = "[opt-in]"
# The columns are fixed-width in the binary's own output (`%-28s %-8s %-9s %-16s %s`), but an
# empty one collapses when whitespace is collapsed with it — so the words are read for what
# they are rather than for where they sit. Kind and severity both come from a closed
# vocabulary, which makes that safe.
KINDS = {"active", "passive"}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class CrackwebError(RuntimeError):
    """The CLI could not be run, or could not do what it was asked to do."""


def find_binary() -> str:
    """Where the crackweb binary is: CRACKWEB_BIN, then PATH.

    A wrapper that guesses at a path would be worse than one that says it could not find the
    tool, so a missing binary is an error with the fix in the message.
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

    English and no colour are not preferences here, they are what makes the output stable to
    read: findings are recognised by their severity word, and colour codes would have to be
    stripped from every line.
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


def _repeat(flag: str, values: object) -> list[str]:
    """A flag the CLI accepts more than once."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for value in values:  # type: ignore[union-attr]
        if value is not None and str(value) != "":
            out += [flag, str(value)]
    return out


def _flag(flag: str, value: object) -> list[str]:
    """A flag that takes one value, or nothing when it was not asked for."""
    if value is None or value is False:
        return []
    if value is True:
        return [flag]
    return [flag, str(value)]


@dataclass
class RequestOptions:
    """The flags scan, crawl and proxy all share — the CLI's request flags.

    Every field is optional and none of them has a default of its own: what is left out is
    left to crackweb, which is the only thing that should be deciding these.
    """

    checks: object = None
    enable_unsafe: bool = False
    sessions: object = None
    cookies: object = None
    headers: object = None
    basic_auth: str | None = None
    jwt_secrets: object = None
    proxy: str | None = None
    request_timeout: str | None = None
    rate: float | None = None
    threads: int | None = None
    sensitivity: int | None = None
    insecure: bool = False
    user_agent: str | None = None
    random_ua: bool = False
    templates: object = None
    skip_params: object = None
    no_normalize: bool = False
    verbose: bool = False
    no_waf: bool = False
    no_assume_waf: bool = False
    oob_http: str | None = None
    oob_dns: str | None = None
    oob_domain: str | None = None
    oob_interactsh: str | None = None
    oob_token: str | None = None
    report_path: str | None = None

    def args(self) -> list[str]:
        """The flags, in one fixed order so a test can assert the whole command line."""
        out: list[str] = []
        if self.checks:
            out += ["--checks", self.checks if isinstance(self.checks, str) else ",".join(self.checks)]  # type: ignore[arg-type]
        out += _flag("--enable-unsafe-checks", self.enable_unsafe)
        out += _repeat("--session", self.sessions)
        out += _repeat("--cookie", self.cookies)
        out += _repeat("--header", self.headers)
        out += _flag("--basic-auth", self.basic_auth)
        out += _repeat("--jwt-secret", self.jwt_secrets)
        out += _flag("--proxy", self.proxy)
        out += _flag("--timeout", self.request_timeout)
        out += _flag("--rate", self.rate)
        out += _flag("--threads", self.threads)
        out += _flag("--sensitivity", self.sensitivity)
        out += _flag("--insecure", self.insecure)
        out += _flag("--user-agent", self.user_agent)
        out += _flag("--random-ua", self.random_ua)
        out += _repeat("--templates", self.templates)
        out += _repeat("--skip-param", self.skip_params)
        out += _flag("--no-normalize", self.no_normalize)
        out += _flag("--verbose", self.verbose)
        out += _flag("--no-waf", self.no_waf)
        out += _flag("--no-assume-waf", self.no_assume_waf)
        out += _flag("--oob-http", self.oob_http)
        out += _flag("--oob-dns", self.oob_dns)
        out += _flag("--oob-domain", self.oob_domain)
        out += _flag("--oob-interactsh", self.oob_interactsh)
        out += _flag("--oob-token", self.oob_token)
        return out


@dataclass
class Target:
    """What `scan` needs beyond the shared options: which request to test."""

    url: str | None = None
    raw: str | None = None
    method: str | None = None
    data: str | None = None
    forms: bool = False
    api_docs: object = field(default=None)

    def args(self) -> list[str]:
        out: list[str] = []
        out += _flag("--url", self.url)
        out += _flag("--raw", self.raw)
        out += _flag("--method", self.method)
        out += _flag("--data", self.data)
        out += _flag("--forms", self.forms)
        out += _repeat("--api-doc", self.api_docs)
        return out


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


def read_report(path: Path) -> dict:
    """The report a one-shot command wrote, as a dictionary."""
    report = json.loads(path.read_text(encoding="utf-8"))
    return report if isinstance(report, dict) else {"report": report}


def one_shot(command: str, args: list[str], timeout: float, report_copy: str | None = None) -> dict:
    """Run a scanning command once and return the report it wrote.

    The report is the structured result; the exit code and whatever the CLI said on stderr
    are kept so a failure can be explained rather than guessed at. A caller that named a
    report path gets its own copy, and always gets the findings inline.
    """
    with tempfile.TemporaryDirectory(prefix="crackweb-mcp-") as workdir:
        own_report = Path(workdir) / "report.json"
        done = run([*args, "-o", str(own_report)], timeout=timeout)

        result: dict = {
            "command": command,
            "args": args,
            "exit_code": done.returncode,
            "stderr": tail(done.stderr),
            "stdout": tail(done.stdout, 800),
            "findings": [],
            "summary": {},
        }
        if own_report.exists():
            report = read_report(own_report)
            result["findings"] = report.get("findings", [])
            result["summary"] = {
                key: report[key]
                for key in ("target", "started", "finished", "duration", "requests", "endpoints")
                if key in report
            }
            if report_copy:
                copy = Path(report_copy).expanduser()
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_text(json.dumps(report, indent=2), encoding="utf-8")
                result["report_path"] = str(copy)
        elif done.returncode != 0:
            raise CrackwebError(
                f"crackweb {command} failed with exit code {done.returncode}: "
                f"{tail(done.stderr) or tail(done.stdout)}"
            )
        result["finding_count"] = len(result["findings"])
        return result


def scan(options: RequestOptions, target: Target, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """`crackweb scan`, with every flag that command takes."""
    args = ["scan", "-q", *target.args(), *options.args()]
    return one_shot("scan", args, timeout, report_copy=options.report_path)


def crawl(
    options: RequestOptions,
    target: Target,
    depth: int | None = None,
    engine: str | None = None,
    max_pages: int | None = None,
    scope: object = None,
    no_discovery: bool = False,
    allow_state_change: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """`crackweb crawl`, with every flag that command takes."""
    args = ["crawl", "-q", *target.args()]
    args += _flag("--depth", depth)
    args += _flag("--engine", engine)
    args += _flag("--max-pages", max_pages)
    args += _repeat("--scope", scope)
    args += _flag("--no-discovery", no_discovery)
    args += _flag("--allow-state-change", allow_state_change)
    args += options.args()
    return one_shot("crawl", args, timeout, report_copy=options.report_path)


def proxy_args(
    options: RequestOptions,
    listen: str | None = None,
    upstream: str | None = None,
    scope: object = None,
    passive_only: bool = False,
    export_ca: str | None = None,
) -> list[str]:
    """`crackweb proxy`, as a command line. The process itself is managed elsewhere.

    No --quiet here: the proxy command does not have one. Its stdout therefore carries notes
    as well as findings, which is what the reader is built for — a line that is not a finding
    is not read as one.
    """
    args = ["proxy"]
    args += _flag("--listen", listen)
    args += _flag("--upstream", upstream)
    args += _repeat("--scope", scope)
    args += _flag("--passive-only", passive_only)
    args += _flag("--export-ca", export_ca)
    args += options.args()
    return args


def oob_args(
    http: str | None = None,
    dns: str | None = None,
    token: str | None = None,
    domain: str | None = None,
) -> list[str]:
    """`crackweb oob`, as a command line: the out-of-band listener."""
    args = ["oob"]
    args += _flag("--http", http)
    args += _flag("--dns", dns)
    args += _flag("--token", token)
    args += _flag("--domain", domain)
    return args


def local_jwt(
    token: str,
    secret: str | None = None,
    wordlist: str | None = None,
    forge: bool = False,
    claims: object = None,
    timeout: float = 300.0,
) -> dict:
    """`crackweb local jwt`: decode a token, recover its secret, sign one of its own.

    Nothing here sends traffic, which is why it is the one command whose whole point is to be
    run against an artifact the caller already has.
    """
    args = ["local", "jwt", token]
    args += _flag("--secret", secret)
    args += _flag("--wordlist", wordlist)
    args += _flag("--forge", forge)
    args += _repeat("--claim", claims)
    done = run(args, timeout=timeout)
    result = {
        "command": "local jwt",
        "exit_code": done.returncode,
        "stdout": done.stdout.strip(),
        "stderr": tail(done.stderr),
    }
    if done.returncode != 0:
        raise CrackwebError(
            f"crackweb local jwt failed with exit code {done.returncode}: "
            f"{tail(done.stderr) or tail(done.stdout)}"
        )
    return result


def local_hash(
    value: str, wordlist: str | None = None, timeout: float = 300.0
) -> dict:
    """`crackweb local hash`: identify a hash and try to recover what it was made from."""
    args = ["local", "hash", value]
    args += _flag("--wordlist", wordlist)
    done = run(args, timeout=timeout)
    if done.returncode != 0:
        raise CrackwebError(
            f"crackweb local hash failed with exit code {done.returncode}: "
            f"{tail(done.stderr) or tail(done.stdout)}"
        )
    return {
        "command": "local hash",
        "exit_code": done.returncode,
        "stdout": done.stdout.strip(),
        "stderr": tail(done.stderr),
    }


CA_ROW = re.compile(r"^\s{2}(?P<name>[A-Za-z][\w -]{0,15}?)\s{2,}(?P<value>\S.*)$")


def ca(out_dir: str | None = None, force: bool = False, export: str | None = None) -> dict:
    """`crackweb ca`: load or generate the interception CA, and say what it is.

    Reading the block it prints rather than reporting success blindly: the serial, the
    fingerprint and the paths are what a caller needs to decide whether this is the CA it
    expects.
    """
    args = ["ca"]
    args += _flag("--out", out_dir)
    args += _flag("--force", force)
    args += _flag("--export", export)
    done = run(args, timeout=120.0)
    fields: dict[str, str] = {}
    for line in done.stdout.splitlines():
        row = CA_ROW.match(line)
        if row:
            fields[row.group("name").strip().lower()] = row.group("value").strip()
    if done.returncode != 0:
        raise CrackwebError(
            f"crackweb ca failed with exit code {done.returncode}: "
            f"{tail(done.stderr) or tail(done.stdout)}"
        )
    result: dict = {
        "command": "ca",
        "exit_code": done.returncode,
        "ca": fields,
        "stdout": done.stdout.strip(),
        "stderr": tail(done.stderr),
    }
    if len(fields) < 3:
        # The block's labels are read from the output, and the first of them comes from the
        # catalogue rather than from the code. A label long enough to collapse the column gap
        # loses its row, so say how many were readable instead of returning a thin dictionary
        # as if it were the whole block.
        result["warnings"] = [
            f"only {len(fields)} of the block's rows could be read; the raw output is in "
            f"stdout"
        ]
    return result
