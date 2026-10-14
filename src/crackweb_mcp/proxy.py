"""Owning the proxy process between tool calls.

Two things a caller cannot do for itself, and this module does:

* keep the process alive and, more importantly, make sure it dies — an agent will not
  remember to stop a proxy, so every one of them is killed when the server exits and an
  idle one is stopped on its own;
* answer "has it found anything yet?". crackweb has no runtime query interface — its
  report is written when it exits — so the findings stream it prints as findings are
  confirmed is redirected to a file at start, and status queries read that file.

The cursor lives here, one per proxy, and only an explicit status call moves it: a tool
result that mentions the proxy reports how much is waiting without consuming it.
"""

from __future__ import annotations

import atexit
import os
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import crackweb, findings

IDLE_ENV = "CRACKWEB_MCP_IDLE_TIMEOUT"
TMP_ENV = "CRACKWEB_MCP_TMP"
DEFAULT_IDLE = 1800.0
STOP_GRACE = 5.0


def shutdown(process: subprocess.Popen, grace: float = STOP_GRACE) -> None:
    """Ask a proxy to stop the way a person would, and only then insist.

    crackweb writes its report on the way out, and only a signal gives it the chance:
    the proxy handles SIGINT and SIGTERM (`signal.NotifyContext` in the CLI). On POSIX
    that makes terminate() the polite request. On Windows a terminated process runs no
    code at all, so the console break event is tried first — which is why the proxy is
    started in its own process group — and the hard kill is the fallback.
    """
    if process is None or process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.terminate()
        process.wait(timeout=grace)
        return
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.terminate()
        process.wait(timeout=2.0)
    except Exception:  # noqa: BLE001 - the last resort is the hard kill below
        try:
            process.kill()
        except Exception:  # noqa: BLE001 - nothing left to try
            pass


def idle_timeout() -> float:
    """How long a proxy may go untouched before it is stopped. 0 disables it."""
    raw = os.environ.get(IDLE_ENV, "").strip()
    if not raw:
        return DEFAULT_IDLE
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_IDLE


def temp_root() -> Path:
    """Where a run's logs live, until the server exits."""
    root = os.environ.get(TMP_ENV, "").strip()
    base = Path(root).expanduser() if root else Path(tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    return base


def free_port() -> int:
    """A port nothing is listening on, for a proxy the caller did not place."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class Proxy:
    id: str
    listen: str
    process: subprocess.Popen
    findings_log: Path
    trace_log: Path
    report_path: Path
    started_at: float
    last_used: float
    scope: list[str]
    cursor: int = 0

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at


class Registry:
    """Every proxy this server started, and the rules for letting them go."""

    def __init__(self, idle: float | None = None) -> None:
        self._proxies: dict[str, Proxy] = {}
        self._counter = 0
        self._idle = idle_timeout() if idle is None else idle
        self._workdirs: list[Path] = []
        atexit.register(self.stop_all)

    # -- starting ---------------------------------------------------------------

    def start(
        self,
        scope: list[str],
        listen: str | None = None,
        upstream: str | None = None,
        checks: object = None,
        passive_only: bool = False,
        enable_unsafe: bool = False,
    ) -> Proxy:
        """Start a proxy and return it. Scope is not optional.

        A scope is what keeps interception to the hosts that were asked about, and this
        is the one place where a wrong default would be intrusive rather than
        disappointing: without it crackweb intercepts everything it sees.
        """
        wanted = [s for s in (scope or []) if str(s).strip()]
        if not wanted:
            raise crackweb.CrackwebError(
                "scope is required: name the host patterns this proxy may intercept "
                "(for example example.com or 10.0.0.0/8)"
            )

        address = listen or f"127.0.0.1:{free_port()}"
        binary = crackweb.find_binary()
        workdir = Path(tempfile.mkdtemp(prefix="crackweb-mcp-proxy-", dir=temp_root()))
        self._workdirs.append(workdir)

        proxy = Proxy(
            id=f"p{self._counter + 1}",
            listen=address,
            process=None,  # type: ignore[arg-type]  (set below, once it exists)
            findings_log=workdir / "findings.log",
            trace_log=workdir / "trace.log",
            report_path=workdir / "report.json",
            started_at=time.time(),
            last_used=time.time(),
            scope=wanted,
        )

        # No -q here: the proxy command does not have one (quiet belongs to scan and
        # crawl). Its stdout therefore carries notes as well as findings, which is what
        # the reader is built for — a line that is not a finding is not read as one.
        args = ["proxy", "-l", address, "-o", str(proxy.report_path)]
        for pattern in wanted:
            args += ["--scope", str(pattern).strip()]
        if upstream:
            args += ["--upstream", upstream]
        if passive_only:
            args.append("--passive-only")
        args += crackweb.selection_args(checks, enable_unsafe)

        # The child gets the files themselves, not a pipe: it writes straight to them,
        # so a finding is on disk the moment crackweb prints it.
        with proxy.findings_log.open("wb") as out, proxy.trace_log.open("wb") as err:
            proxy.process = subprocess.Popen(  # noqa: S603 - a known binary, fixed argv
                [*crackweb.PREFIX, binary, *args],
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                env=crackweb.environment(),
                cwd=str(workdir),
                **process_group_kwargs(),
            )

        time.sleep(0.4)  # a failed start is worth catching before it is reported as fine
        if proxy.process.poll() is not None:
            reason = crackweb.tail(
                proxy.trace_log.read_text(encoding="utf-8", errors="replace")
            )
            self._proxies[proxy.id] = proxy
            self._counter += 1
            raise crackweb.CrackwebError(
                f"crackweb proxy exited immediately with code {proxy.process.returncode}: {reason}"
            )

        self._counter += 1
        self._proxies[proxy.id] = proxy
        self._reap()
        return proxy

    # -- talking to one ---------------------------------------------------------

    def status(self, proxy_id: str, cursor: int | None = None) -> dict:
        """What has happened since the cursor, and whether the proxy is still up.

        Reading is what moves the cursor, so calling this twice returns nothing twice.
        """
        self._reap()
        proxy = self._get(proxy_id)
        proxy.last_used = time.time()

        started_at = proxy.cursor if cursor is None else max(0, int(cursor))
        new, offset = findings.read_since(proxy.findings_log, started_at)
        # A caller may hand back an older cursor; the stored one only ever moves forward.
        proxy.cursor = max(proxy.cursor, offset)
        # The total is read rather than counted: a status call is rare next to the findings
        # it reports, and a cached counter has to be told about truncated logs and reused
        # cursors — the read is right by construction, and this is not a hot loop.
        total = len(findings.read_all(proxy.findings_log)[0])

        result = {
            "proxy_id": proxy.id,
            "running": proxy.running,
            "listen": proxy.listen,
            "elapsed_s": round(proxy.elapsed, 1),
            "cursor": offset,
            "new_findings": new,
            "new_count": len(new),
            "findings_total": total,
            "findings_log": str(proxy.findings_log),
        }
        if not proxy.running:
            result["exit_code"] = proxy.process.returncode
            result["note"] = (
                "the proxy has exited; stop_proxy returns everything it found, and the "
                "report it wrote is at report_path"
            )
        return result

    def stop(self, proxy_id: str, include_report: bool = False) -> dict:
        """Stop a proxy and return what it found. Stopping twice is not an error."""
        proxy = self._get(proxy_id)
        proxy.last_used = time.time()

        if proxy.running:
            shutdown(proxy.process)

        # The report is written on the way out, so it is read after the wait, and only
        # when the caller asked for it: it is much larger than the findings.
        collected, end = findings.read_all(proxy.findings_log)
        # Everything has just been handed over, so the cursor goes to the end: a stopped
        # proxy then stops appearing in other tools' results, having nothing left to say.
        proxy.cursor = end
        result = {
            "proxy_id": proxy.id,
            "stopped": True,
            "listen": proxy.listen,
            "ran_for_s": round(proxy.elapsed, 1),
            "exit_code": proxy.process.returncode,
            "findings": collected,
            "finding_count": len(collected),
            "findings_log": str(proxy.findings_log),
            "report_path": str(proxy.report_path),
            "report_written": proxy.report_path.exists(),
        }
        if not result["report_written"]:
            # Saying why is more useful than a false, and the reason differs by platform: on
            # Windows a stopped process runs no code at all (the console break event this
            # stops with is not one of the signals the proxy handles, so it never gets to the
            # point of writing), while on POSIX the signal it handles was sent and it left
            # before writing anyway. Either way the findings above come from the live stream
            # and are complete.
            if os.name == "nt":
                result["report_note"] = (
                    "crackweb writes its report on the way out, and a process stopped on "
                    "Windows runs no code at all. The findings above come from the live "
                    "stream."
                )
            else:
                result["report_note"] = (
                    "crackweb writes its report on the way out and did not get that far. "
                    "The findings above come from the live stream."
                )
        if include_report and proxy.report_path.exists():
            import json

            result["report"] = json.loads(proxy.report_path.read_text(encoding="utf-8"))
        return result

    # -- about all of them ------------------------------------------------------

    def summary(self) -> list[dict]:
        """A line per proxy for the result of any other tool.

        This is how a caller that never thinks to ask learns that something was found: the
        count is how much is waiting after its cursor, and reading is left to the status call
        that means it. A proxy that has stopped and been read is left out — there is nothing
        left to tell anyone about it.

        The idle check runs here too, because this is the path every other tool takes: a
        caller that only ever calls list_checks or scan is exactly the one whose proxy has to
        stop itself.
        """
        self._reap()
        out: list[dict] = []
        for proxy in self._proxies.values():
            waiting = findings.count_since(proxy.findings_log, proxy.cursor)
            if not proxy.running and waiting == 0:
                continue
            out.append(
                {
                    "proxy_id": proxy.id,
                    "running": proxy.running,
                    "listen": proxy.listen,
                    "findings_total": len(findings.read_all(proxy.findings_log)[0]),
                    "new_findings_waiting": waiting,
                    "cursor": proxy.cursor,
                }
            )
        return out

    def stop_all(self) -> None:
        """Kill everything this server started. Called on exit, and safe to call twice."""
        for proxy in list(self._proxies.values()):
            if proxy.running:
                try:
                    shutdown(proxy.process)
                except Exception:  # noqa: BLE001 - shutdown must not raise
                    pass
        for workdir in self._workdirs:
            try:
                for path in workdir.iterdir():
                    path.unlink()
                workdir.rmdir()
            except Exception:  # noqa: BLE001 - leaving a log behind is not worth failing
                pass

    # -- internals --------------------------------------------------------------

    def _get(self, proxy_id: str) -> Proxy:
        proxy = self._proxies.get(proxy_id)
        if proxy is None:
            known = ", ".join(self._proxies) or "none"
            raise crackweb.CrackwebError(f"unknown proxy {proxy_id!r}; known: {known}")
        return proxy

    def _reap(self) -> None:
        """Stop proxies nobody has asked about for a while."""
        if self._idle <= 0:
            return
        now = time.time()
        for proxy in list(self._proxies.values()):
            if proxy.running and now - proxy.last_used > self._idle:
                try:
                    shutdown(proxy.process)
                except Exception:  # noqa: BLE001 - reaping is best effort
                    pass


def process_group_kwargs() -> dict:
    """Start the proxy in its own process group, so stopping it can be graceful.

    On Windows that is what makes a console break event deliverable to the child (and
    keeps it from opening a window of its own). crackweb does not fork helpers, and the
    browser it can drive is started only for a check that asks for it.
    """
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        return {"creationflags": flags}
    return {"start_new_session": True}
