"""The background processes this server owns: the intercepting proxy, and the OOB listener.

Both are long-running children whose useful output is a stream of lines they print as things
happen — findings for one, callbacks for the other. So both are started with that stream
redirected to a file, both are read through a monotonic byte cursor, and both are stopped
when this server exits or when nobody has asked about them for a while.

Two things a caller cannot do for itself, and this module does:

* keep the process alive and, more importantly, make sure it dies — an agent will not
  remember to stop one, so every process is killed when the server exits and an idle one is
  stopped on its own;
* answer "has anything happened yet?". crackweb has no runtime query interface — its report
  is written when the proxy exits — so the stream it prints is the answer, and the cursor is
  how much of it a caller has already been told.
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import crackweb, events, findings, logs

IDLE_ENV = "CRACKWEB_MCP_IDLE_TIMEOUT"
TMP_ENV = "CRACKWEB_MCP_TMP"
DEFAULT_IDLE = 1800.0
STOP_GRACE = 5.0

# One parser per kind of process: what a line in its stream means.
PARSERS = {
    "proxy": findings.parse,
    "oob": events.parse,
}


def idle_timeout() -> float:
    """How long a process may go untouched before it is stopped. 0 disables it."""
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
    """A port nothing is listening on, for a process the caller did not place."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def shutdown(process: subprocess.Popen, grace: float = STOP_GRACE) -> None:
    """Ask a process to stop the way a person would, and only then insist.

    crackweb writes its report on the way out, and only a signal gives it the chance: the
    proxy handles SIGINT and SIGTERM (`signal.NotifyContext` in the CLI). On POSIX that makes
    terminate() the polite request. On Windows a terminated process runs no code at all, so
    the console break event is tried first — which is why the child is started in its own
    process group — and the hard kill is the fallback.
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


@dataclass
class Process:
    """One child, its stream, and how far a caller has read it."""

    id: str
    kind: str
    listen: str
    process: subprocess.Popen
    log: Path
    trace: Path
    started_at: float
    last_used: float
    scope: list[str] = field(default_factory=list)
    report_path: Path | None = None
    cursor: int = 0

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    def parsed(self, text: str) -> list[dict]:
        return PARSERS[self.kind](text)

    def read_since(self, offset: int) -> tuple[list[dict], int]:
        text, new_offset = logs.read_text_since(self.log, offset)
        if not text:
            return [], new_offset
        return self.parsed(text), new_offset

    def read_all(self) -> tuple[list[dict], int]:
        return self.read_since(0)

    def count_since(self, offset: int) -> int:
        return len(self.read_since(offset)[0])


class Registry:
    """Every process this server started, and the rules for letting them go."""

    def __init__(self, idle: float | None = None) -> None:
        self._processes: dict[str, Process] = {}
        self._counter = 0
        self._idle = idle_timeout() if idle is None else idle
        self._workdirs: list[Path] = []
        atexit.register(self.stop_all)

    # -- starting ---------------------------------------------------------------

    def start_proxy(
        self,
        options: crackweb.RequestOptions,
        scope: list[str],
        listen: str | None = None,
        upstream: str | None = None,
        passive_only: bool = False,
        export_ca: str | None = None,
    ) -> Process:
        """Start the intercepting proxy. Scope is not optional.

        A scope is what keeps interception to the hosts that were asked about, and this is
        the one place where a wrong default would be intrusive rather than disappointing:
        without it crackweb intercepts everything it sees.
        """
        wanted = [s for s in (scope or []) if str(s).strip()]
        if not wanted:
            raise crackweb.CrackwebError(
                "scope is required: name the host patterns this proxy may intercept "
                "(for example example.com or 10.0.0.0/8)"
            )

        address = listen or f"127.0.0.1:{free_port()}"
        args = crackweb.proxy_args(
            options,
            listen=address,
            upstream=upstream,
            scope=[str(s).strip() for s in wanted],
            passive_only=passive_only,
            export_ca=export_ca,
        )
        return self._spawn("proxy", args, listen=address, scope=wanted)

    def start_oob(
        self,
        http: str | None = None,
        dns: str | None = None,
        token: str | None = None,
        domain: str | None = None,
    ) -> Process:
        """Start the out-of-band listener, which collects callbacks from the target."""
        args = crackweb.oob_args(http=http, dns=dns, token=token, domain=domain)
        return self._spawn("oob", args, listen="")

    def _spawn(self, kind: str, args: list[str], listen: str, scope: list[str] | None = None) -> Process:
        binary = crackweb.find_binary()
        workdir = Path(tempfile.mkdtemp(prefix=f"crackweb-mcp-{kind}-", dir=temp_root()))
        self._workdirs.append(workdir)

        self._counter += 1
        entry = Process(
            id=("%s%d" % (kind[0], self._counter)),
            kind=kind,
            listen=listen,
            process=None,  # type: ignore[arg-type]  (set below, once it exists)
            log=workdir / "stream.log",
            trace=workdir / "trace.log",
            started_at=time.time(),
            last_used=time.time(),
            scope=list(scope or []),
            report_path=workdir / "report.json" if kind == "proxy" else None,
        )
        if kind == "proxy":
            args = [*args, "-o", str(entry.report_path)]

        # The child gets the files themselves, not a pipe: it writes straight to them, so a
        # finding is on disk the moment crackweb prints it.
        with entry.log.open("wb") as out, entry.trace.open("wb") as err:
            entry.process = subprocess.Popen(  # noqa: S603 - a known binary, fixed argv
                [*crackweb.PREFIX, binary, *args],
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                env=crackweb.environment(),
                cwd=str(workdir),
                **process_group_kwargs(),
            )

        time.sleep(0.4)  # a failed start is worth catching before it is reported as fine
        if entry.process.poll() is not None:
            # Not registered: a process that is already gone has nothing to report, and an
            # entry for it would only sit in every later result. Its workdir is tracked
            # separately, so stop_all still cleans up.
            raise crackweb.CrackwebError(
                f"crackweb {args[0]} exited immediately with code "
                f"{entry.process.returncode}: {self._trace_text(entry)}"
            )

        if kind == "oob":
            time.sleep(0.3)  # it names its addresses on the way up
            entry.listen = self._listening(entry)

        self._processes[entry.id] = entry
        self._reap()
        return entry

    # -- talking to one ---------------------------------------------------------

    def status(self, process_id: str, cursor: int | None = None) -> dict:
        """What has happened since the cursor, and whether the process is still up.

        Reading is what moves the cursor, so calling this twice returns nothing twice.
        """
        self._reap()
        entry = self._get(process_id)
        entry.last_used = time.time()

        started_at = entry.cursor if cursor is None else max(0, int(cursor))
        new, offset = entry.read_since(started_at)
        # A caller may hand back an older cursor; the stored one only ever moves forward. The
        # value handed back is the stored one, so a client that echoes it cannot ask for the
        # same items twice.
        entry.cursor = max(entry.cursor, offset)
        offset = entry.cursor
        # The total is read rather than counted: a status call is rare next to what it
        # reports, and a cached counter would have to be told about truncated logs and reused
        # cursors — the read is right by construction, and this is not a hot loop.
        total = len(entry.read_all()[0])

        result: dict = {
            "kind": entry.kind,
            f"{entry.kind}_id": entry.id,
            "running": entry.running,
            "listen": entry.listen,
            "elapsed_s": round(entry.elapsed, 1),
            "cursor": offset,
            f"new_{'findings' if entry.kind == 'proxy' else 'events'}": new,
            "new_count": len(new),
            f"{'findings' if entry.kind == 'proxy' else 'events'}_total": total,
            "log": str(entry.log),
        }
        if entry.kind == "oob":
            result["listening"] = self._listened(entry)
        if not entry.running:
            result["exit_code"] = entry.process.returncode
            result["note"] = (
                f"the {entry.kind} has exited; stop_{entry.kind} returns everything it saw"
            )
        return result

    def stop(self, process_id: str, include_report: bool = False) -> dict:
        """Stop a process and return what it saw. Stopping twice is not an error."""
        entry = self._get(process_id)
        entry.last_used = time.time()

        if entry.running:
            shutdown(entry.process)

        # A proxy writes its report on the way out, so it is read after the wait, and only
        # when the caller asked for it: it is much larger than the findings.
        collected, end = entry.read_all()
        # Everything has just been handed over, so the cursor goes to the end: a stopped
        # process then stops appearing in other tools' results, having nothing left to say.
        entry.cursor = end

        key = "findings" if entry.kind == "proxy" else "events"
        result: dict = {
            "kind": entry.kind,
            f"{entry.kind}_id": entry.id,
            "stopped": True,
            "listen": entry.listen,
            "ran_for_s": round(entry.elapsed, 1),
            "exit_code": entry.process.returncode,
            key: collected,
            f"{key[:-1]}_count": len(collected),
            "log": str(entry.log),
        }
        if entry.kind != "proxy":
            return result

        result["report_path"] = str(entry.report_path)
        result["report_written"] = Path(entry.report_path).exists()  # type: ignore[arg-type]
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
        if include_report and result["report_written"]:
            result["report"] = json.loads(
                Path(entry.report_path).read_text(encoding="utf-8")  # type: ignore[arg-type]
            )
        return result

    # -- about all of them ------------------------------------------------------

    def summary(self) -> list[dict]:
        """A line per process for the result of any other tool.

        This is how a caller that never thinks to ask learns that something was found: the
        count is how much is waiting after its cursor, and reading is left to the status call
        that means it. A process that has stopped and been read is left out — there is
        nothing left to tell anyone about it.

        The idle check runs here too, because this is the path every other tool takes: a
        caller that only ever calls list_checks or scan is exactly the one whose processes
        have to stop themselves.
        """
        self._reap()
        out: list[dict] = []
        for entry in self._processes.values():
            waiting = entry.count_since(entry.cursor)
            if not entry.running and waiting == 0:
                continue
            out.append(
                {
                    "kind": entry.kind,
                    f"{entry.kind}_id": entry.id,
                    "running": entry.running,
                    "listen": entry.listen,
                    "items_total": len(entry.read_all()[0]),
                    "new_items_waiting": waiting,
                    "cursor": entry.cursor,
                }
            )
        return out

    def stop_all(self) -> None:
        """Kill everything this server started. Called on exit, and safe to call twice."""
        for entry in list(self._processes.values()):
            if entry.running:
                try:
                    shutdown(entry.process)
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

    def _get(self, process_id: str) -> Process:
        entry = self._processes.get(process_id)
        if entry is None:
            known = ", ".join(self._processes) or "none"
            raise crackweb.CrackwebError(f"unknown process {process_id!r}; known: {known}")
        return entry

    def _reap(self) -> None:
        """Stop processes nobody has asked about for a while."""
        if self._idle <= 0:
            return
        now = time.time()
        for entry in list(self._processes.values()):
            if entry.running and now - entry.last_used > self._idle:
                try:
                    shutdown(entry.process)
                except Exception:  # noqa: BLE001 - reaping is best effort
                    pass

    def _stream_text(self, entry: Process, limit: int = 4000) -> str:
        try:
            return entry.log.read_text(encoding="utf-8", errors="replace")[-limit:]
        except OSError:
            return ""

    def _trace_text(self, entry: Process, limit: int = 2000) -> str:
        try:
            return crackweb.tail(entry.trace.read_text(encoding="utf-8", errors="replace"), limit)
        except OSError:
            return ""

    def _listened(self, entry: Process) -> dict:
        """What the listener said about itself, whichever stream carried it.

        It names its addresses on stderr (a note) and mints its callback address on stdout,
        so both streams are searched: what matters is the content, not the stream.
        """
        found: dict = {}
        for text in (self._trace_text(entry), self._stream_text(entry)):
            found.update({k: v for k, v in events.listening(text).items() if v})
            url = events.callback_url(text)
            if url:
                found["callback_url"] = url
        return found

    def _listening(self, entry: Process) -> str:
        found = self._listened(entry)
        if not found.get("http"):
            return ""
        return "http %s, dns %s" % (found.get("http", "?"), found.get("dns", "?"))


def process_group_kwargs() -> dict:
    """Start the child in its own process group, so stopping it can be graceful.

    On Windows that is what makes a console break event deliverable (and keeps the child from
    opening a window of its own). crackweb does not fork helpers, and the browser it can drive
    is started only for a check that asks for it.
    """
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        return {"creationflags": flags}
    return {"start_new_session": True}
