"""Acceptance: a real crackweb binary, a local target, and the calls an agent would make.

This is not a unit test — it needs an installed crackweb. Point CRACKWEB_BIN at one, or
pass its path, and run it. It starts a proxy, sends one request through it with curl, asks
for findings while the proxy is still up, and stops it. It exits non-zero if no finding
appeared, which is the whole point of the exercise.

    python scripts/acceptance.py /path/to/crackweb
"""

from __future__ import annotations

import http.server
import os
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from crackweb_mcp import tools  # noqa: E402
from crackweb_mcp.proxy import Registry  # noqa: E402

FINDING_WAIT_S = 90


class Target(http.server.BaseHTTPRequestHandler):
    """A target with something to find: an environment file nobody linked to."""

    def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
        if self.path == "/.env":
            body = b"APP_KEY=base64:crackweb\nDB_PASSWORD=hunter2\n"
        elif self.path in ("/", "/index.html"):
            body = b"<html><body><h1>acceptance target</h1></body></html>"
        else:
            self.send_error(404, "not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def main(argv: list[str]) -> int:
    if argv:
        os.environ["CRACKWEB_BIN"] = argv[0]
    os.environ.setdefault("CRACKWEB_MCP_TMP", str(Path(os.environ.get("TEMP", "/tmp")) / "crackweb-mcp-runs"))

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Target)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{port}/index.html"
    print(f"local target: {target}")

    registry = Registry(idle=0)
    findings: list[dict] = []
    try:
        started = tools.start_proxy(registry, scope=["127.0.0.1"])
        print(f"proxy {started['proxy_id']} listening on {started['listen']}")

        curl = subprocess.run(
            [
                "curl", "-sS", "--noproxy", "", "-x", f"http://{started['listen']}",
                "-o", os.devnull, "-w", "%{http_code}", target,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        print(f"request through the proxy: {curl.stdout.strip()} {curl.stderr.strip()[:200]}")

        deadline = time.time() + FINDING_WAIT_S
        while time.time() < deadline:
            time.sleep(4)
            status = tools.proxy_status(registry, started["proxy_id"])
            print(
                f"  status: running={status['running']} new={status['new_count']} "
                f"total={status['findings_total']} elapsed={status['elapsed_s']}s"
            )
            for found in status["new_findings"]:
                print(f"    {found['severity']:8} {found['check']:24} {found['url']}")
            findings.extend(status["new_findings"])
            if status["new_count"] or not status["running"]:
                break

        stopped = tools.stop_proxy(registry, started["proxy_id"])
        print(
            "stopped: findings=%d report_written=%s"
            % (stopped["finding_count"], stopped["report_written"])
        )
        if not stopped["report_written"]:
            print("  note:", stopped.get("report_note", ""))
    finally:
        registry.stop_all()
        server.shutdown()

    if not findings:
        print("no findings appeared: the proxy ran but nothing was reported")
        return 1
    print(f"ok: {len(findings)} finding(s) through the proxy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
