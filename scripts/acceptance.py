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

from crackweb_mcp import crackweb, tools  # noqa: E402
from crackweb_mcp.crackweb import RequestOptions  # noqa: E402
from crackweb_mcp.processes import Registry  # noqa: E402

FINDING_WAIT_S = 90


class LabTarget(http.server.BaseHTTPRequestHandler):
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


def check_flags() -> list[str]:
    """Every flag the wrapper can build has to be one the command documents.

    The stand-in binary the unit tests use ignores flags it does not know, so a misspelling
    is invisible there: `-q`, which crackweb does not define, reached a user before this check
    existed. This asks the real one.
    """
    options = RequestOptions(
        checks="all", enable_unsafe=True, sessions=["Cookie: a=b"], cookies=["a=b"],
        headers=["X: y"], basic_auth="a:b", jwt_secrets=["k"], proxy="http://127.0.0.1:1",
        request_timeout="5s", rate=1.0, threads=1, sensitivity=1, insecure=True,
        user_agent="ua", random_ua=True, templates=["/tmp/t"], skip_params=["p"],
        no_normalize=True, verbose=True, no_waf=True, no_assume_waf=True,
        oob_http="127.0.0.1:1", oob_dns="127.0.0.1:2", oob_domain="d.example.com",
        oob_interactsh="https://interact.example.com", oob_token="t", report_path="/tmp/r.json",
    )
    target = crackweb.Target(
        url="http://127.0.0.1/", method="GET", data="a=b", forms=True,
    )
    plans = {
        "scan": ["scan", "--quiet", *target.args(), *options.args()],
        "crawl": [
            "crawl", "--quiet", "--url", "http://127.0.0.1/", "--api-doc", "/openapi.json",
            "--depth", "1", "--engine", "http",
            "--max-pages", "1", "--scope", "x", "--no-discovery", "--allow-state-change",
            *options.args(),
        ],
        "proxy": crackweb.proxy_args(
            options, listen="127.0.0.1:1", upstream="http://127.0.0.1:2", scope=["x"],
            passive_only=True, export_ca="/tmp/ca.crt",
        ),
        "oob": crackweb.oob_args(http="127.0.0.1:1", dns="127.0.0.1:2", token="t",
                                 domain="d.example.com"),
    }

    problems: list[str] = []
    for command, args in plans.items():
        documented = crackweb.run([command, "--help"], timeout=60).stdout
        for flag in sorted({item for item in args if item.startswith("--")}):
            if flag not in documented:
                problems.append(f"{command} does not document {flag}")
    return problems


def signed_token(claims: dict, secret: str) -> str:
    """An HS256 token, signed here: what a target's session cookie might hold."""
    import base64
    import hashlib
    import hmac
    import json as _json

    def part(value: object) -> str:
        raw = _json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    body = f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(claims)}"
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def main(argv: list[str]) -> int:
    if argv:
        os.environ["CRACKWEB_BIN"] = argv[0]
    os.environ.setdefault("CRACKWEB_MCP_TMP", str(Path(os.environ.get("TEMP", "/tmp")) / "crackweb-mcp-runs"))

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), LabTarget)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{port}/index.html"
    print(f"local target: {target}")

    registry = Registry(idle=0)
    findings: list[dict] = []
    try:
        # The flags first: a flag the real binary does not accept would make every scan and
        # crawl fail, and the stand-in the unit tests use cannot tell.
        problems = check_flags()
        print("flag check:", "ok" if not problems else problems)

        # A scan through the wrapper, on the same local target the proxy uses: this is the
        # path a caller takes most often, and the one whose flags are easiest to get wrong.
        scanned = tools.scan(
            registry,
            crackweb.Target(url=target),
            RequestOptions(checks="exposed-path", report_path=str(Path(os.environ.get("TEMP", "/tmp")) / "crackweb-mcp-acceptance.json")),
        )
        print(
            "scan through the wrapper: findings=%d requests=%s report_written=%s"
            % (scanned["finding_count"], scanned["summary"].get("requests"),
               bool(scanned.get("report_path")))
        )
        for found in scanned["findings"]:
            print(f"    {found.get('severity'):8} {found.get('check'):24} {found.get('url')}")

        started = tools.start_proxy(registry, ["127.0.0.1"], RequestOptions())
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

    # The offline side, with the same binary: sign a token here, and let crackweb say what it
    # is and recover the key. Nothing is sent anywhere, so this needs no target at all.
    token = signed_token({"sub": "admin", "role": "admin"}, "hunter2")
    decoded = tools.local_jwt(Registry(idle=0), token, secret="hunter2")
    print("offline: crackweb read the token back as")
    print("  " + decoded["stdout"].replace("\n", "\n  "))
    if "admin" not in decoded["stdout"]:
        print("the token's claims did not come back")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
