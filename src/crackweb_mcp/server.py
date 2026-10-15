"""The MCP surface: one tool per crackweb command, and the state that ties them together.

A tool description is the contract a client reads before it calls anything, so each one says
what it does, which of its parameters change what gets tested, and what the result will look
like. Nothing here asks a client to behave in a particular way — a description that said
"call this every few steps" would be a promise this server cannot keep.

Nothing may be written to stdout: that is the protocol channel. Anything a human might want
to see goes to stderr.
"""

from __future__ import annotations

import os
import signal
import sys

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCP_Server
except ImportError:  # mcp 2.x renamed FastMCP to MCPServer, and kept the same shape
    from mcp.server.mcpserver import MCPServer as MCP_Server

from . import __version__, crackweb, tools
from .crackweb import RequestOptions, Target
from .processes import Registry

INSTRUCTIONS = (
    "crackweb is a traffic-driven web DAST scanner. These tools run its commands: scan and "
    "crawl test a target, the proxy tools test traffic you generate, the oob tools collect "
    "out-of-band callbacks, and local_* work offline on an artifact you already have. "
    "Findings are confirmed evidence rather than guesses, so report them as they are, with "
    "the evidence beside them. Checks marked opt-in in list_checks run page scripts or write "
    "to a shared cache: those only run when a call says enable_unsafe. A proxy needs a scope "
    "— the hosts it may intercept — and nothing outside it is touched."
)

# The parameters scan, crawl and start_proxy share, in the words a client reads. Kept in one
# place so the three signatures cannot drift apart.
SHARED_PARAMS = """
    checks: Which checks to run: names, tags, or "all" (see list_checks).
    enable_unsafe: Run the opt-in checks too — the ones that execute page scripts or write to
        a shared cache. Off unless a caller asks, because they change the target.
    sessions: Full header lines of identities to scan as, e.g. "Cookie: sess=alice". Two of
        them enable the access-control check, which needs two people to compare.
    cookies: Cookie headers, e.g. "sess=alice; uid=1". Repeatable.
    headers: Extra headers, e.g. "X-Api-Key: ...". Repeatable.
    basic_auth: HTTP Basic credentials, "user:password".
    jwt_secrets: Known signing keys to try against the tokens the target issues.
    proxy: Send the scanner's own probes through this proxy, e.g. "http://127.0.0.1:8080".
    request_timeout: How long one request may take, e.g. "30s".
    rate: Requests per second to stay under. 0 means as fast as the target answers.
    threads: How many requests run at once.
    sensitivity: 1-5, how readily a response difference counts as a finding.
    insecure: Accept invalid TLS certificates. Its own choice, not a default.
    user_agent: The User-Agent to send.
    random_ua: Pick a random User-Agent instead.
    templates: Directories of nuclei-style templates to load as checks. Repeatable.
    skip_params: Parameter names never to test. Repeatable.
    no_normalize: Compare responses without the normaliser.
    verbose: Print every request a check sends to stderr.
    no_waf: Do not treat the target as filtered.
    no_assume_waf: Detect a firewall but never assume one.
    oob_http: The HTTP address of an out-of-band listener to plant, e.g. "10.0.0.5:8081".
    oob_dns: The DNS address of that listener.
    oob_domain: The domain the listener is reachable as.
    oob_interactsh: An interactsh server to use instead of a local listener.
    oob_token: The token that server was started with.
    report_path: Also write the report here. The findings come back either way.
    timeout_s: How long this tool call may take before it gives up.
"""


def _options(**kwargs: object) -> RequestOptions:
    """The shared options, with everything the caller left alone left alone."""
    given = {k: v for k, v in kwargs.items() if v is not None and v is not False and v != ""}
    return RequestOptions(**given)  # type: ignore[arg-type]


def build_server(registry: Registry | None = None) -> MCP_Server:
    """Wire the tools onto a server. One registry, so one place processes live."""
    registry = registry or Registry()
    server = MCP_Server(name="crackweb", instructions=INSTRUCTIONS)

    @server.tool(
        name="list_checks",
        description=(
            "Every check the installed crackweb offers: id, severity, tags, and whether it is "
            "opt-in. Call it before choosing checks for a scan."
        ),
    )
    def list_checks() -> dict:
        return tools.list_checks(registry)

    @server.tool(
        name="scan",
        description=(
            "Test one request once and return the report's findings. url is the address to "
            "test; raw is a file holding a full request line instead, for anything a URL "
            "cannot say. options:"
            + SHARED_PARAMS
        ),
    )
    def scan(
        url: str | None = None,
        raw: str | None = None,
        method: str | None = None,
        data: str | None = None,
        forms: bool = False,
        checks: str | None = None,
        enable_unsafe: bool = False,
        sessions: list[str] | None = None,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        basic_auth: str | None = None,
        jwt_secrets: list[str] | None = None,
        proxy: str | None = None,
        request_timeout: str | None = None,
        rate: float | None = None,
        threads: int | None = None,
        sensitivity: int | None = None,
        insecure: bool = False,
        user_agent: str | None = None,
        random_ua: bool = False,
        templates: list[str] | None = None,
        skip_params: list[str] | None = None,
        no_normalize: bool = False,
        verbose: bool = False,
        no_waf: bool = False,
        no_assume_waf: bool = False,
        oob_http: str | None = None,
        oob_dns: str | None = None,
        oob_domain: str | None = None,
        oob_interactsh: str | None = None,
        oob_token: str | None = None,
        report_path: str | None = None,
        timeout_s: float | None = None,
    ) -> dict:
        return tools.scan(
            registry,
            Target(url=url, raw=raw, method=method, data=data, forms=forms),
            _options(
                checks=checks, enable_unsafe=enable_unsafe, sessions=sessions, cookies=cookies,
                headers=headers, basic_auth=basic_auth, jwt_secrets=jwt_secrets, proxy=proxy,
                request_timeout=request_timeout, rate=rate, threads=threads,
                sensitivity=sensitivity, insecure=insecure, user_agent=user_agent,
                random_ua=random_ua, templates=templates, skip_params=skip_params,
                no_normalize=no_normalize, verbose=verbose, no_waf=no_waf,
                no_assume_waf=no_assume_waf, oob_http=oob_http, oob_dns=oob_dns,
                oob_domain=oob_domain, oob_interactsh=oob_interactsh, oob_token=oob_token,
                report_path=report_path,
            ),
            timeout_s=timeout_s,
        )

    @server.tool(
        name="crawl",
        description=(
            "Discover a target's pages and test them — usually the first call against a site. "
            "Beyond the shared options it takes: depth and max_pages to bound the crawl, "
            "engine (http, headless or hybrid), scope to allow more hosts than the seed, "
            "api_docs to read an API description from a path you name, no_discovery to look "
            "at nothing but the addresses given, and allow_state_change if sending a form is "
            "acceptable. options:"
            + SHARED_PARAMS
        ),
    )
    def crawl(
        url: str | None = None,
        depth: int | None = None,
        engine: str | None = None,
        max_pages: int | None = None,
        scope: str | list[str] | None = None,
        api_docs: list[str] | None = None,
        no_discovery: bool = False,
        allow_state_change: bool = False,
        checks: str | None = None,
        enable_unsafe: bool = False,
        sessions: list[str] | None = None,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        basic_auth: str | None = None,
        jwt_secrets: list[str] | None = None,
        proxy: str | None = None,
        request_timeout: str | None = None,
        rate: float | None = None,
        threads: int | None = None,
        sensitivity: int | None = None,
        insecure: bool = False,
        user_agent: str | None = None,
        random_ua: bool = False,
        templates: list[str] | None = None,
        skip_params: list[str] | None = None,
        no_normalize: bool = False,
        verbose: bool = False,
        no_waf: bool = False,
        no_assume_waf: bool = False,
        oob_http: str | None = None,
        oob_dns: str | None = None,
        oob_domain: str | None = None,
        oob_interactsh: str | None = None,
        oob_token: str | None = None,
        report_path: str | None = None,
        timeout_s: float | None = None,
    ) -> dict:
        return tools.crawl(
            registry,
            Target(url=url),
            _options(
                checks=checks, enable_unsafe=enable_unsafe, sessions=sessions, cookies=cookies,
                headers=headers, basic_auth=basic_auth, jwt_secrets=jwt_secrets, proxy=proxy,
                request_timeout=request_timeout, rate=rate, threads=threads,
                sensitivity=sensitivity, insecure=insecure, user_agent=user_agent,
                random_ua=random_ua, templates=templates, skip_params=skip_params,
                no_normalize=no_normalize, verbose=verbose, no_waf=no_waf,
                no_assume_waf=no_assume_waf, oob_http=oob_http, oob_dns=oob_dns,
                oob_domain=oob_domain, oob_interactsh=oob_interactsh, oob_token=oob_token,
                report_path=report_path,
            ),
            depth=depth,
            engine=engine,
            max_pages=max_pages,
            scope=scope,
            api_docs=api_docs,
            no_discovery=no_discovery,
            allow_state_change=allow_state_change,
            timeout_s=timeout_s,
        )

    @server.tool(
        name="start_proxy",
        description=(
            "Start an intercepting proxy and return its address; point whatever generates "
            "traffic at it (curl -x, a script's proxy setting) and crackweb tests that traffic "
            "as it passes. scope is required and lists the host patterns the proxy may "
            "intercept — anything else is tunnelled untouched. upstream sends everything the "
            "proxy fetches through another proxy, passive_only watches without ever sending a "
            "request of its own, and export_ca writes the interception certificate to a file. "
            "The proxy is stopped when this server exits, and on its own if left idle. "
            "options:" + SHARED_PARAMS
        ),
    )
    def start_proxy(
        scope: str | list[str],
        listen: str | None = None,
        upstream: str | None = None,
        passive_only: bool = False,
        export_ca: str | None = None,
        checks: str | None = None,
        enable_unsafe: bool = False,
        sessions: list[str] | None = None,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        basic_auth: str | None = None,
        jwt_secrets: list[str] | None = None,
        proxy: str | None = None,
        request_timeout: str | None = None,
        rate: float | None = None,
        threads: int | None = None,
        sensitivity: int | None = None,
        insecure: bool = False,
        user_agent: str | None = None,
        random_ua: bool = False,
        templates: list[str] | None = None,
        skip_params: list[str] | None = None,
        no_normalize: bool = False,
        verbose: bool = False,
        no_waf: bool = False,
        no_assume_waf: bool = False,
        oob_http: str | None = None,
        oob_dns: str | None = None,
        oob_domain: str | None = None,
        oob_interactsh: str | None = None,
        oob_token: str | None = None,
        report_path: str | None = None,
    ) -> dict:
        return tools.start_proxy(
            registry,
            scope,
            _options(
                checks=checks, enable_unsafe=enable_unsafe, sessions=sessions, cookies=cookies,
                headers=headers, basic_auth=basic_auth, jwt_secrets=jwt_secrets, proxy=proxy,
                request_timeout=request_timeout, rate=rate, threads=threads,
                sensitivity=sensitivity, insecure=insecure, user_agent=user_agent,
                random_ua=random_ua, templates=templates, skip_params=skip_params,
                no_normalize=no_normalize, verbose=verbose, no_waf=no_waf,
                no_assume_waf=no_assume_waf, oob_http=oob_http, oob_dns=oob_dns,
                oob_domain=oob_domain, oob_interactsh=oob_interactsh, oob_token=oob_token,
                report_path=report_path,
            ),
            listen=listen,
            upstream=upstream,
            passive_only=passive_only,
            export_ca=export_ca,
        )

    @server.tool(
        name="proxy_status",
        description=(
            "What the proxy has found since your cursor, and whether it is still running. The "
            "cursor is in the reply: pass it back to get only what is new, or omit it to "
            "continue from where the last call left off. Reading moves the cursor, so calling "
            "this often is cheap and never repeats a finding — and every other tool's result "
            "carries how many findings are waiting for you."
        ),
    )
    def proxy_status(proxy_id: str, cursor: int | None = None) -> dict:
        return tools.proxy_status(registry, proxy_id, cursor=cursor)

    @server.tool(
        name="stop_proxy",
        description=(
            "Stop the proxy and return everything it found. Safe to call twice. Set "
            "include_report to also get the full report crackweb wrote on exit — it is much "
            "larger than the findings, and on Windows it may not exist at all."
        ),
    )
    def stop_proxy(proxy_id: str, include_report: bool = False) -> dict:
        return tools.stop_proxy(registry, proxy_id, include_report=include_report)

    @server.tool(
        name="start_oob",
        description=(
            "Start an out-of-band listener: a place the target can call back to, which is what "
            "makes blind vulnerabilities (blind SSRF, blind injection) demonstrable. It is "
            "started on loopback on free ports unless you name addresses with http and dns, "
            "and with domain when the target has to reach a name. Pass the addresses it "
            "returns to scan or crawl as oob_http and oob_dns. Stopped when this server exits, "
            "and on its own if left idle."
        ),
    )
    def start_oob(
        http: str | None = None,
        dns: str | None = None,
        token: str | None = None,
        domain: str | None = None,
    ) -> dict:
        return tools.start_oob(registry, http=http, dns=dns, token=token, domain=domain)

    @server.tool(
        name="oob_status",
        description=(
            "Callbacks the listener has collected since your cursor: when, over which "
            "protocol, from where, and the detail that says which injection caused it. The "
            "cursor works exactly like proxy_status's, and a callback is what turns 'the "
            "target behaved oddly' into evidence."
        ),
    )
    def oob_status(oob_id: str, cursor: int | None = None) -> dict:
        return tools.oob_status(registry, oob_id, cursor=cursor)

    @server.tool(
        name="stop_oob",
        description="Stop the listener and return every callback it collected. Safe to call twice.",
    )
    def stop_oob(oob_id: str) -> dict:
        return tools.stop_oob(registry, oob_id)

    @server.tool(
        name="local_jwt",
        description=(
            "Work on a JSON Web Token offline — nothing is sent anywhere. It decodes the "
            "token, says what it is signed with, tries to recover the key (a built-in list "
            "plus any wordlist file you name, or secret to test one directly), and with forge "
            "prints a token of your own, whose claims you can replace with claims "
            "(name=value; a value of true/false/42/{\"a\":1} takes that type)."
        ),
    )
    def local_jwt(
        token: str,
        secret: str | None = None,
        wordlist: str | None = None,
        forge: bool = False,
        claims: list[str] | None = None,
    ) -> dict:
        return tools.local_jwt(
            registry, token, secret=secret, wordlist=wordlist, forge=forge, claims=claims
        )

    @server.tool(
        name="local_hash",
        description=(
            "Identify a hash offline and try to recover what it was made from: the algorithm "
            "it is, and the plaintext when a built-in list or a wordlist file you name has it. "
            "Nothing is sent anywhere."
        ),
    )
    def local_hash(value: str, wordlist: str | None = None) -> dict:
        return tools.local_hash(registry, value, wordlist=wordlist)

    @server.tool(
        name="ca",
        description=(
            "Load the interception certificate authority crackweb uses for HTTPS, or generate "
            "one if there is none, and report what the block says: the authority's name, "
            "serial, expiry, fingerprint, and the paths of its certificate and key. export "
            "writes the certificate to a file; force regenerates the authority, which "
            "invalidates every certificate anyone already installed. A row that cannot be read "
            "is reported rather than dropped silently."
        ),
    )
    def ca(
        out_dir: str | None = None,
        force: bool = False,
        export: str | None = None,
    ) -> dict:
        return tools.ca(registry, out_dir=out_dir, force=force, export=export)

    return server


def force_utf8() -> None:
    """Speak UTF-8 whatever the console's code page is.

    MCP is UTF-8 JSON on stdout. A Windows console defaults to a code page that cannot
    represent some of what a tool description says, and a stream that encodes it its own way
    hands the client a parse error instead of a tool list. stderr goes the same way, so that
    a diagnostic is readable rather than mangled.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):  # a stream that cannot be reconfigured
            pass


def _install_signal_handlers(registry: Registry) -> None:
    """Make the exits that can be handled stop the processes on the way out."""

    def handler(signum: int, _frame: object) -> None:
        registry.stop_all()
        raise SystemExit(0 if signum in (signal.SIGINT, signal.SIGTERM) else 1)

    for name in ("SIGINT", "SIGTERM"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, handler)
        except (ValueError, OSError):  # not the main thread, or not supported here
            pass


def main(argv: list[str] | None = None) -> int:
    """Entry point: `crackweb-mcp [--binary PATH]` over stdio."""
    force_utf8()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("--version", "-V"):
        print(f"crackweb-mcp {__version__}")
        return 0
    if args and args[0] == "--binary":
        if len(args) < 2:
            print("--binary needs a path", file=sys.stderr)
            return 2
        os.environ[crackweb.BINARY_ENV] = args[1]
    elif args:
        print(f"unknown argument {args[0]!r}", file=sys.stderr)
        return 2

    try:
        binary = crackweb.find_binary()
    except crackweb.CrackwebError as exc:
        print(f"crackweb-mcp: {exc}", file=sys.stderr)
        return 2

    registry = Registry()
    _install_signal_handlers(registry)
    print(f"crackweb-mcp {__version__} serving {binary} over stdio", file=sys.stderr)
    build_server(registry).run()
    registry.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
