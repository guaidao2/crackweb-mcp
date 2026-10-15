"""The tools, against a stand-in binary that records its own command line.

Real processes, no lab, no browser: what is asserted here is the flags the wrapper builds and
the shapes it returns, not what crackweb does with them.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from crackweb_mcp import crackweb, tools
from crackweb_mcp.crackweb import RequestOptions, Target
from crackweb_mcp.processes import Registry

# The stand-in prints its second finding after this long, so a status call that waits a little
# longer than it sees both.
SETTLE = 1.2


def flags(argv: list[str]) -> dict[str, list[str]]:
    """A command line as flag to values, so a test can ask what was passed."""
    out: dict[str, list[str]] = {}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item.startswith("--"):
            value = ""
            if index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                value = argv[index + 1]
                index += 1
            out.setdefault(item, []).append(value)
        index += 1
    return out


def test_list_checks_reads_the_binarys_own_table(
    fake_crackweb: object, registry: Registry
) -> None:
    result = tools.list_checks(registry)
    by_id = {check["id"]: check for check in result["checks"]}
    assert by_id["dom-xss"]["opt_in"] is True
    assert by_id["dom-xss"]["severity"] == "high"
    assert "xss" in by_id["dom-xss"]["tags"]
    assert by_id["exposed-path"]["opt_in"] is False
    assert by_id["sqli-union"]["severity"] == "critical"
    assert by_id["passive-security-headers"]["kind"] == "passive"
    assert result["count"] == len(result["checks"])
    assert result["processes"] == []


def test_scan_passes_every_shared_flag_it_was_given(
    fake_crackweb: object, registry: Registry, argv_log
) -> None:
    tools.scan(
        registry,
        Target(url="http://example.com/?q=1", method="POST", data="a=1"),
        RequestOptions(
            checks="sqli,injection",
            enable_unsafe=True,
            sessions=["Cookie: sess=alice", "Cookie: sess=bob"],
            cookies=["sess=alice; uid=1"],
            headers=["X-Api-Key: k"],
            basic_auth="alice:s3cret",
            jwt_secrets=["hunter2"],
            proxy="http://127.0.0.1:8080",
            request_timeout="30s",
            rate=5.0,
            threads=4,
            sensitivity=2,
            insecure=True,
            user_agent="probe/1",
            random_ua=True,
            templates=["/templates"],
            skip_params=["csrf"],
            no_normalize=True,
            verbose=True,
            no_waf=True,
            no_assume_waf=True,
            oob_http="10.0.0.5:8081",
            oob_dns="10.0.0.5:5353",
            oob_domain="oob.example.com",
            oob_interactsh="https://interact.sh",
            oob_token="tok",
        ),
    )
    sent = flags(argv_log()[0])
    assert sent["--session"] == ["Cookie: sess=alice", "Cookie: sess=bob"]
    assert sent["--cookie"] == ["sess=alice; uid=1"]
    assert sent["--header"] == ["X-Api-Key: k"]
    assert sent["--basic-auth"] == ["alice:s3cret"]
    assert sent["--jwt-secret"] == ["hunter2"]
    assert sent["--proxy"] == ["http://127.0.0.1:8080"]
    assert sent["--timeout"] == ["30s"]
    assert sent["--rate"] == ["5.0"]
    assert sent["--threads"] == ["4"]
    assert sent["--sensitivity"] == ["2"]
    assert sent["--user-agent"] == ["probe/1"]
    assert sent["--templates"] == ["/templates"]
    assert sent["--skip-param"] == ["csrf"]
    assert sent["--oob-http"] == ["10.0.0.5:8081"]
    assert sent["--oob-dns"] == ["10.0.0.5:5353"]
    assert sent["--oob-domain"] == ["oob.example.com"]
    assert sent["--oob-interactsh"] == ["https://interact.sh"]
    assert sent["--oob-token"] == ["tok"]
    assert sent["--checks"] == ["sqli,injection"]
    assert sent["--url"] == ["http://example.com/?q=1"]
    assert sent["--method"] == ["POST"]
    assert sent["--data"] == ["a=1"]
    for bare in (
        "--enable-unsafe-checks", "--insecure", "--random-ua", "--no-normalize",
        "--verbose", "--no-waf", "--no-assume-waf",
    ):
        assert bare in sent, bare


def test_scan_returns_the_report_it_wrote(fake_crackweb: object, registry: Registry) -> None:
    result = tools.scan(registry, Target(url="http://example.com/?q=1"), RequestOptions())
    assert result["exit_code"] == 0
    assert result["finding_count"] == 1
    assert result["findings"][0]["check"] == "exposed-path"
    assert result["summary"]["requests"] == 7
    assert result["stderr"] == ""


def test_a_named_report_path_gets_a_copy(
    fake_crackweb: object, registry: Registry, tmp_path: Path
) -> None:
    wanted = tmp_path / "out" / "report.json"
    result = tools.scan(
        registry,
        Target(url="http://example.com"),
        RequestOptions(report_path=str(wanted)),
    )
    assert result["report_path"] == str(wanted)
    assert wanted.exists()
    assert '"exposed-path"' in wanted.read_text(encoding="utf-8")


def test_crawl_passes_its_own_flags(
    fake_crackweb: object, registry: Registry, argv_log
) -> None:
    tools.crawl(
        registry,
        Target(url="http://example.com"),
        RequestOptions(checks="dom-xss", enable_unsafe=True),
        depth=3,
        engine="headless",
        max_pages=40,
        scope=["example.com", "*.example.com"],
        no_discovery=True,
        allow_state_change=True,
        api_docs=["/openapi.json"],
    )
    sent = flags(argv_log()[0])
    assert sent["--depth"] == ["3"]
    assert sent["--engine"] == ["headless"]
    assert sent["--max-pages"] == ["40"]
    assert sent["--scope"] == ["example.com", "*.example.com"]
    assert "--no-discovery" in sent
    assert "--allow-state-change" in sent
    assert sent["--checks"] == ["dom-xss"]
    assert sent["--api-doc"] == ["/openapi.json"]


def test_a_global_flag_is_spelled_the_way_the_cli_defines_it(
    fake_crackweb: object, registry: Registry, argv_log
) -> None:
    # crackweb defines --quiet and not -q. The stand-in ignores what it does not know, which
    # is why the spelling itself is asserted here — a real binary said so the hard way.
    tools.scan(registry, Target(url="http://example.com"), RequestOptions())
    assert "--quiet" in argv_log()[0]
    assert "-q" not in argv_log()[0]

    tools.crawl(registry, Target(url="http://example.com"), RequestOptions())
    assert "--quiet" in argv_log()[-1]
    assert "-q" not in argv_log()[-1]


def test_a_failure_is_reported_with_what_the_cli_said(
    fake_crackweb: object, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FAIL", "1")
    with pytest.raises(crackweb.CrackwebError) as raised:
        tools.scan(registry, Target(url="http://example.com"), RequestOptions(checks="nope"))
    assert "none of the requested checks exist" in str(raised.value)
    assert "exit code 2" in str(raised.value)


def test_a_missing_binary_says_so(registry: Registry, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(crackweb.BINARY_ENV, "/nowhere/crackweb")
    with pytest.raises(crackweb.CrackwebError, match="does not exist"):
        tools.scan(registry, Target(url="http://example.com"), RequestOptions())


def test_the_proxy_lifecycle(fake_crackweb: object, registry: Registry) -> None:
    started = tools.start_proxy(registry, ["example.com"], RequestOptions())
    proxy_id = started["proxy_id"]
    assert started["running"] is True
    assert started["listen"].startswith("127.0.0.1:")
    assert started["log"].endswith("stream.log")

    time.sleep(SETTLE)
    first = tools.proxy_status(registry, proxy_id)
    assert first["running"] is True
    assert first["new_count"] == 2
    assert [f["check"] for f in first["new_findings"]] == ["exposed-path", "sqli-union"]
    assert first["findings_total"] == 2
    assert first["cursor"] > 0

    # Reading moved the cursor: the same findings are not handed out twice.
    second = tools.proxy_status(registry, proxy_id)
    assert second["new_count"] == 0
    assert second["new_findings"] == []
    assert second["findings_total"] == 2

    stopped = tools.stop_proxy(registry, proxy_id)
    assert stopped["stopped"] is True
    assert stopped["finding_count"] == 2
    assert stopped["report_path"].endswith("report.json")
    # Stopping hands everything over, so there is nothing left for other tools to report.
    assert registry.summary() == []


def test_start_proxy_passes_its_own_flags(
    fake_crackweb: object, registry: Registry, argv_log
) -> None:
    started = tools.start_proxy(
        registry,
        ["example.com"],
        RequestOptions(cookies=["sess=alice"]),
        listen="127.0.0.1:0",
        upstream="http://127.0.0.1:3128",
        passive_only=True,
        export_ca="/tmp/ca.crt",
    )
    sent = flags(argv_log()[0])
    assert sent["--listen"] == ["127.0.0.1:0"]
    assert sent["--upstream"] == ["http://127.0.0.1:3128"]
    assert sent["--scope"] == ["example.com"]
    assert sent["--cookie"] == ["sess=alice"]
    assert sent["--export-ca"] == ["/tmp/ca.crt"]
    assert "--passive-only" in sent
    assert "-o" in argv_log()[0]  # the report it writes on the way out
    tools.stop_proxy(registry, started["proxy_id"])


def test_scope_is_required(registry: Registry) -> None:
    with pytest.raises(crackweb.CrackwebError, match="scope is required"):
        tools.start_proxy(registry, [], RequestOptions())
    with pytest.raises(crackweb.CrackwebError, match="scope is required"):
        tools.start_proxy(registry, ["   "], RequestOptions())


def test_a_proxy_that_dies_at_once_is_not_reported_as_running(
    fake_crackweb: object, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_START_FAIL", "1")
    with pytest.raises(crackweb.CrackwebError, match="exited immediately"):
        tools.start_proxy(registry, ["example.com"], RequestOptions())


def test_an_unknown_process_is_an_error_not_a_guess(registry: Registry) -> None:
    with pytest.raises(crackweb.CrackwebError, match="unknown process"):
        tools.proxy_status(registry, "p42")


def test_a_missing_report_says_why_instead_of_pretending(
    fake_crackweb: object, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_NO_REPORT", "1")
    started = tools.start_proxy(registry, ["example.com"], RequestOptions())
    time.sleep(SETTLE)
    stopped = tools.stop_proxy(registry, started["proxy_id"])
    assert stopped["finding_count"] == 2  # the stream is the source, and it is complete
    assert stopped["report_written"] is False
    assert "report" in stopped["report_note"].lower()


def test_a_nobody_asks_about_process_stops_itself(
    fake_crackweb: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CRACKWEB_MCP_TMP", str(tmp_path / "idle"))
    idle_registry = Registry(idle=0.2)
    try:
        started = tools.start_proxy(idle_registry, ["example.com"], RequestOptions())
        time.sleep(0.6)
        # The idle check runs on the path every other tool takes, which is the path a caller
        # that never asks about its processes does take.
        listed = tools.list_checks(idle_registry)["processes"]
        entry = next(p for p in listed if p["proxy_id"] == started["proxy_id"])
        assert entry["running"] is False
    finally:
        idle_registry.stop_all()


def test_the_oob_lifecycle(fake_crackweb: object, registry: Registry, argv_log) -> None:
    started = tools.start_oob(registry)
    oob_id = started["oob_id"]
    assert started["running"] is True
    # The stand-in names its addresses on the way up, and the wrapper reads them.
    assert "127.0.0.1:8081" in started["listen"]
    assert "5353" in started["listen"]
    assert started["callback_url"].endswith("/minted-token")

    time.sleep(SETTLE)
    first = tools.oob_status(registry, oob_id)
    assert first["new_count"] == 1
    assert first["new_events"][0]["protocol"] == "http"
    assert first["new_events"][0]["detail"] == "/probe?token=abc"
    assert first["listening"]["dns"] == "127.0.0.1:5353"
    assert first["listening"]["callback_url"].endswith("/minted-token")

    second = tools.oob_status(registry, oob_id)
    assert second["new_count"] == 0

    stopped = tools.stop_oob(registry, oob_id)
    assert stopped["stopped"] is True
    assert stopped["event_count"] == 1
    assert "report_path" not in stopped  # only a proxy writes one


def test_the_offline_subjects_pass_through(
    fake_crackweb: object, registry: Registry, argv_log
) -> None:
    jwt = tools.local_jwt(
        registry,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.x",
        secret="hunter2",
        forge=True,
        claims=["sub=admin", "admin=true"],
    )
    assert jwt["exit_code"] == 0
    assert "claims" in jwt["stdout"]
    sent = flags(argv_log()[0])
    assert sent["--secret"] == ["hunter2"]
    assert sent["--claim"] == ["sub=admin", "admin=true"]
    assert "--forge" in sent

    digest = tools.local_hash(registry, "5f4dcc3b5aa765d61d8327deb882cf99", wordlist="/w.txt")
    assert "md5" in digest["stdout"]
    sent = flags(argv_log()[-1])
    assert sent["--wordlist"] == ["/w.txt"]


def test_the_ca_is_reported_as_fields(
    fake_crackweb: object, registry: Registry, argv_log, tmp_path: Path
) -> None:
    result = tools.ca(registry, export=str(tmp_path / "ca.crt"))
    assert result["ca"]["sha-256"] == "11:22:33:44"
    assert result["ca"]["certificate"] == "/tmp/ca/ca.crt"
    assert flags(argv_log()[0])["--export"] == [str(tmp_path / "ca.crt")]
