"""The tools, against a stand-in binary: real processes, no lab, no browser."""

from __future__ import annotations

import time

import pytest

from crackweb_mcp import crackweb, tools
from crackweb_mcp.proxy import Registry

# The stand-in prints its second finding after this long, so a status call that waits a
# little longer than it sees both.
SETTLE = 1.2


def test_list_checks_reads_the_binarys_own_table(fake_crackweb: object, registry: Registry) -> None:
    result = tools.list_checks(registry)
    by_id = {check["id"]: check for check in result["checks"]}
    assert by_id["dom-xss"]["opt_in"] is True
    assert by_id["dom-xss"]["severity"] == "high"
    assert "xss" in by_id["dom-xss"]["tags"]
    assert by_id["exposed-path"]["opt_in"] is False
    assert by_id["sqli-union"]["severity"] == "critical"
    assert by_id["passive-security-headers"]["kind"] == "passive"
    assert result["count"] == len(result["checks"])
    assert result["proxies"] == []


def test_scan_returns_the_report_it_wrote(fake_crackweb: object, registry: Registry) -> None:
    result = tools.scan(registry, "http://example.com/?q=1")
    assert result["exit_code"] == 0
    assert result["finding_count"] == 1
    assert result["findings"][0]["check"] == "exposed-path"
    assert result["findings"][0]["payload"] == "/swagger.json"
    assert result["summary"]["requests"] == 7
    assert result["stderr"] == ""


def test_crawl_is_the_same_shape_as_scan(fake_crackweb: object, registry: Registry) -> None:
    result = tools.crawl(registry, "http://example.com")
    assert result["command"] == "crawl"
    assert result["finding_count"] == 1


def test_a_failure_is_reported_with_what_the_cli_said(
    fake_crackweb: object, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FAIL", "1")
    with pytest.raises(crackweb.CrackwebError) as raised:
        tools.scan(registry, "http://example.com", checks="nope")
    assert "none of the requested checks exist" in str(raised.value)
    assert "exit code 2" in str(raised.value)


def test_a_missing_binary_says_so(registry: Registry, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(crackweb.BINARY_ENV, "/nowhere/crackweb")
    with pytest.raises(crackweb.CrackwebError, match="does not exist"):
        tools.scan(registry, "http://example.com")


def test_the_proxy_lifecycle(fake_crackweb: object, registry: Registry) -> None:
    started = tools.start_proxy(registry, scope=["example.com"])
    proxy_id = started["proxy_id"]
    assert started["running"] is True
    assert started["listen"].startswith("127.0.0.1:")
    assert started["findings_log"].endswith("findings.log")

    time.sleep(SETTLE)
    first = tools.proxy_status(registry, proxy_id)
    assert first["running"] is True
    assert first["new_count"] == 2
    assert [f["check"] for f in first["new_findings"]] == ["exposed-path", "sqli"]
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
    assert registry.summary()[0]["running"] is False


def test_another_tool_reports_what_is_waiting_without_consuming_it(
    fake_crackweb: object, registry: Registry
) -> None:
    started = tools.start_proxy(registry, scope="example.com")
    time.sleep(SETTLE)

    waiting = tools.list_checks(registry)["proxies"][0]
    assert waiting["proxy_id"] == started["proxy_id"]
    assert waiting["new_findings_waiting"] == 2
    # Reading is what a status call means, and nothing else moves the cursor.
    assert tools.list_checks(registry)["proxies"][0]["new_findings_waiting"] == 2

    assert tools.proxy_status(registry, started["proxy_id"])["new_count"] == 2
    assert tools.list_checks(registry)["proxies"][0]["new_findings_waiting"] == 0


def test_scope_is_required_and_scoped_proxies_are_told_about(registry: Registry) -> None:
    with pytest.raises(crackweb.CrackwebError, match="scope is required"):
        tools.start_proxy(registry, scope=[])
    with pytest.raises(crackweb.CrackwebError, match="scope is required"):
        tools.start_proxy(registry, scope=["   "])


def test_a_proxy_that_dies_at_once_is_not_reported_as_running(
    fake_crackweb: object, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_START_FAIL", "1")
    with pytest.raises(crackweb.CrackwebError, match="exited immediately"):
        tools.start_proxy(registry, scope=["example.com"])


def test_an_unknown_proxy_is_an_error_not_a_guess(registry: Registry) -> None:
    with pytest.raises(crackweb.CrackwebError, match="unknown proxy"):
        tools.proxy_status(registry, "p42")
