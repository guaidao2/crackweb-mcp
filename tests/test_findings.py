"""The findings stream: what it looks like, and what a cursor means."""

from __future__ import annotations

from pathlib import Path

from crackweb_mcp import findings

BLOCK = (
    "[High] File served that was never meant to be served  exposed-path\n"
    "    GET http://example.com/swagger.json\n"
    "    Param: q\n"
    "    Payload: /swagger.json\n"
    "\n"
)


def test_reads_a_finding_out_of_the_stream() -> None:
    parsed = findings.parse(BLOCK)
    assert len(parsed) == 1
    assert parsed[0]["severity"] == "high"
    assert parsed[0]["check"] == "exposed-path"
    assert parsed[0]["method"] == "GET"
    assert parsed[0]["url"] == "http://example.com/swagger.json"
    assert parsed[0]["fields"]["param"] == "q"
    assert parsed[0]["fields"]["payload"] == "/swagger.json"


def test_a_line_that_is_not_a_finding_is_ignored() -> None:
    text = "crackweb v1.6.8\nscanning http://example.com\n[Nope] not a severity  check\n"
    assert findings.parse(text) == []


def test_colour_codes_do_not_hide_a_finding() -> None:
    text = "\x1b[31m[High]\x1b[0m Something found  sqli\n"
    parsed = findings.parse(text)
    assert len(parsed) == 1
    assert parsed[0]["severity"] == "high"


def test_two_findings_are_two_findings() -> None:
    text = BLOCK + "[Critical] Injected  sqli\n    POST http://example.com/login\n\n"
    parsed = findings.parse(text)
    assert [f["severity"] for f in parsed] == ["high", "critical"]
    assert parsed[1]["method"] == "POST"


def test_a_header_this_reader_did_not_understand_does_not_donate_its_detail_lines() -> None:
    # The line below is header-shaped but carries no check id, so it is not a finding — and
    # the request under it is not the previous finding's either.
    text = BLOCK + "[Medium] A header without a check id\n    POST http://example.com/other\n\n"
    parsed = findings.parse(text)
    assert len(parsed) == 1
    assert parsed[0]["method"] == "GET"
    assert parsed[0]["url"] == "http://example.com/swagger.json"


def test_a_line_that_is_not_a_finding_ends_the_block_before_it() -> None:
    text = BLOCK + "crackweb proxy listening on 127.0.0.1:7777\n    Param: not-this-finding\n"
    parsed = findings.parse(text)
    assert len(parsed) == 1
    assert parsed[0]["fields"] == {"param": "q", "payload": "/swagger.json"}


def test_a_severity_in_brackets_is_not_enough_on_its_own() -> None:
    # What follows the two spaces has to look like a check id; a sentence does not.
    assert findings.parse("[High] Something happened  See the README.\n") == []
    assert len(findings.parse("[High] Something happened  exposed-path\n")) == 1


def test_a_cursor_reads_forward_and_leaves_a_partial_line_alone(tmp_path: Path) -> None:
    log = tmp_path / "findings.log"
    log.write_text(BLOCK, encoding="utf-8")
    # The size comes from the file, not from the string: the platform decides how a
    # newline is stored, and a cursor counts bytes.
    first, offset = findings.read_since(log, 0)
    assert len(first) == 1
    assert offset == log.stat().st_size

    # Nothing new yet.
    again, offset = findings.read_since(log, offset)
    assert again == []
    assert offset == log.stat().st_size

    # A finding that has only been half written waits for the rest of itself.
    with log.open("a", encoding="utf-8") as handle:
        handle.write("[Critical] Half a fin")
    partial, offset_after_partial = findings.read_since(log, offset)
    assert partial == []
    assert offset_after_partial == offset

    with log.open("a", encoding="utf-8") as handle:
        handle.write("ding  sqli\n")
    complete, last = findings.read_since(log, offset)
    assert len(complete) == 1
    assert complete[0]["title"] == "Half a finding"
    assert last == log.stat().st_size


def test_a_file_that_shrank_is_read_from_the_start(tmp_path: Path) -> None:
    log = tmp_path / "findings.log"
    log.write_text(BLOCK, encoding="utf-8")
    _, offset = findings.read_since(log, 0)

    log.write_text(BLOCK, encoding="utf-8")  # replaced by a shorter or equal one
    parsed, fresh = findings.read_since(log, offset + 500)
    assert len(parsed) == 1
    assert fresh == log.stat().st_size


def test_counting_does_not_move_the_cursor(tmp_path: Path) -> None:
    log = tmp_path / "findings.log"
    log.write_text(BLOCK + BLOCK, encoding="utf-8")
    assert findings.count_since(log, 0) == 2
    assert findings.count_since(log, 0) == 2
    parsed, offset = findings.read_since(log, 0)
    assert len(parsed) == 2
    assert findings.count_since(log, offset) == 0


def test_a_missing_log_is_not_an_error(tmp_path: Path) -> None:
    assert findings.read_since(tmp_path / "nothing.log", 12) == ([], 12)
