"""Reading findings out of crackweb's console stream.

While a scan or a proxy runs, the only machine-readable thing crackweb emits is the
one-line-per-finding stream it prints as each finding is confirmed. The report is
written when it exits, which is too late to answer "has it found anything yet?".

The shapes below are the whole contract, and they are deliberately read loosely:

    [High] File served that was never meant to be served  exposed-path
        GET http://example.com/swagger.json
        Param: q
        Payload: /swagger.json

A header line is anchored on its severity, because that is the part that cannot be
translated away: the wrapper runs every invocation with CRACKWEB_LANG=en, and the
severity words are what the catalogue uses in English. Everything else in the block is
captured as a name/value pair rather than a fixed field, so a renamed label becomes a
differently named key instead of a parse failure.

A cursor is a byte offset into the log, not a line number: a line written in two pieces
is then either fully consumed or not consumed at all.
"""

from __future__ import annotations

import re
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
HEADER = re.compile(
    r"^\[(?P<severity>" + "|".join(SEVERITIES) + r")\]\s+(?P<title>.+?)\s{2,}(?P<check>\S+)\s*$"
)
METHOD_LINE = re.compile(r"^\s{2,}(?P<method>[A-Z]{3,7})\s+(?P<url>\S+)\s*$")
FIELD_LINE = re.compile(r"^\s{2,}(?P<name>[A-Za-z][^:]{0,23}):\s?(?P<value>.*)$")


def strip_ansi(text: str) -> str:
    """Drop colour codes, which should already be absent (NO_COLOR is set)."""
    return ANSI.sub("", text)


def parse(text: str) -> list[dict]:
    """Turn a block of console output into findings."""
    findings: list[dict] = []
    current: dict | None = None
    for raw in strip_ansi(text).splitlines():
        header = HEADER.match(raw)
        if header:
            current = {
                "severity": header.group("severity").lower(),
                "title": header.group("title").strip(),
                "check": header.group("check"),
                "url": "",
                "method": "",
                "fields": {},
            }
            findings.append(current)
            continue
        if current is None:
            continue
        method = METHOD_LINE.match(raw)
        if method:
            current["method"] = method.group("method")
            current["url"] = method.group("url")
            continue
        field = FIELD_LINE.match(raw)
        if field:
            current["fields"][field.group("name").strip().lower()] = field.group("value").strip()
    return findings


def read_since(path: str | Path, offset: int = 0) -> tuple[list[dict], int]:
    """Findings that arrived since `offset` bytes, and the offset to use next time.

    A file that shrank means it was replaced or truncated, so the offset no longer
    means anything and reading starts over. A file whose last line has no newline yet
    is left alone: the writer is mid-line, and half a finding parses as nothing.
    """
    log = Path(path)
    if not log.exists():
        return [], offset

    size = log.stat().st_size
    if size < offset:
        offset = 0

    with log.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read()

    complete = chunk
    if chunk and not chunk.endswith(b"\n"):
        cut = chunk.rfind(b"\n")
        complete = chunk[: cut + 1] if cut != -1 else b""

    new_offset = offset + len(complete)
    if not complete:
        return [], new_offset
    return parse(complete.decode("utf-8", "replace")), new_offset


def read_all(path: str | Path) -> tuple[list[dict], int]:
    """Every finding in the log, and the offset at the end of it."""
    return read_since(path, 0)


def count_since(path: str | Path, offset: int = 0) -> int:
    """How many findings sit after the cursor, without moving it."""
    return len(read_since(path, offset)[0])
