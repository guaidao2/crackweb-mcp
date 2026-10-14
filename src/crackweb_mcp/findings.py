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

from . import logs

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
# The trailing token has to look like a check id, which is what keeps an ordinary line that
# happens to carry a severity in brackets from being read as a finding. A note that mimics
# the shape exactly would still get through — nothing in this stream distinguishes the two —
# so the reader also closes a block at the first line that is not part of it.
CHECK_ID = r"[a-z0-9][a-z0-9-]*"
HEADER = re.compile(
    r"^\[(?P<severity>"
    + "|".join(SEVERITIES)
    + r")\]\s+(?P<title>.+?)\s{2,}(?P<check>"
    + CHECK_ID
    + r")\s*$"
)
METHOD_LINE = re.compile(r"^\s{2,}(?P<method>[A-Z]{3,7})\s+(?P<url>\S+)\s*$")
FIELD_LINE = re.compile(r"^\s{2,}(?P<name>[A-Za-z][^:]{0,23}):\s?(?P<value>.*)$")


def strip_ansi(text: str) -> str:
    """Drop colour codes, which should already be absent (NO_COLOR is set)."""
    return ANSI.sub("", text)


def parse(text: str) -> list[dict]:
    """Turn a block of console output into findings.

    A finding is a header line and the indented lines that follow it, and the block ends at
    the first line that is neither: a blank line, or a line that starts in column zero. That
    matters more than it looks — everything the proxy prints besides findings lands between
    blocks, and without the boundary the first such line after a finding would hand the
    finding detail it never produced.
    """
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
        if not raw.strip() or not raw[:1].isspace():
            # A blank line, or something that is not indented: whatever it is, it is not
            # this finding's. Closed rather than left open, so nothing can be attached to a
            # finding that did not produce it.
            current = None
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

    The reading itself — whole lines only, and starting over when the file shrank — is
    `logs.read_text_since`, which the out-of-band listener's reader uses too.
    """
    text, new_offset = logs.read_text_since(path, offset)
    if not text:
        return [], new_offset
    return parse(text), new_offset


def read_all(path: str | Path) -> tuple[list[dict], int]:
    """Every finding in the log, and the offset at the end of it."""
    return read_since(path, 0)


def count_since(path: str | Path, offset: int = 0) -> int:
    """How many findings sit after the cursor, without moving it."""
    return len(read_since(path, offset)[0])
