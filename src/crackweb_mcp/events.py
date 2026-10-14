"""Reading the out-of-band listener's output.

`crackweb oob` prints one line when it starts, naming the addresses it is listening on, and
then one line per interaction it collects:

    out-of-band server listening: http 127.0.0.1:8081, dns 127.0.0.1:5353
    14:22:07  HTTP  example.com:54321  /probe?token=abc

The second shape is what makes a finding demonstrable: it is the target reaching a host that
only the scan knows about, and the detail field usually carries the injected marker.
"""

from __future__ import annotations

import re

LISTENING = re.compile(
    r"listening:\s*http\s*(?P<http>\S+?)\s*,\s*dns\s*(?P<dns>\S+)", re.IGNORECASE
)
CALLBACK_URL = re.compile(r"callback URLs look like\s+(?P<url>\S+)")
EVENT = re.compile(
    r"^(?P<at>\d{2}:\d{2}:\d{2})\s{2,}(?P<protocol>\S+)\s{2,}(?P<remote>\S+)\s{2,}(?P<detail>.+?)\s*$"
)


def listening(text: str) -> dict:
    """The addresses the listener named when it started, if it said anything yet."""
    found = LISTENING.search(text)
    if not found:
        return {}
    return {"http": found.group("http"), "dns": found.group("dns")}


def callback_url(text: str) -> str:
    """The address the listener mints callbacks at.

    The listener records the interactions whose address carries a token it minted, so this is
    the address to hand to a target — and the one to fetch when proving, by hand, that the
    listener is reachable at all.
    """
    found = CALLBACK_URL.search(text)
    return found.group("url") if found else ""


def parse(text: str) -> list[dict]:
    """The interactions in a block of the listener's output."""
    events: list[dict] = []
    for line in text.splitlines():
        found = EVENT.match(line)
        if not found:
            continue
        events.append(
            {
                "at": found.group("at"),
                "protocol": found.group("protocol").lower(),
                "remote": found.group("remote"),
                "detail": found.group("detail").strip(),
            }
        )
    return events
