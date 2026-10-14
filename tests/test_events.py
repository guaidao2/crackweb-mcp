"""The out-of-band listener's output: what it says on the way up, and what a callback is."""

from __future__ import annotations

from crackweb_mcp import events

LISTENING = "out-of-band server listening: http 127.0.0.1:8081, dns 127.0.0.1:5353\n"
CALLBACKS = (
    "14:22:07  HTTP  example.com:54321  /probe?token=abc\n"
    "14:22:09  DNS   example.com:4444   abc.crackweb.example.com\n"
)


def test_the_addresses_it_names_are_read() -> None:
    found = events.listening(LISTENING + CALLBACKS)
    assert found == {"http": "127.0.0.1:8081", "dns": "127.0.0.1:5353"}


def test_nothing_said_yet_is_not_an_error() -> None:
    assert events.listening("") == {}
    assert events.listening("no addresses here\n") == {}


def test_a_callback_is_read_field_by_field() -> None:
    parsed = events.parse(CALLBACKS)
    assert len(parsed) == 2
    assert parsed[0] == {
        "at": "14:22:07",
        "protocol": "http",
        "remote": "example.com:54321",
        "detail": "/probe?token=abc",
    }
    assert parsed[1]["protocol"] == "dns"
    assert parsed[1]["detail"] == "abc.crackweb.example.com"


def test_the_listening_line_is_not_a_callback() -> None:
    assert events.parse(LISTENING) == []


def test_a_detail_with_spaces_keeps_them() -> None:
    parsed = events.parse("14:22:11  HTTP  example.com:1  /a?x=1 2\n")
    assert parsed[0]["detail"] == "/a?x=1 2"
