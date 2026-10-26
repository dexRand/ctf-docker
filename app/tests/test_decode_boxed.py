"""Decode: characters drawn in ASCII-art boxes "( p ) ( i ) ..."."""
from __future__ import annotations

from backend.analyzers.decode import candidates


def test_boxed_characters_joined_across_rows():
    # the flag is split over several boxed rows, with art between the rows
    art = (
        "   _     _\n"
        "  / \\   / \\\n"
        " ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { )\n"
        "  \\_/   \\_/\n"
        "   _     _\n"
        "  / \\   / \\\n"
        " ( x ) ( } )\n"
    ).encode()
    out = candidates(art)
    assert b"picoCTF{x}" in out.get("boxed", b"")


def test_plain_parentheses_do_not_trigger():
    out = candidates(b"just some (text) with (a) few parens")
    assert "boxed" not in out
