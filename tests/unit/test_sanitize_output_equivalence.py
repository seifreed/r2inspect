"""Equivalence guard for the sanitize_output fast path.

sanitize_output replaced a per-character ``isprintable()`` generator with a
pure-ASCII ``str.translate`` fast path (falling back to the generator for
non-ASCII input). These tests pin the optimized implementation to a literal
reference of the original generator so the two can never diverge.
"""

from __future__ import annotations

import re

from r2inspect.adapters.validation_primitives import sanitize_output

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _reference_sanitize(output: str) -> str:
    """The pre-optimization sanitize_output, verbatim, as the oracle."""
    if not output:
        return ""
    output = _ANSI_ESCAPE.sub("", output)
    output = "".join(char for char in output if char.isprintable() or char in "\n\t")
    output = output.strip()
    output = output.replace("&nbsp;", " ").replace("&amp;", "&")
    output = output.replace("&lt;", "<").replace("&gt;", ">")
    output = output.replace("&quot;", '"').replace("&#39;", "'")
    return output


def test_every_ascii_codepoint_matches_reference():
    # The fast path stands or falls on the ASCII translate table reproducing
    # the isprintable()/whitespace predicate for every ASCII code point.
    for cp in range(0x80):
        sample = f"a{chr(cp)}b"
        assert sanitize_output(sample) == _reference_sanitize(sample), hex(cp)


def test_ascii_control_run_matches_reference():
    raw = "".join(chr(cp) for cp in range(0x00, 0x20)) + "text\x7f"
    assert sanitize_output(raw) == _reference_sanitize(raw)


def test_non_ascii_falls_back_to_reference():
    # Printable non-ASCII is kept; non-ASCII separators/controls are dropped.
    samples = [
        "café",  # printable accented latin
        "ünïcödé\x00ctrl",  # printable non-ASCII mixed with a NUL
        "line1 line2",  # U+2028 line separator -> removed
        "tab\tnewline\nend",  # whitespace preserved
        " nbsp-sep",  # U+00A0 no-break space (Zs) -> removed
        "emoji\U0001f600here",  # astral printable kept
    ]
    for raw in samples:
        assert sanitize_output(raw) == _reference_sanitize(raw), repr(raw)


def test_ansi_and_entities_match_reference():
    raw = "Section \x1b[0m &amp;\x07 test &lt;x&gt; &quot;q&quot; &#39;a&#39;&nbsp;end"
    assert sanitize_output(raw) == _reference_sanitize(raw)
    assert "\x1b" not in sanitize_output(raw)


def test_empty_and_whitespace():
    assert sanitize_output("") == ""
    assert sanitize_output("   \n  ") == _reference_sanitize("   \n  ")
