"""Regression test for loop iteration 5.

The RichPE hash entries-fallback (used when pefile is unavailable, e.g. the
direct-file decode path) hashed only the comp-id/count pairs, omitting the
16-byte ``DanS`` + padding prefix that pefile's ``clear_data`` carries. The
resulting hash matched neither pefile's ``get_rich_header_hash`` nor this
module's own pefile path, breaking RichPE-hash IOC interoperability.
"""

from __future__ import annotations

import hashlib
import struct

from r2inspect.domain.services.rich_header import calculate_richpe_hash


def test_richpe_fallback_matches_pefile_clear_data_layout() -> None:
    entries = [{"prodid": 0x00930001, "count": 7}]
    # Canonical pefile clear_data: "DanS" + three zeroed padding dwords + pairs.
    canonical_clear = b"DanS" + b"\x00" * 12 + struct.pack("<I", 0x00930001) + struct.pack("<I", 7)
    expected = hashlib.md5(canonical_clear, usedforsecurity=False).hexdigest()

    via_entries = calculate_richpe_hash({"entries": entries})
    via_clear_data = calculate_richpe_hash({"clear_data_bytes": canonical_clear})

    assert via_entries == expected
    # The entries fallback must agree with the pefile clear_data path.
    assert via_entries == via_clear_data
