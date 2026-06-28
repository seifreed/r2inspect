"""Coverage for file-backed-map-scoped /x hex searches.

The adapter restricts /x searches to file-backed io maps so a statically
linked binary's ~1 GB anonymous BSS map is never scanned. All tests use a
real R2PipeAdapter wrapping a FakeR2Adapter -- no mocks, no monkeypatch.
"""

from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from tests.helpers.r2_fakes import FakeR2Adapter


def _make_adapter(*, cmd_responses=None, cmdj_responses=None) -> R2PipeAdapter:
    fake = FakeR2Adapter(cmd_responses=cmd_responses, cmdj_responses=cmdj_responses)
    return R2PipeAdapter(fake)


def test_search_hex_falls_back_to_plain_when_no_file_info():
    fake = FakeR2Adapter(cmd_responses={"/x deadbeef": "0x400000 hit0_0 deadbeef\n"})
    adapter = R2PipeAdapter(fake)

    result = adapter.search_hex("deadbeef")

    assert "0x400000" in result
    assert "/x deadbeef" in fake.calls["cmd"]
    assert not any("@e:search.in=io.map" in c for c in fake.calls["cmd"])


def test_search_hex_scopes_to_file_backed_maps_only():
    omj = [
        {"from": 0x1000, "to": 0x1FFF, "delta": 0},  # file-backed -> searched
        {"from": 0x3000, "to": 0x3FFF, "delta": 0x1000},  # file-backed -> searched
        {"from": 0x2000, "to": 0x40000000, "delta": 0},  # oversized BSS -> skipped
        123,  # not a dict -> skipped
        {"from": "x", "to": 1, "delta": 0},  # bad field type -> skipped
        {"from": 0x50, "to": 0x10, "delta": 0},  # non-positive length -> skipped
    ]
    cmd_responses = {
        "/x cafe @e:search.in=io.map @ 0x1000": "0x1000 hit0_0 cafe\n",
        # 0x3000 map intentionally returns "" to exercise the empty-output filter
    }
    fake = FakeR2Adapter(
        cmd_responses=cmd_responses,
        # FakeR2 treats a list response as a queue; wrap omj so the whole list
        # is returned as a single response.
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    result = adapter.search_hex("cafe")

    assert result.strip() == "0x1000 hit0_0 cafe"
    issued = fake.calls["cmd"]
    assert "/x cafe @e:search.in=io.map @ 0x1000" in issued
    assert "/x cafe @e:search.in=io.map @ 0x3000" in issued
    assert not any("@ 0x2000" in c for c in issued)  # BSS never scanned
    assert "/x cafe" not in issued  # no unscoped fallback

    # Second search reuses the resolved map starts (no extra omj/ij queries).
    omj_calls_before = fake.calls["cmdj"].count("omj")
    adapter.search_hex("cafe")
    assert fake.calls["cmdj"].count("omj") == omj_calls_before


def test_resolve_file_size_rejects_non_dict_core():
    fake = FakeR2Adapter(
        cmd_responses={"/x ab": "0x1 hit\n"},
        cmdj_responses={"ij": {"core": "not-a-dict"}, "omj": [{"from": 1, "to": 2, "delta": 0}]},
    )
    adapter = R2PipeAdapter(fake)

    adapter.search_hex("ab")

    assert "/x ab" in fake.calls["cmd"]  # fell back: size unresolved


def test_resolve_file_size_rejects_zero_size():
    fake = FakeR2Adapter(
        cmd_responses={"/x ab": "0x1 hit\n"},
        cmdj_responses={"ij": {"core": {"size": 0}}, "omj": [{"from": 1, "to": 2, "delta": 0}]},
    )
    adapter = R2PipeAdapter(fake)

    adapter.search_hex("ab")

    assert "/x ab" in fake.calls["cmd"]


def test_resolve_file_size_rejects_missing_size():
    fake = FakeR2Adapter(
        cmd_responses={"/x ab": "0x1 hit\n"},
        cmdj_responses={"ij": {"core": {}}, "omj": [{"from": 1, "to": 2, "delta": 0}]},
    )
    adapter = R2PipeAdapter(fake)

    adapter.search_hex("ab")

    assert "/x ab" in fake.calls["cmd"]


def test_search_text_scopes_to_executable_maps():
    omj = [{"from": 0x401000, "to": 0x401FFF, "delta": 0x1000, "perm": "r-x"}]
    fake = FakeR2Adapter(
        cmd_responses={"/aa xor @e:search.in=io.map @ 0x401000": "0x401005 xor eax, eax\n"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    result = adapter.search_text("xor")

    assert "xor" in result
    assert "/aa xor @e:search.in=io.map @ 0x401000" in fake.calls["cmd"]
    assert "/aa xor" not in fake.calls["cmd"]


def test_search_text_skips_non_executable_maps():
    # /aa disassembles, so only r-x maps can hold instructions. A data map is
    # file-backed (so /x would scan it) but must not be disassembled by /aa.
    omj = [
        {"from": 0x401000, "to": 0x401FFF, "delta": 0x1000, "perm": "r-x"},
        {"from": 0x402000, "to": 0x402FFF, "delta": 0x2000, "perm": "rw-"},
    ]
    fake = FakeR2Adapter(
        cmd_responses={"/aa cpuid @e:search.in=io.map @ 0x401000": "0x401005 cpuid\n"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    adapter.search_text("cpuid")

    issued = fake.calls["cmd"]
    assert "/aa cpuid @e:search.in=io.map @ 0x401000" in issued
    assert not any("@ 0x402000" in c for c in issued)  # data map never disassembled


def test_search_hex_reads_maps_once_and_finds_in_memory():
    # One file-backed map of 16 bytes with "deadbeef" at offset 2 -> vaddr 0x1002.
    omj = [{"from": 0x1000, "to": 0x100F, "delta": 0, "perm": "r--"}]
    fake = FakeR2Adapter(
        cmd_responses={"p8 16 @ 4096": "0011deadbeef22334455667788990011"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    result = adapter.search_hex("deadbeef")

    assert result == "0x1002"
    # The in-memory read replaces the per-pattern /x scan entirely.
    assert not any(c.startswith("/x") for c in fake.calls["cmd"])


def test_search_hex_in_memory_matches_non_overlapping():
    # A run of repeated bytes: r2's /x steps past each hit by the pattern length,
    # so "aaaa" (2 bytes) over six 0xAA bytes matches at offsets 0, 2, 4 -- not
    # the overlapping 0, 1, 2, 3, 4 that a one-byte step would report.
    omj = [{"from": 0x1000, "to": 0x1005, "delta": 0, "perm": "r--"}]
    fake = FakeR2Adapter(
        cmd_responses={"p8 6 @ 4096": "aaaaaaaaaaaa"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    result = adapter.search_hex("aaaa")

    assert result == "0x1000\n0x1002\n0x1004"


def test_search_hex_falls_back_to_scan_on_short_map_read():
    # omj resolves but the p8 read isn't available (returns ""), so the in-memory
    # view is incomplete and the search must fall back to /x for correctness.
    omj = [{"from": 0x1000, "to": 0x100F, "delta": 0, "perm": "r--"}]
    fake = FakeR2Adapter(
        cmd_responses={"/x cafe @e:search.in=io.map @ 0x1000": "0x1000 hit cafe\n"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    result = adapter.search_hex("cafe")

    assert "0x1000" in result
    assert any(c.startswith("/x cafe") for c in fake.calls["cmd"])


def test_search_executable_hex_scopes_to_executable_maps_only():
    # An r-x map and a rw- map both contain 0f31; only the executable hit counts
    # (the same byte pair in a data section is not an instruction).
    omj = [
        {"from": 0x1000, "to": 0x1007, "delta": 0, "perm": "r-x"},
        {"from": 0x2000, "to": 0x2007, "delta": 0x1000, "perm": "rw-"},
    ]
    fake = FakeR2Adapter(
        cmd_responses={
            "p8 8 @ 4096": "00000f3100000000",  # 0f31 at exec vaddr 0x1002
            "p8 8 @ 8192": "0f31000000000000",  # 0f31 at data vaddr 0x2000 (ignored)
        },
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    assert adapter.search_executable_hex("0f31") == "0x1002"


def test_search_executable_hex_returns_none_without_executable_maps():
    omj = [{"from": 0x2000, "to": 0x2007, "delta": 0, "perm": "rw-"}]
    fake = FakeR2Adapter(
        cmd_responses={"p8 8 @ 8192": "0f31000000000000"},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    assert adapter.search_executable_hex("0f31") is None


def test_search_executable_hex_rejects_non_hex_and_empty():
    adapter = R2PipeAdapter(FakeR2Adapter())
    assert adapter.search_executable_hex("zz") is None
    assert adapter.search_executable_hex("") is None


def test_search_executable_hex_returns_none_on_short_map_read():
    # omj resolves but the p8 read isn't available, so the in-memory view is
    # incomplete and the caller must fall back rather than miss hits.
    omj = [{"from": 0x1000, "to": 0x100F, "delta": 0, "perm": "r-x"}]
    fake = FakeR2Adapter(
        cmd_responses={},
        cmdj_responses={"ij": {"core": {"size": 0x100000}}, "omj": [omj]},
    )
    adapter = R2PipeAdapter(fake)

    assert adapter.search_executable_hex("0f31") is None


def test_search_hex_non_hex_pattern_falls_back():
    # A pattern that isn't plain hex can't be searched in memory; /x handles it.
    fake = FakeR2Adapter(cmd_responses={"/x zz": "0x2000 hit\n"})
    adapter = R2PipeAdapter(fake)

    assert "0x2000" in adapter.search_hex("zz")


def test_search_hex_empty_pattern_returns_no_hits():
    adapter = R2PipeAdapter(FakeR2Adapter())
    assert adapter.search_hex("") == ""


def test_search_text_falls_back_without_maps():
    fake = FakeR2Adapter(cmd_responses={"/aa rol": "0x401005 rol eax, 3\n"})
    adapter = R2PipeAdapter(fake)

    result = adapter.search_text("rol")

    assert "rol" in result
    assert "/aa rol" in fake.calls["cmd"]


def test_compute_returns_empty_when_omj_not_a_list():
    fake = FakeR2Adapter(
        cmd_responses={"/x ab": "0x1 hit\n"},
        cmdj_responses={"ij": {"core": {"size": 0x1000}}},  # omj absent -> "" -> not a list
    )
    adapter = R2PipeAdapter(fake)

    adapter.search_hex("ab")

    assert "/x ab" in fake.calls["cmd"]
