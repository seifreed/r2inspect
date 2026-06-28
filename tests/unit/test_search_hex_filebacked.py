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
