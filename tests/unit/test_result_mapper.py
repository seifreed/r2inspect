"""Regression tests for the result_mapper / result_mapper_builders split.

These pin the dict -> typed-entity conversion behavior so the refactor
that moved the per-entity builders into result_mapper_builders.py cannot
silently change output. Pure data conversion -- no r2, no mocks.
"""

from __future__ import annotations

from r2inspect.application.result_mapper import _build_list, build_analysis_result
from r2inspect.application.result_mapper_builders import (
    build_section_info,
    build_security_features,
)
from r2inspect.schemas.results_models import AnalysisResult


def test_build_analysis_result_maps_known_keys_to_typed_fields():
    raw = {
        "file_info": {"name": "evil.exe", "size": 4096, "sha256": "ab" * 32, "arch": "x86"},
        "hashing": {"ssdeep": "3:abc", "imphash": "deadbeef"},
        "security": {"nx": True, "aslr": True},
        "imports": [{"name": "CreateFileW", "lib": "kernel32.dll"}],
        "sections": [{"name": ".text", "vaddr": 4096, "entropy": 6.1}],
        "strings": ["http://c2.example"],
        "execution_time": 1.5,
    }

    result = build_analysis_result(raw)

    assert isinstance(result, AnalysisResult)
    assert result.file_info.name == "evil.exe"
    assert result.file_info.size == 4096
    assert result.file_info.architecture == "x86"
    assert result.hashing.ssdeep == "3:abc"
    assert result.hashing.imphash == "deadbeef"
    assert result.security.nx is True
    assert result.security.aslr is True
    assert result.imports[0].name == "CreateFileW"
    assert result.imports[0].library == "kernel32.dll"
    assert result.sections[0].name == ".text"
    assert result.sections[0].virtual_address == 4096
    assert result.strings == ["http://c2.example"]
    assert result.execution_time == 1.5


def test_build_analysis_result_accepts_iterable_functions():
    raw = {
        "file_info": {"name": "evil.exe"},
        "functions": ({"name": "sub_1000", "size": 12}, {"name": "sub_2000", "size": 24}),
    }

    result = build_analysis_result(raw)

    assert [func.name for func in result.functions] == ["sub_1000", "sub_2000"]


def test_build_analysis_result_is_idempotent():
    raw = {"file_info": {"name": "x"}, "execution_time": 0.0}
    once = build_analysis_result(raw)
    twice = build_analysis_result(once)
    assert twice is once


def test_build_analysis_result_empty_input_yields_safe_defaults():
    result = build_analysis_result({})
    assert isinstance(result, AnalysisResult)
    assert result.file_info.name == ""
    assert result.hashing.ssdeep == ""
    assert result.security.nx is False
    assert result.imports == []
    assert result.sections == []
    assert result.functions == []


def test_build_security_features_drops_unknown_keys():
    sec = build_security_features({"nx": True, "totally_unknown": "boom", "aslr": True})
    assert sec.nx is True
    assert sec.aslr is True
    assert not hasattr(sec, "totally_unknown")


def test_build_security_features_invalid_input_is_all_false():
    sec = build_security_features(None)
    assert sec.get_enabled_features() == []


def test_build_section_info_resolves_r2_key_aliases():
    section = build_section_info(
        {"name": ".data", "vaddr": 8192, "vsize": 512, "size": 256, "perm": 5}
    )
    assert section.name == ".data"
    assert section.virtual_address == 8192
    assert section.virtual_size == 512
    assert section.raw_size == 256
    # non-str permissions are coerced to str by the builder
    assert section.permissions == "5"


def test_build_list_preserves_non_dict_items():
    sentinel = object()
    assert _build_list([sentinel, {"name": "k"}], lambda d: d["name"]) == [sentinel, "k"]
    assert _build_list(None, lambda d: d) == []
    assert _build_list("not a list", lambda d: d) == []


def test_build_list_accepts_other_iterables():
    assert _build_list(({"name": "a"}, {"name": "b"}), lambda d: d["name"]) == ["a", "b"]
