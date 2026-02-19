"""Branch-path coverage for r2inspect/application/batch_stats.py."""

from __future__ import annotations

from r2inspect.application.batch_stats import (
    collect_batch_statistics,
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)


def _empty_stats() -> dict:
    return {
        "packers_detected": [],
        "crypto_patterns": [],
        "suspicious_indicators": [],
        "file_types": {},
        "architectures": {},
        "compilers": {},
    }


# ---------------------------------------------------------------------------
# update_packer_stats (lines 10-11)
# ---------------------------------------------------------------------------


def test_update_packer_stats_detected_packer_appended():
    stats = _empty_stats()
    result = {"packer_info": {"detected": True, "name": "UPX"}}
    update_packer_stats(stats, "file.exe", result)
    assert len(stats["packers_detected"]) == 1
    assert stats["packers_detected"][0]["file"] == "file.exe"
    assert stats["packers_detected"][0]["packer"] == "UPX"


def test_update_packer_stats_detected_packer_unknown_name():
    stats = _empty_stats()
    result = {"packer_info": {"detected": True}}
    update_packer_stats(stats, "file.exe", result)
    assert stats["packers_detected"][0]["packer"] == "Unknown"


def test_update_packer_stats_not_detected_skipped():
    stats = _empty_stats()
    update_packer_stats(stats, "file.exe", {"packer_info": {"detected": False}})
    assert stats["packers_detected"] == []


def test_update_packer_stats_no_packer_info_key_skipped():
    stats = _empty_stats()
    update_packer_stats(stats, "file.exe", {})
    assert stats["packers_detected"] == []


# ---------------------------------------------------------------------------
# update_crypto_stats (lines 21-23)
# ---------------------------------------------------------------------------


def test_update_crypto_stats_patterns_appended():
    stats = _empty_stats()
    result = {"crypto_info": ["AES", "RC4"]}
    update_crypto_stats(stats, "malware.dll", result)
    assert len(stats["crypto_patterns"]) == 2
    assert stats["crypto_patterns"][0] == {"file": "malware.dll", "pattern": "AES"}
    assert stats["crypto_patterns"][1] == {"file": "malware.dll", "pattern": "RC4"}


def test_update_crypto_stats_empty_list_skipped():
    stats = _empty_stats()
    update_crypto_stats(stats, "file.exe", {"crypto_info": []})
    assert stats["crypto_patterns"] == []


def test_update_crypto_stats_no_crypto_info_key_skipped():
    stats = _empty_stats()
    update_crypto_stats(stats, "file.exe", {})
    assert stats["crypto_patterns"] == []


# ---------------------------------------------------------------------------
# update_indicator_stats (lines 28-29)
# ---------------------------------------------------------------------------


def test_update_indicator_stats_indicators_extended():
    stats = _empty_stats()
    result = {
        "indicators": [
            {"type": "string", "value": "cmd.exe"},
            {"type": "ip", "value": "1.2.3.4"},
        ]
    }
    update_indicator_stats(stats, "sample.bin", result)
    assert len(stats["suspicious_indicators"]) == 2
    assert stats["suspicious_indicators"][0]["file"] == "sample.bin"
    assert stats["suspicious_indicators"][0]["type"] == "string"


def test_update_indicator_stats_empty_list_skipped():
    stats = _empty_stats()
    update_indicator_stats(stats, "file.exe", {"indicators": []})
    assert stats["suspicious_indicators"] == []


def test_update_indicator_stats_no_key_skipped():
    stats = _empty_stats()
    update_indicator_stats(stats, "file.exe", {})
    assert stats["suspicious_indicators"] == []


# ---------------------------------------------------------------------------
# update_file_type_stats (lines 36-41)
# ---------------------------------------------------------------------------


def test_update_file_type_stats_counts_file_type_and_arch():
    stats = _empty_stats()
    result = {"file_info": {"file_type": "PE32", "architecture": "x86"}}
    update_file_type_stats(stats, result)
    assert stats["file_types"]["PE32"] == 1
    assert stats["architectures"]["x86"] == 1


def test_update_file_type_stats_increments_existing_counts():
    stats = _empty_stats()
    stats["file_types"]["ELF"] = 3
    stats["architectures"]["x86_64"] = 2
    update_file_type_stats(stats, {"file_info": {"file_type": "ELF", "architecture": "x86_64"}})
    assert stats["file_types"]["ELF"] == 4
    assert stats["architectures"]["x86_64"] == 3


def test_update_file_type_stats_unknown_defaults():
    stats = _empty_stats()
    update_file_type_stats(stats, {"file_info": {}})
    assert stats["file_types"]["Unknown"] == 1
    assert stats["architectures"]["Unknown"] == 1


def test_update_file_type_stats_no_file_info_key_skipped():
    stats = _empty_stats()
    update_file_type_stats(stats, {})
    assert stats["file_types"] == {}


# ---------------------------------------------------------------------------
# update_compiler_stats (lines 46-50)
# ---------------------------------------------------------------------------


def test_update_compiler_stats_detected_compiler_counted():
    stats = _empty_stats()
    result = {"compiler": {"compiler": "MSVC", "detected": True}}
    update_compiler_stats(stats, result)
    assert stats["compilers"]["MSVC"] == 1


def test_update_compiler_stats_not_detected_skipped():
    stats = _empty_stats()
    update_compiler_stats(stats, {"compiler": {"compiler": "GCC", "detected": False}})
    assert stats["compilers"] == {}


def test_update_compiler_stats_unknown_name_when_missing():
    stats = _empty_stats()
    update_compiler_stats(stats, {"compiler": {"detected": True}})
    assert stats["compilers"]["Unknown"] == 1


def test_update_compiler_stats_no_compiler_key_skipped():
    stats = _empty_stats()
    update_compiler_stats(stats, {})
    assert stats["compilers"] == {}


# ---------------------------------------------------------------------------
# collect_batch_statistics (lines 55-71)
# ---------------------------------------------------------------------------


def test_collect_batch_statistics_aggregates_all_fields():
    all_results = {
        "file_a.exe": {
            "packer_info": {"detected": True, "name": "Themida"},
            "crypto_info": ["AES"],
            "indicators": [{"type": "url", "value": "http://evil.com"}],
            "file_info": {"file_type": "PE32+", "architecture": "x86_64"},
            "compiler": {"compiler": "MSVC", "detected": True},
        },
        "file_b.dll": {
            "packer_info": {"detected": False},
            "crypto_info": [],
            "indicators": [],
            "file_info": {"file_type": "DLL", "architecture": "x86"},
            "compiler": {"compiler": "GCC", "detected": True},
        },
    }
    stats = collect_batch_statistics(all_results)

    assert len(stats["packers_detected"]) == 1
    assert stats["packers_detected"][0]["packer"] == "Themida"

    assert len(stats["crypto_patterns"]) == 1
    assert stats["crypto_patterns"][0]["pattern"] == "AES"

    assert len(stats["suspicious_indicators"]) == 1

    assert stats["file_types"]["PE32+"] == 1
    assert stats["file_types"]["DLL"] == 1

    assert stats["compilers"]["MSVC"] == 1
    assert stats["compilers"]["GCC"] == 1


def test_collect_batch_statistics_returns_empty_when_no_results():
    stats = collect_batch_statistics({})
    assert stats["packers_detected"] == []
    assert stats["crypto_patterns"] == []
    assert stats["suspicious_indicators"] == []
    assert stats["file_types"] == {}
    assert stats["architectures"] == {}
    assert stats["compilers"] == {}


def test_collect_batch_statistics_multiple_files_same_type():
    all_results = {
        "a.exe": {"file_info": {"file_type": "PE32", "architecture": "x86"}},
        "b.exe": {"file_info": {"file_type": "PE32", "architecture": "x86"}},
    }
    stats = collect_batch_statistics(all_results)
    assert stats["file_types"]["PE32"] == 2
    assert stats["architectures"]["x86"] == 2
