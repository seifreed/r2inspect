#!/usr/bin/env python3
"""Branch path tests for crypto/elf/macho domain modules."""

from __future__ import annotations

import r2inspect.modules.crypto_domain as cd
import r2inspect.modules.macho_security_domain as msd
import r2inspect.modules.elf_security_domain as esd


# ---------------------------------------------------------------------------
# crypto_domain.py
# ---------------------------------------------------------------------------

def test_is_candidate_string_re_error_returns_false() -> None:
    """_is_candidate_string returns False when NOISE_PATTERNS contains invalid regex."""
    original = cd.NOISE_PATTERNS
    cd.NOISE_PATTERNS = ["[invalid"]
    try:
        result = cd._is_candidate_string("test")
        assert result is False
    finally:
        cd.NOISE_PATTERNS = original


def test_matches_any_pattern_re_error_continues() -> None:
    """_matches_any_pattern skips patterns that raise re.error and returns False."""
    result = cd._matches_any_pattern("test", ["[invalid", "[also_bad"])
    assert result is False


def test_matches_any_pattern_returns_true_on_match() -> None:
    """_matches_any_pattern returns True when a pattern matches."""
    result = cd._matches_any_pattern("aes key", [r"\baes\b"])
    assert result is True


def test_match_patterns_adds_detection() -> None:
    """_match_patterns populates detected_algos when string matches a crypto pattern."""
    detected: dict = {}
    string_info = {"string": "aes encryption used", "vaddr": 0x1000}
    cd._match_patterns(string_info, "aes encryption used", detected)
    assert "AES" in detected
    assert len(detected["AES"]) == 1
    assert detected["AES"][0]["evidence_type"] == "String Reference"


def test_add_detection_populates_dict() -> None:
    """_add_detection appends an entry to detected_algos under the algo name."""
    detected: dict = {}
    string_info = {"string": "sha256", "vaddr": 0x2000}
    cd._add_detection(detected, "SHA", string_info, "sha256")
    assert "SHA" in detected
    entry = detected["SHA"][0]
    assert entry["evidence"] == "sha256"
    assert entry["confidence"] == 0.4
    assert entry["address"] == hex(0x2000)


def test_consolidate_detections_multiple_evidence_types_boosts_confidence() -> None:
    """consolidate_detections boosts confidence when multiple evidence types exist."""
    detected = {
        "AES": [
            {"evidence_type": "String Reference", "evidence": "aes", "confidence": 0.4, "address": "0x0"},
            {"evidence_type": "Import Reference", "evidence": "AES_init", "confidence": 0.6, "address": "0x10"},
        ]
    }
    result = cd.consolidate_detections(detected)
    assert len(result) == 1
    entry = result[0]
    assert entry["confidence"] > 0.6
    assert entry["confidence"] <= 0.95


def test_consolidate_detections_single_evidence_type_no_boost() -> None:
    """consolidate_detections does not boost confidence for a single evidence type."""
    detected = {
        "MD5": [
            {"evidence_type": "String Reference", "evidence": "md5", "confidence": 0.4, "address": "0x0"},
        ]
    }
    result = cd.consolidate_detections(detected)
    assert result[0]["confidence"] == 0.4


# ---------------------------------------------------------------------------
# macho_security_domain.py
# ---------------------------------------------------------------------------

def test_is_pie_returns_false_for_none() -> None:
    """is_pie returns False when macho_info is None."""
    assert msd.is_pie(None) is False


def test_is_pie_returns_false_for_empty_dict() -> None:
    """is_pie returns False when macho_info has no 'bin' key."""
    assert msd.is_pie({}) is False


def test_has_stack_canary_returns_true() -> None:
    """has_stack_canary returns True when ___stack_chk_fail symbol is present."""
    symbols = [{"name": "___stack_chk_fail"}]
    assert msd.has_stack_canary(symbols) is True


def test_has_stack_canary_returns_false_for_empty() -> None:
    """has_stack_canary returns False when symbol list is empty."""
    assert msd.has_stack_canary([]) is False


def test_has_arc_returns_true() -> None:
    """has_arc returns True when _objc_retain symbol is present."""
    symbols = [{"name": "_objc_retain"}]
    assert msd.has_arc(symbols) is True


def test_has_arc_returns_false_for_empty() -> None:
    """has_arc returns False when no ARC symbol is present."""
    assert msd.has_arc([]) is False


def test_is_encrypted_returns_true() -> None:
    """is_encrypted returns True when LC_ENCRYPTION_INFO header with cryptid > 0."""
    headers = [{"type": "LC_ENCRYPTION_INFO", "cryptid": 1}]
    assert msd.is_encrypted(headers) is True


def test_is_encrypted_returns_false_for_no_match() -> None:
    """is_encrypted returns False when no encryption header matches."""
    headers = [{"type": "LC_LOAD_DYLIB"}]
    assert msd.is_encrypted(headers) is False


def test_is_signed_returns_true() -> None:
    """is_signed returns True when LC_CODE_SIGNATURE header is present."""
    headers = [{"type": "LC_CODE_SIGNATURE"}]
    assert msd.is_signed(headers) is True


def test_is_signed_returns_false_for_empty() -> None:
    """is_signed returns False when header list is empty."""
    assert msd.is_signed([]) is False


# ---------------------------------------------------------------------------
# elf_security_domain.py
# ---------------------------------------------------------------------------

def test_has_nx_returns_false_for_empty_ph_info() -> None:
    """has_nx returns False when ph_info is empty."""
    assert esd.has_nx([]) is False


def test_has_nx_returns_false_when_no_gnu_stack() -> None:
    """has_nx returns False when no GNU_STACK header is present."""
    headers = [{"type": "LOAD", "flags": "r-x"}]
    assert esd.has_nx(headers) is False


def test_has_nx_returns_true_when_gnu_stack_without_exec() -> None:
    """has_nx returns True when GNU_STACK header exists and flags have no 'x'."""
    headers = [{"type": "GNU_STACK", "flags": "rw-"}]
    assert esd.has_nx(headers) is True


def test_has_nx_returns_false_when_gnu_stack_with_exec() -> None:
    """has_nx returns False when GNU_STACK header flags include 'x'."""
    headers = [{"type": "GNU_STACK", "flags": "rwx"}]
    assert esd.has_nx(headers) is False


def test_has_stack_canary_elf_returns_true() -> None:
    """ELF has_stack_canary returns True when __stack_chk_fail symbol is present."""
    symbols = [{"name": "__stack_chk_fail"}]
    assert esd.has_stack_canary(symbols) is True


def test_is_pie_elf_returns_false_for_missing_bin() -> None:
    """ELF is_pie returns False when elf_info has no 'bin' key."""
    assert esd.is_pie({}) is False


def test_path_features_rpath_and_runpath() -> None:
    """path_features correctly detects RPATH and RUNPATH strings."""
    info = "NEEDED libc.so RPATH /usr/lib RUNPATH /opt/lib"
    result = esd.path_features(info)
    assert result["rpath"] is True
    assert result["runpath"] is True


def test_path_features_neither() -> None:
    """path_features returns False for both when neither is present."""
    result = esd.path_features("NEEDED libc.so")
    assert result["rpath"] is False
    assert result["runpath"] is False
