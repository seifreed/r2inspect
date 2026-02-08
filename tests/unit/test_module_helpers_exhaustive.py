from __future__ import annotations

from r2inspect.modules import crypto_domain, domain_helpers, search_helpers
from r2inspect.modules.security_scoring import _grade_from_percentage, build_security_score
from r2inspect.modules.similarity_scoring import (
    jaccard_similarity,
    normalized_difference_similarity,
)
from r2inspect.modules.string_classification import (
    classify_string_type,
    is_api_string,
    is_path_string,
    is_registry_string,
    is_url_string,
)
from r2inspect.modules.string_extraction import (
    extract_ascii_from_bytes,
    extract_strings_from_entries,
    split_null_terminated,
)


def test_domain_helpers_entropy_and_scoring() -> None:
    assert domain_helpers.shannon_entropy(b"") == 0.0
    assert domain_helpers.entropy_from_ints([]) == 0.0
    assert domain_helpers.clamp_score(-1, minimum=0, maximum=10) == 0
    assert domain_helpers.clamp_score(20, minimum=0, maximum=10) == 10
    assert (
        domain_helpers.count_suspicious_imports(
            [{"name": "VirtualAlloc"}, {"name": "Other"}], {"VirtualAlloc"}
        )
        == 1
    )
    assert domain_helpers.normalize_section_name(None) == ""
    assert domain_helpers.suspicious_section_name_indicator("UPX0", ["upx"]) is not None
    assert domain_helpers.suspicious_section_name_indicator("text", ["upx"]) is None


def test_security_scoring_branches() -> None:
    result = {
        "mitigations": {
            "ASLR": {"enabled": True, "high_entropy": True},
            "DEP": {"enabled": True},
        },
        "vulnerabilities": [{"severity": "high"}, {"severity": "medium"}],
    }
    scored = build_security_score(result)
    assert scored["max_score"] > 0
    assert scored["grade"] in {"A", "B", "C", "D", "F"}

    scored_empty = build_security_score({"mitigations": {}, "vulnerabilities": []})
    assert scored_empty["grade"] == "F"
    assert _grade_from_percentage(0, 0) == "Unknown"


def test_similarity_scoring_paths() -> None:
    assert jaccard_similarity(set(), set()) == 1.0
    assert jaccard_similarity(set(), {"a"}) == 0.0
    assert jaccard_similarity({"a"}, {"a"}) == 1.0
    assert normalized_difference_similarity(0, 1) == 0.0
    assert normalized_difference_similarity(10, 20) > 0.0


def test_string_classification_and_extraction() -> None:
    assert is_api_string("CreateFileA")
    assert is_path_string("C:\\temp\\file.txt")
    assert is_url_string("https://example.com")
    assert is_registry_string("HKEY_LOCAL_MACHINE\\Software")

    assert classify_string_type("https://example.com") == "url"
    assert classify_string_type("C:\\Windows") == "path"
    assert classify_string_type("HKEY_LOCAL_MACHINE") == "registry"
    assert classify_string_type("CreateFileA") == "api"
    assert classify_string_type("error: failed") == "error"
    assert classify_string_type("plain") is None

    entries = [{"string": "test"}, {"string": "a"}]
    assert extract_strings_from_entries(entries, min_length=2) == ["test"]
    assert extract_strings_from_entries([], min_length=2) == []

    data = [0x41, 0x42, 0x00, 0x43, 0x44, 0x45, 0x00]
    assert extract_ascii_from_bytes(data, min_length=2, limit=10) == ["AB", "CDE"]
    assert split_null_terminated("foo\0bar\0x", min_length=2) == ["foo", "bar"]


def test_crypto_domain_detection() -> None:
    detected: dict[str, list] = {}
    crypto_domain.detect_algorithms_from_strings(
        [{"string": "AES-256", "vaddr": 4096}, {"string": "std::string"}],
        detected,
    )
    assert "AES" in detected

    consolidated = crypto_domain.consolidate_detections(detected)
    assert consolidated
    assert consolidated[0]["algorithm"]


def test_search_helpers_normalization() -> None:
    class DummyAdapter:
        def search_text(self, pattern: str) -> str:
            return f"text:{pattern}"

        def search_hex(self, pattern: str) -> str:
            return f"hex:{pattern}"

    adapter = DummyAdapter()
    assert search_helpers.search_text(adapter, None, " test ") == "text:test"
    assert search_helpers.search_hex(adapter, None, " ff ") == "hex:ff"
    assert search_helpers.search_text(None, None, "x") == ""
