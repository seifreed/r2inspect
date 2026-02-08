from __future__ import annotations

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


def test_authenticode_verify_signature_integrity():
    analyzer = AuthenticodeAnalyzer(adapter=None)

    assert analyzer._verify_signature_integrity({"has_signature": False}) is False

    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": [],
                "errors": [],
                "security_directory": {"size": 10},
            }
        )
        is False
    )

    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": ["c"],
                "errors": ["err"],
                "security_directory": {"size": 10},
            }
        )
        is False
    )

    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": ["c"],
                "errors": [],
                "security_directory": {"size": 0},
            }
        )
        is False
    )

    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": ["c"],
                "errors": [],
                "security_directory": {"size": 10},
            }
        )
        is True
    )
