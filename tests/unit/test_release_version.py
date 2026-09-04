from __future__ import annotations

from scripts.check_release_version import declared_versions, version_errors


def test_v4_release_versions_and_tag_are_consistent() -> None:
    versions = declared_versions()

    assert set(versions.values()) == {"4.0.0"}
    assert version_errors(versions, "v4.0.0") == []
    assert version_errors(versions, "v3.0.0") == ["tag v3.0.0 does not match v4.0.0"]
