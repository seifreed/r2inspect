from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.testing.fixtures import (
    ensure_expected_snapshots,
    resolve_fixture_source_root,
    sync_sample_fixtures,
)


def _make_source_tree(root: Path) -> None:
    (root / "pe").mkdir(parents=True)
    (root / "elf").mkdir(parents=True)
    (root / "mach0").mkdir(parents=True)
    (root / "edge").mkdir(parents=True)

    (root / "pe" / "hello_pe.exe").write_bytes(b"MZ\x00\x00payload")
    (root / "elf" / "hello_elf").write_bytes(b"\x7fELFpayload")
    (root / "mach0" / "hello_macho").write_bytes(b"\xfe\xed\xfa\xcfpayload")
    (root / "mach0" / "hello_macho_stripped").write_bytes(b"\xfe\xed\xfa\xcfstrip")
    (root / "edge" / "edge_tiny.bin").write_bytes(b"\x00")
    (root / "edge" / "edge_packed.bin").write_bytes(b"UPX!\x00")
    (root / "edge" / "edge_bad_pe.bin").write_bytes(b"MZbad")
    (root / "edge" / "edge_high_entropy.bin").write_bytes(bytes(range(64)))


def test_resolve_fixture_source_root_supports_external_repo_layout(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    external = tmp_path / "r2inspect-test-binaries"
    _make_source_tree(external)

    assert resolve_fixture_source_root(repo_root) == external


def test_sync_sample_fixtures_repairs_dangling_symlink_and_generates_expected(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "fixture-source"
    _make_source_tree(source_root)
    target_dir = tmp_path / "samples" / "fixtures"
    target_dir.mkdir(parents=True)

    broken = target_dir / "hello_pe.exe"
    broken.symlink_to(tmp_path / "missing" / "hello_pe.exe")

    created = sync_sample_fixtures(target_dir, source_root)

    assert broken.exists()
    assert any(path.name == "expected" for path in created)
    assert (target_dir / "expected" / "hello_pe.json").exists()
    assert (target_dir / "hello_elf").exists()


def test_sync_sample_fixtures_copies_when_requested(tmp_path: Path) -> None:
    source_root = tmp_path / "fixture-source"
    _make_source_tree(source_root)
    target_dir = tmp_path / "samples" / "fixtures"

    sync_sample_fixtures(target_dir, source_root, copy_files=True)

    target = target_dir / "hello_pe.exe"
    assert not target.is_symlink()
    assert target.read_bytes() == b"MZ\x00\x00payload"


def test_sync_sample_fixtures_keeps_existing_real_files(tmp_path: Path) -> None:
    source_root = tmp_path / "fixture-source"
    _make_source_tree(source_root)
    target_dir = tmp_path / "samples" / "fixtures"
    target_dir.mkdir(parents=True)
    existing = target_dir / "hello_pe.exe"
    existing.write_bytes(b"PRESERVE")

    created = sync_sample_fixtures(target_dir, source_root)

    assert existing.read_bytes() == b"PRESERVE"
    assert existing not in created


def test_sync_sample_fixtures_skips_missing_source_entries(tmp_path: Path) -> None:
    source_root = tmp_path / "fixture-source"
    _make_source_tree(source_root)
    (source_root / "elf" / "hello_elf").unlink()
    target_dir = tmp_path / "samples" / "fixtures"

    created = sync_sample_fixtures(target_dir, source_root)

    assert not (target_dir / "hello_elf").exists()
    assert (target_dir / "hello_pe.exe").exists()
    assert all(path.name != "hello_elf" for path in created)


def test_sync_sample_fixtures_replaces_symlinked_expected_dir(tmp_path: Path) -> None:
    source_root = tmp_path / "fixture-source"
    _make_source_tree(source_root)
    target_dir = tmp_path / "samples" / "fixtures"
    target_dir.mkdir(parents=True)
    (target_dir / "expected").symlink_to(tmp_path)

    sync_sample_fixtures(target_dir, source_root)

    assert (target_dir / "expected").is_dir()
    assert not (target_dir / "expected").is_symlink()


def test_sync_sample_fixtures_raises_without_supported_layout(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sync_sample_fixtures(tmp_path / "out", tmp_path / "empty-source")


def test_ensure_expected_snapshots_creates_json_payloads(tmp_path: Path) -> None:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "hello_pe.exe").write_bytes(b"MZ\x00\x00payload")

    ensure_expected_snapshots(fixtures_dir)

    payload = (fixtures_dir / "expected" / "hello_pe.json").read_text(encoding="utf-8")
    assert '"file_format": "PE"' in payload
