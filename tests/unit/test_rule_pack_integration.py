import hashlib
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from r2inspect.application.rule_pack_operations import (
    build_rule_pack,
    default_rule_pack_root,
    install_rule_pack,
    list_rule_packs,
    sign_rule_pack,
)
from r2inspect.application import rule_packs
from r2inspect.application.rule_packs import (
    RulePackManifest,
    load_verified_manifest,
    verify_rule_pack,
)
from r2inspect.cli.rules_cli import rules_cli
from r2inspect.modules.yara_analyzer import YaraAnalyzer, clear_yara_cache
from r2inspect.modules.yara_rule_pack_support import verify_rules_path
from r2inspect.pipeline.stages_detection import DetectionStage


def _keys() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
    )


def _pack(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yar").write_text("rule demo { condition: true }", encoding="utf-8")
    private, public = _keys()
    build_rule_pack(source, pack_id="demo", version="1.0.0")
    sign_rule_pack(source, private)
    return source, private, public


def test_rule_pack_build_sign_install_update_and_list(tmp_path) -> None:
    source, private, public = _pack(tmp_path)
    manifest = verify_rule_pack(source, public_key=public)
    install_root = tmp_path / "installed"

    _, destination = install_rule_pack(source, public, root=install_root)
    metadata, _digest = verify_rules_path(destination)
    assert metadata == {
        "pack_id": "demo",
        "pack_version": "1.0.0",
        "manifest_digest": metadata["manifest_digest"],
        "signing_key_id": metadata["signing_key_id"],
        "rule_count": 1,
        "loaded_rules": 1,
        "failed_rules": 0,
    }
    assert list_rule_packs(install_root)[0]["pack_id"] == manifest.pack_id

    (source / "demo.yar").write_text("rule updated { condition: false }", encoding="utf-8")
    build_rule_pack(source, pack_id="demo", version="1.0.0")
    sign_rule_pack(source, private)
    install_rule_pack(source, public, root=install_root, replace_existing=True)
    assert "updated" in (destination / "demo.yar").read_text(encoding="utf-8")


def test_rule_pack_rejects_parent_and_symlink_escape(tmp_path) -> None:
    outside = tmp_path / "outside.yar"
    outside.write_text("rule outside { condition: true }", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    (pack / "manifest.json").write_text(
        json.dumps({"pack_id": "bad", "version": "1", "files": {"../outside.yar": digest}})
    )
    with pytest.raises(ValueError, match="escapes"):
        load_verified_manifest(pack)

    (pack / "link.yar").symlink_to(outside)
    (pack / "manifest.json").write_text(
        json.dumps({"pack_id": "bad", "version": "1", "files": {"link.yar": digest}})
    )
    with pytest.raises(ValueError, match="escapes"):
        load_verified_manifest(pack)


def test_yara_cache_invalidates_when_rule_content_changes(tmp_path) -> None:
    rule = tmp_path / "demo.yar"
    rule.write_text("rule one { condition: true }", encoding="utf-8")
    analyzer = object.__new__(YaraAnalyzer)
    compiled = []

    def compile_rules(_path):
        result = object()
        compiled.append(result)
        return result

    analyzer._compile_rules = compile_rules
    clear_yara_cache()
    first = analyzer._get_cached_rules(str(rule))
    assert analyzer._get_cached_rules(str(rule)) is first
    rule.write_text("rule two { condition: false }", encoding="utf-8")
    assert analyzer._get_cached_rules(str(rule)) is not first
    assert len(compiled) == 2


def test_detection_stage_exposes_rule_pack_report() -> None:
    metadata = {
        "pack_id": "demo",
        "pack_version": "1.0.0",
        "manifest_digest": "abc",
        "signing_key_id": "key",
        "rule_count": 2,
        "loaded_rules": 1,
        "failed_rules": 1,
    }

    class Analyzer:
        rule_pack_metadata = metadata

        def analyze(self, _custom):
            return []

    class Registry:
        def get_analyzer_class(self, _name):
            return Analyzer

        def get_metadata(self, _name):
            return None

    stage = DetectionStage(
        Registry(),
        object(),
        object(),
        "sample.bin",
        {},
        analyzer_factory=lambda _class, **_kwargs: Analyzer(),
    )
    context = {"results": {}}
    stage._run_yara_analysis(context)
    assert context["results"]["rule_pack"] == metadata


def test_rules_cli_build_sign_verify_install_list_and_update(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yar").write_text("rule demo { condition: true }", encoding="utf-8")
    private, public = _keys()
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "public.key"
    private_path.write_bytes(private)
    public_path.write_bytes(public)
    root = tmp_path / "installed"
    runner = CliRunner()

    commands = [
        ["build", str(source), "--pack-id", "demo", "--version", "1.0.0"],
        ["sign", str(source), "--private-key", str(private_path)],
        ["verify", str(source), "--public-key", str(public_path)],
        ["install", str(source), "--public-key", str(public_path), "--root", str(root)],
        ["list", "--root", str(root)],
        ["update", str(source), "--public-key", str(public_path), "--root", str(root)],
    ]
    for command in commands:
        result = runner.invoke(rules_cli, command)
        assert result.exit_code == 0, result.output


def test_rule_pack_validation_errors_and_default_root(tmp_path, monkeypatch) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no YARA"):
        build_rule_pack(empty, pack_id="demo", version="1")

    rule = empty / "demo.yar"
    rule.write_text("rule demo { condition: true }")
    with pytest.raises(ValueError, match="invalid pack ID"):
        build_rule_pack(empty, pack_id="../bad", version="1")

    manifest = empty / "manifest.json"
    manifest.write_text("[]")
    with pytest.raises(ValueError, match="invalid rule pack manifest"):
        RulePackManifest.load(manifest)

    digest = hashlib.sha256(rule.read_bytes()).hexdigest()
    payload = {"pack_id": "demo", "version": "1", "files": {"demo.yar": digest}}
    manifest.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="unsigned"):
        verify_rule_pack(empty)
    manifest.write_text(json.dumps({**payload, "signature": "invalid"}))
    with pytest.raises(ValueError, match="public key is required"):
        verify_rule_pack(empty)

    signed_root = tmp_path / "signed"
    signed_root.mkdir()
    source, _private, public = _pack(signed_root)
    root = tmp_path / "installed"
    install_rule_pack(source, public, root=root)
    with pytest.raises(ValueError, match="already installed"):
        install_rule_pack(source, public, root=root)

    monkeypatch.setenv("R2INSPECT_RULE_PACKS_DIR", str(root))
    assert default_rule_pack_root() == root
    assert list_rule_packs(tmp_path / "missing") == []


def test_rule_pack_rejects_corruption_and_wrong_keys(tmp_path, monkeypatch, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"files": {"rule.yar": "digest"}}))
    with pytest.raises(ValueError, match="invalid rule pack manifest"):
        RulePackManifest.load(invalid)

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "manifest.json").write_text(
        json.dumps({"pack_id": "demo", "version": "1", "files": {"missing.yar": "x"}})
    )
    with pytest.raises(ValueError, match="file is missing"):
        load_verified_manifest(pack)

    rule = pack / "rule.yar"
    rule.write_text("rule demo { condition: true }")
    (pack / "manifest.json").write_text(
        json.dumps({"pack_id": "demo", "version": "1", "files": {"rule.yar": "bad"}})
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        load_verified_manifest(pack)

    signed_root = tmp_path / "signed-again"
    signed_root.mkdir()
    source, _private, public = _pack(signed_root)
    wrong_public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_rule_pack(source, public_key=wrong_public)

    rsa_public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    with pytest.raises(ValueError, match="not Ed25519"):
        rule_packs.public_key_id(
            rsa_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    public_path = tmp_path / "public.key"
    public_path.write_bytes(public)
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify-pack", str(source), "--public-key", str(public_path)],
    )
    rule_packs.verify_main()
    assert "demo 1.0.0: verified" in capsys.readouterr().out
