from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.packer_detector import PackerDetector

pytestmark = pytest.mark.requires_r2


def test_authenticode_and_mitigations_real(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    bad_pe = samples_dir / "edge_bad_pe.bin"

    for sample in (pe_sample, bad_pe):
        with create_inspector(str(sample)) as inspector:
            auth = AuthenticodeAnalyzer(inspector.adapter).analyze()
            assert "available" in auth
            assert "has_signature" in auth

            mitigations = ExploitMitigationAnalyzer(inspector.adapter).analyze()
            assert "available" in mitigations
            assert "mitigations" in mitigations


def test_packer_and_overlay_real(samples_dir: Path) -> None:
    packed_sample = samples_dir / "edge_packed.bin"
    pe_sample = samples_dir / "hello_pe.exe"

    for sample in (packed_sample, pe_sample):
        with create_inspector(str(sample)) as inspector:
            packer = PackerDetector(inspector.adapter, inspector.config).detect()
            assert "is_packed" in packer
            assert "confidence" in packer
            assert "indicators" in packer

            overlay = OverlayAnalyzer(inspector.adapter).analyze()
            assert "available" in overlay
            assert "has_overlay" in overlay
            assert "overlay_size" in overlay


def test_compiler_detection_real(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    elf_sample = samples_dir / "hello_elf"

    for sample in (pe_sample, elf_sample):
        with create_inspector(str(sample)) as inspector:
            detector = CompilerDetector(inspector.adapter, inspector.config)
            results = detector.detect_compiler()
            assert "detected" in results
            assert "compiler" in results
            assert "confidence" in results
