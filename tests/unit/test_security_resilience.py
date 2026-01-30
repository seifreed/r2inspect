import base64
import json
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer
from r2inspect.modules.impfuzzy_analyzer import IMPFUZZY_AVAILABLE, ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDEEP_LIBRARY_AVAILABLE, SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer
from r2inspect.modules.yara_analyzer import YaraAnalyzer


class FakeR2:
    def __init__(self, cmdj_map=None):
        self._cmdj_map = cmdj_map or {}

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class ConfigStub:
    def __init__(self, rules_path: str):
        self._rules_path = rules_path

    def get_yara_rules_path(self):
        return self._rules_path


def test_ssdeep_missing_file_error(tmp_path):
    missing = tmp_path / "missing.bin"
    analyzer = SSDeepAnalyzer(filepath=str(missing))
    result = analyzer.analyze()
    assert result["available"] is False
    assert "does not exist" in result["error"].lower()


def test_yara_scan_missing_rules_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_text("hello")
    config = ConfigStub(str(tmp_path / "no_rules"))
    analyzer = YaraAnalyzer(FakeR2(cmdj_map={"ij": {"core": {"file": str(sample)}}}), config)
    matches = analyzer.scan(custom_rules_path=str(tmp_path / "missing_rules"))
    assert matches == []


def test_binbloom_deserialize_invalid():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    payload = {
        "version": 2,
        "error_rate": 0.1,
        "capacity": 10,
        "count": 0,
        "bitarray": [],
    }
    blob = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    assert BinbloomAnalyzer.deserialize_bloom(blob) is None


def test_optional_library_availability_flags(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_text("hello")

    if not TLSH_AVAILABLE:
        result = TLSHAnalyzer(FakeR2(), filename=str(sample)).analyze()
        assert result["available"] is False

    if not TELFHASH_AVAILABLE:
        result = TelfhashAnalyzer(FakeR2(), filepath=str(sample)).analyze()
        assert result["available"] is False

    if not IMPFUZZY_AVAILABLE:
        result = ImpfuzzyAnalyzer(FakeR2(), filepath=str(sample)).analyze()
        assert result["available"] is False

    if not SIMHASH_AVAILABLE:
        result = SimHashAnalyzer(FakeR2(), filepath=str(sample)).analyze()
        assert result["available"] is False

    if not SSDEEP_LIBRARY_AVAILABLE and not SSDeepAnalyzer.is_available():
        result = SSDeepAnalyzer(filepath=str(sample)).analyze()
        assert result["available"] is False
