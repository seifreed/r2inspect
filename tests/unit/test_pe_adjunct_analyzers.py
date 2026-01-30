import hashlib

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.import_analyzer import ImportAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.section_analyzer import SectionAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class DummyConfig:
    pass


def test_resource_type_name_and_entropy():
    analyzer = ResourceAnalyzer(FakeR2())
    assert analyzer._get_resource_type_name(3) == "RT_ICON"
    assert analyzer._get_resource_type_name(999) == "UNKNOWN_999"

    entropy = analyzer._calculate_entropy([0, 0, 0, 0])
    assert entropy == 0.0


def test_resource_analyze_resource_data_hashes():
    r2 = FakeR2(cmdj_map={"pxj 4 @ 100": [1, 2, 3, 4]})
    analyzer = ResourceAnalyzer(r2)
    resource = {"offset": 100, "size": 4, "entropy": 0.0, "hashes": {}}

    analyzer._analyze_resource_data(resource)

    data_bytes = bytes([1, 2, 3, 4])
    assert resource["hashes"]["md5"] == hashlib.md5(data_bytes, usedforsecurity=False).hexdigest()
    assert resource["entropy"] > 0.0


def test_overlay_calculate_pe_end_uses_security_dir():
    r2 = FakeR2(
        cmdj_map={
            "iSj": [
                {"paddr": 0, "size": 100},
                {"paddr": 100, "size": 100},
            ],
            "iDj": [{"name": "SECURITY", "paddr": 300, "size": 20}],
        }
    )
    analyzer = OverlayAnalyzer(r2)
    assert analyzer._calculate_pe_end() == 320


def test_section_entropy_and_name_indicators():
    r2 = FakeR2(cmd_map={"p8 4 @ 4096": "00010203"})
    analyzer = SectionAnalyzer(r2, DummyConfig())

    section = {"name": "upx0", "vaddr": 4096, "size": 4, "vsize": 4}
    entropy = analyzer._calculate_entropy(section)
    assert entropy > 0.0

    indicators = analyzer._check_section_name_indicators("upx0")
    assert any("Suspicious section name" in item for item in indicators)

    indicators = analyzer._check_section_name_indicators("custom")
    assert "Non-standard section name" in indicators


def test_import_risk_and_patterns():
    analyzer = ImportAnalyzer(FakeR2(), DummyConfig())
    risk = analyzer._calculate_risk_score("CreateRemoteThread")
    assert risk["risk_level"] == "Critical"
    assert "Remote Thread Injection" in risk["risk_tags"]

    imports = [
        {"name": "VirtualAllocEx", "category": "Memory Management"},
        {"name": "WriteProcessMemory", "category": "Memory Management"},
        {"name": "CreateRemoteThread", "category": "Process/Thread Management"},
    ]
    patterns = analyzer._find_suspicious_patterns(imports)
    assert any(p["pattern"] == "DLL Injection" for p in patterns)


def test_export_characteristics_with_function():
    r2 = FakeR2(cmdj_map={"afij @ 4096": [{"size": 16, "cc": 2}]})
    analyzer = ExportAnalyzer(r2, DummyConfig())

    exp = {"name": "RunService", "vaddr": 4096}
    characteristics = analyzer._get_export_characteristics(exp)
    assert characteristics["suspicious_name"] is True
    assert characteristics["is_function"] is True


def test_exploit_mitigation_dll_characteristics():
    flags = 0x0040 | 0x0100 | 0x4000
    r2 = FakeR2(cmdj_map={"iHj": {"dll_characteristics": flags}})
    analyzer = ExploitMitigationAnalyzer(r2)
    result = {"mitigations": {}, "dll_characteristics": {}}

    analyzer._check_dll_characteristics(result)

    assert result["mitigations"]["ASLR"]["enabled"] is True
    assert result["mitigations"]["DEP"]["enabled"] is True
    assert result["mitigations"]["CFG"]["enabled"] is True


def test_authenticode_helpers():
    analyzer = AuthenticodeAnalyzer(FakeR2())
    cert_length, cert_revision, cert_type = analyzer._parse_win_cert_header(
        [0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00]
    )
    assert cert_length == 8
    assert cert_revision == 2
    assert cert_type == 2
    assert analyzer._get_cert_type_name(0x0002) == "PKCS#7"

    sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    assert analyzer._detect_digest_algorithm(sha256_oid) == "SHA256"
    assert analyzer._detect_encryption_algorithm(rsa_oid) == "RSA"
