"""Comprehensive tests for r2inspect/schemas/results_models.py"""

from datetime import datetime

import pytest

from r2inspect.schemas.results_models import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    StringInfo,
    YaraMatch,
    _default_security_features,
)


def test_default_security_features():
    features = _default_security_features()
    assert features.aslr is False
    assert features.dep is False
    assert features.nx is False
    assert features.pie is False
    assert features.canary is False


def test_file_info_creation():
    file_info = FileInfo(
        name="test.exe",
        path="/tmp/test.exe",
        size=1024,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_type="PE",
        architecture="x64",
        bits=64,
        endian="little",
        mime_type="application/x-dosexec",
    )
    assert file_info.name == "test.exe"
    assert file_info.size == 1024
    assert file_info.bits == 64


def test_file_info_defaults():
    file_info = FileInfo()
    assert file_info.name == ""
    assert file_info.size == 0
    assert file_info.md5 == ""
    assert file_info.bits == 0


def test_file_info_to_dict():
    file_info = FileInfo(name="test.exe", size=1024)
    result = file_info.to_dict()
    assert isinstance(result, dict)
    assert result["name"] == "test.exe"
    assert result["size"] == 1024


def test_hashing_result_creation():
    hashing = HashingResult(
        ssdeep="3:abc:def",
        tlsh="T1234",
        imphash="abc123",
        impfuzzy="fuzzy:hash",
        ccbhash="ccb123",
    )
    assert hashing.ssdeep == "3:abc:def"
    assert hashing.tlsh == "T1234"


def test_hashing_result_defaults():
    hashing = HashingResult()
    assert hashing.ssdeep == ""
    assert hashing.tlsh == ""
    assert hashing.imphash == ""


def test_hashing_result_to_dict():
    hashing = HashingResult(ssdeep="3:abc:def")
    result = hashing.to_dict()
    assert isinstance(result, dict)
    assert result["ssdeep"] == "3:abc:def"


def test_hashing_result_has_hash():
    hashing = HashingResult(ssdeep="3:abc:def", tlsh="")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False


def test_hashing_result_has_hash_whitespace():
    hashing = HashingResult(ssdeep="   ", tlsh="T1234")
    assert hashing.has_hash("ssdeep") is False
    assert hashing.has_hash("tlsh") is True


def test_hashing_result_has_hash_unknown_type():
    hashing = HashingResult()
    assert hashing.has_hash("unknown") is False


def test_import_info_creation():
    import_info = ImportInfo(
        name="CreateFile",
        library="kernel32.dll",
        address="0x401000",
        ordinal=42,
        category="file",
        risk_score=50,
        risk_level="Medium",
        risk_tags=["file_operation"],
    )
    assert import_info.name == "CreateFile"
    assert import_info.risk_score == 50


def test_import_info_defaults():
    import_info = ImportInfo()
    assert import_info.name == ""
    assert import_info.ordinal == 0
    assert import_info.risk_level == "Low"
    assert import_info.risk_tags == []


def test_import_info_to_dict():
    import_info = ImportInfo(name="CreateFile", library="kernel32.dll")
    result = import_info.to_dict()
    assert isinstance(result, dict)
    assert result["name"] == "CreateFile"


def test_export_info_creation():
    export_info = ExportInfo(
        name="DllMain", address="0x10001000", ordinal=1, size=256
    )
    assert export_info.name == "DllMain"
    assert export_info.ordinal == 1


def test_export_info_defaults():
    export_info = ExportInfo()
    assert export_info.name == ""
    assert export_info.ordinal == 0
    assert export_info.size == 0


def test_export_info_to_dict():
    export_info = ExportInfo(name="DllMain")
    result = export_info.to_dict()
    assert isinstance(result, dict)
    assert result["name"] == "DllMain"


def test_yara_match_creation():
    yara_match = YaraMatch(
        rule="MalwareRule",
        namespace="malware",
        tags=["trojan", "backdoor"],
        meta={"author": "test", "version": "1.0"},
        strings=[{"offset": 0x1000, "data": "test"}],
    )
    assert yara_match.rule == "MalwareRule"
    assert len(yara_match.tags) == 2


def test_yara_match_defaults():
    yara_match = YaraMatch()
    assert yara_match.rule == ""
    assert yara_match.tags == []
    assert yara_match.meta == {}
    assert yara_match.strings == []


def test_yara_match_to_dict():
    yara_match = YaraMatch(rule="TestRule", namespace="test")
    result = yara_match.to_dict()
    assert isinstance(result, dict)
    assert result["rule"] == "TestRule"


def test_string_info_creation():
    string_info = StringInfo(
        value="C:\\Windows\\System32",
        address="0x402000",
        length=18,
        encoding="ascii",
        is_suspicious=True,
    )
    assert string_info.value == "C:\\Windows\\System32"
    assert string_info.is_suspicious is True


def test_string_info_defaults():
    string_info = StringInfo()
    assert string_info.value == ""
    assert string_info.length == 0
    assert string_info.is_suspicious is False


def test_string_info_to_dict():
    string_info = StringInfo(value="test", length=4)
    result = string_info.to_dict()
    assert isinstance(result, dict)
    assert result["value"] == "test"


def test_function_info_creation():
    func_info = FunctionInfo(
        name="main",
        address=0x401000,
        size=512,
        complexity=10,
        basic_blocks=15,
        call_refs=5,
        data_refs=8,
    )
    assert func_info.name == "main"
    assert func_info.complexity == 10


def test_function_info_defaults():
    func_info = FunctionInfo()
    assert func_info.name == ""
    assert func_info.address == 0
    assert func_info.complexity == 0


def test_function_info_to_dict():
    func_info = FunctionInfo(name="main", size=512)
    result = func_info.to_dict()
    assert isinstance(result, dict)
    assert result["name"] == "main"


def test_anti_analysis_result_creation():
    anti_analysis = AntiAnalysisResult(
        anti_debug=True,
        anti_vm=True,
        anti_sandbox=False,
        timing_checks=True,
        techniques=[{"type": "IsDebuggerPresent", "location": "0x401000"}],
    )
    assert anti_analysis.anti_debug is True
    assert len(anti_analysis.techniques) == 1


def test_anti_analysis_result_defaults():
    anti_analysis = AntiAnalysisResult()
    assert anti_analysis.anti_debug is False
    assert anti_analysis.anti_vm is False
    assert anti_analysis.techniques == []


def test_anti_analysis_result_to_dict():
    anti_analysis = AntiAnalysisResult(anti_debug=True)
    result = anti_analysis.to_dict()
    assert isinstance(result, dict)
    assert result["anti_debug"] is True


def test_anti_analysis_has_evasion():
    anti_analysis = AntiAnalysisResult(anti_debug=True)
    assert anti_analysis.has_evasion() is True


def test_anti_analysis_no_evasion():
    anti_analysis = AntiAnalysisResult()
    assert anti_analysis.has_evasion() is False


def test_anti_analysis_has_evasion_partial():
    anti_analysis = AntiAnalysisResult(anti_vm=True, anti_debug=False)
    assert anti_analysis.has_evasion() is True


def test_packer_result_creation():
    packer = PackerResult(
        is_packed=True,
        packer_type="UPX",
        confidence=95,
        indicators=["high_entropy", "modified_header"],
    )
    assert packer.is_packed is True
    assert packer.packer_type == "UPX"


def test_packer_result_defaults():
    packer = PackerResult()
    assert packer.is_packed is False
    assert packer.confidence == 0
    assert packer.indicators == []


def test_packer_result_to_dict():
    packer = PackerResult(is_packed=True, packer_type="UPX")
    result = packer.to_dict()
    assert isinstance(result, dict)
    assert result["is_packed"] is True


def test_crypto_result_creation():
    crypto = CryptoResult(
        algorithms=[{"name": "AES", "location": "0x401000"}],
        constants=[{"type": "S-box", "offset": 0x402000}],
        functions=["CryptEncrypt", "CryptDecrypt"],
    )
    assert len(crypto.algorithms) == 1
    assert len(crypto.functions) == 2


def test_crypto_result_defaults():
    crypto = CryptoResult()
    assert crypto.algorithms == []
    assert crypto.constants == []
    assert crypto.functions == []


def test_crypto_result_to_dict():
    crypto = CryptoResult(functions=["CryptEncrypt"])
    result = crypto.to_dict()
    assert isinstance(result, dict)
    assert len(result["functions"]) == 1


def test_crypto_has_crypto():
    crypto = CryptoResult(algorithms=[{"name": "AES"}])
    assert crypto.has_crypto() is True


def test_crypto_has_crypto_with_constants():
    crypto = CryptoResult(constants=[{"type": "S-box"}])
    assert crypto.has_crypto() is True


def test_crypto_no_crypto():
    crypto = CryptoResult()
    assert crypto.has_crypto() is False


def test_indicator_creation():
    indicator = Indicator(
        type="Packer", description="UPX detected", severity="High"
    )
    assert indicator.type == "Packer"
    assert indicator.severity == "High"


def test_indicator_defaults():
    indicator = Indicator()
    assert indicator.type == ""
    assert indicator.severity == "Low"


def test_indicator_to_dict():
    indicator = Indicator(type="Packer", description="Test")
    result = indicator.to_dict()
    assert isinstance(result, dict)
    assert result["type"] == "Packer"


def test_analysis_result_creation():
    result = AnalysisResult()
    assert isinstance(result.file_info, FileInfo)
    assert isinstance(result.hashing, HashingResult)
    assert isinstance(result.anti_analysis, AntiAnalysisResult)


def test_analysis_result_with_data():
    file_info = FileInfo(name="test.exe", size=1024)
    result = AnalysisResult(
        file_info=file_info, execution_time=1.5, error=None
    )
    assert result.file_info.name == "test.exe"
    assert result.execution_time == 1.5


def test_analysis_result_to_dict():
    result = AnalysisResult()
    data = result.to_dict()
    assert isinstance(data, dict)
    assert "file_info" in data
    assert "hashing" in data
    assert "timestamp" in data


def test_analysis_result_to_dict_with_nested():
    file_info = FileInfo(name="test.exe", size=1024)
    import_info = ImportInfo(name="CreateFile", library="kernel32.dll")
    result = AnalysisResult(file_info=file_info, imports=[import_info])
    data = result.to_dict()
    assert data["file_info"]["name"] == "test.exe"
    assert len(data["imports"]) == 1
    assert data["imports"][0]["name"] == "CreateFile"


def test_analysis_result_timestamp_serialization():
    result = AnalysisResult()
    data = result.to_dict()
    assert isinstance(data["timestamp"], str)
    datetime.fromisoformat(data["timestamp"])


def test_analysis_result_has_error():
    result = AnalysisResult(error="Test error")
    assert result.has_error() is True


def test_analysis_result_no_error():
    result = AnalysisResult(error=None)
    assert result.has_error() is False


def test_analysis_result_is_suspicious_with_indicators():
    indicator = Indicator(type="Packer", severity="High")
    result = AnalysisResult(indicators=[indicator])
    assert result.is_suspicious() is True


def test_analysis_result_is_suspicious_with_evasion():
    anti_analysis = AntiAnalysisResult(anti_debug=True)
    result = AnalysisResult(anti_analysis=anti_analysis)
    assert result.is_suspicious() is True


def test_analysis_result_is_suspicious_with_packer():
    packer = PackerResult(is_packed=True)
    result = AnalysisResult(packer=packer)
    assert result.is_suspicious() is True


def test_analysis_result_not_suspicious():
    result = AnalysisResult()
    assert result.is_suspicious() is False


def test_analysis_result_get_high_severity_indicators():
    high_indicator = Indicator(type="Packer", severity="High")
    critical_indicator = Indicator(type="Anti-Debug", severity="Critical")
    low_indicator = Indicator(type="Test", severity="Low")
    result = AnalysisResult(
        indicators=[high_indicator, critical_indicator, low_indicator]
    )
    high_severity = result.get_high_severity_indicators()
    assert len(high_severity) == 2
    assert high_indicator in high_severity
    assert critical_indicator in high_severity


def test_analysis_result_summary():
    file_info = FileInfo(
        name="test.exe",
        file_type="PE",
        size=1024,
        md5="abc123",
        sha256="def456",
    )
    packer = PackerResult(is_packed=True, packer_type="UPX")
    result = AnalysisResult(file_info=file_info, packer=packer)
    summary = result.summary()
    assert summary["file_name"] == "test.exe"
    assert summary["is_packed"] is True
    assert summary["packer_type"] == "UPX"


def test_analysis_result_summary_with_imports_and_exports():
    import1 = ImportInfo(name="CreateFile")
    import2 = ImportInfo(name="WriteFile")
    export1 = ExportInfo(name="DllMain")
    result = AnalysisResult(imports=[import1, import2], exports=[export1])
    summary = result.summary()
    assert summary["total_imports"] == 2
    assert summary["total_exports"] == 1


def test_analysis_result_summary_yara_matches():
    yara1 = YaraMatch(rule="Rule1")
    yara2 = YaraMatch(rule="Rule2")
    result = AnalysisResult(yara_matches=[yara1, yara2])
    summary = result.summary()
    assert summary["yara_matches_count"] == 2


def test_analysis_result_all_fields():
    result = AnalysisResult(
        file_info=FileInfo(name="test.exe"),
        hashing=HashingResult(ssdeep="test"),
        imports=[ImportInfo(name="API1")],
        exports=[ExportInfo(name="Export1")],
        strings=["string1", "string2"],
        yara_matches=[YaraMatch(rule="Rule1")],
        functions=[FunctionInfo(name="main")],
        anti_analysis=AntiAnalysisResult(anti_debug=True),
        packer=PackerResult(is_packed=True),
        crypto=CryptoResult(algorithms=[{"name": "AES"}]),
        indicators=[Indicator(type="Packer")],
        error=None,
        execution_time=2.5,
    )
    data = result.to_dict()
    assert data["file_info"]["name"] == "test.exe"
    assert data["hashing"]["ssdeep"] == "test"
    assert len(data["strings"]) == 2
    assert data["execution_time"] == 2.5


def test_analysis_result_security_features_in_summary():
    from r2inspect.schemas.format import SecurityFeatures

    security = SecurityFeatures(aslr=True, dep=True, nx=True)
    result = AnalysisResult(security=security)
    summary = result.summary()
    assert "security_score" in summary
    assert summary["security_score"] > 0
