import pytest

from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures


def test_section_info_validation_and_permissions():
    section = SectionInfo(name=".text", is_executable=True, is_readable=True)
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False
    assert section.is_suspicious() is False

    with pytest.raises(ValueError):
        SectionInfo(name=" ")


def test_format_analysis_result_validators():
    result = FormatAnalysisResult(available=True, format="pe32", bits=32, endian="LE")
    assert result.format == "PE32"
    assert result.bits == 32
    assert result.endian == "le"
    assert result.is_pe() is True
    assert result.is_elf() is False

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="unknown")

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_security_features_score():
    features = SecurityFeatures(aslr=True, dep=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert features.security_score() > 0
