#!/usr/bin/env python3
"""Comprehensive tests for macho_analyzer - remaining coverage."""

from unittest.mock import MagicMock, Mock, patch

from r2inspect.modules.macho_analyzer import MachOAnalyzer


def test_analyze_complete_workflow():
    """Test analyze method complete workflow."""
    adapter = MagicMock()
    
    analyzer = MachOAnalyzer(adapter)
    
    with patch.object(analyzer, '_get_macho_headers', return_value={"architecture": "x86_64"}):
        with patch.object(analyzer, '_get_compilation_info', return_value={"sdk_version": "11.0"}):
            with patch.object(analyzer, '_get_load_commands', return_value=[]):
                with patch.object(analyzer, '_get_section_info', return_value=[]):
                    with patch.object(analyzer, 'get_security_features', return_value={}):
                        result = analyzer.analyze()
                        assert result["architecture"] == "x86_64"
                        assert result["sdk_version"] == "11.0"


def test_get_macho_headers_complete():
    """Test _get_macho_headers extracts all fields."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    macho_info = {
        "bin": {
            "arch": "arm64",
            "machine": "ARM64",
            "bits": 64,
            "endian": "little",
            "class": "MACH064",
            "format": "mach0",
            "baddr": 0x100000000,
            "cpu": "ARM_64",
            "filetype": "EXECUTE",
        }
    }
    
    with patch.object(analyzer, '_cmdj', return_value=macho_info):
        result = analyzer._get_macho_headers()
        assert result["architecture"] == "arm64"
        assert result["machine"] == "ARM64"
        assert result["bits"] == 64
        assert result["cpu_type"] == "ARM_64"
        assert result["file_type"] == "EXECUTE"


def test_get_macho_headers_missing_bin():
    """Test _get_macho_headers with missing bin info."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmdj', return_value={}):
        result = analyzer._get_macho_headers()
        assert result == {}


def test_get_compilation_info_complete():
    """Test _get_compilation_info combines all sources."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch.object(analyzer, '_extract_build_version', return_value={"platform": "macOS", "sdk_version": "11.0"}):
        with patch.object(analyzer, '_extract_version_min', return_value={}):
            with patch.object(analyzer, '_extract_dylib_info', return_value={}):
                with patch.object(analyzer, '_extract_uuid', return_value="ABC-123"):
                    result = analyzer._get_compilation_info()
                    assert result["platform"] == "macOS"
                    assert result["sdk_version"] == "11.0"
                    assert result["uuid"] == "ABC-123"


def test_get_compilation_info_with_estimate():
    """Test _get_compilation_info uses estimate when no compile time."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch.object(analyzer, '_extract_build_version', return_value={}):
        with patch.object(analyzer, '_extract_version_min', return_value={}):
            with patch.object(analyzer, '_extract_dylib_info', return_value={}):
                with patch.object(analyzer, '_extract_uuid', return_value=None):
                    with patch.object(analyzer, '_estimate_compile_time', return_value=""):
                        result = analyzer._get_compilation_info()
                        assert result["compile_time"] == ""


def test_extract_build_version_with_lc_build_version():
    """Test _extract_build_version extracts build version."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_BUILD_VERSION", "platform": "macOS", "minos": "10.15", "sdk": "11.0"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.estimate_from_sdk_version', return_value="2020"):
            result = analyzer._extract_build_version()
            assert result["platform"] == "macOS"
            assert result["min_os_version"] == "10.15"
            assert result["sdk_version"] == "11.0"
            assert result["compile_time"] == "2020"


def test_extract_build_version_no_sdk_estimate():
    """Test _extract_build_version without SDK version."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_BUILD_VERSION", "platform": "iOS", "minos": "14.0", "sdk": ""}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        result = analyzer._extract_build_version()
        assert result["platform"] == "iOS"
        assert "compile_time" not in result


def test_extract_build_version_no_headers():
    """Test _extract_build_version with no LC_BUILD_VERSION."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_LOAD_DYLIB", "name": "test.dylib"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        result = analyzer._extract_build_version()
        assert result == {}


def test_extract_version_min_with_version_min():
    """Test _extract_version_min extracts version min."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_VERSION_MIN_MACOSX", "version": "10.14", "sdk": "10.15"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.platform_from_version_min', return_value="macOS"):
            result = analyzer._extract_version_min()
            assert result["version_min_type"] == "LC_VERSION_MIN_MACOSX"
            assert result["min_version"] == "10.14"
            assert result["sdk_version"] == "10.15"
            assert result["platform"] == "macOS"


def test_extract_version_min_no_platform():
    """Test _extract_version_min with no platform mapping."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_VERSION_MIN_UNKNOWN", "version": "1.0", "sdk": "1.0"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.platform_from_version_min', return_value=None):
            result = analyzer._extract_version_min()
            assert result["version_min_type"] == "LC_VERSION_MIN_UNKNOWN"
            assert "platform" not in result


def test_extract_dylib_info_with_lc_id_dylib():
    """Test _extract_dylib_info extracts dylib info."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_ID_DYLIB", "timestamp": 1609459200, "name": "test.dylib", "version": "1.0.0", "compatibility": "1.0.0"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.dylib_timestamp_to_string', return_value=("2021-01-01", 1609459200)):
            result = analyzer._extract_dylib_info()
            assert result["compile_time"] == "2021-01-01"
            assert result["dylib_timestamp"] == "1609459200"
            assert result["dylib_name"] == "test.dylib"
            assert result["dylib_version"] == "1.0.0"


def test_extract_dylib_info_no_timestamp():
    """Test _extract_dylib_info with no timestamp."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_ID_DYLIB", "timestamp": 0, "name": "test.dylib", "version": "1.0.0", "compatibility": "1.0.0"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.dylib_timestamp_to_string', return_value=(None, None)):
            result = analyzer._extract_dylib_info()
            assert "compile_time" not in result
            assert result["dylib_name"] == "test.dylib"


def test_extract_uuid_with_lc_uuid():
    """Test _extract_uuid extracts UUID."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_UUID", "uuid": "ABC-DEF-123-456"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        result = analyzer._extract_uuid()
        assert result == "ABC-DEF-123-456"


def test_extract_uuid_no_uuid():
    """Test _extract_uuid with no UUID."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_UUID", "uuid": ""}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        result = analyzer._extract_uuid()
        assert result is None


def test_get_load_commands_with_headers():
    """Test _get_load_commands builds commands."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_LOAD_DYLIB", "name": "test.dylib"},
        {"type": "LC_UUID", "uuid": "ABC-123"},
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.build_load_commands', return_value=[{"type": "LC_LOAD_DYLIB"}]) as mock_build:
            result = analyzer._get_load_commands()
            mock_build.assert_called_once_with(headers)
            assert len(result) == 1


def test_get_section_info_with_adapter():
    """Test _get_section_info with adapter having get_sections."""
    adapter = MagicMock()
    adapter.get_sections.return_value = [
        {"name": "__text", "size": 1000, "vaddr": 0x100000000},
        {"name": "__data", "size": 500, "vaddr": 0x100001000},
    ]
    
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.build_sections', return_value=[{"name": "__text"}]) as mock_build:
        result = analyzer._get_section_info()
        mock_build.assert_called_once()


def test_get_section_info_no_adapter():
    """Test _get_section_info with no adapter."""
    adapter = None
    analyzer = MachOAnalyzer(MagicMock())
    analyzer.adapter = None
    
    with patch('r2inspect.modules.macho_analyzer.build_sections', return_value=[]) as mock_build:
        result = analyzer._get_section_info()
        mock_build.assert_called_once_with([])


def test_get_section_info_adapter_no_method():
    """Test _get_section_info with adapter without get_sections."""
    adapter = Mock(spec=[])
    analyzer = MachOAnalyzer(MagicMock())
    analyzer.adapter = adapter
    
    with patch('r2inspect.modules.macho_analyzer.build_sections', return_value=[]):
        result = analyzer._get_section_info()
        assert result == []


def test_supports_format_all_variants():
    """Test supports_format accepts all Mach-O variants."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("MACHO") is True
    assert analyzer.supports_format("MACH-O") is True
    assert analyzer.supports_format("MACH064") is True
    assert analyzer.supports_format("mach0") is True
    assert analyzer.supports_format("PE") is False


def test_get_macho_headers_exception():
    """Test _get_macho_headers handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmdj', side_effect=Exception("Test error")):
        result = analyzer._get_macho_headers()
        assert result == {}


def test_extract_build_version_exception():
    """Test _extract_build_version handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("Test error")):
        result = analyzer._extract_build_version()
        assert result == {}


def test_extract_version_min_exception():
    """Test _extract_version_min handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("Test error")):
        result = analyzer._extract_version_min()
        assert result == {}


def test_extract_dylib_info_exception():
    """Test _extract_dylib_info handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("Test error")):
        result = analyzer._extract_dylib_info()
        assert result == {}


def test_get_load_commands_exception():
    """Test _get_load_commands handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("Test error")):
        result = analyzer._get_load_commands()
        assert result == []


def test_get_section_info_exception():
    """Test _get_section_info handles exception."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.build_sections', side_effect=Exception("Test error")):
        result = analyzer._get_section_info()
        assert result == []


def test_get_security_features():
    """Test get_security_features delegates correctly."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer._get_security_features', return_value={"PIE": True, "ARC": True}):
        result = analyzer.get_security_features()
        assert result == {"PIE": True, "ARC": True}


def test_extract_build_version_with_empty_headers():
    """Test _extract_build_version with empty headers list."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_build_version()
        assert result == {}


def test_extract_version_min_with_empty_headers():
    """Test _extract_version_min with empty headers list."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_version_min()
        assert result == {}


def test_extract_dylib_info_with_empty_headers():
    """Test _extract_dylib_info with empty headers list."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_dylib_info()
        assert result == {}


def test_extract_uuid_with_empty_headers():
    """Test _extract_uuid with empty headers list."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_uuid()
        assert result is None


def test_get_macho_headers_with_defaults():
    """Test _get_macho_headers handles missing fields with defaults."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    macho_info = {
        "bin": {
            "arch": "x86_64",
        }
    }
    
    with patch.object(analyzer, '_cmdj', return_value=macho_info):
        result = analyzer._get_macho_headers()
        assert result["architecture"] == "x86_64"
        assert result["machine"] == "Unknown"
        assert result["bits"] == 0


def test_get_section_info_not_list():
    """Test _get_section_info handles non-list return."""
    adapter = MagicMock()
    adapter.get_sections.return_value = None
    
    analyzer = MachOAnalyzer(adapter)
    
    with patch('r2inspect.modules.macho_analyzer.build_sections', return_value=[]) as mock_build:
        result = analyzer._get_section_info()
        mock_build.assert_called_once_with([])


def test_extract_build_version_with_sdk_version_info():
    """Test _extract_build_version stores sdk_version_info."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_BUILD_VERSION", "platform": "macOS", "minos": "10.15", "sdk": "11.0"}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.estimate_from_sdk_version', return_value="2020"):
            result = analyzer._extract_build_version()
            assert result["sdk_version_info"] == "11.0"


def test_extract_dylib_info_with_missing_fields():
    """Test _extract_dylib_info handles missing fields."""
    adapter = MagicMock()
    analyzer = MachOAnalyzer(adapter)
    
    headers = [
        {"type": "LC_ID_DYLIB", "timestamp": 1609459200}
    ]
    
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=headers):
        with patch('r2inspect.modules.macho_analyzer.dylib_timestamp_to_string', return_value=("2021-01-01", 1609459200)):
            result = analyzer._extract_dylib_info()
            assert result["dylib_name"] == "Unknown"
            assert result["dylib_version"] == "Unknown"
            assert result["dylib_compatibility"] == "Unknown"
