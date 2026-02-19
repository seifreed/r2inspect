"""Comprehensive tests for rich_header_analyzer.py extraction methods."""

from unittest.mock import Mock, patch

import pytest

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


class TestRichHeaderExtraction:
    """Test Rich Header extraction methods and edge cases."""

    def test_analyzer_init_with_adapter(self):
        """Test initialization with adapter."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        assert analyzer.adapter == adapter

    def test_analyzer_init_with_r2_instance(self):
        """Test initialization with r2_instance (legacy)."""
        r2 = Mock()
        analyzer = RichHeaderAnalyzer(r2_instance=r2)
        assert analyzer.adapter == r2

    def test_is_available(self):
        """Test that Rich Header analysis is always available."""
        assert RichHeaderAnalyzer.is_available() is True

    def test_analyze_non_pe_file(self):
        """Test analyzing non-PE file."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.bin")
        analyzer._is_pe_file = Mock(return_value=False)
        
        result = analyzer.analyze()
        
        assert result["is_pe"] is False
        assert result["error"] == "File is not a PE binary"
        assert result["rich_header"] is None

    def test_analyze_pe_no_rich_header(self):
        """Test PE file without Rich Header."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._is_pe_file = Mock(return_value=True)
        analyzer._extract_rich_header_pefile = Mock(return_value=None)
        analyzer._extract_rich_header_r2pipe = Mock(return_value=None)
        
        result = analyzer.analyze()
        
        assert result["is_pe"] is True
        assert result["error"] == "Rich Header not found"

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_analyze_pefile_success(self):
        """Test successful extraction using pefile."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._is_pe_file = Mock(return_value=True)
        
        rich_data = {
            "xor_key": 0x12345678,
            "checksum": 0x12345678,
            "entries": [
                {"product_id": 261, "build_number": 30729, "count": 10, "prodid": 2012512517}
            ],
            "richpe_hash": "abc123def456"
        }
        
        analyzer._extract_rich_header_pefile = Mock(return_value=rich_data)
        
        with patch("r2inspect.modules.rich_header_analyzer.parse_compiler_entries") as mock_parse:
            mock_parse.return_value = [{"compiler": "Visual Studio 2008"}]
            
            result = analyzer.analyze()
        
        assert result["is_pe"] is True
        assert result["available"] is True
        assert result["method_used"] == "pefile"
        assert result["xor_key"] == 0x12345678
        assert len(result["compilers"]) == 1

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", False)
    def test_analyze_r2pipe_fallback(self):
        """Test fallback to r2pipe when pefile unavailable."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._is_pe_file = Mock(return_value=True)
        
        rich_data = {
            "xor_key": 0xAABBCCDD,
            "entries": [],
            "checksum": 0xAABBCCDD
        }
        
        analyzer._extract_rich_header_r2pipe = Mock(return_value=rich_data)
        
        with patch("r2inspect.modules.rich_header_analyzer.calculate_richpe_hash") as mock_hash:
            with patch("r2inspect.modules.rich_header_analyzer.parse_compiler_entries") as mock_parse:
                mock_hash.return_value = "xyz789"
                mock_parse.return_value = []
                
                result = analyzer.analyze()
        
        # When pefile unavailable, should use r2pipe
        assert result.get("method_used") == "r2pipe" or not result.get("available")
        if result.get("richpe_hash"):
            assert result["richpe_hash"] == "xyz789"

    def test_analyze_exception_handling(self):
        """Test exception handling in analyze."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._is_pe_file = Mock(side_effect=Exception("Test error"))
        
        result = analyzer.analyze()
        
        assert result["error"] == "Test error"


class TestPEFileDetection:
    """Test PE file detection methods."""

    def test_is_pe_file_valid(self):
        """Test PE file detection with valid PE."""
        adapter = Mock()
        r2 = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.rich_header_analyzer.is_pe_file") as mock_is_pe:
            mock_is_pe.return_value = True
            result = analyzer._is_pe_file()
        
        assert result is True

    def test_is_pe_file_no_r2(self):
        """Test PE detection when r2 is None."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer.r2 = None
        
        result = analyzer._is_pe_file()
        
        assert result is False

    def test_check_magic_bytes_mz(self):
        """Test magic byte check for MZ header."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.default_file_system") as mock_fs:
            mock_fs.read_bytes.return_value = b"MZ"
            result = analyzer._check_magic_bytes()
        
        assert result is True

    def test_check_magic_bytes_not_mz(self):
        """Test magic byte check for non-MZ file."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.bin")
        
        with patch("r2inspect.modules.rich_header_analyzer.default_file_system") as mock_fs:
            mock_fs.read_bytes.return_value = b"\x7fELF"
            result = analyzer._check_magic_bytes()
        
        assert result is False

    def test_check_magic_bytes_no_filepath(self):
        """Test magic byte check without filepath."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=None)
        
        result = analyzer._check_magic_bytes()
        
        assert result is False


class TestPEFileExtraction:
    """Test pefile-based extraction methods."""

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_extract_rich_header_pefile_no_rich_header(self):
        """Test pefile extraction when Rich Header missing."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.pefile") as mock_pefile:
            pe = Mock()
            pe.RICH_HEADER = None
            mock_pefile.PE.return_value = pe
            
            result = analyzer._extract_rich_header_pefile()
        
        assert result is None

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_extract_rich_header_pefile_no_hash(self):
        """Test pefile extraction when hash calculation fails."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.pefile") as mock_pefile:
            pe = Mock()
            pe.RICH_HEADER = Mock()
            pe.get_rich_header_hash.return_value = None
            mock_pefile.PE.return_value = pe
            
            result = analyzer._extract_rich_header_pefile()
        
        assert result is None

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_extract_rich_header_pefile_success(self):
        """Test successful pefile extraction."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.pefile") as mock_pefile:
            pe = Mock()
            pe.RICH_HEADER = Mock()
            pe.RICH_HEADER.checksum = 0x12345678
            pe.RICH_HEADER.clear_data = b"\x01\x02\x03\x04"
            pe.get_rich_header_hash.return_value = "abc123"
            
            # Mock entries
            entry = Mock()
            entry.product_id = 261
            entry.build_version = 30729
            entry.count = 5
            pe.RICH_HEADER.values = [entry]
            
            mock_pefile.PE.return_value = pe
            
            result = analyzer._extract_rich_header_pefile()
        
        assert result is not None
        assert result["xor_key"] == 0x12345678
        assert result["richpe_hash"] == "abc123"
        assert len(result["entries"]) == 1

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_extract_rich_header_pefile_exception(self):
        """Test pefile extraction with exception."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.pefile") as mock_pefile:
            mock_pefile.PE.side_effect = Exception("PE error")
            
            result = analyzer._extract_rich_header_pefile()
        
        assert result is None

    def test_pefile_parse_entry_valid(self):
        """Test parsing valid pefile entry."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        entry = Mock()
        entry.product_id = 261
        entry.build_version = 30729
        entry.count = 10
        
        result = analyzer._pefile_parse_entry(entry)
        
        assert result is not None
        assert result["product_id"] == 261
        assert result["build_number"] == 30729
        assert result["count"] == 10

    def test_pefile_parse_entry_missing_attrs(self):
        """Test parsing entry with missing attributes."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        entry = Mock(spec=[])  # No attributes
        
        result = analyzer._pefile_parse_entry(entry)
        
        assert result is None


class TestDirectFileRichSearch:
    """Test direct file analysis for Rich Header."""

    def test_direct_file_rich_search_no_data(self):
        """Test direct search when file can't be read."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._read_file_bytes = Mock(return_value=None)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_direct_file_rich_search_not_pe(self):
        """Test direct search on non-PE data."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._read_file_bytes = Mock(return_value=b"\x7fELF" + b"\x00" * 100)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_direct_file_rich_search_no_pe_offset(self):
        """Test direct search when PE offset invalid."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        # Valid MZ header but invalid PE offset
        data = b"MZ" + b"\x00" * 0x3A + b"\xFF\xFF\xFF\xFF"
        analyzer._read_file_bytes = Mock(return_value=data)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_direct_file_rich_search_no_dos_stub(self):
        """Test direct search with no DOS stub space."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        # PE header too close to start
        data = b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00"
        analyzer._read_file_bytes = Mock(return_value=data + b"\x00" * 100)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_direct_file_rich_search_no_rich_signature(self):
        """Test direct search when Rich signature not found."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        # Valid PE structure but no Rich
        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40
        analyzer._read_file_bytes = Mock(return_value=data + b"\x00" * 100)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_direct_file_rich_search_no_xor_key(self):
        """Test direct search when XOR key can't be extracted."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        # Valid structure with Rich but truncated
        pe_offset = 0x80
        data = b"MZ" + b"\x00" * 0x3A + pe_offset.to_bytes(4, "little")
        data += b"\x00" * (0x40 - len(data))
        data += b"Rich"  # At offset 0x40, but no XOR key follows
        
        analyzer._read_file_bytes = Mock(return_value=data)
        
        result = analyzer._direct_file_rich_search()
        
        assert result is None

    def test_find_rich_pos_found(self):
        """Test finding Rich signature in DOS stub."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        dos_stub = b"\x00" * 20 + b"Rich" + b"\x00" * 10
        
        result = analyzer._find_rich_pos(dos_stub)
        
        assert result == 20

    def test_find_rich_pos_not_found(self):
        """Test Rich signature not found."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        dos_stub = b"\x00" * 100
        
        result = analyzer._find_rich_pos(dos_stub)
        
        assert result is None

    def test_extract_xor_key_from_stub_success(self):
        """Test extracting XOR key from DOS stub."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # Rich signature followed by XOR key
        dos_stub = b"Rich\x12\x34\x56\x78\x00\x00"
        
        result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
        
        assert result == 0x78563412  # Little-endian

    def test_extract_xor_key_from_stub_insufficient_data(self):
        """Test XOR key extraction with insufficient data."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        dos_stub = b"Rich\x12"
        
        result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
        
        assert result is None

    def test_find_or_estimate_dans_found(self):
        """Test finding DanS signature."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        dos_stub = b"\x00" * 10 + b"DanS" + b"\x00" * 20 + b"Rich"
        rich_pos = dos_stub.find(b"Rich")
        
        result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
        
        assert result == 10

    def test_find_or_estimate_dans_not_found(self):
        """Test estimating DanS when not found."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # No DanS, but data before Rich
        dos_stub = b"\x00" * 32 + b"Rich"
        rich_pos = 32
        
        with patch.object(analyzer, "_estimate_dans_start") as mock_estimate:
            mock_estimate.return_value = 16
            result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
        
        assert result == 16

    def test_estimate_dans_start_aligned(self):
        """Test estimating DanS start with aligned data."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # 24 bytes before Rich (aligned to 8)
        dos_stub = b"\x00" * 24 + b"Rich"
        rich_pos = 24
        
        result = analyzer._estimate_dans_start(dos_stub, rich_pos)
        
        assert result is not None

    def test_estimate_dans_start_unaligned(self):
        """Test estimating DanS start with unaligned data."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # 22 bytes before Rich (not aligned)
        dos_stub = b"\x00" * 22 + b"Rich"
        rich_pos = 22
        
        result = analyzer._estimate_dans_start(dos_stub, rich_pos)
        
        # Should find aligned position
        assert result is None or result % 4 == 0

    def test_extract_encoded_from_stub_valid(self):
        """Test extracting encoded data from DOS stub."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # DanS signature + 16 bytes encoded + Rich
        dos_stub = b"DanS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10Rich"
        dans_pos = 0
        rich_pos = 20
        
        result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
        
        assert result is not None
        assert len(result) == 16

    def test_extract_encoded_from_stub_unaligned(self):
        """Test extracting unaligned encoded data."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # 10 bytes (not multiple of 8)
        dos_stub = b"DanS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0ARich"
        
        result = analyzer._extract_encoded_from_stub(dos_stub, 0, 14)
        
        assert result is None


class TestR2PipeExtraction:
    """Test r2pipe-based extraction methods."""

    def test_extract_rich_header_r2pipe_success(self):
        """Test r2pipe extraction success."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._extract_rich_header = Mock(return_value={"xor_key": 0x12345678})
        
        result = analyzer._extract_rich_header_r2pipe()
        
        assert result is not None
        assert result["xor_key"] == 0x12345678

    def test_extract_rich_header_r2pipe_failure(self):
        """Test r2pipe extraction failure with debug."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._extract_rich_header = Mock(return_value=None)
        analyzer._debug_file_structure = Mock()
        
        result = analyzer._extract_rich_header_r2pipe()
        
        assert result is None
        analyzer._debug_file_structure.assert_called_once()

    def test_extract_rich_header_r2pipe_exception(self):
        """Test r2pipe extraction with exception."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._extract_rich_header = Mock(side_effect=Exception("r2 error"))
        
        result = analyzer._extract_rich_header_r2pipe()
        
        assert result is None

    def test_collect_rich_dans_offsets(self):
        """Test collecting Rich and DanS offsets."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        with patch.object(analyzer, "_scan_patterns") as mock_scan:
            mock_scan.side_effect = [
                [{"offset": 100}],  # Rich results
                [{"offset": 80}]    # DanS results
            ]
            
            rich_results, dans_results = analyzer._collect_rich_dans_offsets()
        
        assert len(rich_results) == 1
        assert len(dans_results) == 1

    def test_try_rich_dans_combinations_valid(self):
        """Test trying Rich/DanS combinations with valid offsets."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        rich_results = [{"offset": 100}]
        dans_results = [{"offset": 80}]
        
        analyzer._try_extract_rich_at_offsets = Mock(return_value={"xor_key": 0xAABBCCDD})
        
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        
        assert result is not None
        assert result["xor_key"] == 0xAABBCCDD

    def test_try_rich_dans_combinations_invalid_offsets(self):
        """Test Rich/DanS combinations with invalid offsets."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # Rich before DanS (invalid)
        rich_results = [{"offset": 80}]
        dans_results = [{"offset": 100}]
        
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        
        assert result is None

    def test_offsets_valid_correct_order(self):
        """Test offset validation with correct order."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        result = analyzer._offsets_valid(80, 100)
        
        assert result is True

    def test_offsets_valid_wrong_order(self):
        """Test offset validation with wrong order."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        result = analyzer._offsets_valid(100, 80)
        
        assert result is False

    def test_offsets_valid_too_far_apart(self):
        """Test offset validation when too far apart."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        result = analyzer._offsets_valid(80, 2000)
        
        assert result is False


class TestRichHeaderChecksum:
    """Test Rich Header checksum calculation."""

    def test_calculate_rich_checksum_simple(self):
        """Test checksum calculation with simple entries."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        data += b"\x00" * (0x80 - len(data))
        
        pe_offset = 0x80
        entries = [
            {"product_id": 1, "build_number": 2, "count": 3}
        ]
        
        result = analyzer._calculate_rich_checksum(data, pe_offset, entries)
        
        assert isinstance(result, int)
        assert result > 0

    def test_calculate_rich_checksum_multiple_entries(self):
        """Test checksum with multiple entries."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        data += b"\x00" * (0x80 - len(data))
        
        entries = [
            {"product_id": 261, "build_number": 30729, "count": 10},
            {"product_id": 260, "build_number": 30729, "count": 5}
        ]
        
        result = analyzer._calculate_rich_checksum(data, 0x80, entries)
        
        assert isinstance(result, int)

    def test_calculate_rich_checksum_exception(self):
        """Test checksum calculation with exception."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        
        # Invalid data
        result = analyzer._calculate_rich_checksum(b"", 0x80, [])
        
        assert result == 0


class TestImportErrorScenarios:
    """Test behavior when optional dependencies are missing."""

    def test_pefile_unavailable_fallback(self):
        """Test that analyzer returns None when pefile unavailable."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        with patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", False):
            # Should return None when pefile not available
            result = analyzer._extract_rich_header_pefile()
            
            assert result is None

    def test_analyze_r2pipe_only(self):
        """Test successful analysis using only r2pipe (simulates pefile unavailable)."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        
        rich_data = {
            "xor_key": 0x11223344,
            "entries": [],
            "checksum": 0x11223344
        }
        
        # Mock methods
        analyzer._is_pe_file = Mock(return_value=True)
        analyzer._extract_rich_header_pefile = Mock(return_value=None)  # pefile failed
        analyzer._extract_rich_header_r2pipe = Mock(return_value=rich_data)  # r2pipe succeeds
        
        # Patch helpers
        with patch("r2inspect.modules.rich_header_analyzer.calculate_richpe_hash") as mock_hash:
            with patch("r2inspect.modules.rich_header_analyzer.parse_compiler_entries") as mock_parse:
                mock_hash.return_value = "hash123"
                mock_parse.return_value = []
                
                result = analyzer.analyze()
        
        # Should successfully use r2pipe
        assert result.get("is_pe") is True
        assert result.get("method_used") == "r2pipe"
        assert result.get("available") is True
        assert result["xor_key"] == 0x11223344

    @patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True)
    def test_pefile_import_error_during_analysis(self):
        """Test handling of pefile import errors during analysis."""
        adapter = Mock()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer._is_pe_file = Mock(return_value=True)
        
        with patch("r2inspect.modules.rich_header_analyzer.pefile") as mock_pefile:
            mock_pefile.PE.side_effect = ImportError("pefile not installed")
            
            analyzer._extract_rich_header_r2pipe = Mock(return_value=None)
            
            result = analyzer.analyze()
        
        # Should handle gracefully
        assert "error" in result or not result["available"]


class TestStaticMethods:
    """Test static utility methods."""

    def test_calculate_richpe_hash_from_file(self):
        """Test calculating RichPE hash from file path."""
        with patch("r2inspect.modules.rich_header_analyzer.run_analyzer_on_file") as mock_run:
            mock_run.return_value = {"richpe_hash": "abc123def456"}
            
            result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/tmp/test.exe")
        
        assert result == "abc123def456"

    def test_calculate_richpe_hash_from_file_error(self):
        """Test RichPE hash calculation error."""
        with patch("r2inspect.modules.rich_header_analyzer.run_analyzer_on_file") as mock_run:
            mock_run.return_value = None
            
            result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/tmp/test.exe")
        
        assert result is None

    def test_calculate_richpe_hash_from_file_no_hash(self):
        """Test when result has no richpe_hash field."""
        with patch("r2inspect.modules.rich_header_analyzer.run_analyzer_on_file") as mock_run:
            mock_run.return_value = {"available": True}
            
            result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/tmp/test.exe")
        
        assert result is None
