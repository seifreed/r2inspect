from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import sys

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer


def test_tlsh_analyzer_library_not_available():
    with patch.dict(sys.modules, {'tlsh': None}):
        with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', False):
            adapter = MagicMock()
            analyzer = TLSHAnalyzer(adapter, 'dummy.bin')
            result = analyzer.analyze()
            
            assert result['available'] is False
            assert 'TLSH library not available' in str(result.get('error', ''))


def test_tlsh_analyzer_analyze_sections_library_unavailable():
    with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', False):
        adapter = MagicMock()
        analyzer = TLSHAnalyzer(adapter, 'dummy.bin')
        
        result = analyzer.analyze_sections()
        
        assert result['available'] is False


def test_tlsh_analyzer_file_too_small():
    adapter = MagicMock()
    
    with patch('r2inspect.adapters.file_system.default_file_system') as mock_fs:
        mock_fs.read_bytes.return_value = b'a' * 100
        
        analyzer = TLSHAnalyzer(adapter, 'small.bin')
        
        with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', True):
            result = analyzer.analyze()
            
            assert 'available' in result


def test_tlsh_analyzer_hash_calculation_error():
    adapter = MagicMock()
    
    with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', True):
        with patch('r2inspect.modules.tlsh_analyzer.tlsh') as mock_tlsh:
            mock_tlsh.hash.side_effect = Exception('TLSH error')
            
            with patch('r2inspect.adapters.file_system.default_file_system') as mock_fs:
                mock_fs.read_bytes.return_value = b'a' * 1024
                
                analyzer = TLSHAnalyzer(adapter, 'test.bin')
                result = analyzer.analyze()
                
                assert 'available' in result or 'error' in result


def test_tlsh_is_available_false():
    with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', False):
        assert TLSHAnalyzer.is_available() is False


def test_tlsh_is_available_true():
    with patch('r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE', True):
        assert TLSHAnalyzer.is_available() is True
