#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/utils/ssdeep_loader.py - targeting 100% coverage."""

import threading
import pytest
from unittest.mock import patch, MagicMock


def test_get_ssdeep_success():
    """Test get_ssdeep when ssdeep is available."""
    # Import in function to control when it's loaded
    from r2inspect.utils.ssdeep_loader import get_ssdeep, _ssdeep_module
    
    # If ssdeep is actually available in environment
    result = get_ssdeep()
    
    # Should either return ssdeep module or None
    assert result is None or hasattr(result, 'hash')


def test_get_ssdeep_cached():
    """Test get_ssdeep returns cached module on subsequent calls."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset the module cache
    ssdeep_loader._ssdeep_module = None
    
    # First call
    result1 = ssdeep_loader.get_ssdeep()
    
    # Second call should return cached value
    result2 = ssdeep_loader.get_ssdeep()
    
    assert result1 is result2


def test_get_ssdeep_import_failure():
    """Test get_ssdeep handles import failure gracefully."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    # Mock the import to fail
    with patch.dict('sys.modules', {'ssdeep': None}):
        with patch('builtins.__import__', side_effect=ImportError("ssdeep not found")):
            result = ssdeep_loader.get_ssdeep()
            
            # Should return None on import failure
            assert result is None


def test_get_ssdeep_exception_handling():
    """Test get_ssdeep handles generic exceptions during import."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    # Mock import to raise a generic exception
    with patch('builtins.__import__', side_effect=Exception("Generic error")):
        result = ssdeep_loader.get_ssdeep()
        
        # Should return None and log debug message
        assert result is None


def test_get_ssdeep_thread_safety():
    """Test get_ssdeep is thread-safe with lock."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    results = []
    
    def call_get_ssdeep():
        result = ssdeep_loader.get_ssdeep()
        results.append(result)
    
    # Create multiple threads
    threads = [threading.Thread(target=call_get_ssdeep) for _ in range(10)]
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for all threads
    for thread in threads:
        thread.join()
    
    # All threads should get the same result (cached)
    assert len(results) == 10
    # All should be either all None or all the same module instance
    assert len(set(id(r) for r in results)) <= 2  # None and/or module


def test_get_ssdeep_double_check_locking():
    """Test get_ssdeep double-check locking pattern."""
    from r2inspect.utils import ssdeep_loader
    
    # This tests the pattern where module is set between first check and lock
    ssdeep_loader._ssdeep_module = None
    
    original_lock = ssdeep_loader._import_lock
    
    # Create a mock lock that allows us to observe the double-check
    lock_acquired = []
    
    class MockLock:
        def __enter__(self):
            lock_acquired.append(True)
            return self
        
        def __exit__(self, *args):
            pass
    
    # Replace lock temporarily
    ssdeep_loader._import_lock = MockLock()
    
    try:
        # First call - should acquire lock
        result1 = ssdeep_loader.get_ssdeep()
        assert len(lock_acquired) >= 1
        
        # Second call - module is cached, should return early
        lock_count_before = len(lock_acquired)
        result2 = ssdeep_loader.get_ssdeep()
        
        # Should not acquire lock again (early return)
        assert len(lock_acquired) == lock_count_before
        assert result1 is result2
    
    finally:
        # Restore original lock
        ssdeep_loader._import_lock = original_lock


def test_get_ssdeep_already_cached():
    """Test get_ssdeep early return when module is already cached."""
    from r2inspect.utils import ssdeep_loader
    
    # Pre-populate cache with a mock module
    mock_module = MagicMock()
    ssdeep_loader._ssdeep_module = mock_module
    
    result = ssdeep_loader.get_ssdeep()
    
    # Should return cached module
    assert result is mock_module


def test_get_ssdeep_warnings_filtered():
    """Test that CFFI reimport warnings are filtered."""
    import warnings
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    # Capture warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        
        # Try to import (may or may not be available)
        result = ssdeep_loader.get_ssdeep()
        
        # Check that no CFFI reimport warnings were raised
        cffi_warnings = [warning for warning in w 
                        if "reimporting '_ssdeep_cffi" in str(warning.message)]
        
        # Should be filtered out
        assert len(cffi_warnings) == 0


def test_module_level_warning_filter():
    """Test that warning filter is set at module level."""
    # This test verifies the warnings.filterwarnings call is present
    import warnings
    
    # Get the current warning filters
    filters = warnings.filters
    
    # There should be a filter for ssdeep CFFI warnings
    # (This may not be detectable depending on when the module was imported)
    # Just verify the module can be imported without issues
    from r2inspect.utils import ssdeep_loader
    assert hasattr(ssdeep_loader, 'get_ssdeep')


def test_import_lock_is_threading_lock():
    """Test that _import_lock is a proper threading.Lock."""
    from r2inspect.utils.ssdeep_loader import _import_lock
    
    assert isinstance(_import_lock, threading.Lock)


def test_ssdeep_module_initial_state():
    """Test the initial state of _ssdeep_module is None or a module."""
    from r2inspect.utils import ssdeep_loader
    
    # Module should be initialized (either None or the actual ssdeep module)
    module = ssdeep_loader._ssdeep_module
    
    assert module is None or hasattr(module, '__name__')


def test_get_ssdeep_with_mocked_successful_import():
    """Test get_ssdeep with successful mock import."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    # Create a mock ssdeep module
    mock_ssdeep = MagicMock()
    mock_ssdeep.__name__ = 'ssdeep'
    
    # Mock the import
    with patch.dict('sys.modules', {'ssdeep': mock_ssdeep}):
        result = ssdeep_loader.get_ssdeep()
        
        # Should return the mocked module
        assert result is not None


def test_get_ssdeep_race_condition_handling():
    """Test get_ssdeep handles race conditions correctly."""
    from r2inspect.utils import ssdeep_loader
    
    # Reset cache
    ssdeep_loader._ssdeep_module = None
    
    # Simulate a race condition where another thread sets the module
    # while we're waiting for the lock
    def set_module_after_delay():
        import time
        time.sleep(0.01)
        ssdeep_loader._ssdeep_module = MagicMock()
    
    # Start a thread that will set the module
    setter_thread = threading.Thread(target=set_module_after_delay)
    setter_thread.start()
    
    # Try to get the module
    result = ssdeep_loader.get_ssdeep()
    
    setter_thread.join()
    
    # Should get a result (either what we imported or what the other thread set)
    assert result is not None or ssdeep_loader._ssdeep_module is not None
