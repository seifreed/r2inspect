"""
Wave-3 coverage tests targeting specific missing lines:

- r2inspect/utils/logger.py               lines 34-39, 87, 89, 94, 95
- r2inspect/core/file_validator.py        lines 77-79, 158-159, 174-176
- r2inspect/infrastructure/r2_session.py  lines 167, 231-232, 236-239
- r2inspect/modules/crypto_analyzer.py   lines 257-258, 329, 334, 339, 350
- r2inspect/modules/overlay_analyzer.py  lines 56, 112-113, 186-188
- r2inspect/registry/metadata_extraction.py lines 20, 27, 32, 63-64, 93-94
- r2inspect/modules/bindiff_analyzer.py  lines 113-115, 179, 199, 271
- r2inspect/modules/compiler_detector.py lines 275, 279, 283, 322-324

Rules: no unittest.mock / MagicMock / patch; real code + plain functions only.
Module-level monkey-patching (saving/restoring originals) is allowed.
"""

from __future__ import annotations

import logging
import os
import platform
import struct
from pathlib import Path
from typing import Any

import psutil
import pytest


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _cleanup_logger(name: str) -> None:
    lg = logging.getLogger(name)
    for h in list(lg.handlers):
        try:
            h.flush()
            h.close()
        except Exception:
            pass
        lg.removeHandler(h)


# ===========================================================================
# logger.py – lines 34-39
# Trigger path: handlers exist but at least one has a closed stream.
# setup_logger detects the closed handler, removes all handlers, and rebuilds.
# ===========================================================================


def test_setup_logger_reinit_on_closed_file_handler(tmp_path: Path) -> None:
    """Lines 34-39: setup_logger cleans up closed handlers and re-initialises.

    Python's FileHandler.close() sets stream=None, so _handler_is_closed would
    not fire on a handler that was properly closed.  Instead we inject a
    *already-closed* io.StringIO as the stream directly; that leaves stream
    non-None but stream.closed=True, which is exactly what _handler_is_closed
    checks for.
    """
    import io

    from r2inspect.utils.logger import _loggers_initialized, setup_logger

    name = "r2inspect.test.wave3.closed_handler"
    _cleanup_logger(name)
    _loggers_initialized.discard(name)

    try:
        lg = setup_logger(name, level=logging.DEBUG, thread_safe=False)
        if not lg.handlers:
            pytest.skip("No handlers attached; cannot inject closed stream")

        # Inject a closed stream into the first handler so that
        # _handler_is_closed(handler) returns True on the next setup_logger call.
        closed_stream = io.StringIO()
        closed_stream.close()  # closed_stream.closed == True
        lg.handlers[0].stream = closed_stream  # type: ignore[attr-defined]

        # Re-calling setup_logger should detect the closed stream (lines 34-39).
        lg2 = setup_logger(name, level=logging.DEBUG, thread_safe=False)
        assert lg2 is not None
    finally:
        _cleanup_logger(name)
        _loggers_initialized.discard(name)


# ===========================================================================
# logger.py – lines 87, 89, 94, 95
# Trigger path: file handler creation fails → fallback to console-only formatter.
# We point HOME at a path that cannot be created (a file blocks the directory).
# ===========================================================================


def test_setup_logger_fallback_console_when_log_dir_unwritable(tmp_path: Path) -> None:
    """Lines 87/89/94/95: fallback formatter used when RotatingFileHandler fails."""
    from r2inspect.utils.logger import _loggers_initialized, setup_logger

    name = "r2inspect.test.wave3.fallback_console"
    _cleanup_logger(name)
    _loggers_initialized.discard(name)

    # Place a *file* at the path that Python would try to create as a directory.
    blocker = tmp_path / "block_home"
    blocker.write_text("I am a file, not a directory")
    fake_home = str(blocker / "deep")  # mkdir would fail: parent is a file

    old_home = os.environ.get("HOME")
    os.environ["HOME"] = fake_home
    try:
        lg = setup_logger(name, level=logging.DEBUG, thread_safe=True)
        assert lg is not None
        assert len(lg.handlers) >= 1
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
        _cleanup_logger(name)
        _loggers_initialized.discard(name)


# ===========================================================================
# file_validator.py – lines 77-79 and 158-159
# Trigger path: file exists and size is valid, but memory limit check fails.
# We temporarily lower max_file_size_mb to 0 so any file exceeds it.
# ===========================================================================


def test_file_validator_fails_memory_limit(tmp_path: Path) -> None:
    """Lines 77-79 / 158-159: validate() returns False when memory limit exceeded."""
    from r2inspect.core.file_validator import FileValidator
    from r2inspect.utils.memory_manager import global_memory_monitor

    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 256)

    old_limit = global_memory_monitor.limits.max_file_size_mb
    global_memory_monitor.limits.max_file_size_mb = 0  # any file exceeds 0 MB
    try:
        validator = FileValidator(str(target))
        assert validator.validate() is False
    finally:
        global_memory_monitor.limits.max_file_size_mb = old_limit


# ===========================================================================
# file_validator.py – lines 174-176
# Trigger path: file exists and size is valid, but open() raises OSError
# because the file has no read permissions.
# ===========================================================================


def test_file_validator_unreadable_file(tmp_path: Path) -> None:
    """Lines 174-176: _is_readable returns False on OSError."""
    from r2inspect.core.file_validator import FileValidator

    target = tmp_path / "locked.bin"
    target.write_bytes(b"A" * 256)
    os.chmod(str(target), 0o000)

    try:
        validator = FileValidator(str(target))
        assert validator.validate() is False
    finally:
        os.chmod(str(target), 0o644)


# ===========================================================================
# r2_session.py – line 167
# Trigger path: fat Mach-O file containing an arm64 slice on an ARM64 host
# causes _select_r2_flags to add ["-a", "arm", "-b", "64"].
# ===========================================================================


def _write_fat_macho_arm64(path: Path) -> None:
    """Minimal fat Mach-O with a single arm64 slice."""
    data = bytearray()
    data += (0xCAFEBABE).to_bytes(4, "big")   # big-endian magic
    data += (1).to_bytes(4, "big")             # nfat_arch = 1
    # 20-byte arch entry: cputype(4) + 16 padding bytes
    data += (0x0100000C).to_bytes(4, "big")    # arm64 cputype
    data += b"\x00" * 16
    path.write_bytes(bytes(data))


def test_select_r2_flags_arm64_fat_macho(tmp_path: Path) -> None:
    """Line 167: ARM architecture flags added when host is arm64 and binary has arm64."""
    from r2inspect.infrastructure.r2_session import R2Session

    if "arm" not in platform.machine().lower():
        pytest.skip("Host is not ARM; line 167 requires an arm64 host")

    fat_file = tmp_path / "fat_arm64.bin"
    _write_fat_macho_arm64(fat_file)

    session = R2Session(str(fat_file))
    flags = session._select_r2_flags()

    assert "-a" in flags
    assert "arm" in flags
    assert "-b" in flags
    assert "64" in flags


# ===========================================================================
# r2_session.py – lines 231-232
# Trigger path: psutil.process_iter yields a fake "radare2" process whose
# terminate() raises NoSuchProcess, exercising the except/continue block.
# ===========================================================================


def test_terminate_r2_processes_handles_no_such_process(tmp_path: Path) -> None:
    """Lines 231-232: NoSuchProcess exception in _terminate_radare2_processes handled."""
    from r2inspect.infrastructure import r2_session as session_module
    from r2inspect.infrastructure.r2_session import R2Session

    target = tmp_path / "fake.bin"
    target.write_bytes(b"x" * 64)

    class _FakeProc:
        info = {"name": "radare2", "cmdline": [str(target)]}

        def terminate(self) -> None:
            raise psutil.NoSuchProcess(pid=99999)

    original_iter = session_module.psutil.process_iter
    session_module.psutil.process_iter = lambda *_a, **_kw: iter([_FakeProc()])
    try:
        session = R2Session(str(target))
        session._terminate_radare2_processes()  # must not raise
    finally:
        session_module.psutil.process_iter = original_iter


# ===========================================================================
# r2_session.py – lines 236-239
# Trigger path: _reopen_safe_mode() closes the current session, opens a new
# one in safe mode ("-n"), and returns the new r2pipe instance.
# r2pipe.open is replaced at module level so no real binary is needed.
# ===========================================================================


def test_reopen_safe_mode(tmp_path: Path) -> None:
    """Lines 236-239: _reopen_safe_mode closes existing r2 and opens safe-mode session."""
    from r2inspect.infrastructure import r2_session as session_module
    from r2inspect.infrastructure.r2_session import R2Session

    target = tmp_path / "sample.bin"
    target.write_bytes(b"x" * 64)

    class _FakeR2:
        def quit(self) -> None:
            pass

    original_open = session_module.r2pipe.open
    session_module.r2pipe.open = lambda *_a, **_kw: _FakeR2()
    try:
        session = R2Session(str(target))
        session.r2 = _FakeR2()
        session._cleanup_required = True

        result = session._reopen_safe_mode()
        assert isinstance(result, _FakeR2)
        assert session._cleanup_required is True
    finally:
        session_module.r2pipe.open = original_open


# ===========================================================================
# crypto_analyzer.py – lines 257-258
# Trigger path: _read_bytes returns an object whose .hex() yields invalid hex,
# so bytes.fromhex() raises ValueError → _calculate_section_entropy returns 0.0.
# ===========================================================================


class _BadHexAdapter:
    """Returns a fake-bytes object whose .hex() produces non-hex characters."""

    class _FakeBytes:
        def hex(self) -> str:
            return "ZZZZ"  # bytes.fromhex("ZZZZ") raises ValueError

        def __bool__(self) -> bool:
            return True

    def read_bytes(self, vaddr: int, size: int) -> "_BadHexAdapter._FakeBytes":
        return _BadHexAdapter._FakeBytes()

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "size": 100, "vaddr": 0}]

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []


def test_calculate_section_entropy_invalid_hex_returns_zero() -> None:
    """Lines 257-258: ValueError from bytes.fromhex → returns 0.0."""
    from r2inspect.modules.crypto_analyzer import CryptoAnalyzer

    analyzer = CryptoAnalyzer(adapter=_BadHexAdapter())
    entropy = analyzer._calculate_section_entropy({"name": ".text", "size": 100, "vaddr": 0})
    assert entropy == 0.0


# ===========================================================================
# crypto_analyzer.py – lines 329, 334, 339, 350
# Trigger path: adapter is None → all fallback "return []" / "return b''" paths.
# ===========================================================================


def test_crypto_analyzer_none_adapter_fallbacks() -> None:
    """Lines 329/334/339/350: None adapter triggers all early-return fallbacks."""
    from r2inspect.modules.crypto_analyzer import CryptoAnalyzer

    analyzer = CryptoAnalyzer(adapter=None)
    assert analyzer._get_imports() == []    # line 329
    assert analyzer._get_sections() == []   # line 334
    assert analyzer._get_strings() == []    # line 339
    assert analyzer._read_bytes(0, 64) == b""  # line 350


# ===========================================================================
# overlay_analyzer.py – line 56
# Trigger path: pe_end returned equals file_size, making overlay_size == 0,
# so the early-return branch (line 56) is taken.
# ===========================================================================


def test_overlay_analyzer_zero_overlay_size() -> None:
    """Line 56: analyze() returns default result when overlay_size <= 0."""
    from r2inspect.modules.overlay_analyzer import OverlayAnalyzer

    class _ZeroOverlay(OverlayAnalyzer):
        def _get_file_size(self) -> int:
            return 100

        def _get_valid_pe_end(self, file_size: int) -> int:
            return file_size  # overlay_size = file_size - pe_end = 0

    result = _ZeroOverlay(adapter=None).analyze()
    assert result["has_overlay"] is False
    assert result["overlay_size"] == 0


# ===========================================================================
# overlay_analyzer.py – lines 112-113
# Trigger path: _calculate_pe_end returns a non-numeric string so int() raises
# ValueError, and _get_valid_pe_end returns None (line 113).
# ===========================================================================


def test_overlay_analyzer_pe_end_not_castable_to_int() -> None:
    """Lines 112-113: ValueError in int(pe_end) causes _get_valid_pe_end to return None."""
    from r2inspect.modules.overlay_analyzer import OverlayAnalyzer

    class _BadPeEnd(OverlayAnalyzer):
        def _get_file_size(self) -> int:
            return 200

        def _calculate_pe_end(self) -> Any:  # type: ignore[override]
            return "not_a_number"

    result = _BadPeEnd(adapter=None).analyze()
    assert result["has_overlay"] is False


# ===========================================================================
# overlay_analyzer.py – lines 186-188
# Trigger path: overlay_data contains integers > 255 so bytes(overlay_data)
# raises ValueError inside the inner try/except, logging the error and setting
# result["overlay_hashes"] = {}.
# _calculate_entropy is overridden to bypass its own bytes() call.
# ===========================================================================


def test_overlay_analyzer_hash_calculation_error() -> None:
    """Lines 186-188: exception in bytes() for hash sets overlay_hashes={}."""
    from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
    from r2inspect.utils.hashing import calculate_hashes_for_bytes

    class _BadHashOverlay(OverlayAnalyzer):
        def _get_file_size(self) -> int:
            return 500

        def _get_valid_pe_end(self, file_size: int) -> int:
            return 100  # overlay_size = 400

        def _cmdj(self, command: str, default: Any = None) -> Any:
            if "pxj" in command:
                # Values > 255 → bytes() raises ValueError
                return [300, 400, 500]
            return default

        def _calculate_entropy(self, data: list[int]) -> float:  # type: ignore[override]
            return 5.0  # bypass bytes() call for entropy

        def _check_patterns(self, data: list[int]) -> list[dict[str, Any]]:
            return []

        def _determine_overlay_type(
            self, patterns: list[dict[str, Any]], data: list[int]
        ) -> str:
            return "data"

        def _extract_strings(
            self, data: list[int], min_length: int = 4
        ) -> list[str]:
            return []

        def _check_file_signatures(
            self, data: list[int]
        ) -> list[dict[str, Any]]:
            return []

    result = _BadHashOverlay(adapter=None).analyze()
    assert result["overlay_hashes"] == {}


# ===========================================================================
# metadata_extraction.py – lines 20, 27, 32
# Trigger paths:
#   line 20: category_value is already an AnalyzerCategory → returned directly
#   line 27: unknown string → ValueError raised
#   line 32: non-string, non-enum → TypeError raised
# ===========================================================================


def test_parse_category_already_enum_value() -> None:
    """Line 20: AnalyzerCategory instance is returned as-is."""
    from r2inspect.registry.categories import AnalyzerCategory
    from r2inspect.registry.metadata_extraction import parse_category

    cat = AnalyzerCategory.DETECTION
    assert parse_category(cat) is cat


def test_parse_category_unknown_string_raises_value_error() -> None:
    """Line 27: unknown string raises ValueError."""
    from r2inspect.registry.metadata_extraction import parse_category

    with pytest.raises(ValueError, match="Unknown category string"):
        parse_category("not_a_valid_category")


def test_parse_category_wrong_type_raises_type_error() -> None:
    """Line 32: non-string, non-enum type raises TypeError."""
    from r2inspect.registry.metadata_extraction import parse_category

    with pytest.raises(TypeError, match="Category must be AnalyzerCategory"):
        parse_category(42)


# ===========================================================================
# metadata_extraction.py – lines 63-64
# Trigger path: analyzer_class.__init__ raises so extract_metadata_from_class
# wraps it in RuntimeError (lines 63-64).
# ===========================================================================


def test_extract_metadata_from_class_raises_runtime_error_on_init_failure() -> None:
    """Lines 63-64: RuntimeError raised when analyzer instantiation fails."""
    from r2inspect.registry.metadata_extraction import extract_metadata_from_class

    class _FailingAnalyzer:
        __name__ = "_FailingAnalyzer"

        def __init__(self, **kwargs: Any) -> None:
            raise RuntimeError("deliberate init failure")

    with pytest.raises(RuntimeError, match="Failed to extract metadata"):
        extract_metadata_from_class(
            _FailingAnalyzer,  # type: ignore[arg-type]
            is_base_analyzer=lambda cls: True,
            name="test",
        )


# ===========================================================================
# metadata_extraction.py – lines 93-94
# Trigger path: auto_extract=True and extraction fails → warning logged,
# original metadata tuple returned unchanged.
# ===========================================================================


def test_auto_extract_metadata_logs_warning_on_failure() -> None:
    """Lines 93-94: extraction failure logged; original values returned."""
    from r2inspect.registry.metadata_extraction import auto_extract_metadata

    class _FailingAnalyzer:
        __name__ = "_FailingAnalyzer"

        def __init__(self, **kwargs: Any) -> None:
            raise RuntimeError("deliberate init failure")

    category, file_formats, description = auto_extract_metadata(
        _FailingAnalyzer,  # type: ignore[arg-type]
        name="test",
        category=None,
        file_formats=None,
        description="",
        auto_extract=True,
        is_base_analyzer=lambda cls: True,
    )
    # Extraction failed so the original None/None/"" values are returned.
    assert category is None
    assert file_formats is None
    assert description == ""


# ===========================================================================
# bindiff_analyzer.py – lines 113-115
# Trigger path: compare_with(None) causes AttributeError inside the try block
# (None has no .get()), which the outer except catches (lines 113-115).
# ===========================================================================


def test_bindiff_compare_with_none_triggers_exception_handler(tmp_path: Path) -> None:
    """Lines 113-115: outer except in compare_with fires when other_results is None."""
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    target = tmp_path / "stub.bin"
    target.write_bytes(b"x" * 64)

    analyzer = BinDiffAnalyzer(adapter=None, filepath=str(target))
    result = analyzer.compare_with(None)  # type: ignore[arg-type]
    assert "error" in result


# ===========================================================================
# bindiff_analyzer.py – line 179
# Trigger path: adapter present but lacks analyze_all → cmd_helper used (line 179).
# ===========================================================================


class _NoAnalyzeAllAdapter:
    """Adapter without analyze_all; returns minimal stubs for other calls."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []


def test_bindiff_extract_function_features_uses_cmd_helper_without_analyze_all(
    tmp_path: Path,
) -> None:
    """Line 179: cmd_helper('aaa') called when adapter lacks analyze_all."""
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    target = tmp_path / "stub.bin"
    target.write_bytes(b"x" * 64)

    analyzer = BinDiffAnalyzer(adapter=_NoAnalyzeAllAdapter(), filepath=str(target))
    features = analyzer._extract_function_features()
    # Adapter returns no functions; features dict may be empty but must not raise.
    assert isinstance(features, dict)


# ===========================================================================
# bindiff_analyzer.py – line 199
# Trigger path: adapter.get_cfg returns a plain dict (not a list), so the
# elif isinstance(cfg, dict) branch (line 199) is taken.
# ===========================================================================


class _DictCfgAdapter(_NoAnalyzeAllAdapter):
    """Adapter whose get_cfg returns a dict so the elif path is exercised."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"offset": 0x1000, "size": 64, "name": "sym.main"}]

    def get_cfg(self, address: int) -> dict[str, Any]:
        return {"blocks": [1, 2], "edges": []}


def test_bindiff_extract_function_features_dict_cfg(tmp_path: Path) -> None:
    """Line 197: cfg_data = cfg when get_cfg returns a non-empty dict."""
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    target = tmp_path / "stub.bin"
    target.write_bytes(b"x" * 64)

    analyzer = BinDiffAnalyzer(adapter=_DictCfgAdapter(), filepath=str(target))
    features = analyzer._extract_function_features()
    assert isinstance(features, dict)
    cfg_features = features.get("cfg_features", [])
    assert len(cfg_features) >= 1
    assert cfg_features[0]["nodes"] == 2


class _NullCfgAdapter(_NoAnalyzeAllAdapter):
    """Adapter whose get_cfg returns None, exercising the else branch (line 199)."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"offset": 0x1000, "size": 64, "name": "sym.main"}]

    def get_cfg(self, address: int) -> None:
        return None


def test_bindiff_extract_function_features_null_cfg(tmp_path: Path) -> None:
    """Line 199: cfg_data = {} when get_cfg returns None (neither list nor dict)."""
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    target = tmp_path / "stub.bin"
    target.write_bytes(b"x" * 64)

    analyzer = BinDiffAnalyzer(adapter=_NullCfgAdapter(), filepath=str(target))
    features = analyzer._extract_function_features()
    # None cfg → else branch → cfg_data = {} → not appended to cfg_features
    assert isinstance(features, dict)
    assert features.get("cfg_features", []) == []


# ===========================================================================
# bindiff_analyzer.py – line 271
# Trigger path: adapter is None so the else branch uses cmd_helper (line 271).
# ===========================================================================


def test_bindiff_extract_byte_features_uses_cmd_helper_without_entropy_adapter(
    tmp_path: Path,
) -> None:
    """Line 271: cmd_helper used for entropy when adapter is None."""
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    target = tmp_path / "stub.bin"
    target.write_bytes(b"x" * 64)

    # adapter=None → self.adapter is falsy → else branch (line 271)
    analyzer = BinDiffAnalyzer(adapter=None, filepath=str(target))
    features = analyzer._extract_byte_features()
    assert isinstance(features, dict)


# ===========================================================================
# compiler_detector.py – line 275
# Trigger path: _detect_compiler_version called with an unknown compiler name
# that is absent from version_detectors → returns "Unknown" (line 275).
# ===========================================================================


def test_compiler_detect_version_unknown_compiler() -> None:
    """Line 275: returns 'Unknown' for compiler not in version_detectors."""
    from r2inspect.modules.compiler_detector import CompilerDetector

    detector = CompilerDetector(adapter=None)
    version = detector._detect_compiler_version("UnknownXYZ", [], [])
    assert version == "Unknown"


# ===========================================================================
# compiler_detector.py – line 279
# Trigger path: _detect_msvc_version called → calls detect_msvc_version (line 279).
# ===========================================================================


def test_compiler_detect_msvc_version() -> None:
    """Line 279: _detect_msvc_version delegates to detect_msvc_version."""
    from r2inspect.modules.compiler_detector import CompilerDetector

    detector = CompilerDetector(adapter=None)
    # Provide a runtime DLL string that maps to a known MSVC version.
    version = detector._detect_msvc_version(["MSVCR140.dll"], ["MSVCR140.dll"])
    assert isinstance(version, str)


# ===========================================================================
# compiler_detector.py – line 283
# Trigger path: _detect_gcc_version called → calls detect_gcc_version (line 283).
# ===========================================================================


def test_compiler_detect_gcc_version() -> None:
    """Line 283: _detect_gcc_version delegates to detect_gcc_version."""
    from r2inspect.modules.compiler_detector import CompilerDetector

    detector = CompilerDetector(adapter=None)
    version = detector._detect_gcc_version(["GCC: (Ubuntu 9.3.0) 9.3.0"], [])
    assert isinstance(version, str)


# ===========================================================================
# compiler_detector.py – lines 322-324
# _coerce_dict_list static method:
#   line 322: isinstance(value, dict) → [value]
#   line 324: neither list nor dict    → []
# ===========================================================================


def test_coerce_dict_list_with_dict_input() -> None:
    """Line 322: single dict wrapped in a list."""
    from r2inspect.modules.compiler_detector import CompilerDetector

    result = CompilerDetector._coerce_dict_list({"key": "val"})
    assert result == [{"key": "val"}]


def test_coerce_dict_list_with_non_list_non_dict() -> None:
    """Line 324: non-list, non-dict returns empty list."""
    from r2inspect.modules.compiler_detector import CompilerDetector

    assert CompilerDetector._coerce_dict_list("a_string") == []
    assert CompilerDetector._coerce_dict_list(42) == []
    assert CompilerDetector._coerce_dict_list(None) == []
