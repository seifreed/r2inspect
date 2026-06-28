"""Per-compiler version-detection methods for :class:`CompilerDetector`.

Split out as a mixin to keep ``compiler_detector.py`` focused on the
detection flow. Each method is a thin adapter over the domain version
detectors; the host class provides ``msvc_versions``.
"""

from __future__ import annotations

from ..domain.formats.compiler import (
    detect_clang_version,
    detect_gcc_version,
    detect_go_version,
    detect_msvc_version,
    detect_rust_version,
)
from .compiler_detector_support import (
    detect_compiler_version as _detect_compiler_version,
)


class CompilerVersionDetectionMixin:
    """Maps a detected compiler to its version string."""

    msvc_versions: dict[str, str]  # provided by host class

    def _detect_compiler_version(
        self, compiler: str, strings_data: list[str], imports_data: list[str]
    ) -> str:
        """Detect specific compiler version"""
        return _detect_compiler_version(
            compiler,
            strings_data,
            imports_data,
            detectors={
                "MSVC": self._detect_msvc_version,
                "GCC": self._detect_gcc_version,
                "Clang": self._detect_clang_version,
                "Intel": self._detect_intel_version,
                "Borland": self._detect_borland_version,
                "MinGW": self._detect_mingw_version,
                "Go": self._detect_go_version,
                "Rust": self._detect_rust_version,
                "Delphi": self._detect_delphi_version,
            },
        )

    def _detect_msvc_version(self, strings_data: list[str], imports_data: list[str]) -> str:
        """Detect MSVC version"""
        return detect_msvc_version(strings_data, imports_data, self.msvc_versions)

    def _detect_gcc_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect GCC version"""
        return detect_gcc_version(strings_data)

    def _detect_clang_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Clang version"""
        return detect_clang_version(strings_data)

    def _detect_intel_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Intel version"""
        return "Unknown"

    def _detect_borland_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Borland version"""
        return "Unknown"

    def _detect_mingw_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect MinGW version"""
        return "Unknown"

    def _detect_go_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Go version"""
        return detect_go_version(strings_data)

    def _detect_rust_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Rust version"""
        return detect_rust_version(strings_data)

    def _detect_delphi_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Delphi version"""
        return "Unknown"
