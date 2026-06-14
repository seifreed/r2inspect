"""Typed helpers for impfuzzy import analysis.

Both the import extraction and the detailed-analysis orchestration are
Template-Methods over the host analyzer's overridable steps (subclasses
script ``_cmdj`` / ``_extract_imports`` / ``_process_imports`` in tests), so
they depend on the explicit :class:`ImpfuzzyHost` protocol rather than an
untyped host.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol, cast

from ..interfaces.binary_analyzer import BinaryAnalyzerInterface


class ImpfuzzyHost(Protocol):
    """Overridable collaboration contract the impfuzzy helpers depend on."""

    filepath: Path
    adapter: BinaryAnalyzerInterface | None

    def _cmdj(self, command: str, default: Any | None = None) -> Any: ...
    def _is_pe_file(self) -> bool: ...
    def _extract_imports(self) -> list[dict[str, Any]]: ...
    def _process_imports(self, imports_data: list[dict[str, Any]]) -> list[str]: ...


def _coerce_import_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [imp for imp in raw if isinstance(imp, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def extract_imports(host: ImpfuzzyHost, *, logger: logging.Logger) -> list[dict[str, Any]]:
    try:
        raw_imports: Any
        if host.adapter is not None and hasattr(host.adapter, "get_imports"):
            raw_imports = host.adapter.get_imports()
        else:
            raw_imports = host._cmdj("iij", [])
        imports = _coerce_import_list(raw_imports)

        if not imports:
            logger.debug("No imports found with 'iij' command")
            imports = _coerce_import_list(host._cmdj("ii", []))

        if not imports:
            logger.debug("No imports found with any method")
            return []

        logger.debug("Extracted %s import entries", len(imports))
        return imports
    except Exception as exc:
        logger.error("Error extracting imports: %s", exc)
        return []


def analyze_imports(
    host: ImpfuzzyHost, *, impfuzzy_available: bool, pyimpfuzzy: Any, logger: logging.Logger
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "available": False,
        "impfuzzy_hash": None,
        "import_count": 0,
        "dll_count": 0,
        "imports_processed": [],
        "error": None,
        "library_available": impfuzzy_available,
    }

    if not impfuzzy_available:
        results["error"] = "pyimpfuzzy library not available"
        logger.warning("pyimpfuzzy library not available for impfuzzy calculation")
        return results

    try:
        if not host._is_pe_file():
            results["error"] = "File is not a PE binary"
            logger.debug("File %s is not a PE binary", host.filepath)
            return results

        imports_data = host._extract_imports()
        if not imports_data:
            results["error"] = "No imports found or failed to extract imports"
            logger.debug("No imports found in PE file")
            return results

        processed_imports = host._process_imports(imports_data)
        if not processed_imports:
            results["error"] = "No valid imports found after processing"
            logger.debug("No valid imports found after processing")
            return results

        impfuzzy_hash = pyimpfuzzy.get_impfuzzy(str(host.filepath))
        if not impfuzzy_hash:
            results["error"] = "Failed to calculate impfuzzy hash"
            logger.debug("Failed to calculate impfuzzy hash")
            return results

        unique_dlls = {imp_str.split(".")[0] for imp_str in processed_imports}
        results.update(
            {
                "available": True,
                "impfuzzy_hash": impfuzzy_hash,
                "import_count": len(processed_imports),
                "dll_count": len(unique_dlls),
                "imports_processed": processed_imports[:50],
                "total_imports": len(processed_imports),
            }
        )
        logger.debug("Impfuzzy calculated successfully: %s", impfuzzy_hash)
        logger.debug(
            "Processed %s imports from %s DLLs",
            len(processed_imports),
            len(unique_dlls),
        )
    except Exception as exc:
        logger.error("Impfuzzy analysis failed: %s", exc)
        results["error"] = str(exc)

    return results


def _import_dll(imp: dict[str, Any]) -> Any:
    return (
        imp.get("libname") or imp.get("lib") or imp.get("library") or imp.get("module") or "unknown"
    )


def _import_func(imp: dict[str, Any]) -> Any:
    return imp.get("name") or imp.get("func") or imp.get("function") or imp.get("symbol")


def _normalized_import(imp: dict[str, Any]) -> tuple[str, str] | None:
    func_name = _import_func(imp)
    if not func_name or func_name == "unknown":
        return None
    dll = _import_dll(imp)
    if not isinstance(dll, str) or not isinstance(func_name, str):
        raise TypeError("Import fields must be strings")
    func_clean = func_name.lower()
    if func_clean.startswith("ord_"):
        return None
    return dll.lower().replace(".dll", ""), func_clean


def process_imports(imports_data: list[Any], *, logger: logging.Logger) -> list[str]:
    dll_funcs: defaultdict[str, list[str]] = defaultdict(list)

    try:
        for imp in imports_data:
            if not isinstance(imp, dict):
                continue
            normalized = _normalized_import(imp)
            if normalized is None:
                continue
            dll_clean, func_clean = normalized
            dll_funcs[dll_clean].append(func_clean)

        processed_imports = sorted(
            f"{dll}.{func}" for dll, functions in dll_funcs.items() for func in functions
        )
        logger.debug("Processed imports into %s dll.function entries", len(processed_imports))
        return processed_imports
    except Exception as exc:
        logger.error("Error processing imports: %s", exc)
        return []


def compare_hashes(
    hash1: str, hash2: str, *, impfuzzy_available: bool, logger: logging.Logger, get_ssdeep_fn: Any
) -> int | None:
    if not impfuzzy_available or not hash1 or not hash2:
        return None
    try:
        ssdeep_module = get_ssdeep_fn()
        if ssdeep_module is None:
            logger.warning("ssdeep library required for impfuzzy comparison")
            return None
        return cast(int, ssdeep_module.compare(hash1, hash2))
    except Exception as exc:
        logger.warning("Impfuzzy comparison failed: %s", exc)
        return None


def calculate_impfuzzy_from_file(
    filepath: str, *, impfuzzy_available: bool, pyimpfuzzy: Any, logger: logging.Logger
) -> str | None:
    if not impfuzzy_available:
        return None
    try:
        return cast(str | None, pyimpfuzzy.get_impfuzzy(filepath))
    except Exception as exc:
        logger.error("Error calculating impfuzzy from file: %s", exc)
        return None
