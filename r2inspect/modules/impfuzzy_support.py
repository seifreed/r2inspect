"""Shared helper operations for impfuzzy analysis."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, cast

from ..infrastructure.ssdeep_loader import get_ssdeep


def analyze_imports(
    analyzer: Any, *, impfuzzy_available: bool, pyimpfuzzy: Any, logger: Any
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
        if not analyzer._is_pe_file():
            results["error"] = "File is not a PE binary"
            logger.debug("File %s is not a PE binary", analyzer.filepath)
            return results

        imports_data = analyzer._extract_imports()
        if not imports_data:
            results["error"] = "No imports found or failed to extract imports"
            logger.debug("No imports found in PE file")
            return results

        processed_imports = analyzer._process_imports(imports_data)
        if not processed_imports:
            results["error"] = "No valid imports found after processing"
            logger.debug("No valid imports found after processing")
            return results

        impfuzzy_hash = pyimpfuzzy.get_impfuzzy(str(analyzer.filepath))
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


def extract_imports(analyzer: Any, *, logger: Any) -> list[dict[str, Any]]:
    try:
        imports: list[dict[str, Any]] = []
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_imports"):
            raw_imports = analyzer.adapter.get_imports()
        else:
            raw_imports = analyzer._cmdj("iij", [])

        if isinstance(raw_imports, list):
            imports = [imp for imp in raw_imports if isinstance(imp, dict)]
        elif isinstance(raw_imports, dict):
            imports = [raw_imports]

        if not imports:
            logger.debug("No imports found with 'iij' command")
            raw_imports = analyzer._cmdj("ii", [])
            if isinstance(raw_imports, list):
                imports = [imp for imp in raw_imports if isinstance(imp, dict)]
            elif isinstance(raw_imports, dict):
                imports = [raw_imports]

        if not imports:
            logger.debug("No imports found with any method")
            return []

        logger.debug("Extracted %s import entries", len(imports))
        return imports
    except Exception as exc:
        logger.error("Error extracting imports: %s", exc)
        return []


def process_imports(imports_data: list[Any], *, logger: Any) -> list[str]:
    processed_imports: list[str] = []
    dll_funcs: defaultdict[str, list[str]] = defaultdict(list)

    try:
        for imp in imports_data:
            if not isinstance(imp, dict):
                continue
            dll = (
                imp.get("libname")
                or imp.get("lib")
                or imp.get("library")
                or imp.get("module")
                or "unknown"
            )
            func_name = (
                imp.get("name") or imp.get("func") or imp.get("function") or imp.get("symbol")
            )
            if func_name and func_name != "unknown":
                if not isinstance(dll, str) or not isinstance(func_name, str):
                    raise TypeError("Import fields must be strings")
                dll_clean = dll.lower().replace(".dll", "")
                func_clean = func_name.lower()
                if func_clean.startswith("ord_"):
                    continue
                dll_funcs[dll_clean].append(func_clean)

        for dll, functions in dll_funcs.items():
            for func in functions:
                processed_imports.append(f"{dll}.{func}")

        processed_imports.sort()
        logger.debug("Processed imports into %s dll.function entries", len(processed_imports))
        return processed_imports
    except Exception as exc:
        logger.error("Error processing imports: %s", exc)
        return []


def compare_hashes(
    hash1: str, hash2: str, *, impfuzzy_available: bool, logger: Any, get_ssdeep_fn: Any
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
    filepath: str, *, impfuzzy_available: bool, pyimpfuzzy: Any, logger: Any
) -> str | None:
    if not impfuzzy_available:
        return None
    try:
        return cast(str | None, pyimpfuzzy.get_impfuzzy(filepath))
    except Exception as exc:
        logger.error("Error calculating impfuzzy from file: %s", exc)
        return None
