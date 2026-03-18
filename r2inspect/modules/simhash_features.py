"""Feature extraction helpers for SimHash analyzer."""

from __future__ import annotations

from typing import Any, cast


def extract_string_features(analyzer: Any, *, logger: Any) -> list[str]:
    string_features: list[str] = []
    try:
        strings_data = analyzer._get_strings_data()
        if isinstance(strings_data, list):
            analyzer._collect_string_features(strings_data, string_features)
        string_features.extend(analyzer._extract_data_section_strings())
        logger.debug("Extracted %s string features", len(string_features))
        return string_features
    except Exception as exc:
        logger.debug("Error extracting string features: %s", exc)
        return []


def extract_opcodes_features(analyzer: Any, *, logger: Any) -> list[str]:
    opcode_features: list[str] = []
    try:
        functions = analyzer._get_functions()
        if not functions:
            logger.debug("No functions found for opcode extraction, trying alternative methods")
            functions = analyzer._cmd_list("afl")
            if not functions:
                return []
        for func in functions:
            func_addr = func.get("offset") or func.get("addr")
            if func_addr is None:
                continue
            func_name = func.get("name", f"func_{func_addr}")
            func_opcodes = analyzer._extract_function_opcodes(func_addr, func_name)
            if func_opcodes:
                opcode_features.extend(func_opcodes)
                logger.debug("Extracted %s opcodes from %s", len(func_opcodes), func_name)
            if len(opcode_features) > 10000:
                logger.debug("Opcode feature limit reached, truncating")
                break
        logger.debug(
            "Extracted %s opcode features from %s functions",
            len(opcode_features),
            len(functions),
        )
        return opcode_features
    except Exception as exc:
        logger.debug("Error extracting opcode features: %s", exc)
        return []


def extract_function_features(
    analyzer: Any, simhash_cls: Any, *, logger: Any
) -> dict[str, dict[str, Any]]:
    function_features: dict[str, dict[str, Any]] = {}
    try:
        functions = analyzer._get_functions()
        if not functions:
            return {}
        for func in functions:
            if not isinstance(func, dict):
                continue
            func_addr = func.get("offset") or func.get("addr")
            if func_addr is None:
                continue
            func_name = func.get("name", f"func_{func_addr}")
            func_size = func.get("size", 0)
            func_opcodes = analyzer._extract_function_opcodes(func_addr, func_name)
            if not func_opcodes:
                continue
            try:
                func_simhash = simhash_cls(func_opcodes)
                function_features[func_name] = {
                    "addr": func_addr,
                    "size": func_size,
                    "simhash": func_simhash.value,
                    "simhash_hex": hex(func_simhash.value),
                    "feature_count": len(func_opcodes),
                    "unique_opcodes": len(set(func_opcodes)),
                }
            except Exception as exc:
                logger.debug("Error creating SimHash for function %s: %s", func_name, exc)
                continue
        logger.debug("Extracted SimHash features for %s functions", len(function_features))
        return function_features
    except Exception as exc:
        logger.debug("Error extracting function features: %s", exc)
        return {}


def extract_function_opcodes(
    analyzer: Any, func_addr: int, func_name: str, *, logger: Any
) -> list[str]:
    try:
        if analyzer.adapter is None or not hasattr(analyzer.adapter, "get_disasm"):
            return []
        disasm = analyzer.adapter.get_disasm(address=func_addr)
        ops = analyzer._extract_ops_from_disasm(disasm)
        if ops:
            return cast(list[str], analyzer._extract_opcodes_from_ops(ops))
        disasm_range = analyzer.adapter.get_disasm(
            address=func_addr, size=analyzer.max_instructions_per_function
        )
        ops = analyzer._extract_ops_from_disasm(disasm_range)
        if ops:
            return cast(list[str], analyzer._extract_opcodes_from_ops(ops))
    except Exception as exc:
        logger.debug("Error extracting opcodes from function %s: %s", func_name, exc)
    return []
