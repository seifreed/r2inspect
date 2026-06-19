"""Feature extraction helpers for SimHash analyzer."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from ..abstractions.coercion_support import coerce_int
from .simhash_support import SimHashHost


def _to_int(value: Any) -> int:
    return coerce_int(value)


def _coerce_function_list(functions: Any) -> list[dict[str, Any]]:
    if isinstance(functions, list):
        return [func for func in functions if isinstance(func, dict)]
    try:
        return [func for func in list(functions) if isinstance(func, dict)]
    except TypeError:
        return []


def _function_name(func: dict[str, Any], func_addr: int | None = None) -> str:
    name = func.get("name")
    if isinstance(name, str) and name:
        return name
    if func_addr is not None and func_addr > 0:
        return f"func_{func_addr}"
    return "unknown"


def extract_string_features(host: SimHashHost, *, logger: logging.Logger) -> list[str]:
    string_features: list[str] = []
    try:
        strings_data = host._get_strings_data()
        if isinstance(strings_data, list):
            string_source = strings_data
        elif isinstance(strings_data, (dict, str, bytes)) or not isinstance(strings_data, Iterable):
            string_source = []
        else:
            string_source = list(strings_data)
        if string_source:
            host._collect_string_features(string_source, string_features)
        data_section_strings = host._extract_data_section_strings()
        if not isinstance(data_section_strings, (dict, str, bytes)) and isinstance(
            data_section_strings, Iterable
        ):
            string_features.extend(
                value for value in data_section_strings if isinstance(value, str)
            )
        logger.debug("Extracted %s string features", len(string_features))
        return string_features
    except Exception as exc:
        logger.debug("Error extracting string features: %s", exc)
        return []


def extract_opcodes_features(host: SimHashHost, *, logger: logging.Logger) -> list[str]:
    opcode_features: list[str] = []
    try:
        functions = _coerce_function_list(host._get_functions())
        if not functions:
            logger.debug("No functions found for opcode extraction, trying alternative methods")
            functions = _coerce_function_list(host._cmd_list("afl"))
            if not functions:
                return []
        for func in functions:
            if not isinstance(func, dict):
                continue
            func_addr = _to_int(func.get("offset") or func.get("addr"))
            if func_addr <= 0:
                continue
            func_name = _function_name(func, func_addr)
            func_opcodes = host._extract_function_opcodes(func_addr, func_name)
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
    host: SimHashHost, simhash_cls: Any, *, logger: logging.Logger
) -> dict[str, dict[str, Any]]:
    function_features: dict[str, dict[str, Any]] = {}
    try:
        functions = host._get_functions()
        if isinstance(functions, list):
            function_source = functions
        elif isinstance(functions, (dict, str, bytes)) or not isinstance(functions, Iterable):
            return {}
        else:
            function_source = list(functions)
        if not function_source:
            return {}
        for func in function_source:
            if not isinstance(func, dict):
                continue
            func_addr = _to_int(func.get("offset") or func.get("addr"))
            if func_addr <= 0:
                continue
            func_name = _function_name(func, func_addr)
            func_size = _to_int(func.get("size", 0))
            func_opcodes = host._extract_function_opcodes(func_addr, func_name)
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
    host: SimHashHost, func_addr: int, func_name: str, *, logger: logging.Logger
) -> list[str]:
    try:
        if host.adapter is None or not hasattr(host.adapter, "get_disasm"):
            return []
        disasm = host.adapter.get_disasm(address=func_addr)
        ops = host._extract_ops_from_disasm(disasm)
        if ops:
            return host._extract_opcodes_from_ops(ops)
        disasm_range = host.adapter.get_disasm(
            address=func_addr, size=host.max_instructions_per_function
        )
        ops = host._extract_ops_from_disasm(disasm_range)
        if ops:
            return host._extract_opcodes_from_ops(ops)
    except Exception as exc:
        logger.debug("Error extracting opcodes from function %s: %s", func_name, exc)
    return []
