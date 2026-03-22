"""Shared r2 command execution and adapter dispatch helpers."""

from __future__ import annotations

import json
import os
import threading
from typing import Any, cast

from ..adapters.validation import validate_r2_data
from ..domain.constants import SUBPROCESS_TIMEOUT_SECONDS
from ..error_handling import handle_errors
from ..error_handling.presets import (
    R2_ANALYSIS_POLICY,
    R2_JSON_DICT_POLICY,
    R2_JSON_LIST_POLICY,
    R2_TEXT_POLICY,
)
from ..interfaces import R2CommandInterface
from .logging import get_logger

logger = get_logger(__name__)

_SIMPLE_BASE_CALLS: dict[str, str] = {
    "aaa": "analyze_all",
    "i": "get_info_text",
    "id": "get_dynamic_info_text",
    "p=e 100": "get_entropy_pattern",
    "iR~version": "get_pe_version_info_text",
    "iHH": "get_pe_security_text",
    "izz~..": "get_strings_text",
    "izzj": "get_strings",
    "izj": "get_strings_basic",
    "iij": "get_imports",
    "iEj": "get_exports",
    "iSj": "get_sections",
    "isj": "get_symbols",
    "ij": "get_file_info",
    "iej": "get_entry_info",
    "ihj": "get_headers_json",
    "iHj": "get_pe_optional_header",
    "iDj": "get_data_directories",
    "iRj": "get_resources_info",
    "afl": "get_functions",
}


def safe_cmdj(
    r2_instance: R2CommandInterface, command: str, default: Any | None = None
) -> Any | None:
    policy = _select_json_policy(command, default)

    @handle_errors(policy)
    def _execute() -> Any:
        if hasattr(r2_instance, "cmdj"):
            try:
                native = r2_instance.cmdj(command)
                if native is not None:
                    return native
            except Exception as exc:
                logger.debug("Native cmdj failed for %s: %s", command, exc)
        raw = _run_cmd_with_timeout(r2_instance, command, default)
        if not isinstance(raw, str) or not raw.strip():
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return default

    return _execute()


def safe_cmdj_any(
    r2_instance: R2CommandInterface, command: str, default: Any | None = None
) -> Any | None:
    if hasattr(r2_instance, "cmdj"):
        try:
            return r2_instance.cmdj(command)
        except Exception as exc:
            logger.debug("safe_cmdj_any cmdj failed for %s: %s", command, exc)
    return safe_cmdj(r2_instance, command, default)


def _run_cmd_with_timeout(
    r2_instance: R2CommandInterface, command: str, default: Any | None
) -> Any | None:
    result: dict[str, Any] = {"value": default, "done": False}

    def _run() -> None:
        try:
            result["value"] = r2_instance.cmd(command)
        except Exception as exc:
            logger.debug("r2 cmd failed for %s: %s", command, exc)
            result["value"] = default
        finally:
            result["done"] = True

    timeout_seconds: float = float(SUBPROCESS_TIMEOUT_SECONDS)
    env_timeout = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS")
    if env_timeout:
        try:
            timeout_seconds = float(env_timeout)
        except ValueError:
            timeout_seconds = SUBPROCESS_TIMEOUT_SECONDS

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if not result["done"]:
        logger.warning("r2 command timed out: %s", command)
        return default

    return result["value"]


def _parse_address(command: str) -> tuple[str, int | None]:
    if "@" not in command:
        return command.strip(), None
    base, address_text = command.split("@", 1)
    base = base.strip()
    address_text = address_text.strip()
    if not address_text:
        return base, None
    try:
        return base, int(address_text, 0)
    except ValueError:
        return base, None


def _parse_size(base: str) -> int | None:
    parts = base.split()
    if len(parts) <= 1:
        return None
    try:
        return int(parts[1], 0)
    except ValueError:
        return None


def _handle_search(adapter: Any, command: str) -> Any | None:
    if command.startswith("/xj ") and hasattr(adapter, "search_hex_json"):
        return adapter.search_hex_json(command[4:].strip())
    if command.startswith("/c ") and hasattr(adapter, "search_text"):
        return adapter.search_text(command[3:].strip())
    if command.startswith("/x ") and hasattr(adapter, "search_hex"):
        return adapter.search_hex(command[3:].strip())
    return None


def _handle_simple(adapter: Any, base: str, command: str, address: int | None) -> Any | None:
    if base.startswith("iz~") and hasattr(adapter, "get_strings_filtered"):
        return adapter.get_strings_filtered(command)
    if base == "aflj":
        if address is not None and hasattr(adapter, "get_functions_at"):
            return adapter.get_functions_at(address)
        if hasattr(adapter, "get_functions"):
            return adapter.get_functions()
    if base.startswith("afij") and address is not None and hasattr(adapter, "get_function_info"):
        return adapter.get_function_info(address)
    method_name = _SIMPLE_BASE_CALLS.get(base)
    if method_name and hasattr(adapter, method_name):
        return getattr(adapter, method_name)()
    return None


def _handle_disasm(adapter: Any, base: str, address: int | None) -> Any | None:
    if base.startswith("pdfj") and hasattr(adapter, "get_disasm"):
        return adapter.get_disasm(address=address)
    if base.startswith("pdj") and hasattr(adapter, "get_disasm"):
        return adapter.get_disasm(address=address, size=_parse_size(base))
    if base.startswith("pi") and hasattr(adapter, "get_disasm_text"):
        return adapter.get_disasm_text(address=address, size=_parse_size(base))
    if base.startswith("agj") and hasattr(adapter, "get_cfg"):
        return adapter.get_cfg(address=address)
    return None


def _handle_bytes(adapter: Any, base: str, address: int | None) -> Any | None:
    if address is None:
        return None
    if base.startswith("p8j") and hasattr(adapter, "read_bytes_list"):
        size = _parse_size(base)
        return adapter.read_bytes_list(address, size) if size is not None else None
    if base.startswith("p8") and hasattr(adapter, "read_bytes"):
        size = _parse_size(base)
        if size is None:
            return None
        data = adapter.read_bytes(address, size)
        return data.hex() if data else ""
    if base.startswith("pxj") and hasattr(adapter, "read_bytes_list"):
        size = _parse_size(base)
        return adapter.read_bytes_list(address, size) if size is not None else None
    return None


def _maybe_use_adapter(adapter: Any, command: str) -> Any | None:
    if adapter is None:
        return None
    search_result = _handle_search(adapter, command)
    if search_result is not None:
        return search_result
    base, address = _parse_address(command)
    simple_result = _handle_simple(adapter, base, command, address)
    if simple_result is not None:
        return simple_result
    disasm_result = _handle_disasm(adapter, base, address)
    if disasm_result is not None:
        return disasm_result
    bytes_result = _handle_bytes(adapter, base, address)
    if bytes_result is not None:
        return bytes_result
    return None


def _cmd_fallback(r2_fallback: Any, command: str) -> str:
    if r2_fallback is None or not hasattr(r2_fallback, "cmd"):
        return ""
    return safe_cmd(r2_fallback, command, "")


def _cmdj_fallback(r2_fallback: Any, command: str, default: Any) -> Any:
    if r2_fallback is None or (
        not hasattr(r2_fallback, "cmd") and not hasattr(r2_fallback, "cmdj")
    ):
        return default
    return safe_cmdj_any(r2_fallback, command, default)


def cmd(adapter: Any, r2_fallback: Any, command: str) -> str:
    """Execute a text command, trying the adapter first then r2_fallback."""
    adapter_result = _maybe_use_adapter(adapter, command)
    if isinstance(adapter_result, str):
        return adapter_result
    return _cmd_fallback(r2_fallback, command)


def cmdj(adapter: Any, r2_fallback: Any, command: str, default: Any) -> Any:
    """Execute a JSON command, trying the adapter first then r2_fallback."""
    adapter_result = _maybe_use_adapter(adapter, command)
    if adapter_result is not None:
        return adapter_result
    return _cmdj_fallback(r2_fallback, command, default)


def cmd_list(adapter: Any, r2_fallback: Any, command: str) -> list[Any]:
    """Execute a JSON command and return the result as a list."""
    result = cmdj(adapter, r2_fallback, command, [])
    return result if isinstance(result, list) else []


def _select_json_policy(command: str, default: Any) -> Any:
    command_lower = command.lower().strip()
    if command_lower.startswith(("aaa", "aac", "af", "a")):
        return R2_ANALYSIS_POLICY
    if isinstance(default, list):
        return R2_JSON_LIST_POLICY
    return R2_JSON_DICT_POLICY


def safe_cmd_list(r2_instance: R2CommandInterface, command: str) -> list[dict[str, Any]]:
    result = safe_cmdj(r2_instance, command, [])
    return cast(list[dict[str, Any]], validate_r2_data(result, "list"))


def safe_cmd_dict(r2_instance: R2CommandInterface, command: str) -> dict[str, Any]:
    result = safe_cmdj(r2_instance, command, {})
    return cast(dict[str, Any], validate_r2_data(result, "dict"))


def safe_cmd(r2_instance: R2CommandInterface, command: str, default: str = "") -> str:
    @handle_errors(R2_TEXT_POLICY)
    def _execute() -> Any:
        return _run_cmd_with_timeout(r2_instance, command, default)

    return cast(str, _execute())
