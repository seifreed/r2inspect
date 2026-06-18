"""Parsing helpers for Authenticode analysis."""

from __future__ import annotations

from typing import Any


def _to_int(value: Any) -> int | None:
    try:
        return int(value, 0) if isinstance(value, str) else int(value or 0)
    except (TypeError, ValueError):
        return None


def get_security_directory(cmdj: Any) -> dict[str, Any] | None:
    data_dirs = cmdj("iDj", [])
    if not isinstance(data_dirs, list):
        return None
    for dd in data_dirs:
        if isinstance(dd, dict) and dd.get("name") == "SECURITY":
            return dd
    return None


def _validate_security_dir(
    security_dir: dict[str, Any], result: dict[str, Any]
) -> tuple[int, int] | None:
    errors = result.get("errors")
    if not isinstance(errors, list):
        errors = []
        result["errors"] = errors
    cert_offset = _to_int(security_dir.get("paddr", 0))
    cert_size = _to_int(security_dir.get("size", 0))
    if cert_offset is None or cert_size is None:
        errors.append("Invalid security directory types")
        return None
    if cert_offset <= 0 or cert_size <= 0 or cert_offset > 0xFFFFFFFF or cert_size > 0xFFFFFFFF:
        errors.append("Invalid security directory")
        return None
    return cert_offset, cert_size


def _augment_pkcs7(
    cert_info: dict[str, Any],
    *,
    cert_type: int,
    cert_length: int,
    cert_offset: int,
    parse_pkcs7_fn: Any,
) -> None:
    if cert_type != 0x0002:
        return
    cert_info["format"] = "PKCS#7"
    if cert_length >= 8:
        pkcs7_info = parse_pkcs7_fn(cert_offset + 8, cert_length - 8)
        if pkcs7_info:
            cert_info.update(pkcs7_info)


def read_win_certificate(
    *,
    cmdj: Any,
    security_dir: dict[str, Any],
    result: dict[str, Any],
    parse_header_fn: Any,
    get_cert_type_name_fn: Any,
    parse_pkcs7_fn: Any,
) -> dict[str, Any] | None:
    validated = _validate_security_dir(security_dir, result)
    if validated is None:
        return None
    cert_offset, cert_size = validated

    result["signature_offset"] = cert_offset
    result["signature_size"] = cert_size
    win_cert_data = cmdj(f"pxj 8 @ {cert_offset}", [])
    if not (win_cert_data and len(win_cert_data) >= 8):
        return None

    cert_length, cert_revision, cert_type = parse_header_fn(win_cert_data)
    cert_info = {
        "length": cert_length,
        "revision": hex(cert_revision),
        "type": get_cert_type_name_fn(cert_type),
        "type_value": hex(cert_type),
    }
    _augment_pkcs7(
        cert_info,
        cert_type=cert_type,
        cert_length=cert_length,
        cert_offset=cert_offset,
        parse_pkcs7_fn=parse_pkcs7_fn,
    )
    return cert_info


def parse_pkcs7(
    *,
    cmdj: Any,
    offset: int,
    size: int,
    logger: Any,
    detect_digest_algorithm_fn: Any,
    detect_encryption_algorithm_fn: Any,
    extract_common_names_fn: Any,
    has_timestamp_fn: Any,
) -> dict[str, Any] | None:
    try:
        result: dict[str, Any] = {
            "signer_info": [],
            "certificates_chain": [],
            "digest_algorithm": None,
            "encryption_algorithm": None,
            "has_timestamp": False,
        }
        offset_int = _to_int(offset)
        size_int = _to_int(size)
        if offset_int is None or size_int is None or size_int <= 0 or offset_int < 0:
            return None
        read_size = min(size_int, 1024)
        pkcs7_data = cmdj(f"pxj {read_size} @ {offset_int}", [])
        if not pkcs7_data:
            return None
        result["digest_algorithm"] = detect_digest_algorithm_fn(pkcs7_data)
        result["encryption_algorithm"] = detect_encryption_algorithm_fn(pkcs7_data)
        result["signer_info"] = extract_common_names_fn(pkcs7_data, offset_int)
        if has_timestamp_fn(pkcs7_data):
            result["has_timestamp"] = True
        return result
    except Exception as exc:
        logger.error("Error parsing PKCS#7: %s", exc)
        return None
