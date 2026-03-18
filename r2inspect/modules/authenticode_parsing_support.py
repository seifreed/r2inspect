"""Parsing helpers for Authenticode analysis."""

from __future__ import annotations

from typing import Any


def get_security_directory(cmdj: Any) -> dict[str, Any] | None:
    data_dirs = cmdj("iDj", [])
    if not isinstance(data_dirs, list):
        return None
    for dd in data_dirs:
        if isinstance(dd, dict) and dd.get("name") == "SECURITY":
            return dd
    return None


def read_win_certificate(
    *,
    cmdj: Any,
    security_dir: dict[str, Any],
    result: dict[str, Any],
    parse_header_fn: Any,
    get_cert_type_name_fn: Any,
    parse_pkcs7_fn: Any,
) -> dict[str, Any] | None:
    cert_offset = security_dir.get("paddr", 0)
    cert_size = security_dir.get("size", 0)
    if not isinstance(cert_offset, int) or not isinstance(cert_size, int):
        result["errors"].append("Invalid security directory types")
        return None
    if cert_offset <= 0 or cert_size <= 0 or cert_offset > 0xFFFFFFFF or cert_size > 0xFFFFFFFF:
        result["errors"].append("Invalid security directory")
        return None

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

    if cert_type == 0x0002:
        cert_info["format"] = "PKCS#7"
        if cert_length >= 8:
            pkcs7_info = parse_pkcs7_fn(cert_offset + 8, cert_length - 8)
            if pkcs7_info:
                cert_info.update(pkcs7_info)

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
        if not isinstance(offset, int) or not isinstance(size, int) or size <= 0 or offset < 0:
            return None
        read_size = min(size, 1024)
        pkcs7_data = cmdj(f"pxj {read_size} @ {offset}", [])
        if not pkcs7_data:
            return None
        result["digest_algorithm"] = detect_digest_algorithm_fn(pkcs7_data)
        result["encryption_algorithm"] = detect_encryption_algorithm_fn(pkcs7_data)
        result["signer_info"] = extract_common_names_fn(pkcs7_data, offset)
        if has_timestamp_fn(pkcs7_data):
            result["has_timestamp"] = True
        return result
    except Exception as exc:
        logger.error("Error parsing PKCS#7: %s", exc)
        return None
