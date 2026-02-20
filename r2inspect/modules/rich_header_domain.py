#!/usr/bin/env python3
"""Domain helpers for Rich Header parsing."""

from __future__ import annotations

import hashlib
import struct
from typing import Any, cast

COMPILER_PRODUCTS = {
    0x0000: "Unknown",
    0x0001: "Import0",
    0x0002: "Linker510",
    0x0003: "Cvtomf510",
    0x0004: "Linker600",
    0x0005: "Cvtomf600",
    0x0006: "Cvtres500",
    0x0007: "Utc11_Basic",
    0x0008: "Utc11_C",
    0x0009: "Utc11_CPP",
    0x000A: "AliasObj60",
    0x000B: "VisualBasic60",
    0x000C: "Masm613",
    0x000D: "Masm710",
    0x000E: "Linker511",
    0x000F: "Cvtomf511",
    0x0010: "Masm614",
    0x0011: "Linker512",
    0x0012: "Cvtomf512",
    0x0013: "Utc12_Basic",
    0x0014: "Utc12_C",
    0x0015: "Utc12_CPP",
    0x0016: "AliasObj70",
    0x0017: "Linker620",
    0x0018: "Cvtomf620",
    0x0019: "AliasObj71",
    0x001A: "Linker621",
    0x001B: "Cvtomf621",
    0x001C: "Masm615",
    0x001D: "Utc13_Basic",
    0x001E: "Utc13_C",
    0x001F: "Utc13_CPP",
    0x0020: "AliasObj80",
    0x0021: "AliasObj90",
    0x0022: "Utc12_C_Std",
    0x0023: "Utc12_CPP_Std",
    0x0024: "Utc12_C_Book",
    0x0025: "Utc12_CPP_Book",
    0x0026: "Implib622",
    0x0027: "Cvtomf622",
    0x0028: "Cvtres501",
    0x002A: "Utc13_C_Std",
    0x002B: "Utc13_CPP_Std",
    0x002C: "Cvtpgd1300",
    0x002D: "Linker622",
    0x002E: "Linker700",
    0x002F: "Export622",
    0x0030: "Export700",
    0x0031: "Masm700",
    0x0032: "Utc13_POGO_I_C",
    0x0033: "Utc13_POGO_I_CPP",
    0x0034: "Utc13_POGO_O_C",
    0x0035: "Utc13_POGO_O_CPP",
    0x0036: "Cvtres700",
    0x0037: "Cvtres710p",
    0x0038: "Linker710p",
    0x0039: "Cvtomf710p",
    0x003A: "Export710p",
    0x003B: "Implib710p",
    0x003C: "Masm710p",
    0x003D: "Utc1310p_C",
    0x003E: "Utc1310p_CPP",
    0x003F: "Utc1310p_C_Std",
    0x0040: "Utc1310p_CPP_Std",
    0x0041: "Utc1310p_LTCG_C",
    0x0042: "Utc1310p_LTCG_CPP",
    0x0043: "Utc1310p_POGO_I_C",
    0x0044: "Utc1310p_POGO_I_CPP",
    0x0045: "Utc1310p_POGO_O_C",
    0x0046: "Utc1310p_POGO_O_CPP",
    0x0047: "Linker624",
    0x0048: "Cvtomf624",
    0x0049: "Export624",
    0x004A: "Implib624",
    0x004B: "Linker710",
    0x004C: "Cvtomf710",
    0x004D: "Export710",
    0x004E: "Implib710",
    0x004F: "Cvtres710",
    0x0050: "Utc1310_C",
    0x0051: "Utc1310_CPP",
    0x0052: "Utc1310_C_Std",
    0x0053: "Utc1310_CPP_Std",
    0x0054: "Utc1310_LTCG_C",
    0x0055: "Utc1310_LTCG_CPP",
    0x0056: "Utc1310_POGO_I_C",
    0x0057: "Utc1310_POGO_I_CPP",
    0x0058: "Utc1310_POGO_O_C",
    0x0059: "Utc1310_POGO_O_CPP",
    0x005A: "Cvtpgd1310",
    0x005B: "Linker771",
    0x005C: "Cvtomf771",
    0x005D: "Export771",
    0x005E: "Implib771",
    0x005F: "Cvtres771",
    0x0060: "Utc1400_C",
    0x0061: "Utc1400_CPP",
    0x0062: "Utc1400_C_Std",
    0x0063: "Utc1400_CPP_Std",
    0x0064: "Utc1400_LTCG_C",
    0x0065: "Utc1400_LTCG_CPP",
    0x0066: "Utc1400_POGO_I_C",
    0x0067: "Utc1400_POGO_I_CPP",
    0x0068: "Utc1400_POGO_O_C",
    0x0069: "Utc1400_POGO_O_CPP",
    0x006A: "Cvtpgd1400",
    0x006B: "Linker800",
    0x006C: "Cvtomf800",
    0x006D: "Export800",
    0x006E: "Implib800",
    0x006F: "Cvtres800",
    0x0070: "Masm800",
    0x0071: "Utc1500_C",
    0x0072: "Utc1500_CPP",
    0x0073: "Utc1500_C_Std",
    0x0074: "Utc1500_CPP_Std",
    0x0075: "Utc1500_LTCG_C",
    0x0076: "Utc1500_LTCG_CPP",
    0x0077: "Utc1500_POGO_I_C",
    0x0078: "Utc1500_POGO_I_CPP",
    0x0079: "Utc1500_POGO_O_C",
    0x007A: "Utc1500_POGO_O_CPP",
    0x007B: "Cvtpgd1500",
    0x007C: "Linker900",
    0x007D: "Cvtomf900",
    0x007E: "Export900",
    0x007F: "Implib900",
    0x0080: "Cvtres900",
    0x0081: "Masm900",
    0x0082: "Utc1600_C",
    0x0083: "Utc1600_CPP",
    0x0084: "Utc1600_C_Std",
    0x0085: "Utc1600_CPP_Std",
    0x0086: "Utc1600_LTCG_C",
    0x0087: "Utc1600_LTCG_CPP",
    0x0088: "Utc1600_POGO_I_C",
    0x0089: "Utc1600_POGO_I_CPP",
    0x008A: "Utc1600_POGO_O_C",
    0x008B: "Utc1600_POGO_O_CPP",
    0x008C: "Cvtpgd1600",
    0x008D: "Linker1000",
    0x008E: "Cvtomf1000",
    0x008F: "Export1000",
    0x0090: "Implib1000",
    0x0091: "Cvtres1000",
    0x0092: "Masm1000",
    0x0093: "Utc1700_C",
    0x0094: "Utc1700_CPP",
    0x0095: "Utc1700_C_Std",
    0x0096: "Utc1700_CPP_Std",
    0x0097: "Utc1700_LTCG_C",
    0x0098: "Utc1700_LTCG_CPP",
    0x0099: "Utc1700_POGO_I_C",
    0x009A: "Utc1700_POGO_I_CPP",
    0x009B: "Utc1700_POGO_O_C",
    0x009C: "Utc1700_POGO_O_CPP",
    0x009D: "Cvtpgd1700",
    0x009E: "Linker1100",
    0x009F: "Cvtomf1100",
    0x00A0: "Export1100",
    0x00A1: "Implib1100",
    0x00A2: "Cvtres1100",
    0x00A3: "Masm1100",
    0x00A4: "Utc1800_C",
    0x00A5: "Utc1800_CPP",
    0x00A6: "Utc1800_C_Std",
    0x00A7: "Utc1800_CPP_Std",
    0x00A8: "Utc1800_LTCG_C",
    0x00A9: "Utc1800_LTCG_CPP",
    0x00AA: "Utc1800_POGO_I_C",
    0x00AB: "Utc1800_POGO_I_CPP",
    0x00AC: "Utc1800_POGO_O_C",
    0x00AD: "Utc1800_POGO_O_CPP",
    0x00AE: "Cvtpgd1800",
    0x00AF: "Linker1200",
    0x00B0: "Cvtomf1200",
    0x00B1: "Export1200",
    0x00B2: "Implib1200",
    0x00B3: "Cvtres1200",
    0x00B4: "Masm1200",
    0x00B5: "Utc1900_C",
    0x00B6: "Utc1900_CPP",
    0x00B7: "Utc1900_C_Std",
    0x00B8: "Utc1900_CPP_Std",
    0x00B9: "Utc1900_LTCG_C",
    0x00BA: "Utc1900_LTCG_CPP",
    0x00BB: "Utc1900_POGO_I_C",
    0x00BC: "Utc1900_POGO_I_CPP",
    0x00BD: "Utc1900_POGO_O_C",
    0x00BE: "Utc1900_POGO_O_CPP",
    0x00BF: "Cvtpgd1900",
    0x00C0: "Linker1300",
    0x00C1: "Cvtomf1300",
    0x00C2: "Export1300",
    0x00C3: "Implib1300",
    0x00C4: "Cvtres1300",
    0x00C5: "Masm1300",
    0x00C6: "Utc1900_C",
    0x00C7: "Utc1900_CPP",
    0x00C8: "Utc1910_C",
    0x00C9: "Utc1910_CPP",
    0x9CB4: "MSVC_2019_CPP",
    0x9CB5: "MSVC_2019_C",
    0x9E37: "MSVC_2022_CPP",
    0x9E38: "MSVC_2022_C",
    0xA09E: "MSVC_Linker_14x",
    0x5E3B: "MSVC_Resource_14x",
}


def parse_clear_data_entries(clear_data: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for i in range(0, len(clear_data), 8):
        if i + 8 > len(clear_data):
            break
        prodid, count = struct.unpack("<II", clear_data[i : i + 8])
        if count > 0:
            product_id = prodid & 0xFFFF
            build_number = (prodid >> 16) & 0xFFFF
            entries.append(
                {
                    "product_id": product_id,
                    "build_number": build_number,
                    "count": count,
                    "prodid": prodid,
                }
            )
    return entries


def get_compiler_description(compiler_name: str, build_number: int) -> str:
    descriptions = {
        "Utc": "Microsoft C/C++ Compiler",
        "Linker": "Microsoft Linker",
        "Masm": "Microsoft Macro Assembler",
        "Cvtres": "Microsoft Resource Converter",
        "Export": "Microsoft Export Tool",
        "Implib": "Microsoft Import Library Tool",
        "Cvtomf": "Microsoft OMF Converter",
        "AliasObj": "Microsoft Alias Object Tool",
        "VisualBasic": "Microsoft Visual Basic",
        "Cvtpgd": "Microsoft Profile Guided Optimization Tool",
    }
    for key, desc in descriptions.items():
        if key in compiler_name:
            return f"{desc} (Build {build_number})"
    return f"{compiler_name} (Build {build_number})"


def parse_compiler_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compilers: list[dict[str, Any]] = []
    for entry in entries:
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        product_id = prodid & 0xFFFF
        build_number = (prodid >> 16) & 0xFFFF
        compiler_name = COMPILER_PRODUCTS.get(product_id, f"Unknown_0x{product_id:04X}")
        compilers.append(
            {
                "product_id": product_id,
                "build_number": build_number,
                "count": count,
                "compiler_name": compiler_name,
                "full_prodid": prodid,
                "description": get_compiler_description(compiler_name, build_number),
            }
        )
    return compilers


def decode_rich_header(encoded_data: bytes, xor_key: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not encoded_data:
        return entries
    try:
        for i in range(4, len(encoded_data) - 4, 8):
            if i + 8 > len(encoded_data):
                break
            entry_bytes = encoded_data[i : i + 8]
            if len(entry_bytes) < 8:  # pragma: no cover
                break  # pragma: no cover
            prodid_encoded, count_encoded = struct.unpack("<II", entry_bytes)
            prodid = prodid_encoded ^ xor_key
            count = count_encoded ^ xor_key
            if count > 0:
                entries.append(
                    {
                        "prodid": prodid,
                        "count": count,
                        "prodid_encoded": prodid_encoded,
                        "count_encoded": count_encoded,
                    }
                )
    except Exception:
        return []
    return entries


def validate_decoded_entries(decoded_entries: list[dict[str, Any]]) -> bool:
    if not decoded_entries:
        return False
    valid_entries = 0
    for entry in decoded_entries:
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        if 0 < count < 10000 and 0 <= prodid < 0x10000:
            valid_entries += 1
    return valid_entries > 0


def build_rich_header_result(decoded_entries: list[dict[str, Any]], xor_key: int) -> dict[str, Any]:
    checksum = 0
    for entry in decoded_entries:
        checksum ^= entry.get("prodid", 0)
        checksum ^= entry.get("count", 0)
    return {
        "xor_key": xor_key,
        "checksum": checksum,
        "entries": decoded_entries,
    }


def calculate_richpe_hash(rich_data: dict[str, Any]) -> str | None:
    clear_data_bytes = rich_data.get("clear_data_bytes")
    if clear_data_bytes:
        return hashlib.md5(clear_data_bytes, usedforsecurity=False).hexdigest()
    richpe_hash = rich_data.get("richpe_hash")
    if richpe_hash:
        return cast(str, richpe_hash)
    entries = rich_data.get("entries", [])
    if not entries:
        return None
    clear_bytes = bytearray()
    for entry in entries:
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        clear_bytes.extend(struct.pack("<I", prodid))
        clear_bytes.extend(struct.pack("<I", count))
    return hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()
