"""Compiler metadata helpers for Rich Header analysis."""

from __future__ import annotations

from typing import Any


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


def parse_compiler_entries(
    entries: list[dict[str, Any]], compiler_products: dict[int, str]
) -> list[dict[str, Any]]:
    compilers: list[dict[str, Any]] = []
    for entry in entries:
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        product_id = prodid & 0xFFFF
        build_number = (prodid >> 16) & 0xFFFF
        compiler_name = compiler_products.get(product_id, f"Unknown_0x{product_id:04X}")
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
