"""Dependency-free PE header, symbol, and mitigation parser."""

from __future__ import annotations

from typing import Any

from .binary_view import BinaryView

_MACHINES = {
    0x014C: "x86",
    0x01C0: "arm",
    0x01C4: "armv7",
    0x8664: "x86_64",
    0xAA64: "arm64",
}


def _rva_offset(rva: int, sections: list[dict[str, Any]], headers_size: int) -> int:
    if rva < headers_size:
        return rva
    for section in sections:
        start = int(section["vaddr"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < start + span:
            return int(section["paddr"]) + rva - start
    raise ValueError(f"PE RVA {rva:#x} is not mapped")


def _sections(view: BinaryView, offset: int, count: int) -> list[dict[str, Any]]:
    if count > 96:
        raise ValueError(f"unreasonable PE section count: {count}")
    sections = []
    for index in range(count):
        current = offset + index * 40
        name = view.read(current, 8).split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, vaddr, raw_size, paddr = view.unpack("<IIII", current + 8)
        characteristics = int(view.unpack("<I", current + 36)[0])
        if raw_size and paddr + raw_size > view.size:
            raise ValueError(f"PE section {name} extends outside the file")
        sections.append(
            {
                "name": name,
                "vaddr": vaddr,
                "size": virtual_size,
                "virtual_size": virtual_size,
                "paddr": paddr,
                "raw_size": raw_size,
                "flags": characteristics,
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
            }
        )
    return sections


def _imports(
    view: BinaryView,
    directory: tuple[int, int],
    sections: list[dict[str, Any]],
    headers_size: int,
    bits: int,
) -> list[dict[str, Any]]:
    rva, size = directory
    if not rva or not size:
        return []
    offset = _rva_offset(rva, sections, headers_size)
    imports = []
    for index in range(min(size // 20, 4096)):
        original_thunk, timestamp, forwarder, name_rva, first_thunk = view.unpack(
            "<IIIII", offset + index * 20
        )
        if not any((original_thunk, timestamp, forwarder, name_rva, first_thunk)):
            break
        library = view.cstring(_rva_offset(name_rva, sections, headers_size))
        thunk_rva = original_thunk or first_thunk
        thunk_offset = _rva_offset(thunk_rva, sections, headers_size)
        width, fmt, ordinal_mask = (8, "<Q", 1 << 63) if bits == 64 else (4, "<I", 1 << 31)
        for thunk_index in range(65536):
            value = int(view.unpack(fmt, thunk_offset + thunk_index * width)[0])
            if value == 0:
                break
            if value & ordinal_mask:
                imports.append({"library": library, "ordinal": value & 0xFFFF})
            else:
                name_offset = _rva_offset(value, sections, headers_size)
                imports.append({"library": library, "name": view.cstring(name_offset + 2)})
    return imports


def _exports(
    view: BinaryView,
    directory: tuple[int, int],
    sections: list[dict[str, Any]],
    headers_size: int,
) -> list[dict[str, Any]]:
    rva, size = directory
    if not rva or size < 40:
        return []
    offset = _rva_offset(rva, sections, headers_size)
    fields = view.unpack("<IIHHIIIIIII", offset)
    ordinal_base, function_count, name_count = map(int, fields[5:8])
    functions_rva, names_rva, ordinals_rva = map(int, fields[8:11])
    if name_count > 65536 or function_count > 65536:
        raise ValueError("unreasonable PE export count")
    functions_offset = _rva_offset(functions_rva, sections, headers_size)
    names_offset = _rva_offset(names_rva, sections, headers_size)
    ordinals_offset = _rva_offset(ordinals_rva, sections, headers_size)
    exports = []
    for index in range(name_count):
        name_rva = int(view.unpack("<I", names_offset + index * 4)[0])
        ordinal_index = int(view.unpack("<H", ordinals_offset + index * 2)[0])
        if ordinal_index >= function_count:
            continue
        function_rva = int(view.unpack("<I", functions_offset + ordinal_index * 4)[0])
        exports.append(
            {
                "name": view.cstring(_rva_offset(name_rva, sections, headers_size)),
                "ordinal": ordinal_base + ordinal_index,
                "vaddr": function_rva,
            }
        )
    return exports


def parse_pe(view: BinaryView) -> dict[str, Any]:
    if view.read(0, 2) != b"MZ":
        raise ValueError("missing DOS signature")
    pe_offset = int(view.unpack("<I", 0x3C)[0])
    if view.read(pe_offset, 4) != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, section_count, timestamp, _, _, optional_size, characteristics = view.unpack(
        "<HHIIIHH", pe_offset + 4
    )
    optional_offset = pe_offset + 24
    magic = int(view.unpack("<H", optional_offset)[0])
    if magic not in {0x10B, 0x20B}:
        raise ValueError(f"unsupported PE optional header: {magic:#x}")
    bits = 64 if magic == 0x20B else 32
    minimum_optional_size = 112 if bits == 64 else 96
    if optional_size < minimum_optional_size:
        raise ValueError(f"truncated PE optional header: {optional_size} bytes")
    entry_rva = int(view.unpack("<I", optional_offset + 16)[0])
    image_base = int(
        view.unpack("<Q" if bits == 64 else "<I", optional_offset + (24 if bits == 64 else 28))[0]
    )
    headers_size = int(view.unpack("<I", optional_offset + 60)[0])
    dll_characteristics = int(view.unpack("<H", optional_offset + 70)[0])
    directory_count_offset = optional_offset + (108 if bits == 64 else 92)
    directory_offset = optional_offset + (112 if bits == 64 else 96)
    directory_count = min(int(view.unpack("<I", directory_count_offset)[0]), 16)
    if directory_offset + directory_count * 8 > optional_offset + optional_size:
        raise ValueError("PE data directories extend outside the optional header")
    directories: list[tuple[int, int]] = []
    for index in range(directory_count):
        rva, size = view.unpack("<II", directory_offset + index * 8)
        directories.append((int(rva), int(size)))
    directories.extend([(0, 0)] * (16 - len(directories)))
    sections = _sections(view, optional_offset + int(optional_size), int(section_count))
    imports = _imports(view, directories[1], sections, headers_size, bits)
    exports = _exports(view, directories[0], sections, headers_size)
    certificate_offset, certificate_size = directories[4]
    image_end = max(
        (int(section["paddr"]) + int(section["raw_size"]) for section in sections),
        default=headers_size,
    )
    overlay_size = max(0, view.size - image_end)
    security = {
        "aslr": bool(dll_characteristics & 0x0040),
        "dep": bool(dll_characteristics & 0x0100),
        "seh": not bool(dll_characteristics & 0x0400),
        "guard_cf": bool(dll_characteristics & 0x4000),
        "high_entropy_va": bool(dll_characteristics & 0x0020),
        "authenticode": bool(certificate_offset and certificate_size),
    }
    return {
        "architecture": _MACHINES.get(int(machine), f"machine-{int(machine):#x}"),
        "bits": bits,
        "endian": "little",
        "type": "DLL" if int(characteristics) & 0x2000 else "EXE",
        "entry_point": image_base + entry_rva,
        "entry_point_rva": entry_rva,
        "image_base": image_base,
        "build_id": f"coff:{int(timestamp):08x}",
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "security_features": security,
        "overlay": {"offset": image_end, "size": overlay_size},
        "signature_status": "present" if security["authenticode"] else "absent",
    }


__all__ = ["parse_pe"]
