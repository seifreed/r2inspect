"""Dependency-free ELF structure, symbol, and mitigation parser."""

from __future__ import annotations

from typing import Any

from .binary_view import BinaryView

_MACHINES = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
    0xF3: "riscv",
}
_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_SEGMENTS = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    6: "PHDR",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
}


def _align(value: int, alignment: int = 4) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _section_headers(
    view: BinaryView,
    endian: str,
    bits: int,
    offset: int,
    entry_size: int,
    count: int,
) -> list[dict[str, Any]]:
    if count > 65536:
        raise ValueError(f"unreasonable ELF section count: {count}")
    fmt = f"{endian}IIQQQQIIQQ" if bits == 64 else f"{endian}IIIIIIIIII"
    minimum_size = 64 if bits == 64 else 40
    if entry_size < minimum_size:
        raise ValueError(f"invalid ELF section-header size: {entry_size}")
    sections = []
    for index in range(count):
        fields = tuple(map(int, view.unpack(fmt, offset + index * entry_size)))
        name, section_type, flags, address, file_offset, size, link, info, align, entsize = fields
        if section_type != 8 and size and file_offset + size > view.size:
            raise ValueError(f"ELF section {index} extends outside the file")
        sections.append(
            {
                "name_offset": name,
                "type": section_type,
                "flags": flags,
                "vaddr": address,
                "paddr": file_offset,
                "size": size,
                "link": link,
                "info": info,
                "alignment": align,
                "entry_size": entsize,
            }
        )
    return sections


def _name_sections(view: BinaryView, sections: list[dict[str, Any]], index: int) -> None:
    if not 0 <= index < len(sections):
        raise ValueError("invalid ELF section-name table index")
    table = sections[index]
    for section in sections:
        name_offset = int(section.pop("name_offset"))
        section["name"] = (
            view.cstring(
                int(table["paddr"]) + name_offset,
                limit=int(table["size"]) - name_offset,
            )
            if name_offset < int(table["size"])
            else ""
        )


def _program_headers(
    view: BinaryView,
    endian: str,
    bits: int,
    offset: int,
    entry_size: int,
    count: int,
) -> list[dict[str, Any]]:
    if count > 65536:
        raise ValueError(f"unreasonable ELF program-header count: {count}")
    fmt = f"{endian}IIQQQQQQ" if bits == 64 else f"{endian}IIIIIIII"
    minimum_size = 56 if bits == 64 else 32
    if count and entry_size < minimum_size:
        raise ValueError(f"invalid ELF program-header size: {entry_size}")
    headers = []
    for index in range(count):
        fields = tuple(map(int, view.unpack(fmt, offset + index * entry_size)))
        if bits == 64:
            kind, flags, file_offset, vaddr, paddr, file_size, memory_size, align = fields
        else:
            kind, file_offset, vaddr, paddr, file_size, memory_size, flags, align = fields
        if file_size and file_offset + file_size > view.size:
            raise ValueError(f"ELF segment {index} extends outside the file")
        headers.append(
            {
                "type": _SEGMENTS.get(kind, f"{kind:#x}"),
                "flags": flags,
                "offset": file_offset,
                "vaddr": vaddr,
                "paddr": paddr,
                "filesz": file_size,
                "memsz": memory_size,
                "alignment": align,
                "readable": bool(flags & 4),
                "writable": bool(flags & 2),
                "executable": bool(flags & 1),
            }
        )
    return headers


def _symbols(
    view: BinaryView,
    sections: list[dict[str, Any]],
    endian: str,
    bits: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    imports, exports = [], []
    fmt = f"{endian}IBBHQQ" if bits == 64 else f"{endian}IIIBBH"
    default_size = 24 if bits == 64 else 16
    for section in sections:
        if section["type"] != 11:
            continue
        link = int(section["link"])
        if not 0 <= link < len(sections):
            raise ValueError("invalid ELF dynamic string-table index")
        strings = sections[link]
        entry_size = int(section["entry_size"]) or default_size
        if entry_size < default_size:
            raise ValueError("invalid ELF symbol-entry size")
        count = min(int(section["size"]) // entry_size, 1_000_000)
        for index in range(count):
            fields = tuple(map(int, view.unpack(fmt, int(section["paddr"]) + index * entry_size)))
            if bits == 64:
                name_offset, info, _, section_index, value, size = fields
            else:
                name_offset, value, size, info, _, section_index = fields
            if not name_offset or name_offset >= int(strings["size"]):
                continue
            name = view.cstring(
                int(strings["paddr"]) + name_offset,
                limit=int(strings["size"]) - name_offset,
            )
            symbol = {"name": name, "vaddr": value, "size": size}
            if section_index == 0:
                imports.append(symbol)
            elif info >> 4 in {1, 2}:
                exports.append(symbol)
    return imports, exports


def _dynamic_paths(
    view: BinaryView,
    sections: list[dict[str, Any]],
    endian: str,
    bits: int,
) -> tuple[list[str], list[str]]:
    rpath: list[str] = []
    runpath: list[str] = []
    fmt, default_size = (f"{endian}qQ", 16) if bits == 64 else (f"{endian}iI", 8)
    for section in sections:
        if section["type"] != 6:
            continue
        link = int(section["link"])
        if not 0 <= link < len(sections):
            continue
        strings = sections[link]
        entry_size = int(section["entry_size"]) or default_size
        if entry_size < default_size:
            raise ValueError("invalid ELF dynamic-entry size")
        for index in range(min(int(section["size"]) // entry_size, 1_000_000)):
            tag, value = map(int, view.unpack(fmt, int(section["paddr"]) + index * entry_size))
            if tag == 0:
                break
            if tag in {15, 29} and value < int(strings["size"]):
                target = rpath if tag == 15 else runpath
                target.append(
                    view.cstring(
                        int(strings["paddr"]) + value,
                        limit=int(strings["size"]) - value,
                    )
                )
    return rpath, runpath


def _build_id(view: BinaryView, sections: list[dict[str, Any]], endian: str) -> str | None:
    section = next((item for item in sections if item.get("name") == ".note.gnu.build-id"), None)
    if section is None:
        return None
    start, size = int(section["paddr"]), int(section["size"])
    cursor = 0
    while cursor + 12 <= size:
        name_size, value_size, note_type = map(int, view.unpack(f"{endian}III", start + cursor))
        name_offset = cursor + 12
        value_offset = _align(name_offset + name_size)
        end = _align(value_offset + value_size)
        if end > size:
            raise ValueError("truncated ELF note")
        name = view.read(start + name_offset, name_size).rstrip(b"\0")
        if name == b"GNU" and note_type == 3:
            return view.read(start + value_offset, value_size).hex()
        cursor = end
    return None


def parse_elf(view: BinaryView) -> dict[str, Any]:
    ident = view.read(0, 16)
    if ident[:4] != b"\x7fELF" or ident[4] not in {1, 2} or ident[5] not in {1, 2}:
        raise ValueError("invalid ELF identification")
    bits = 64 if ident[4] == 2 else 32
    endian, endian_name = ("<", "little") if ident[5] == 1 else (">", "big")
    fmt = f"{endian}HHIQQQIHHHHHH" if bits == 64 else f"{endian}HHIIIIIHHHHHH"
    fields = tuple(map(int, view.unpack(fmt, 16)))
    (
        file_type,
        machine,
        _,
        entry_point,
        program_offset,
        section_offset,
        flags,
        header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_names,
    ) = fields
    if header_size < (64 if bits == 64 else 52):
        raise ValueError(f"truncated ELF header: {header_size} bytes")
    sections = _section_headers(
        view, endian, bits, section_offset, section_entry_size, section_count
    )
    _name_sections(view, sections, section_names)
    program_headers = _program_headers(
        view, endian, bits, program_offset, program_entry_size, program_count
    )
    imports, exports = _symbols(view, sections, endian, bits)
    rpath, runpath = _dynamic_paths(view, sections, endian, bits)
    imported_names = {str(item["name"]) for item in imports}
    stack = next((item for item in program_headers if item["type"] == "GNU_STACK"), None)
    load_addresses = [int(item["vaddr"]) for item in program_headers if item["type"] == "LOAD"]
    image_end = max(
        [
            int(section["paddr"]) + int(section["size"])
            for section in sections
            if section["type"] != 8
        ]
        + [section_offset + section_entry_size * section_count],
        default=0,
    )
    security = {
        "nx": None if stack is None else not bool(stack["executable"]),
        "pie": file_type == 3 and any(item["type"] == "INTERP" for item in program_headers),
        "relro": any(item["type"] == "GNU_RELRO" for item in program_headers),
        "stack_canary": "__stack_chk_fail" in imported_names,
        "canary": "__stack_chk_fail" in imported_names,
        "fortify": any(name.endswith("_chk") for name in imported_names),
        "rpath": bool(rpath),
        "runpath": bool(runpath),
    }
    return {
        "architecture": _MACHINES.get(machine, f"machine-{machine:#x}"),
        "bits": bits,
        "endian": endian_name,
        "type": _TYPES.get(file_type, str(file_type)),
        "flags": flags,
        "entry_point": entry_point,
        "image_base": min(load_addresses, default=0),
        "build_id": _build_id(view, sections, endian),
        "sections": sections,
        "program_headers": program_headers,
        "imports": imports,
        "exports": exports,
        "rpath_entries": rpath,
        "runpath_entries": runpath,
        "security_features": security,
        "overlay": {"offset": image_end, "size": max(0, view.size - image_end)},
    }


__all__ = ["parse_elf"]
