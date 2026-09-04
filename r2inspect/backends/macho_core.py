"""Dependency-free Mach-O load-command and symbol parser."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from .binary_view import BinaryView

_THIN_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", "little", 32),
    b"\xfe\xed\xfa\xce": (">", "big", 32),
    b"\xcf\xfa\xed\xfe": ("<", "little", 64),
    b"\xfe\xed\xfa\xcf": (">", "big", 64),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", 32),
    b"\xbe\xba\xfe\xca": ("<", 32),
    b"\xca\xfe\xba\xbf": (">", 64),
    b"\xbf\xba\xfe\xca": ("<", 64),
}
_CPUS = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    18: "powerpc",
    0x01000012: "powerpc64",
}
_FILE_TYPES = {1: "OBJECT", 2: "EXECUTE", 6: "DYLIB", 8: "BUNDLE", 11: "KEXT"}
_COMMANDS = {
    1: "SEGMENT",
    2: "SYMTAB",
    0xC: "LOAD_DYLIB",
    0x1B: "UUID",
    0x1D: "CODE_SIGNATURE",
    0x19: "SEGMENT_64",
    0x28: "MAIN",
    0x32: "BUILD_VERSION",
}
_DYLIB_COMMANDS = {0xC, 0x18, 0x1F, 0x20, 0x23}


def _text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _version(value: int) -> str:
    return f"{value >> 16}.{value >> 8 & 0xFF}.{value & 0xFF}"


def _architecture(cpu: int) -> str:
    value = cpu & 0xFFFFFFFF
    return _CPUS.get(value, f"cpu-{value:#x}")


def _segment(
    view: BinaryView,
    endian: str,
    bits: int,
    offset: int,
    command_size: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if bits == 64:
        header_size, section_size, section_fmt = 72, 80, f"{endian}16s16sQQIIIIIIII"
        segment_fmt = f"{endian}II16sQQQQiiII"
    else:
        header_size, section_size, section_fmt = 56, 68, f"{endian}16s16sIIIIIIIII"
        segment_fmt = f"{endian}II16sIIIIiiII"
    if command_size < header_size:
        raise ValueError("truncated Mach-O segment command")
    fields = view.unpack(segment_fmt, offset)
    _, _, name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, count, flags = fields
    count = int(count)
    if count > 65536 or header_size + count * section_size > command_size:
        raise ValueError(f"invalid Mach-O section count: {count}")
    if filesize and int(fileoff) + int(filesize) > view.size:
        raise ValueError(f"Mach-O segment {_text(name)} extends outside the file")
    segment = {
        "name": _text(name),
        "vaddr": int(vmaddr),
        "size": int(vmsize),
        "paddr": int(fileoff),
        "file_size": int(filesize),
        "max_protection": int(maxprot),
        "protection": int(initprot),
        "flags": int(flags),
    }
    sections = []
    for index in range(count):
        values = view.unpack(section_fmt, offset + header_size + index * section_size)
        section_name, segment_name = values[:2]
        address, size, file_offset, align, reloc, reloc_count, section_flags = map(int, values[2:9])
        section_type = section_flags & 0xFF
        if section_type not in {1, 0xC, 0x12} and size and file_offset + size > view.size:
            raise ValueError(f"Mach-O section {_text(section_name)} extends outside the file")
        sections.append(
            {
                "name": _text(section_name),
                "segment": _text(segment_name),
                "vaddr": address,
                "size": size,
                "paddr": file_offset,
                "alignment": align,
                "relocation_offset": reloc,
                "relocation_count": reloc_count,
                "flags": section_flags,
                "readable": bool(int(initprot) & 1),
                "writable": bool(int(initprot) & 2),
                "executable": bool(int(initprot) & 4),
            }
        )
    return segment, sections


def _symbols(
    view: BinaryView,
    endian: str,
    bits: int,
    symtab: tuple[int, int, int, int] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if symtab is None:
        return [], []
    symbol_offset, count, string_offset, string_size = symtab
    entry_size = 16 if bits == 64 else 12
    if count > 1_000_000 or symbol_offset + count * entry_size > view.size:
        raise ValueError("invalid Mach-O symbol table")
    if string_offset + string_size > view.size:
        raise ValueError("Mach-O string table extends outside the file")
    fmt = f"{endian}IBBHQ" if bits == 64 else f"{endian}IBBHI"
    imports, exports = [], []
    for index in range(count):
        name_offset, symbol_type, section, _, value = view.unpack(
            fmt, symbol_offset + index * entry_size
        )
        name_offset, symbol_type, section, value = map(
            int, (name_offset, symbol_type, section, value)
        )
        if not name_offset or name_offset >= string_size:
            continue
        name = view.cstring(string_offset + name_offset, limit=string_size - name_offset)
        if not symbol_type & 1:
            continue
        symbol = {"name": name, "vaddr": value}
        if symbol_type & 0xE == 0 and section == 0:
            imports.append(symbol)
        else:
            exports.append(symbol)
    return imports, exports


def _file_to_vm(offset: int, segments: list[dict[str, Any]]) -> int:
    for segment in segments:
        start, size = int(segment["paddr"]), int(segment["file_size"])
        if start <= offset < start + size:
            return int(segment["vaddr"]) + offset - start
    return offset


def _parse_thin(view: BinaryView) -> dict[str, Any]:
    magic = view.read(0, 4)
    if magic not in _THIN_MAGICS:
        raise ValueError("unsupported Mach-O magic")
    endian, endian_name, bits = _THIN_MAGICS[magic]
    fmt = f"{endian}IiiIIIII" if bits == 64 else f"{endian}IiiIIII"
    fields = view.unpack(fmt, 0)
    _, cpu, subtype, file_type, command_count, commands_size, flags = map(int, fields[:7])
    header_size = 32 if bits == 64 else 28
    if command_count > 65536 or header_size + commands_size > view.size:
        raise ValueError("Mach-O load commands extend outside the file")
    cursor = header_size
    segments: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    commands = []
    libraries = []
    symtab: tuple[int, int, int, int] | None = None
    uuid: str | None = None
    build_version: dict[str, Any] | None = None
    entry_offset: int | None = None
    signature: tuple[int, int] | None = None
    for _ in range(command_count):
        command, command_size = map(int, view.unpack(f"{endian}II", cursor))
        if command_size < 8 or cursor + command_size > header_size + commands_size:
            raise ValueError("invalid Mach-O load command size")
        base_command = command & 0x7FFFFFFF
        commands.append(
            {
                "command": _COMMANDS.get(base_command, f"{command:#x}"),
                "offset": cursor,
                "size": command_size,
            }
        )
        if base_command in {1, 0x19}:
            if base_command != (0x19 if bits == 64 else 1):
                raise ValueError("Mach-O segment command does not match header class")
            segment, segment_sections = _segment(view, endian, bits, cursor, command_size)
            segments.append(segment)
            sections.extend(segment_sections)
        elif base_command == 2:
            if command_size < 24:
                raise ValueError("truncated Mach-O symbol-table command")
            symbol_offset, symbol_count, string_offset, string_size = map(
                int, view.unpack(f"{endian}IIII", cursor + 8)
            )
            symtab = (symbol_offset, symbol_count, string_offset, string_size)
        elif base_command in _DYLIB_COMMANDS:
            if command_size < 12:
                raise ValueError("truncated Mach-O dylib command")
            name_offset = int(view.unpack(f"{endian}I", cursor + 8)[0])
            if not 8 <= name_offset < command_size:
                raise ValueError("invalid Mach-O dylib name offset")
            libraries.append(view.cstring(cursor + name_offset, limit=command_size - name_offset))
        elif base_command == 0x1B:
            if command_size < 24:
                raise ValueError("truncated Mach-O UUID command")
            uuid = str(UUID(bytes=view.read(cursor + 8, 16)))
        elif base_command == 0x32:
            if command_size < 24:
                raise ValueError("truncated Mach-O build-version command")
            platform, minimum, sdk, tool_count = map(int, view.unpack(f"{endian}IIII", cursor + 8))
            build_version = {
                "platform": platform,
                "minimum_os": _version(minimum),
                "sdk": _version(sdk),
                "tool_count": tool_count,
            }
        elif base_command == 0x28:
            if command_size < 24:
                raise ValueError("truncated Mach-O entry-point command")
            entry_offset = int(view.unpack(f"{endian}Q", cursor + 8)[0])
        elif base_command == 0x1D:
            if command_size < 16:
                raise ValueError("truncated Mach-O code-signature command")
            signature_offset, signature_size = map(int, view.unpack(f"{endian}II", cursor + 8))
            if signature_offset + signature_size > view.size:
                raise ValueError("Mach-O code signature extends outside the file")
            signature = (signature_offset, signature_size)
        cursor += command_size
    imports, exports = _symbols(view, endian, bits, symtab)
    imported_names = {str(item["name"]) for item in imports}
    content_ends = [
        *[int(item["paddr"]) + int(item["file_size"]) for item in segments],
        header_size + commands_size,
    ]
    if symtab:
        content_ends.append(symtab[2] + symtab[3])
    if signature:
        content_ends.append(signature[0] + signature[1])
    image_end = max(content_ends, default=0)
    security = {
        "pie": bool(flags & 0x200000),
        "nx": not bool(flags & 0x20000),
        "stack_canary": bool({"___stack_chk_fail", "__stack_chk_fail"} & imported_names),
        "canary": bool({"___stack_chk_fail", "__stack_chk_fail"} & imported_names),
        "code_signature": signature is not None,
    }
    return {
        "architecture": _architecture(int(cpu)),
        "cpu_subtype": int(subtype),
        "bits": bits,
        "endian": endian_name,
        "type": _FILE_TYPES.get(int(file_type), str(file_type)),
        "flags": flags,
        "entry_point": _file_to_vm(entry_offset, segments) if entry_offset is not None else 0,
        "image_base": min(
            (int(item["vaddr"]) for item in segments if item["file_size"]), default=0
        ),
        "build_id": uuid,
        "uuid": uuid,
        "build_version": build_version,
        "load_commands": commands,
        "segments": segments,
        "sections": sections,
        "libraries": libraries,
        "imports": imports,
        "exports": exports,
        "security_features": security,
        "signature_status": "present" if signature else "absent",
        "overlay": {"offset": image_end, "size": max(0, view.size - image_end)},
    }


def parse_macho(view: BinaryView) -> dict[str, Any]:
    magic = view.read(0, 4)
    fat = _FAT_MAGICS.get(magic)
    if fat is None:
        return _parse_thin(view)
    endian, bits = fat
    count = int(view.unpack(f"{endian}I", 4)[0])
    if not 0 < count <= 64:
        raise ValueError(f"invalid Mach-O fat architecture count: {count}")
    entry_size = 32 if bits == 64 else 20
    architectures = []
    slices = []
    for index in range(count):
        offset = 8 + index * entry_size
        if bits == 64:
            cpu, _, slice_offset, slice_size, _, _ = view.unpack(f"{endian}iiQQII", offset)
        else:
            cpu, _, slice_offset, slice_size, _ = view.unpack(f"{endian}iiIII", offset)
        architectures.append(_architecture(int(cpu)))
        slices.append((int(slice_offset), int(slice_size)))
    result = _parse_thin(view.subview(*slices[0]))
    result["universal"] = True
    result["architectures"] = architectures
    return result


__all__ = ["parse_macho"]
