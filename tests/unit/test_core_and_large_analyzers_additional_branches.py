from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


class DummyR2:
    def __init__(self, response: str = "ok", delay: float | None = None, fail: bool = False):
        self.response = response
        self.delay = delay
        self.fail = fail
        self.commands: list[str] = []
        self.quit_called = False

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("boom")
        return self.response

    def quit(self) -> None:
        self.quit_called = True


class FailingOpenSession(R2Session):
    def _open_with_timeout(self, flags: list[str], timeout: float) -> DummyR2:
        self.r2 = DummyR2()
        raise RuntimeError("open failed")


def _write_fat_macho(path: Path, endian: str, arches: list[int]) -> None:
    data = bytearray()
    magic = 0xCAFEBABE if endian == "big" else 0xBEBAFECA
    data += magic.to_bytes(4, "big")
    data += len(arches).to_bytes(4, endian)
    for cputype in arches:
        data += cputype.to_bytes(4, endian) + b"\x00" * 16
    path.write_bytes(data)


def test_r2_session_additional_branches(tmp_path: Path, monkeypatch) -> None:
    fat_path = tmp_path / "fat.bin"
    _write_fat_macho(fat_path, "big", [0x01000007, 0x0100000C])
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "1")
    monkeypatch.setattr("platform.machine", lambda: "arm64")

    session = R2Session(str(fat_path))
    flags = session._select_r2_flags()
    assert "-M" in flags
    assert "-NN" in flags
    assert "-a" in flags and "-b" in flags

    little_path = tmp_path / "fat_le.bin"
    _write_fat_macho(little_path, "little", [0x01000007])
    session_le = R2Session(str(little_path))
    assert session_le._detect_fat_macho_arches() == {"x86_64"}

    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"\x00")
    no_fat = R2Session(str(empty_path))
    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "true")
    flags_no_fat = no_fat._select_r2_flags()
    assert "-NN" in flags_no_fat


def test_r2_session_cmd_and_analysis_branches(monkeypatch) -> None:
    session = R2Session("/tmp/sample")
    session.r2 = DummyR2(response="short")
    session._cleanup_required = True

    assert session._run_cmd_with_timeout("i", 0.5) is True
    assert session._run_basic_info_check() is True

    session.r2 = DummyR2(delay=0.05)
    assert session._run_cmd_with_timeout("i", 0.001) is False

    session.r2 = DummyR2(fail=True)
    assert session._run_cmd_with_timeout("i", 0.1) is False

    session.r2 = DummyR2()
    monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "0")
    assert session._perform_initial_analysis(1.0) is True

    monkeypatch.delenv("R2INSPECT_ANALYSIS_DEPTH", raising=False)
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    assert session._perform_initial_analysis(6.0) is True

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "aa")
    assert session._perform_initial_analysis(1.0) is False

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "aaa")
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "0")
    session._test_mode = False
    assert session._perform_initial_analysis(0.1) is False

    session.r2 = None
    assert session._perform_initial_analysis(0.1) is True


def test_r2_session_open_exception_path() -> None:
    session = FailingOpenSession("/tmp/sample")
    assert session.open(file_size_mb=1.0) == ""
    assert session.r2 is not None


class FunctionAdapter:
    def __init__(self) -> None:
        self._functions_calls = 0

    def analyze_all(self) -> str:
        return "ok"

    def get_functions(self) -> list[dict[str, object]]:
        self._functions_calls += 1
        if self._functions_calls == 1:
            return []
        return [
            {"name": "main", "addr": 0x1000, "size": 12, "type": "func", "nbbs": 2},
            {"name": "libc_start", "addr": 0x2000, "size": 4, "type": "thunk"},
        ]

    def get_disasm(self, address: int | None = None, size: int | None = None) -> object:
        if size is None:
            return {"ops": [{"opcode": "mov eax, ebx"}, {"opcode": "ret"}]}
        if size == 3:
            return [{"opcode": "push eax"}, {"opcode": "pop ebx"}]
        return []

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        return "mov eax, ebx\nret"

    def get_cfg(self, address: int | None = None) -> list[dict[str, object]]:
        return [{"jump": 1}, {"fail": 2}]


def test_function_analyzer_branches() -> None:
    adapter = FunctionAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=None)
    functions = analyzer._get_functions()
    assert len(functions) == 2

    mnemonics = analyzer._extract_function_mnemonics("main", 12, 0x1000)
    assert "mov" in mnemonics

    pdj_mnemonics = analyzer._try_pdj_extraction("main", 12, 0x1000)
    assert "push" in pdj_mnemonics

    pi_mnemonics = analyzer._try_pi_extraction("main", 0x1000)
    assert "mov" in pi_mnemonics

    complexity = analyzer._calculate_cyclomatic_complexity({"addr": 0x1000})
    assert complexity >= 1

    stats = analyzer._generate_function_stats(functions)
    assert stats["total_functions"] == 2

    coverage = analyzer._analyze_function_coverage(functions)
    assert coverage["functions_with_blocks"] == 1

    assert analyzer._classify_function_type("j_thunk", {"size": 1}) == "thunk"
    assert analyzer._calculate_std_dev([1.0, 2.0, 3.0]) > 0.0

    hashes = analyzer._generate_machoc_hashes(functions)
    summary = analyzer.generate_machoc_summary({"machoc_hashes": hashes})
    assert "total_functions_hashed" in summary


class ResourceStub(ResourceAnalyzer):
    def __init__(self, command_map: dict[str, object]) -> None:
        super().__init__(adapter=None)
        self._command_map = command_map

    def _cmdj(self, command: str, default: object | None = None) -> object:
        value = self._command_map.get(command, default if default is not None else [])
        if isinstance(value, Exception):
            raise value
        return value


def _make_version_info_data() -> list[int]:
    data = bytearray(b"\x00" * 120)
    data[0:4] = bytes([0xBD, 0x04, 0xEF, 0xFE])
    key_bytes = "CompanyName".encode("utf-16le")
    start = 40
    data[start : start + len(key_bytes)] = key_bytes
    data[start + len(key_bytes) + 4 : start + len(key_bytes) + 12] = "ACME".encode("utf-16le")
    return list(data)


def test_resource_analyzer_branches() -> None:
    command_map = {
        "iDj": [{"name": "RESOURCE", "vaddr": 1, "paddr": 32, "size": 128}],
        "iRj": [
            {
                "name": "res",
                "type": "RT_MANIFEST",
                "type_id": 24,
                "lang": "en",
                "paddr": 64,
                "size": 64,
                "vaddr": 100,
            },
            {
                "name": "ver",
                "type": "RT_VERSION",
                "type_id": 16,
                "lang": "en",
                "paddr": 200,
                "size": 128,
                "vaddr": 300,
            },
        ],
        "pxj 6 @ 64": list(b"M\x00A\x00Z\x00"),
        "pxj 64 @ 64": list(b"M\x00A\x00Z\x00"),
        "pxj 128 @ 200": _make_version_info_data(),
        "pxj 2 @ 200": [0x4D, 0x5A],
    }
    analyzer = ResourceStub(command_map)
    result = analyzer.analyze()
    assert result["has_resources"] is True
    assert result["resource_directory"]["offset"] == 32
    assert result["manifest"] is not None

    # Manual parsing fallback
    manual_map = {
        "iDj": [{"name": "RESOURCE", "vaddr": 1, "paddr": 32, "size": 64}],
        "iRj": RuntimeError("boom"),
        "iSj": [{"name": ".rsrc", "paddr": 32}],
        "pxj 16 @ 32": [0] * 12 + [1, 0, 0, 0],
        "pxj 8 @ 48": [1, 0, 0, 0, 64, 0, 0, 0],
        "pxj 2 @ 96": [0x4D, 0x5A],
    }
    manual = ResourceStub(manual_map)
    parsed = manual._parse_resources_manual()
    assert parsed

    assert analyzer._get_resource_type_name(999).startswith("UNKNOWN_")
    assert analyzer._is_valid_dir_header([0] * 16) is True
    assert analyzer._get_dir_total_entries([0] * 12 + [1, 0, 1, 0]) == 2
    assert analyzer._find_pattern([1, 2, 3], [2, 3]) == 1

    string_val = analyzer._read_resource_as_string(64, 6)
    assert string_val

    entropy_hits = analyzer._check_resource_entropy(
        {"entropy": 8.0, "type_name": "RT_RCDATA", "name": "r", "size": 10}
    )
    assert entropy_hits


class AuthAdapter:
    def __init__(self, command_map: dict[str, object]) -> None:
        self._command_map = command_map

    def get_headers_json(self) -> object:
        return self._command_map.get("ihj", {})

    def get_pe_optional_header(self) -> object:
        return self._command_map.get("iHj", {})

    def get_data_directories(self) -> object:
        return self._command_map.get("iDj", [])

    def read_bytes_list(self, address: int, size: int) -> object:
        return self._command_map.get(f"pxj {size} @ {address}", [])

    def get_file_info(self) -> object:
        return self._command_map.get("ij", {})


def test_authenticode_analyzer_branches() -> None:
    analyzer = AuthenticodeAnalyzer(AuthAdapter({"ihj": {}}))
    result = analyzer.analyze()
    assert result["available"] is False

    pkcs7_data = [
        0x55,
        0x04,
        0x03,
        0x00,
        0x04,
        ord("T"),
        ord("e"),
        ord("s"),
        ord("t"),
    ]
    pkcs7_data += [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    pkcs7_data += [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    pkcs7_data += [
        0x2A,
        0x86,
        0x48,
        0x86,
        0xF7,
        0x0D,
        0x01,
        0x09,
        0x10,
        0x02,
        0x0E,
    ]

    auth_map = {
        "ihj": {"pe": True},
        "iHj": {"optional": True},
        "iDj": [{"name": "SECURITY", "vaddr": 1, "paddr": 100, "size": 32}],
        "pxj 8 @ 100": [16, 0, 0, 0, 2, 0, 2, 0],
        "pxj 24 @ 108": pkcs7_data,
        "ij": {"core": {"size": 512}},
    }
    analyzer2 = AuthenticodeAnalyzer(AuthAdapter(auth_map))
    result2 = analyzer2.analyze()
    assert result2["has_signature"] is True
    assert result2["signature_valid"] is True

    assert analyzer2._get_cert_type_name(0x9999).startswith("UNKNOWN")
    assert analyzer2._verify_signature_integrity({"has_signature": False}) is False


class MitigationAdapter:
    def __init__(self, command_map: dict[str, object]) -> None:
        self._command_map = command_map

    def get_pe_optional_header(self) -> object:
        return self._command_map.get("iHj", {})

    def get_data_directories(self) -> object:
        return self._command_map.get("iDj", [])

    def read_bytes_list(self, address: int, size: int) -> object:
        return self._command_map.get(f"pxj {size} @ {address}", [])

    def get_imports(self) -> object:
        return self._command_map.get("iij", [])

    def get_strings(self) -> object:
        return self._command_map.get("izzj", [])

    def get_sections(self) -> object:
        return self._command_map.get("iSj", [])

    def get_headers_json(self) -> object:
        return self._command_map.get("ihj", {})


def _load_config_bytes(size: int, guard_flags: int) -> list[int]:
    data = [0] * size
    data[0:4] = [size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF, (size >> 24) & 0xFF]
    data[60:64] = [0x10, 0, 0, 0]
    data[140:144] = [
        guard_flags & 0xFF,
        (guard_flags >> 8) & 0xFF,
        (guard_flags >> 16) & 0xFF,
        (guard_flags >> 24) & 0xFF,
    ]
    return data


def test_exploit_mitigation_analyzer_branches() -> None:
    optional_header = {
        "dll_characteristics": 0x0040 | 0x0100 | 0x4000,
        "entry_point": 0x1200,
        "image_base": 0x1000,
        "subsystem": "Windows GUI",
    }
    load_config = _load_config_bytes(160, 0x100 | 0x20000 | 0x40000)
    adapter = MitigationAdapter(
        {
            "iHj": optional_header,
            "iDj": [
                {"name": "LOAD_CONFIG", "vaddr": 1, "paddr": 200, "size": len(load_config)},
                {"name": "SECURITY", "vaddr": 1, "paddr": 400, "size": 10},
            ],
            "pxj 256 @ 200": load_config,
            "pxj 64 @ 200": load_config[:64],
            "iij": [{"name": "__security_cookie"}],
            "izzj": [{"string": "__GSHandlerCheck"}],
            "iSj": [{"vaddr": 0x3000, "vsize": 0x100, "perm": "r--"}],
            "ihj": {"characteristics": 0x2001},
        }
    )
    analyzer = ExploitMitigationAnalyzer(adapter)
    result = analyzer.analyze()
    assert result["mitigations"]["ASLR"]["enabled"] is True
    assert result["mitigations"]["CFG"]["enabled"] is True
    assert result["recommendations"]

    no_dirs = MitigationAdapter({"iHj": {}, "iDj": []})
    analyzer2 = ExploitMitigationAnalyzer(no_dirs)
    result2 = analyzer2.analyze()
    assert result2["mitigations"]["Authenticode"]["enabled"] is False


class RichAdapter:
    def __init__(self, info_text: str, file_info: dict[str, object]) -> None:
        self._info_text = info_text
        self._file_info = file_info

    def get_info_text(self) -> str:
        return self._info_text

    def get_file_info(self) -> dict[str, object]:
        return self._file_info

    def read_bytes(self, address: int, size: int) -> bytes:
        return b"Rich" + b"\x00" * 10


def test_rich_header_helper_branches(tmp_path: Path) -> None:
    mz_path = tmp_path / "mz.bin"
    mz_path.write_bytes(b"MZ" + b"\x00" * 100)
    analyzer = RichHeaderAnalyzer(adapter=object(), filepath=str(mz_path))
    assert analyzer._is_pe_file() is True

    non_mz = tmp_path / "non_mz.bin"
    non_mz.write_bytes(b"\x00" * 100)
    adapter = RichAdapter("PE32", {"bin": {"format": "pe", "class": ""}})
    analyzer2 = RichHeaderAnalyzer(adapter=adapter, filepath=str(non_mz))
    assert analyzer2._is_pe_file() is True

    assert analyzer2._bin_info_has_pe({"format": "pe", "class": ""}) is True
    assert analyzer2._bin_info_has_pe({"format": "", "class": "pe32"}) is True
    assert analyzer2._bin_info_has_pe({"format": "", "class": ""}) is False

    stub = b"AAAA" + b"DanS" + b"\x00" * 8 + b"Rich" + b"\x01\x00\x00\x00"
    rich_pos = analyzer2._find_rich_pos(stub)
    assert rich_pos is not None
    xor_key = analyzer2._extract_xor_key_from_stub(stub, rich_pos)
    assert xor_key == 1

    dans_pos = analyzer2._find_or_estimate_dans(stub, rich_pos)
    assert dans_pos is not None
    encoded = analyzer2._extract_encoded_from_stub(stub, dans_pos, rich_pos)
    assert encoded is not None

    assert analyzer2._find_all_occurrences(b"RichRich", b"Rich") == [0, 4]
    assert analyzer2._find_rich_positions(b"xxRichxxxxxx") == [2]
    assert analyzer2._is_valid_rich_key(b"Rich\x01\x00\x00\x00", 0) is True
    assert analyzer2._find_dans_before_rich(b"DanSRich", 4) == 0
