import hashlib

from r2inspect.modules.elf_analyzer import ELFAnalyzer
from r2inspect.modules.macho_analyzer import MachOAnalyzer
from r2inspect.modules.pe_analyzer import PEAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class DummyConfig:
    analyze_authenticode = False
    analyze_overlay = False
    analyze_resources = False
    analyze_mitigations = False


def test_pe_determine_format():
    pe = PEAnalyzer(FakeR2(), DummyConfig(), filepath="sample.exe")
    assert pe._determine_pe_format({"format": "PE32"}, None) == "PE32"
    assert pe._determine_pe_format({"format": "Unknown", "bits": 64}, None) == "PE32+"
    assert pe._determine_pe_format({"format": "Unknown", "bits": 32}, None) == "PE32"
    pe_header = {"optional_header": {"Magic": 0x10B}}
    assert pe._determine_pe_format({"format": "Unknown", "bits": 0}, pe_header) == "PE32"


def test_pe_calculate_imphash():
    imports = [
        {"libname": "KERNEL32.dll", "name": "CreateFileA"},
        {"libname": "KERNEL32.dll", "name": "ReadFile"},
        {"libname": "USER32.DLL", "name": "MessageBoxA"},
    ]
    r2 = FakeR2(cmdj_map={"iij": imports})
    pe = PEAnalyzer(r2, DummyConfig(), filepath="sample.exe")

    expected_strings = [
        "kernel32.createfilea",
        "kernel32.readfile",
        "user32.messageboxa",
    ]
    expected = hashlib.md5(
        ",".join(expected_strings).encode("utf-8"), usedforsecurity=False
    ).hexdigest()

    assert pe.calculate_imphash() == expected


def test_pe_security_features_from_header():
    ihj = [
        {"name": "DllCharacteristics", "value": 0x0040 | 0x0100 | 0x4000},
    ]
    r2 = FakeR2(cmdj_map={"ihj": ihj})
    pe = PEAnalyzer(r2, DummyConfig(), filepath="sample.exe")

    features = pe.get_security_features()
    assert features["aslr"] is True
    assert features["dep"] is True
    assert features["guard_cf"] is True
    assert features["seh"] is True
    assert features["authenticode"] is False


def test_elf_security_features():
    ihj = [{"type": "GNU_STACK", "flags": "rw"}]
    r2 = FakeR2(
        cmd_map={"id": "BIND_NOW\nRPATH\nRUNPATH"},
        cmdj_map={
            "ihj": ihj,
            "isj": [{"name": "__stack_chk_fail"}],
            "ij": {"bin": {"class": "DYN"}},
        },
    )
    elf = ELFAnalyzer(r2, DummyConfig())

    features = elf.get_security_features()
    assert features["nx"] is True
    assert features["stack_canary"] is True
    assert features["relro"] is True
    assert features["pie"] is True
    assert features["rpath"] is True
    assert features["runpath"] is True


def test_elf_parse_comment_compiler_info():
    elf = ELFAnalyzer(FakeR2(), DummyConfig())
    gcc_info = elf._parse_comment_compiler_info("GCC: (GNU) 9.3.0")
    assert gcc_info["compiler"] == "GCC 9.3.0"
    assert gcc_info["compiler_version"] == "9.3.0"

    clang_info = elf._parse_comment_compiler_info("clang version 15.0.0")
    assert clang_info["compiler"] == "Clang 15.0.0"


def test_macho_security_features():
    headers = [
        {"type": "LC_ENCRYPTION_INFO", "cryptid": 1},
        {"type": "LC_CODE_SIGNATURE"},
    ]
    r2 = FakeR2(
        cmdj_map={
            "ij": {"bin": {"filetype": "PIE"}},
            "isj": [
                {"name": "___stack_chk_fail"},
                {"name": "_objc_retain"},
            ],
            "ihj": headers,
        }
    )
    macho = MachOAnalyzer(r2, DummyConfig())

    features = macho.get_security_features()
    assert features["pie"] is True
    assert features["stack_canary"] is True
    assert features["arc"] is True
    assert features["encrypted"] is True
    assert features["signed"] is True
    assert features["nx"] is True


def test_macho_estimate_from_sdk_version():
    macho = MachOAnalyzer(FakeR2(), DummyConfig())
    assert macho._estimate_from_sdk_version("13.0") == "~2022 (SDK 13.0)"
