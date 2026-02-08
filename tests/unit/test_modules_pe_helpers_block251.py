import types

from r2inspect.modules import pe_imports, pe_info, pe_info_domain, pe_resources, pe_security


class DummyAdapter:
    def __init__(self):
        self._file_info = {
            "bin": {
                "arch": "x86",
                "machine": "i386",
                "bits": 32,
                "endian": "little",
                "class": "PE32",
                "format": "PE",
                "baddr": 100,
                "boffset": 20,
                "type": "executable",
                "subsys": "Windows GUI",
                "compiled": "2025-01-01",
                "debug": True,
            }
        }
        self._headers = [
            {"name": "Signature", "value": 1},
            {"name": "Characteristics", "value": 0x2002},
            {"name": "Magic", "value": 0x10B},
            {"name": "DllCharacteristics", "value": 0x0140},
            {"name": "ImageBase", "value": 0x400000},
            {"name": "AddressOfEntryPoint", "value": 0x1000},
        ]

    def get_file_info(self):
        return self._file_info

    def get_headers_json(self):
        return self._headers

    def get_entry_info(self):
        return [{"vaddr": 1234}]

    def get_strings_text(self):
        return "Compiler: clang"

    def get_imports(self):
        return [
            {"libname": "KERNEL32.dll", "name": "CreateFileA"},
            {"libname": "KERNEL32.dll", "name": "CloseHandle"},
        ]


class DummyLogger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


def test_pe_info_and_characteristics():
    adapter = DummyAdapter()
    logger = DummyLogger()

    info = pe_info.get_pe_headers_info(adapter, None, logger)
    assert info["architecture"] == "x86"
    assert info["entry_point"] == 0x401000
    assert info["format"] == "PE"

    chars = pe_info.get_file_characteristics(adapter, None, logger)
    assert chars["has_debug"] is True
    assert chars["is_executable"] is True

    comp = pe_info.get_compilation_info(adapter, logger)
    assert comp["compile_time"] == "2025-01-01"
    assert "compiler" in comp["compiler_info"].lower()

    subsys = pe_info.get_subsystem_info(adapter, logger)
    assert subsys["subsystem"] == "Windows GUI"
    assert subsys["gui_app"] is True


def test_pe_imports_and_imphash():
    adapter = DummyAdapter()
    logger = DummyLogger()

    imports = pe_imports.fetch_imports(adapter)
    grouped = pe_imports.group_imports_by_library(imports)
    assert "KERNEL32.dll" in grouped

    normalized = pe_imports.normalize_library_name(b"KERNEL32.dll", ["dll"])
    assert normalized == "kernel32"

    imphash = pe_imports.calculate_imphash(adapter, logger)
    assert imphash

    assert pe_imports.compute_imphash(["a.b"]) != ""


def test_pe_security_and_resources():
    adapter = DummyAdapter()
    logger = DummyLogger()

    features = pe_security.get_security_features(adapter, logger)
    assert features["aslr"] is True
    assert features["dep"] is True

    # Force text fallback
    security_info = "DYNAMIC_BASE NX_COMPAT"
    features2 = {
        "aslr": False,
        "dep": False,
        "seh": False,
        "guard_cf": False,
        "authenticode": False,
    }
    pe_security._apply_security_flags_from_text(features2, security_info)
    assert features2["aslr"] is True
    assert features2["dep"] is True

    resources = pe_resources.get_resource_info(adapter, logger)
    assert isinstance(resources, list)

    version_info = pe_resources.get_version_info(adapter, logger)
    assert isinstance(version_info, dict)


def test_pe_info_domain_extras():
    flags = pe_info_domain.characteristics_from_bin({"type": "dll", "class": "pe"}, "file.dll")
    assert flags["is_dll"] is True

    subsys = pe_info_domain.build_subsystem_info("Console")
    assert subsys["gui_app"] is False
