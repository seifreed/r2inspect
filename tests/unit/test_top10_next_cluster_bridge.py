"""Bridge tests for next top-10 low-coverage modules."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import pytest

from r2inspect.adapters import r2pipe_queries
from r2inspect.adapters import validation as validation_mod
from r2inspect.cli import display_base
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.import_analyzer import ImportAnalyzer
from r2inspect.modules.pe_info import (
    _extract_compiler_info,
    _get_entry_info,
    get_compilation_info,
    get_file_characteristics,
    get_pe_headers_info,
    get_subsystem_info,
)
from r2inspect.domain.formats.pe_info import (
    apply_optional_header_info,
    build_subsystem_info,
    characteristics_from_bin,
    characteristics_from_header,
    compute_entry_point,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
    normalize_resource_entries,
    parse_version_info_text,
)
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.cli.output_formatters import OutputFormatter

_UNSET = object()


class _DummyQuery(r2pipe_queries.R2PipeQueryMixin):
    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}
        self.forced: set[str] = set()
        self._fake: Any = None

    @property
    def _r2_iface(self) -> Any:
        return self._fake

    def _cached_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"] = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        if "raise_cached" in self.forced:
            raise RuntimeError("cached fail")
        if data_type == "dict":
            return {"cmd": cmd}
        return [{"cmd": cmd}]

    def _maybe_force_error(self, method: str) -> None:
        if method in self.forced:
            raise RuntimeError(f"forced:{method}")


class _PEImpfuzzy(ImpfuzzyAnalyzer):
    """Impfuzzy double: each hook falls through to the real implementation
    unless its instance attribute is set (so the real _extract_imports /
    _process_imports paths can still be exercised via a scripted _cmdj)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pe: Any = _UNSET
        self.extracted: Any = _UNSET
        self.processed: Any = _UNSET
        self.cmdj_value: Any = _UNSET
        self.cmdj_raises = False

    def _is_pe_file(self) -> bool:
        if self.pe is _UNSET:
            return super()._is_pe_file()
        return bool(self.pe)

    def _extract_imports(self) -> list[dict[str, Any]]:
        if self.extracted is _UNSET:
            return super()._extract_imports()
        return list(self.extracted)

    def _process_imports(self, imports_data: list[dict[str, Any]]) -> list[str]:
        if self.processed is _UNSET:
            return super()._process_imports(imports_data)
        return list(self.processed)

    def _cmdj(self, *args: Any, **kwargs: Any) -> Any:
        if self.cmdj_raises:
            raise RuntimeError("x")
        if self.cmdj_value is _UNSET:
            return super()._cmdj(*args, **kwargs)
        return self.cmdj_value


class _ExportDouble(ExportAnalyzer):
    cmd_list_value: Any = _UNSET
    exports_value: Any = _UNSET
    exports_raises = False

    def _cmd_list(self, command: str) -> Any:
        if self.cmd_list_value is _UNSET:
            return super()._cmd_list(command)
        return self.cmd_list_value

    def get_exports(self) -> Any:
        if self.exports_raises:
            raise RuntimeError("x")
        if self.exports_value is _UNSET:
            return super().get_exports()
        return self.exports_value


class _ImportDouble(ImportAnalyzer):
    cmdj_raises = False
    risk_raises = False
    imports_value: Any = _UNSET

    def _cmdj(self, *args: Any, **kwargs: Any) -> Any:
        if self.cmdj_raises:
            raise RuntimeError("x")
        return super()._cmdj(*args, **kwargs)

    def _calculate_risk_score(self, name: str) -> Any:
        if self.risk_raises:
            raise RuntimeError("x")
        return super()._calculate_risk_score(name)

    def get_imports(self) -> Any:
        if self.imports_value is _UNSET:
            return super().get_imports()
        return self.imports_value


class _CsvFailFormatter(OutputFormatter):
    def _extract_csv_data(self, data: Any) -> Any:
        raise RuntimeError("csv fail")


class _ResourceDouble(ResourceAnalyzer):
    cmdj_value: Any = _UNSET
    cmdj_raises = False
    resource_string: Any = _UNSET
    resource_string_raises = False

    def _cmdj(self, cmd: Any = None, default: Any = None) -> Any:
        if self.cmdj_raises:
            raise RuntimeError("x")
        if self.cmdj_value is _UNSET:
            return super()._cmdj(cmd, default)
        value = self.cmdj_value
        if callable(value):
            return value(cmd, default)
        return value

    def _read_resource_as_string(self, *args: Any, **kwargs: Any) -> Any:
        if self.resource_string_raises:
            raise RuntimeError("x")
        if self.resource_string is _UNSET:
            return super()._read_resource_as_string(*args, **kwargs)
        return self.resource_string


class _DummyYA:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def list_available_rules(self, _p: str) -> list[dict[str, Any]]:
        return [{"name": "a.yar", "size": 1, "path": "/tmp/a.yar", "relative_path": "a.yar"}]


def test_impfuzzy_analyzer_paths(tmp_path: Path) -> None:
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    analyzer = _PEImpfuzzy(adapter=SimpleNamespace(), filepath=str(sample))

    ok, msg = analyzer._check_library_availability(available_fn=lambda: False)
    assert ok is False and "pyimpfuzzy" in str(msg)
    assert analyzer._check_library_availability(available_fn=lambda: True) == (True, None)

    analyzer.pe = False
    assert analyzer._calculate_hash()[2] == "File is not a PE binary"

    analyzer.pe = True
    assert analyzer._calculate_hash(
        pyimpfuzzy_mod=SimpleNamespace(get_impfuzzy=lambda _p: "h")
    ) == ("h", "python_library", None)
    assert "No imports found" in str(
        analyzer._calculate_hash(pyimpfuzzy_mod=SimpleNamespace(get_impfuzzy=lambda _p: ""))[2]
    )

    assert analyzer.analyze_imports(impfuzzy_available=False)["available"] is False
    analyzer.pe = False
    assert (
        analyzer.analyze_imports(impfuzzy_available=True)["error"] == "File is not a PE binary"
    )

    analyzer.pe = True
    analyzer.extracted = []
    assert "No imports found" in str(analyzer.analyze_imports(impfuzzy_available=True)["error"])

    analyzer.extracted = [{"libname": "KERNEL32.dll", "name": "CreateFileA"}]
    analyzer.processed = []
    assert "No valid imports" in str(analyzer.analyze_imports(impfuzzy_available=True)["error"])

    analyzer.processed = ["kernel32.createfilea"]
    assert "Failed to calculate" in str(
        analyzer.analyze_imports(
            impfuzzy_available=True,
            pyimpfuzzy_mod=SimpleNamespace(get_impfuzzy=lambda _p: ""),
        )["error"]
    )

    success = analyzer.analyze_imports(
        impfuzzy_available=True,
        pyimpfuzzy_mod=SimpleNamespace(get_impfuzzy=lambda _p: "abc"),
    )
    assert success["available"] is True and success["dll_count"] == 1

    analyzer2 = _PEImpfuzzy(adapter=SimpleNamespace(), filepath=str(sample))
    analyzer2.cmdj_value = {"name": "A", "libname": "K.dll"}
    assert analyzer2._extract_imports() == [{"name": "A", "libname": "K.dll"}]
    analyzer2.cmdj_value = []
    analyzer2.adapter = None
    assert analyzer2._extract_imports() == []
    analyzer2.cmdj_value = "not-a-list-or-dict"
    assert analyzer2._extract_imports() == []
    analyzer2.cmdj_value = _UNSET
    analyzer2.cmdj_raises = True
    assert analyzer2._extract_imports() == []

    processed = ImpfuzzyAnalyzer(
        adapter=SimpleNamespace(), filepath=str(sample)
    )._process_imports(
        [
            {"libname": "KERNEL32.dll", "name": "CreateFileA"},
            {"libname": "KERNEL32.dll", "name": "ord_1"},
            "bad",
        ]
    )
    assert processed == ["kernel32.createfilea"]
    assert ImpfuzzyAnalyzer.compare_hashes("", "x") is None

    assert (
        ImpfuzzyAnalyzer.compare_hashes(
            "a", "b", impfuzzy_available=True, get_ssdeep_fn=lambda: None
        )
        is None
    )
    assert (
        ImpfuzzyAnalyzer.compare_hashes(
            "a",
            "b",
            impfuzzy_available=True,
            get_ssdeep_fn=lambda: SimpleNamespace(
                compare=lambda _a, _b: (_ for _ in ()).throw(RuntimeError("x"))
            ),
        )
        is None
    )
    assert (
        ImpfuzzyAnalyzer.compare_hashes(
            "a",
            "b",
            impfuzzy_available=True,
            get_ssdeep_fn=lambda: SimpleNamespace(compare=lambda _a, _b: 73),
        )
        == 73
    )

    assert (
        ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(str(sample), impfuzzy_available=False)
        is None
    )
    assert (
        ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(
            str(sample),
            impfuzzy_available=True,
            pyimpfuzzy_mod=SimpleNamespace(get_impfuzzy=lambda _p: "ok"),
        )
        == "ok"
    )


def test_validation_paths() -> None:
    class BadBytes(bytes):
        def decode(self, *_a: Any, **_k: Any) -> str:
            raise RuntimeError("decode fail")

    class BadStr(str):
        def encode(self, *_a: Any, **_k: Any) -> bytes:
            raise RuntimeError("encode fail")

    assert validation_mod.validate_r2_data({}, "dict") == {}
    assert validation_mod.validate_r2_data([], "list") == []
    assert validation_mod.validate_r2_data("x", "str") == "x"
    assert validation_mod.validate_r2_data(BadBytes(b"x"), "str") == ""
    assert validation_mod.validate_r2_data(BadStr("x"), "bytes") == b""
    assert validation_mod.validate_r2_data("v", "unknown") == "v"
    assert validation_mod.sanitize_r2_output("") == ""
    assert validation_mod.sanitize_r2_output("\x1b[31mA&amp;\n") == "A&"

    assert validation_mod.is_valid_r2_response(None) is False
    assert validation_mod.is_valid_r2_response({}) is False
    assert validation_mod.is_valid_r2_response("Error: nope") is False
    assert validation_mod.is_valid_r2_response(b"x") is True

    with pytest.raises(ValueError):
        validation_mod.validate_address(-1)
    with pytest.raises(ValueError):
        validation_mod.validate_address("abc")
    with pytest.raises(ValueError):
        validation_mod.validate_size(0)
    with pytest.raises(ValueError):
        validation_mod.validate_size("bad")


def test_export_and_import_analyzers_paths() -> None:
    exp = _ExportDouble(adapter=SimpleNamespace())
    assert exp.get_category() == "metadata"
    assert exp.supports_format("dll")
    exp.cmd_list_value = [{"name": "DllRun", "vaddr": 1}, "bad"]
    exports = exp.get_exports()
    assert len(exports) == 1
    ch = exp._get_export_characteristics({"name": "DllInstall", "vaddr": 2})
    assert ch.get("dll_export") is True
    exp.cmd_list_value = [123]
    assert exp._get_export_characteristics({"name": "x", "vaddr": 3}).get("is_function") is False
    exp.exports_value = [
        {
            "name": "a",
            "is_forwarded": True,
            "characteristics": {"is_function": True, "suspicious_name": True},
        },
        "bad",
    ]
    stats = exp.get_export_statistics()
    assert stats["forwarded_exports"] == 1 and stats["suspicious_exports"] == 1
    exp.exports_value = _UNSET
    exp.exports_raises = True
    assert exp.get_export_statistics()["total_exports"] == 0

    imp = _ImportDouble(adapter=SimpleNamespace())
    assert imp.get_category() == "metadata"
    assert imp.supports_format("PE32")
    result = imp.analyze()
    assert "statistics" in result
    imp.cmdj_raises = True
    assert imp.get_imports() == []
    imp.cmdj_raises = False
    imp.risk_raises = True
    assert "error" in imp._analyze_import({"name": "A"})
    imp.risk_raises = False
    imp.imports_value = [
        {"category": "X", "risk_level": "Low", "library": "k", "name": "CreateFileA"}
    ]
    stats2 = imp.get_import_statistics()
    assert stats2["total_imports"] == 1
    imp.imports_value = []
    imp.adapter = SimpleNamespace(get_strings=lambda: [{"string": "CreateFileA"}])
    assert "CreateFileA" in imp.get_missing_imports()
    assert (
        imp.analyze_api_usage(
            [{"name": "A"}],
            categorize_fn=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x")),
        )["risk_score"]
        == 0
    )


def test_output_and_display_base_paths() -> None:
    fmt = _CsvFailFormatter(
        {"file_info": {"name": "a", "size": 1, "file_type": "PE", "md5": "m"}}
    )
    assert "CSV Export Failed" in fmt.to_csv()
    assert fmt._flatten_results({"a": [1]})[-1]["field"] == "a[0]"
    tbl = fmt.format_imports(
        [
            {
                "name": "a",
                "library": "k",
                "category": "c",
                "risk_score": 90,
                "risk_level": "Critical",
                "risk_tags": ["x", "y", "z"],
            },
            {
                "name": "b",
                "library": "k",
                "category": "c",
                "risk_score": 60,
                "risk_level": "High",
                "risk_tags": [],
            },
            {
                "name": "c",
                "library": "k",
                "category": "c",
                "risk_score": 40,
                "risk_level": "Medium",
                "risk_tags": [],
            },
            {
                "name": "d",
                "library": "k",
                "category": "c",
                "risk_score": 20,
                "risk_level": "Low",
                "risk_tags": [],
            },
        ]
    )
    assert tbl is not None
    fmt2 = OutputFormatter(
        {
            "indicators": [{"type": "a", "description": "d"}] * 6,
            "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 0.5},
            "yara_matches": [{"rule": "R"}],
        }
    )
    assert "and 1 more" in fmt2.format_summary()

    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("a" * 40, max_length=4).endswith("...")

    display_base.handle_list_yara_option({}, None, yara_analyzer_cls=_DummyYA)
    display_base.display_validation_errors(["x"])
    display_base.display_error_statistics(
        {
            "total_errors": 1,
            "recent_errors": 1,
            "recovery_strategies_available": 1,
            "errors_by_category": {"io_error": 1},
            "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
        }
    )


def test_r2pipe_queries_paths() -> None:
    q = _DummyQuery()
    assert q.get_file_info() == {}
    assert q.get_sections() == [{"cmd": "iSj"}]

    q.forced.add("get_functions_at")
    assert q.get_functions_at(0x10) == []
    q.forced.clear()

    q._fake = SimpleNamespace(cmdj=lambda _c: [{"h": 1}], cmd=lambda _c: "")
    assert q.get_pe_header() == {"headers": [{"h": 1}]}
    q._fake = SimpleNamespace(cmdj=lambda _c: {"h": 1}, cmd=lambda _c: "")
    assert q.get_pe_header() == {"h": 1}
    q._fake = SimpleNamespace(cmdj=lambda _c: "x", cmd=lambda _c: "")
    assert q.get_pe_header() == {}

    q._fake = SimpleNamespace(cmdj=lambda _c: [{"r": 1}], cmd=lambda _c: "")
    assert q.get_resources_info() == [{"r": 1}]

    q._fake = SimpleNamespace(cmdj=lambda _c: None, cmd=lambda _c: "not-hex")
    assert q.read_bytes(1, 4) == b""
    with pytest.raises(ValueError):
        q.read_bytes(-1, 1)
    # An empty command response also yields b"" (same contract as a failed
    # address validation) without patching the validator.
    q._fake = SimpleNamespace(cmdj=lambda _c: None, cmd=lambda _c: "")
    assert q.read_bytes(1, 1) == b""


def test_pe_info_domain_and_pe_info_paths(tmp_path: Path) -> None:
    assert determine_pe_file_type({"class": "PE32"}, None, "dll file") == "DLL"
    assert determine_pe_file_type({"class": "PE32"}, None, "portable executable") == "EXE"
    assert determine_pe_file_type({"class": "PE32"}, None, "kernel driver sys") == "SYS"
    assert determine_pe_format({"bits": 32}, None) == "PE32"
    assert determine_pe_format({"bits": 64}, None) == "PE32+"
    assert determine_pe_format({"bits": 0}, {"optional_header": {"Magic": 0x10B}}) == "PE32"
    assert normalize_pe_format("Unknown") == "PE"
    assert compute_entry_point({"baddr": 1, "boffset": 2}, [{"vaddr": 99}]) == 99
    assert apply_optional_header_info({"image_base": 0}, None)["image_base"] == 0
    assert characteristics_from_header({"file_header": {"Characteristics": "x"}}) is None
    assert normalize_resource_entries([{}])[0]["name"] == "Unknown"
    assert parse_version_info_text("A=B") == {"A": "B"}
    assert characteristics_from_bin({"type": "dll", "class": ""}, "a.dll")["is_dll"] is True
    assert build_subsystem_info("console")["gui_app"] is False

    logger = SimpleNamespace(error=lambda *_a, **_k: None, debug=lambda *_a, **_k: None)
    adapter = SimpleNamespace(
        get_file_info=lambda: {
            "bin": {
                "arch": "x86",
                "machine": "i386",
                "bits": 32,
                "endian": "little",
                "baddr": 1,
                "boffset": 2,
                "format": "PE32",
            }
        },
        get_entry_info=lambda: [{"vaddr": 123}],
        get_strings_text=lambda: "compiler: x",
    )
    info = get_pe_headers_info(adapter, str(tmp_path / "x.exe"), logger)
    assert info["entry_point"] == 123
    assert _extract_compiler_info(adapter) == "compiler: x"
    assert (
        _get_entry_info(
            SimpleNamespace(get_entry_info=lambda: (_ for _ in ()).throw(RuntimeError("x"))), logger
        )
        is None
    )
    assert get_compilation_info(adapter, logger).get("compiler_info") == "compiler: x"
    assert "subsystem" in get_subsystem_info(
        SimpleNamespace(get_file_info=lambda: {"bin": {"subsys": "Windows GUI"}}), logger
    )

    err_adapter = SimpleNamespace(get_file_info=lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert get_pe_headers_info(err_adapter, None, logger) == {}
    assert get_file_characteristics(err_adapter, None, logger) == {}


def test_resource_analyzer_paths() -> None:
    ra = _ResourceDouble(adapter=SimpleNamespace())
    ra.cmdj_raises = True
    assert ra._parse_resources() == []
    ra.cmdj_raises = False

    cmd_map: dict[str, Any] = {
        "iSj": [{"name": ".rsrc", "paddr": 0}],
    }
    ra.cmdj_value = lambda cmd, default=None: cmd_map.get(cmd, default)
    assert ra._parse_resources_manual() == []

    data = [0] * 80
    data[16:20] = [0xBD, 0x04, 0xEF, 0xFE]
    data[24:28] = [1, 0, 2, 0]
    data[28:32] = [3, 0, 4, 0]
    # key "FileVersion" utf-16le + 4 pad + value "1.2"
    key = list("FileVersion".encode("utf-16le"))
    val = list("1.2".encode("utf-16le")) + [0, 0]
    pos = 40
    data[pos : pos + len(key)] = key
    data[pos + len(key) + 4 : pos + len(key) + 4 + len(val)] = val
    ra.cmdj_value = data
    parsed = ra._parse_version_info(1, 100)
    assert parsed and parsed["file_version"]
    assert parsed["strings"].get("FileVersion") == "1.2"

    resources = [{"type_name": "RT_MANIFEST", "offset": 1, "size": 10}]
    ra.resource_string = "requireAdministrator dpiAware"
    out: dict[str, Any] = {}
    ra._extract_manifest(out, resources)
    assert out["manifest"]["requires_admin"] is True

    ra.resource_string = _UNSET
    ra.resource_string_raises = True
    out2: dict[str, Any] = {}
    ra._extract_manifest(out2, resources)

    res_strings = [{"type_name": "RT_STRING", "offset": 1, "size": 10}]
    ra._extract_strings(out2, res_strings)
