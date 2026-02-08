from r2inspect.modules import import_domain
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.import_analyzer import ImportAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.section_analyzer import SectionAnalyzer


class DummyConfig:
    def __init__(self):
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.analysis = type("Analysis", (), {})()
        self.typed_config.analysis.deep_analysis = False


class DummyAdapter:
    def get_imports(self):
        return [
            {"name": "CreateRemoteThread", "libname": "KERNEL32.dll", "plt": 1},
            {"name": "VirtualAlloc", "libname": "KERNEL32.dll", "plt": 2},
        ]

    def get_exports(self):
        return [
            {"name": "DllMain", "vaddr": 1, "ordinal": 1, "type": "func", "size": 10},
        ]

    def get_sections(self):
        return [
            {"name": ".text", "vaddr": 0, "vsize": 10, "size": 10, "flags": "r-x"},
            {"name": ".data", "vaddr": 10, "vsize": 5, "size": 5, "flags": "rw-"},
        ]

    def get_symbols(self):
        return [{"name": "main"}]

    def get_strings(self):
        return [{"string": "http://example.com", "vaddr": 1}]

    def get_disasm(self, address=None, size=None):
        return {"ops": [{"opcode": "mov eax, ebx"}, {"opcode": "ret"}]}

    def get_cfg(self, _addr):
        return {"blocks": [{"type": "code"}, {"type": "code"}]}

    def get_data_directories(self):
        return [{"name": "RESOURCE", "vaddr": 1, "paddr": 2, "size": 10}]

    def get_resources_info(self):
        return [
            {"name": "1", "type": "ICON", "size": 4, "lang": "en", "address": 1},
            {"name": "2", "type": "VERSION", "size": 4, "lang": "en", "address": 2},
        ]

    def read_bytes(self, _addr, size):
        return bytes([0, 1, 2, 3])[:size]


def test_import_domain_helpers():
    categories = import_domain.build_api_categories()
    imports = [{"name": "CreateRemoteThread", "category": "Process/Thread Management"}]
    categorized = import_domain.categorize_apis(
        imports, {"Process/Thread Management": ["CreateRemoteThread"]}
    )
    assert categorized["Process/Thread Management"]["count"] == 1

    suspicious, score = import_domain.assess_api_risk({"Anti-Analysis": {"count": 2}})
    assert suspicious
    assert score >= 0

    patterns = import_domain.find_suspicious_patterns(
        [
            {"name": "CreateRemoteThread"},
            {"name": "VirtualAllocEx"},
            {"name": "WriteProcessMemory"},
        ]
    )
    assert patterns

    counts = import_domain.count_import_categories(imports)
    assert counts["Process/Thread Management"] == 1

    max_score, tags = import_domain.find_max_risk_score("CreateRemoteThread", categories)
    assert max_score > 0
    assert tags

    assert import_domain.risk_level_from_score(80) == "Critical"


def test_import_export_section_resource_function_analyzers():
    adapter = DummyAdapter()
    config = DummyConfig()

    import_analyzer = ImportAnalyzer(adapter, config)
    imports_result = import_analyzer.analyze()
    assert imports_result["available"] is True

    export_analyzer = ExportAnalyzer(adapter, config)
    exports_result = export_analyzer.analyze()
    assert exports_result["total_exports"] == 1

    section_analyzer = SectionAnalyzer(adapter, config)
    sections_result = section_analyzer.analyze()
    assert sections_result["total_sections"] == 2

    function_analyzer = FunctionAnalyzer(adapter, config)
    func_result = function_analyzer.analyze_functions()
    assert func_result["total_functions"] >= 0

    resource_analyzer = ResourceAnalyzer(adapter)
    res_result = resource_analyzer.analyze()
    assert res_result["has_resources"] is True
