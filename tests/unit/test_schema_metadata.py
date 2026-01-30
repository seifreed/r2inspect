import pytest

from r2inspect.schemas.metadata import ExportInfo, FunctionInfo, ImportInfo, ImportStatistics


def test_import_info_bounds():
    info = ImportInfo(name="CreateFileW", risk_score=10)
    assert info.risk_score == 10

    with pytest.raises(ValueError):
        ImportInfo(name="CreateFileW", risk_score=200)


def test_export_info_and_function_info():
    export = ExportInfo(name="Export", ordinal=1)
    assert export.name == "Export"

    func = FunctionInfo(name="Func", address=4096, size=10)
    assert func.address == 4096


def test_import_statistics_defaults():
    stats = ImportStatistics()
    assert stats.total_imports == 0
    assert stats.category_distribution == {}
