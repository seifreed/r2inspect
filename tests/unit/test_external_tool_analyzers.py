from r2inspect.application.report_builder import build_report_v1
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.modules.external_tool_analyzers import CapaAnalyzer, FlossAnalyzer


def test_external_tools_report_missing_dependencies_explicitly() -> None:
    def missing(_name: str) -> None:
        return None

    assert (
        CapaAnalyzer(filename="sample.exe", executable_lookup=missing).analyze()[
            "library_available"
        ]
        is False
    )
    assert (
        FlossAnalyzer(filename="sample.exe", executable_lookup=missing).analyze()[
            "library_available"
        ]
        is False
    )


def test_report_normalizes_capa_and_floss_results() -> None:
    result = build_analysis_result(
        {
            "file_info": {"file_type": "PE"},
            "capa": {"available": True, "result": {"rules": {"send HTTP request": {}}}},
            "floss": {
                "available": True,
                "result": {"strings": {"decoded_strings": ["secret.example"]}},
            },
        }
    )

    report = build_report_v1(result, analysis_id="external", commit="abc", radare2_version="6.1.8")

    assert report.capabilities[0]["name"] == "send HTTP request"
    assert report.artifacts[0]["value"] == "secret.example"
