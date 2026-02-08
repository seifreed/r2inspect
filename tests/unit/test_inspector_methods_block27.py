from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector


def test_inspector_wrapper_methods():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    with create_inspector(str(sample)) as inspector:
        assert inspector.get_file_info() is None or isinstance(inspector.get_file_info(), dict)
        assert inspector.get_pe_info() is None or isinstance(inspector.get_pe_info(), dict)
        assert isinstance(inspector.get_strings(), list)
        assert isinstance(inspector.get_imports(), list)
        assert isinstance(inspector.get_exports(), list)
        assert isinstance(inspector.get_sections(), list)

        assert isinstance(inspector.detect_packer(), dict)
        assert isinstance(inspector.detect_crypto(), dict)
        assert isinstance(inspector.detect_anti_analysis(), dict)
        assert isinstance(inspector.detect_compiler(), dict)

        assert isinstance(inspector.run_yara_rules(), list)
        assert isinstance(inspector.search_xor("AA"), list)

        results = inspector.analyze(full_analysis=False)
        assert isinstance(results, dict)

        assert isinstance(inspector.generate_indicators(results), list)

        assert isinstance(inspector.analyze_functions(), dict)
        assert isinstance(inspector.analyze_ssdeep(), dict)
        assert isinstance(inspector.analyze_tlsh(), dict)
        assert isinstance(inspector.analyze_telfhash(), dict)
        assert isinstance(inspector.analyze_rich_header(), dict)
        assert isinstance(inspector.analyze_impfuzzy(), dict)
        assert isinstance(inspector.analyze_ccbhash(), dict)
        assert isinstance(inspector.analyze_binlex(), dict)
        assert isinstance(inspector.analyze_binbloom(), dict)
        assert isinstance(inspector.analyze_simhash(), dict)
        assert isinstance(inspector.analyze_bindiff(), dict)

        summary = inspector.generate_executive_summary(results)
        assert isinstance(summary, dict)
