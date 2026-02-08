from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_helper_type_and_entropy_and_pattern():
    analyzer = ResourceAnalyzer(adapter=None)

    assert analyzer._get_resource_type_name(1) == "RT_CURSOR"
    assert analyzer._get_resource_type_name(9999).startswith("UNKNOWN")

    entropy_zero = analyzer._calculate_entropy([0] * 100)
    entropy_rand = analyzer._calculate_entropy(list(range(256)))
    assert entropy_zero == 0.0
    assert entropy_rand > 0.0

    data = [1, 2, 3, 4, 5, 6, 7]
    assert analyzer._find_pattern(data, [3, 4]) == 2
    assert analyzer._find_pattern(data, [9, 9]) == -1


def test_resource_helper_dir_entries():
    analyzer = ResourceAnalyzer(adapter=None)
    # Simulate IMAGE_RESOURCE_DIRECTORY with 2 named, 1 id entries at offsets 12 and 14
    dir_data = [0] * 16
    dir_data[12] = 2
    dir_data[13] = 0
    dir_data[14] = 1
    dir_data[15] = 0

    assert analyzer._is_valid_dir_header(dir_data) is True
    assert analyzer._get_dir_total_entries(dir_data) == 3

    assert analyzer._is_valid_dir_header(None) is False
