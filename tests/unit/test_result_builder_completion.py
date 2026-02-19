from __future__ import annotations

import pytest

from r2inspect.abstractions.result_builder import init_result, mark_unavailable


def test_init_result_minimal() -> None:
    result = init_result()

    assert result["available"] is False
    assert result["error"] is None
    assert result["execution_time"] == 0.0
    assert "analyzer" not in result


def test_init_result_with_analyzer_name() -> None:
    result = init_result("test_analyzer")

    assert result["available"] is False
    assert result["error"] is None
    assert result["execution_time"] == 0.0
    assert result["analyzer"] == "test_analyzer"


def test_init_result_with_additional_fields() -> None:
    additional = {"hash_value": None, "hash_type": "ssdeep", "custom_field": 42}

    result = init_result(additional_fields=additional)

    assert result["available"] is False
    assert result["error"] is None
    assert result["execution_time"] == 0.0
    assert result["hash_value"] is None
    assert result["hash_type"] == "ssdeep"
    assert result["custom_field"] == 42


def test_init_result_with_analyzer_and_fields() -> None:
    additional = {"data": "test", "count": 5}

    result = init_result("my_analyzer", additional)

    assert result["available"] is False
    assert result["error"] is None
    assert result["analyzer"] == "my_analyzer"
    assert result["data"] == "test"
    assert result["count"] == 5


def test_init_result_without_execution_time() -> None:
    result = init_result(include_execution_time=False)

    assert result["available"] is False
    assert result["error"] is None
    assert "execution_time" not in result


def test_init_result_with_name_and_no_execution_time() -> None:
    result = init_result("analyzer", include_execution_time=False)

    assert result["analyzer"] == "analyzer"
    assert "execution_time" not in result


def test_init_result_all_options() -> None:
    result = init_result(
        "full_analyzer",
        {"field1": "value1", "field2": 123},
        include_execution_time=True,
    )

    assert result["available"] is False
    assert result["error"] is None
    assert result["analyzer"] == "full_analyzer"
    assert result["field1"] == "value1"
    assert result["field2"] == 123
    assert result["execution_time"] == 0.0


def test_mark_unavailable_basic() -> None:
    result = {"available": True, "error": None}

    updated = mark_unavailable(result, "Test error")

    assert updated["available"] is False
    assert updated["error"] == "Test error"
    assert "library_available" not in updated


def test_mark_unavailable_with_library_available_true() -> None:
    result = {"available": True}

    updated = mark_unavailable(result, "Error occurred", library_available=True)

    assert updated["available"] is False
    assert updated["error"] == "Error occurred"
    assert updated["library_available"] is True


def test_mark_unavailable_with_library_available_false() -> None:
    result = {"available": True}

    updated = mark_unavailable(result, "Library missing", library_available=False)

    assert updated["available"] is False
    assert updated["error"] == "Library missing"
    assert updated["library_available"] is False


def test_mark_unavailable_preserves_other_fields() -> None:
    result = {
        "available": True,
        "error": None,
        "analyzer": "test",
        "data": {"key": "value"},
        "execution_time": 1.5,
    }

    updated = mark_unavailable(result, "Failed")

    assert updated["available"] is False
    assert updated["error"] == "Failed"
    assert updated["analyzer"] == "test"
    assert updated["data"] == {"key": "value"}
    assert updated["execution_time"] == 1.5


def test_mark_unavailable_overwrites_existing_error() -> None:
    result = {"available": True, "error": "Old error"}

    updated = mark_unavailable(result, "New error")

    assert updated["error"] == "New error"


def test_mark_unavailable_returns_same_dict() -> None:
    result = {"available": True}

    updated = mark_unavailable(result, "Error")

    assert updated is result
