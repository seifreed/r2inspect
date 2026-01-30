from r2inspect.utils.r2_helpers import validate_r2_data


def test_validate_r2_data_cleans_html_entities():
    data = [{"name": "Foo&amp;Bar&nbsp;Baz"}]
    cleaned = validate_r2_data(data, "list")
    assert cleaned[0]["name"] == "Foo&Bar Baz"
