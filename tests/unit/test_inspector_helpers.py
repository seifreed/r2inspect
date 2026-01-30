from r2inspect.core.inspector import R2Inspector


def test_as_dict_and_bool_dict_and_str():
    assert R2Inspector._as_dict({"a": 1}) == {"a": 1}
    assert R2Inspector._as_dict([1, 2]) == {}

    bools = R2Inspector._as_bool_dict({"a": 1, "b": False})
    assert bools == {"a": True, "b": False}

    assert R2Inspector._as_str("ok") == "ok"
    assert R2Inspector._as_str(123, default="x") == "x"
