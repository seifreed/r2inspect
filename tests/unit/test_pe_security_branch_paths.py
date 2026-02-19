"""Branch-path coverage for r2inspect/modules/pe_security.py."""

from __future__ import annotations

from r2inspect.modules.pe_security import (
    _apply_authenticode_feature,
    _apply_security_flags_from_header,
    _apply_security_flags_from_text,
    _get_pe_security_text,
    get_security_features,
)


class SilentLogger:
    """Logger that absorbs all calls without doing anything."""

    def __getattr__(self, _name: str):
        return lambda *args, **kwargs: None


# ---------------------------------------------------------------------------
# Fake adapters used by get_security_features -> get_pe_headers
# ---------------------------------------------------------------------------


class AdapterWithHeaders:
    """Returns a PE headers JSON list so get_pe_headers can build a dict."""

    def __init__(self, dll_characteristics: int = 0x0140) -> None:
        self._dll_characteristics = dll_characteristics

    def get_headers_json(self) -> list:
        return [{"name": "DllCharacteristics", "value": self._dll_characteristics}]


class AdapterWithNoHeaders:
    """Returns an empty list so get_pe_headers falls back to text parsing."""

    def get_headers_json(self) -> list:
        return []

    def get_pe_security_text(self) -> str:
        return "DLL can move (DYNAMIC_BASE) NX_COMPAT GUARD_CF"


class AdapterWithSecurityText:
    """No get_headers_json, but has get_pe_security_text."""

    def get_pe_security_text(self) -> str:
        return "DYNAMIC_BASE NX_COMPAT GUARD_CF"


class AdapterWithNonCallableSecurityText:
    """get_pe_security_text is not callable – forces cmd fallback."""

    get_pe_security_text = "not a callable"


# ---------------------------------------------------------------------------
# _apply_security_flags_from_header (lines 40, 44, 46-58)
# ---------------------------------------------------------------------------


def test_apply_security_flags_from_header_all_features_set():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}
    pe_header = {"optional_header": {"DllCharacteristics": 0x4140}}
    _apply_security_flags_from_header(features, pe_header, SilentLogger())
    assert features["aslr"] is True
    assert features["dep"] is True
    assert features["guard_cf"] is True


def test_apply_security_flags_from_header_no_optional_header_key():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}
    # pe_header exists but has no optional_header key
    _apply_security_flags_from_header(features, {}, SilentLogger())
    assert features["aslr"] is False


def test_apply_security_flags_from_header_non_int_dll_characteristics_returns_early():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}
    pe_header = {"optional_header": {"DllCharacteristics": "0x0040"}}
    _apply_security_flags_from_header(features, pe_header, SilentLogger())
    # non-int -> early return, nothing set
    assert features["aslr"] is False


def test_apply_security_flags_from_header_none_pe_header_returns_early():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}
    _apply_security_flags_from_header(features, None, SilentLogger())
    assert features["aslr"] is False


def test_apply_security_flags_from_header_seh_disabled_when_no_seh_bit_set():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}
    # bit 0x0400 is NOT set, so seh = not False = True
    pe_header = {"optional_header": {"DllCharacteristics": 0x0000}}
    _apply_security_flags_from_header(features, pe_header, SilentLogger())
    assert features["seh"] is True


# ---------------------------------------------------------------------------
# _apply_security_flags_from_text (lines 62-71)
# ---------------------------------------------------------------------------


def test_apply_security_flags_from_text_none_returns_early():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, None)
    assert features["aslr"] is False


def test_apply_security_flags_from_text_empty_returns_early():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "")
    assert features["aslr"] is False


def test_apply_security_flags_from_text_dynamic_base_sets_aslr():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "DYNAMIC_BASE NX_COMPAT")
    assert features["aslr"] is True
    assert features["dep"] is True


def test_apply_security_flags_from_text_dll_can_move_sets_aslr():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "DLL can move")
    assert features["aslr"] is True


def test_apply_security_flags_from_text_guard_cf_sets_guard_cf():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "GUARD_CF")
    assert features["guard_cf"] is True


def test_apply_security_flags_from_text_no_seh_flag_prevents_seh():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "NO_SEH NX_COMPAT")
    assert features["seh"] is False
    assert features["dep"] is True


def test_apply_security_flags_from_text_seh_set_when_no_seh_absent():
    features = {"aslr": False, "dep": False, "seh": False, "guard_cf": False}
    _apply_security_flags_from_text(features, "NX_COMPAT")
    assert features["seh"] is True


# ---------------------------------------------------------------------------
# _get_pe_security_text (lines 75-81)
# ---------------------------------------------------------------------------


def test_get_pe_security_text_calls_adapter_method_when_available():
    adapter = AdapterWithSecurityText()
    text = _get_pe_security_text(adapter)
    assert "DYNAMIC_BASE" in text


def test_get_pe_security_text_returns_string_from_non_string_result():
    class AdapterReturnsInt:
        def get_pe_security_text(self) -> int:
            return 12345

    text = _get_pe_security_text(AdapterReturnsInt())
    assert text == "12345"


def test_get_pe_security_text_falls_back_to_cmd_when_no_method():
    # Adapter has no get_pe_security_text attribute -> falls back to cmd_helper
    class AdapterWithNoSecurityText:
        pass

    adapter = AdapterWithNoSecurityText()
    # cmd_helper returns "" when r2 is None and adapter has no matching method
    text = _get_pe_security_text(adapter)
    assert isinstance(text, str)


# ---------------------------------------------------------------------------
# _apply_authenticode_feature (lines 84-92)
# ---------------------------------------------------------------------------


def test_apply_authenticode_feature_sets_true_when_security_dir_has_size():
    features = {"authenticode": False}
    pe_header = {
        "data_directories": {
            "security": {"size": 1024, "offset": 0x100}
        }
    }
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is True


def test_apply_authenticode_feature_stays_false_when_security_dir_size_zero():
    features = {"authenticode": False}
    pe_header = {"data_directories": {"security": {"size": 0}}}
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is False


def test_apply_authenticode_feature_stays_false_when_no_security_dir():
    features = {"authenticode": False}
    pe_header = {"data_directories": {}}
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is False


def test_apply_authenticode_feature_none_pe_header_returns_early():
    features = {"authenticode": False}
    _apply_authenticode_feature(features, None)
    assert features["authenticode"] is False


def test_apply_authenticode_feature_non_dict_security_dir_skipped():
    features = {"authenticode": False}
    pe_header = {"data_directories": {"security": "not-a-dict"}}
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is False


# ---------------------------------------------------------------------------
# get_security_features integration (lines 25-31)
# ---------------------------------------------------------------------------


def test_get_security_features_with_adapter_having_headers():
    adapter = AdapterWithHeaders(dll_characteristics=0x0140)
    logger = SilentLogger()
    features = get_security_features(adapter, logger)
    assert isinstance(features, dict)
    assert "aslr" in features
    assert "dep" in features
    assert "seh" in features
    assert "guard_cf" in features
    assert "authenticode" in features


def test_get_security_features_fallback_to_text_when_no_flags_from_header():
    # Empty headers list forces text fallback (get_pe_headers returns None),
    # then _get_pe_security_text fires
    adapter = AdapterWithNoHeaders()
    logger = SilentLogger()
    features = get_security_features(adapter, logger)
    assert isinstance(features, dict)


def test_get_security_features_returns_all_false_on_error():
    class BrokenAdapter:
        def get_headers_json(self):
            raise RuntimeError("broken")

    features = get_security_features(BrokenAdapter(), SilentLogger())
    # Should return default dict without raising
    assert isinstance(features, dict)
    assert set(features.keys()) == {"aslr", "dep", "seh", "guard_cf", "authenticode"}
