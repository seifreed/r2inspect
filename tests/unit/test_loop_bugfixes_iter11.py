"""Regression test for loop iteration 11.

The YARA default-rules fallback compiled only ``packer_detection.yar``, silently
dropping the bundled suspicious-API and crypto rule sets, so on that path those
matches never fired (a false-clean for those rules). The fallback now compiles
every bundled default rule set.
"""

from __future__ import annotations

from r2inspect.modules.yara_analyzer import YaraAnalyzer


class _Config:
    def __init__(self, rules_path: str) -> None:
        self._rules_path = rules_path

    def get_yara_rules_path(self) -> str:
        return self._rules_path


def test_default_rules_include_all_bundled_rule_sets(tmp_path) -> None:
    rules_path = str(tmp_path / "rules")
    analyzer = YaraAnalyzer(object(), config=_Config(rules_path), filepath=None)

    compiled = analyzer._compile_default_rules(rules_path)

    assert compiled is not None
    identifiers = {rule.identifier for rule in compiled}
    # Rules from all three bundled files must be present; previously only the
    # packer_detection.yar rules (UPX_Packed / Generic_Packer) survived.
    assert {
        "UPX_Packed",
        "Generic_Packer",
        "Suspicious_Process_APIs",
        "Anti_Debug_APIs",
        "Crypto_Constants",
    } <= identifiers
