from __future__ import annotations

from typing import Any

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


class AuthAdapter:
    def __init__(self, responses: dict[str, Any] | None = None, raises: set[str] | None = None):
        self.responses = responses or {}
        self.raises = raises or set()

    def cmdj(self, cmd: str):
        if cmd in self.raises:
            raise RuntimeError(f"boom:{cmd}")
        return self.responses.get(cmd)

    def cmd(self, _cmd: str) -> str:
        return ""


def test_authenticode_security_directory_detection_behaves_consistently() -> None:
    analyzer = AuthenticodeAnalyzer(
        AuthAdapter({"iDj": [{"name": "SECURITY", "paddr": 1, "vaddr": 2, "size": 3}]})
    )
    assert analyzer._get_security_directory() == {
        "name": "SECURITY",
        "paddr": 1,
        "vaddr": 2,
        "size": 3,
    }

    analyzer = AuthenticodeAnalyzer(AuthAdapter({"iDj": [{"name": "NOT_SECURITY"}]}))
    assert analyzer._get_security_directory() is None


def test_rich_header_combines_rich_and_dans_offsets_when_direct_search_fails() -> None:
    class _CombiningRichHeader(RichHeaderAnalyzer):
        def _direct_file_rich_search(self):
            return None

        def _collect_rich_dans_offsets(self):
            return ([{"offset": 1}], [{"offset": 2}])

        def _try_rich_dans_combinations(self, r, d):
            return {"entries": [], "xor_key": 1}

    analyzer = _CombiningRichHeader(adapter=object(), filepath="/tmp/a.bin", r2_instance=object())
    assert analyzer._extract_rich_header() == {"entries": [], "xor_key": 1}
