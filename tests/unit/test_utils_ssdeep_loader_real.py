from __future__ import annotations

import importlib
import sys
from pathlib import Path

from r2inspect.utils import ssdeep_loader


def test_ssdeep_loader_success_and_failure(tmp_path: Path) -> None:
    ssdeep_loader._ssdeep_module = None
    sys.modules.pop("ssdeep", None)

    module_dir = tmp_path / "fake_ssdeep"
    module_dir.mkdir()
    (module_dir / "ssdeep.py").write_text("value = 1\n", encoding="utf-8")

    old_path = sys.path
    try:
        sys.path = [str(module_dir)]
        module = ssdeep_loader.get_ssdeep()
        assert module is not None
        assert getattr(module, "value", None) == 1

        ssdeep_loader._ssdeep_module = None
        sys.modules.pop("ssdeep", None)
        sys.path = []
        assert ssdeep_loader.get_ssdeep() is None
    finally:
        sys.path = old_path
        ssdeep_loader._ssdeep_module = None
        sys.modules.pop("ssdeep", None)
        importlib.invalidate_caches()
