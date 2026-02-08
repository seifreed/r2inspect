import hashlib
import importlib
import sys
from pathlib import Path

from r2inspect.utils import hashing, ssdeep_loader


class BlockSSDeepFinder:
    def find_spec(self, fullname, _path=None, _target=None):
        if fullname == "ssdeep":
            raise ImportError("blocked")
        return None


def test_calculate_hashes_and_imphash(tmp_path: Path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"hello")

    hashes = hashing.calculate_hashes(str(file_path))
    assert hashes["md5"] == hashlib.md5(b"hello", usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(b"hello", usedforsecurity=False).hexdigest()

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    error = hashing.calculate_hashes(str(tmp_path))
    assert error["md5"].startswith("Error:")

    assert hashing.calculate_imphash([]) is None
    imports = [
        {"library": "KERNEL32", "name": "CreateFileA"},
        {"library": "USER32", "name": "MessageBoxA"},
    ]
    imphash = hashing.calculate_imphash(imports)
    assert imphash is not None


def test_calculate_ssdeep_and_loader(tmp_path: Path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"hello")

    hash_value = hashing.calculate_ssdeep(str(file_path))
    assert hash_value is None or isinstance(hash_value, str)

    original_module = ssdeep_loader._ssdeep_module
    ssdeep_loader._ssdeep_module = object()
    try:
        assert ssdeep_loader.get_ssdeep() is ssdeep_loader._ssdeep_module
    finally:
        ssdeep_loader._ssdeep_module = original_module

    original_sys_modules = sys.modules.copy()
    original_meta_path = list(sys.meta_path)
    ssdeep_loader._ssdeep_module = None
    sys.modules.pop("ssdeep", None)
    sys.meta_path.insert(0, BlockSSDeepFinder())
    try:
        assert ssdeep_loader.get_ssdeep() is None
    finally:
        sys.meta_path[:] = original_meta_path
        sys.modules.clear()
        sys.modules.update(original_sys_modules)
        ssdeep_loader._ssdeep_module = original_module
