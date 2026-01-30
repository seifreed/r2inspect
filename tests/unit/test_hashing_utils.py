import hashlib

from r2inspect.utils.hashing import calculate_hashes, calculate_imphash


def test_calculate_hashes_matches_hashlib(tmp_path):
    data = b"r2inspect-test-data"
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(data)

    expected = {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }

    assert calculate_hashes(str(file_path)) == expected


def test_calculate_hashes_missing_file_returns_empty_hashes(tmp_path):
    missing = tmp_path / "missing.bin"
    hashes = calculate_hashes(str(missing))
    assert hashes == {"md5": "", "sha1": "", "sha256": "", "sha512": ""}


def test_calculate_imphash_builds_expected_string():
    imports = [
        {"library": "KERNEL32.DLL", "name": "CreateFileW"},
        {"library": "user32.dll", "name": "MessageBoxA"},
    ]
    import_string = "kernel32.dll.createfilew,user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert calculate_imphash(imports) == expected


def test_calculate_imphash_returns_none_on_empty():
    assert calculate_imphash([]) is None
