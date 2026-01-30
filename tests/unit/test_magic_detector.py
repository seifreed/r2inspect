from r2inspect.utils.magic_detector import MagicByteDetector


def _write_bytes(tmp_path, name, payload):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_detects_pe32(tmp_path):
    # Minimal PE: MZ header + e_lfanew at 0x3C pointing to 0x40 + PE signature
    data = bytearray(b"MZ")
    data.extend(b"\x00" * (0x3C - len(data)))
    data.extend((0x40).to_bytes(4, "little"))
    if len(data) < 0x40:
        data.extend(b"\x00" * (0x40 - len(data)))
    data.extend(b"PE\x00\x00" + b"\x00" * 20)

    path = _write_bytes(tmp_path, "sample.exe", bytes(data))
    detector = MagicByteDetector()
    result = detector.detect_file_type(str(path))

    assert result["file_format"].startswith("PE")
    assert result["is_executable"] is True
    assert result["confidence"] >= 0.9


def test_detects_elf64(tmp_path):
    payload = b"\x7fELF\x02" + b"\x00" * 100
    path = _write_bytes(tmp_path, "sample.elf", payload)
    detector = MagicByteDetector()
    result = detector.detect_file_type(str(path))

    assert result["file_format"] == "ELF64"
    assert result["is_executable"] is True
    assert result["confidence"] >= 0.8


def test_unknown_file(tmp_path):
    path = _write_bytes(tmp_path, "sample.bin", b"NOPE")
    detector = MagicByteDetector()
    result = detector.detect_file_type(str(path))

    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0
