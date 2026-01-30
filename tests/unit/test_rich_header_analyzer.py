import struct

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def test_parse_clear_data_entries():
    analyzer = RichHeaderAnalyzer(FakeR2(), filepath="/tmp/pe.bin")
    prodid1 = (0x1234 << 16) | 0x002E
    prodid2 = (0x4321 << 16) | 0x0031
    data = struct.pack("<II", prodid1, 5) + struct.pack("<II", prodid2, 0)

    entries = analyzer._parse_clear_data_entries(data)
    assert len(entries) == 1
    assert entries[0]["product_id"] == 0x002E
    assert entries[0]["build_number"] == 0x1234
    assert entries[0]["count"] == 5


def test_decode_rich_header_entries():
    analyzer = RichHeaderAnalyzer(FakeR2(), filepath="/tmp/pe.bin")
    xor_key = 0xA1B2C3D4
    prodid = 0x0010002E
    count = 7
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    encoded_data = b"DanS" + encoded_entry + b"Rich"

    entries = analyzer._decode_rich_header(encoded_data, xor_key)
    assert len(entries) == 1
    assert entries[0]["prodid"] == prodid
    assert entries[0]["count"] == count


def test_parse_compiler_entries_and_description():
    analyzer = RichHeaderAnalyzer(FakeR2(), filepath="/tmp/pe.bin")
    prodid = (0x1234 << 16) | 0x002E  # Linker700
    entries = [{"prodid": prodid, "count": 3}]

    compilers = analyzer._parse_compiler_entries(entries)
    assert compilers[0]["compiler_name"] == "Linker700"
    assert "Microsoft Linker" in compilers[0]["description"]


def test_bin_info_has_pe_and_magic_bytes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 10)

    analyzer = RichHeaderAnalyzer(FakeR2(cmd_map={"i": "pe"}), filepath=str(sample))
    assert analyzer._check_magic_bytes() is True
    assert analyzer._check_info_command() is True
    assert analyzer._bin_info_has_pe({"format": "pe32"}) is True
    assert analyzer._bin_info_has_pe({"class": "PE32"}) is True
