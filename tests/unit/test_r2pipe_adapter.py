import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class FakeR2:
    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command)

    def cmd(self, command):
        return self.cmd_map.get(command, "")


def test_adapter_requires_instance():
    with pytest.raises(ValueError):
        R2PipeAdapter(None)


def test_get_file_info_and_cache():
    r2 = FakeR2(cmdj_map={"ij": {"arch": "x86", "bits": 32}})
    adapter = R2PipeAdapter(r2)
    info = adapter.get_file_info()
    assert info.get("arch") == "x86"
    # cached call should return same
    info2 = adapter.get_file_info()
    assert info2 == info


def test_get_sections_cached_query():
    r2 = FakeR2(cmdj_map={"iSj": [{"name": ".text"}]})
    adapter = R2PipeAdapter(r2)
    sections = adapter.get_sections()
    assert sections == [{"name": ".text"}]


def test_read_bytes_converts_hex():
    r2 = FakeR2(cmd_map={"p8 4 @ 4096": "41424344"})
    adapter = R2PipeAdapter(r2)
    data = adapter.read_bytes(4096, 4)
    assert data == b"ABCD"


def test_execute_command_json_and_text():
    r2 = FakeR2(cmdj_map={"ij": {"a": 1}}, cmd_map={"pd 1": "nop"})
    adapter = R2PipeAdapter(r2)
    assert adapter.execute_command("ij") == {"a": 1}
    assert adapter.execute_command("pd 1") == "nop"
