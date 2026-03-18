from __future__ import annotations

from r2inspect.infrastructure.file_type import is_elf_file, is_pe_file


class QuietLogger:
    def debug(self, *_args, **_kwargs) -> None:
        pass

    def error(self, *_args, **_kwargs) -> None:
        pass


class RaisingDebugLogger(QuietLogger):
    def debug(self, *_args, **_kwargs) -> None:
        raise RuntimeError("debug failed")


class BadPath:
    def __fspath__(self) -> str:
        raise OSError("bad path")


class PEAdapterInfoRaises:
    def get_info_text(self) -> str:
        raise RuntimeError("info text failed")

    def cmdj(self, _command: str):
        return {}


class PEAdapterCmdjRaises:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self):
        raise RuntimeError("cmdj failed")


class ElfAdapterCmdRaises:
    def get_info_text(self) -> str:
        raise RuntimeError("cmd failed")

    def get_file_info(self):
        return {}


class ElfAdapterCmdjRaises:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self):
        raise RuntimeError("cmdj failed")


def test_is_pe_file_handles_magic_and_info_text_failures() -> None:
    assert (
        is_pe_file(
            filepath=BadPath(),
            adapter=PEAdapterInfoRaises(),
            r2_instance=None,
            logger=QuietLogger(),
        )
        is False
    )


def test_is_pe_file_handles_cmdj_failure_and_outer_fallback() -> None:
    assert (
        is_pe_file(
            filepath=None, adapter=PEAdapterCmdjRaises(), r2_instance=None, logger=QuietLogger()
        )
        is False
    )
    assert (
        is_pe_file(
            filepath=None,
            adapter=PEAdapterCmdjRaises(),
            r2_instance=None,
            logger=RaisingDebugLogger(),
        )
        is False
    )


def test_is_elf_file_handles_cmd_and_cmdj_failures() -> None:
    logger = QuietLogger()
    assert (
        is_elf_file(filepath=None, adapter=ElfAdapterCmdRaises(), r2_instance=None, logger=logger)
        is False
    )
    assert (
        is_elf_file(filepath=None, adapter=ElfAdapterCmdjRaises(), r2_instance=None, logger=logger)
        is False
    )
    assert (
        is_elf_file(
            filepath=BadPath(), adapter=ElfAdapterCmdjRaises(), r2_instance=None, logger=logger
        )
        is False
    )
    assert (
        is_elf_file(
            filepath=None,
            adapter=ElfAdapterCmdRaises(),
            r2_instance=None,
            logger=RaisingDebugLogger(),
        )
        is False
    )
