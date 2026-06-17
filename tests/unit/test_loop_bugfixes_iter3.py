"""Regression test for loop iteration 3.

``terminate_radare2_processes`` matched the target filename as a *substring* of
each cmdline argument, so a safe-mode reopen for ``/tmp/a.bin`` would also kill
an unrelated radare2 analysing ``/tmp/a.bin.packed`` (or ``lib.so`` would match
``mylib.so``). It now matches the filename as a whole argv element.
"""

from __future__ import annotations

from r2inspect.infrastructure.r2_session_cleanup import terminate_radare2_processes


class _FakeProc:
    def __init__(self, cmdline: list[str]) -> None:
        self.info = {"name": "radare2", "cmdline": cmdline}
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_terminate_does_not_kill_superstring_path_matches() -> None:
    target = "/tmp/a.bin"
    exact = _FakeProc([target])
    superstring = _FakeProc(["/tmp/a.bin.packed"])
    sibling = _FakeProc(["/tmp/xa.bin"])

    terminate_radare2_processes(
        target, process_iter=lambda _fields: [exact, superstring, sibling], kill_timeout=0.01
    )

    assert exact.terminated is True
    assert superstring.terminated is False
    assert sibling.terminated is False
