from __future__ import annotations

from collections import defaultdict
from typing import Any


class FakeR2Adapter:
    """Concrete test double for r2-like command/session APIs.

    Responses are provided per-command and consumed in order when lists are used.
    This keeps tests deterministic without monkeypatching module globals.
    """

    def __init__(
        self,
        *,
        cmd_responses: dict[str, Any] | None = None,
        cmdj_responses: dict[str, Any] | None = None,
    ) -> None:
        self._cmd_responses = dict(cmd_responses or {})
        self._cmdj_responses = dict(cmdj_responses or {})
        self.calls: dict[str, list[str]] = defaultdict(list)
        self.is_open = False

    def open(self, *_args: Any, **_kwargs: Any) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def get_file_info(self) -> dict[str, Any] | None:
        response = self._cmdj_responses.get("ij")
        if isinstance(response, Exception):
            raise response
        return response

    def cmd(self, command: str) -> Any:
        self.calls["cmd"].append(command)
        return self._consume(self._cmd_responses, command)

    def cmdj(self, command: str) -> Any:
        self.calls["cmdj"].append(command)
        return self._consume(self._cmdj_responses, command)

    @staticmethod
    def _consume(store: dict[str, Any], command: str) -> Any:
        if command not in store:
            return ""
        value = store[command]
        if isinstance(value, list):
            if not value:
                return ""
            next_value = value.pop(0)
        else:
            next_value = value
        if isinstance(next_value, Exception):
            raise next_value
        return next_value
