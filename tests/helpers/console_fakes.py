from __future__ import annotations


class CaptureConsole:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message) -> None:
        self.messages.append(str(message))
