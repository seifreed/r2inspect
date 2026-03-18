"""Byte-reading query mixin methods for r2pipe adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ..interfaces.core import R2CommandInterface


class R2PipeByteQueryMixin:
    """Methods that read raw bytes from the backend."""

    _maybe_force_error: Any  # provided by host class

    @property
    def _r2_iface(self) -> R2CommandInterface:
        return cast("R2CommandInterface", self)

    def read_bytes_list(self, address: int, size: int) -> list[int]:
        data = self.read_bytes(address, size)
        return list(data) if data else []

    def read_bytes(self, address: int, size: int) -> bytes:
        from . import r2pipe_queries as facade

        try:
            self._maybe_force_error("read_bytes")
            valid_address = facade.validate_address(address)
            valid_size = facade.validate_size(size)
            cmd = f"p8 {valid_size} @ {valid_address}"
            hex_data = facade.safe_cmd(self._r2_iface, cmd, "")

            if not hex_data or not facade.is_valid_r2_response(hex_data):
                facade.logger.warning(
                    "Failed to read %s bytes from address %s",
                    valid_size,
                    hex(valid_address),
                )
                return b""

            hex_data = facade.sanitize_r2_output(hex_data)
            hex_data = hex_data.replace(" ", "").replace("\n", "")

            try:
                return bytes.fromhex(hex_data)
            except ValueError as exc:
                facade.logger.error(
                    "Failed to convert hex data to bytes: %s. Data: %s",
                    exc,
                    hex_data[:100],
                )
                return b""

        except ValueError as exc:
            facade.logger.error("Invalid address or size: %s", exc)
            raise
        except Exception as exc:
            facade.logger.error("Error reading bytes from address %s: %s", hex(address), exc)
            return b""
