import time

import pytest

from r2inspect.utils import command_helpers
from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)
from r2inspect.utils.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)


class DummyR2:
    def __init__(self) -> None:
        self.cmd_calls = []
        self.cmdj_calls = []

    def cmd(self, command: str) -> str:
        self.cmd_calls.append(command)
        if command == "fail":
            raise RuntimeError("boom")
        return f"ok:{command}"

    def cmdj(self, command: str):
        self.cmdj_calls.append(command)
        if command == "failj":
            raise RuntimeError("boom")
        return {"command": command}


class DummyAdapter:
    def search_hex_json(self, value: str):
        return {"hex": value}

    def search_text(self, value: str):
        return [value]

    def search_hex(self, value: str):
        return value

    def get_strings_filtered(self, _command: str):
        return "filtered"

    def get_functions_at(self, address: int):
        return [{"addr": address}]

    def get_functions(self):
        return [{"addr": 1}]

    def get_function_info(self, address: int):
        return {"addr": address}

    def analyze_all(self):
        return "analysis"

    def get_disasm(self, address=None, size=None):
        return {"addr": address, "size": size}

    def get_disasm_text(self, address=None, size=None):
        return f"disasm:{address}:{size}"

    def get_cfg(self, address=None):
        return {"cfg": address}

    def read_bytes_list(self, address, size):
        return [address, size]

    def read_bytes(self, address, size):
        return b"\x01\x02"


def test_circuit_breaker_states_and_stats():
    breaker = CircuitBreaker(
        failure_threshold=2, recovery_timeout=0.0, expected_exception=(ValueError,)
    )

    def fail():
        raise ValueError("fail")

    def ok():
        return 123

    with pytest.raises(ValueError):
        breaker.call(fail)
    with pytest.raises(ValueError):
        breaker.call(fail)

    assert breaker.state == CircuitState.OPEN

    with pytest.raises(ValueError):
        breaker.call(fail)

    assert breaker.state in {CircuitState.OPEN, CircuitState.HALF_OPEN}

    result = breaker.call(ok)
    assert result == 123
    assert breaker.state == CircuitState.CLOSED

    stats = breaker.get_stats()
    assert stats["total_calls"] >= 4

    breaker.reset()
    assert breaker.failure_count == 0

    decorated = breaker(ok)
    assert decorated() == 123


def test_r2_command_circuit_breaker_executes():
    r2 = DummyR2()
    breaker = R2CommandCircuitBreaker()

    assert breaker.execute_command(r2, "ij", command_type="analysis") == {"command": "ij"}
    assert breaker.execute_command(r2, "pd 10", command_type="generic") == "ok:pd 10"

    assert breaker.execute_command(r2, "failj", command_type="search") is None
    assert breaker.execute_command(r2, "fail", command_type="generic") == ""

    stats = breaker.get_stats()
    assert "breaker_analysis" in stats
    assert "command_generic" in stats

    breaker.reset_all()


def test_command_helpers_paths():
    adapter = DummyAdapter()

    base, addr = command_helpers._parse_address("pdj 16 @ 0x10")
    assert base == "pdj 16" and addr == 0x10

    base, addr = command_helpers._parse_address("pdj 16 @ bad")
    assert addr is None

    assert command_helpers._parse_size("pdj 16") == 16
    assert command_helpers._parse_size("pdj bad") is None

    assert command_helpers.cmdj(adapter, None, "/xj deadbeef", {}) == {"hex": "deadbeef"}
    assert command_helpers.cmdj(adapter, None, "/c hello", []) == ["hello"]
    assert command_helpers.cmd(adapter, None, "/x deadbeef") == "deadbeef"

    assert command_helpers.cmdj(adapter, None, "aflj@0x20", []) == [{"addr": 0x20}]
    assert command_helpers.cmdj(adapter, None, "aflj", []) == [{"addr": 1}]
    assert command_helpers.cmdj(adapter, None, "afij@0x20", {}) == {"addr": 0x20}
    assert command_helpers.cmd(adapter, None, "aaa") == "analysis"
    assert command_helpers.cmd(adapter, None, "iz~foo") == "filtered"

    assert command_helpers.cmdj(adapter, None, "pdfj@0x30", {}) == {"addr": 0x30, "size": None}
    assert command_helpers.cmdj(adapter, None, "pdj 8@0x30", {}) == {"addr": 0x30, "size": 8}
    assert command_helpers.cmd(adapter, None, "pi 4@0x30") == "disasm:48:4"
    assert command_helpers.cmdj(adapter, None, "agj@0x30", {}) == {"cfg": 0x30}

    assert command_helpers.cmdj(adapter, None, "p8j 2@0x40", []) == [0x40, 2]
    assert command_helpers.cmd(adapter, None, "p8 2@0x40") == "0102"
    assert command_helpers.cmdj(adapter, None, "pxj 2@0x40", []) == [0x40, 2]

    assert command_helpers.cmd_list(adapter, None, "iij") == []


def test_rate_limiters_basic():
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire(tokens=1, timeout=0.01) is True
    bucket.tokens = 0.0
    assert bucket.acquire(tokens=1, timeout=0.01) is False

    limiter = AdaptiveRateLimiter(
        base_rate=1.0, max_rate=2.0, min_rate=0.5, memory_threshold=0.0, cpu_threshold=0.0
    )
    limiter.last_system_check = 0.0
    assert limiter.acquire_permit(timeout=0.01) in {True, False}
    limiter.record_success()
    limiter.record_error("fail")
    stats = limiter.get_stats()
    assert "current_rate" in stats

    batch = BatchRateLimiter(
        max_concurrent=1, rate_per_second=10.0, burst_size=1, enable_adaptive=False
    )
    assert batch.acquire(timeout=0.01) is True
    batch.release_success()
    stats = batch.get_stats()
    assert "success_rate" in stats

    info = cleanup_memory()
    assert info is None or "rss_mb" in info
