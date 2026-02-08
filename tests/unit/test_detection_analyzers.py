from pathlib import Path

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.yara_analyzer import YaraAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class ConfigStub:
    def __init__(self, entropy_threshold=7.0, yara_path=None):
        self._entropy_threshold = entropy_threshold
        self._yara_path = yara_path
        self.typed_config = type(
            "TypedConfig",
            (),
            {"packer": type("PackerConfig", (), {"entropy_threshold": entropy_threshold})()},
        )()

    def get(self, section, key, default=None):
        if section == "packer" and key == "entropy_threshold":
            return self._entropy_threshold
        return default

    def get_yara_rules_path(self):
        return self._yara_path or "rules/yara"


def test_packer_detector_evidence_triggers_detection():
    hex_data = bytes(range(256)).hex()
    r2 = FakeR2(
        cmd_map={
            "/x 55505821": "0x1000",  # UPX!
            "p8 256 @ 4096": hex_data,
        },
        cmdj_map={
            "iSj": [
                {"name": ".upx0", "vaddr": 4096, "size": 256, "flags": "xw"},
            ],
            "iij": [],
        },
    )
    detector = PackerDetector(R2PipeAdapter(r2), ConfigStub(entropy_threshold=7.0))
    result = detector.detect()

    assert result["is_packed"] is True
    assert result["packer_type"] == "UPX"
    assert result["confidence"] > 0.5


def test_anti_analysis_detects_multiple_indicators():
    r2 = FakeR2(
        cmd_map={
            "/c fs:[0x30]": "0x401000",
            "/c rdtsc": "0x401010",
            "/c cpuid": "0x401020",
            "ii~Sleep|ii~Delay": "Sleep",
            "ii~FindFirst|ii~Process32|ii~Module32": "Process32First",
        },
        cmdj_map={
            "iij": [{"name": "IsDebuggerPresent", "plt": 4096, "libname": "kernel32.dll"}],
            "izj": [
                {"string": "VMware Tools", "vaddr": 8192},
                {"string": "cuckoo sandbox", "vaddr": 8200},
            ],
        },
    )
    detector = AntiAnalysisDetector(R2PipeAdapter(r2), ConfigStub())
    result = detector.detect()

    assert result["anti_debug"] is True
    assert result["anti_vm"] is True
    assert result["anti_sandbox"] is True
    assert result["timing_checks"] is True


def test_compiler_detector_gcc_detection():
    strings_output = "\n".join(
        [
            "0x0 0 0 0 GCC: (GNU) 9.3.0",
            "0x0 0 0 0 __gxx_personality_v0",
            "0x0 0 0 0 __stack_chk_fail",
            "0x0 0 0 0 _GLOBAL_OFFSET_TABLE_",
        ]
    )
    r2 = FakeR2(
        cmd_map={"izz~..": strings_output},
        cmdj_map={
            "ij": {"bin": {"class": "ELF"}},
            "iij": [{"libname": "libgcc_s.so"}, {"name": "__libc_start_main"}],
            "iSj": [{"name": ".eh_frame"}],
            "isj": [{"name": "__libc_start_main"}],
        },
    )
    detector = CompilerDetector(R2PipeAdapter(r2), ConfigStub())
    result = detector.detect_compiler()

    assert result["detected"] is True
    assert result["compiler"] == "GCC"
    assert result["confidence"] > 0.3


def test_crypto_analyzer_detects_api_and_constants():
    r2 = FakeR2(
        cmd_map={
            "/x 67452301": "0x1000",
            "/c xor": "0x2000",
            "p8 4 @ 4096": "00010203",
        },
        cmdj_map={
            "iij": [{"name": "BCryptEncrypt", "libname": "bcrypt.dll", "plt": 4096}],
            "iSj": [{"name": ".text", "size": 4, "vaddr": 4096}],
            "izj": [],
        },
    )
    analyzer = CryptoAnalyzer(R2PipeAdapter(r2), ConfigStub())
    result = analyzer.detect()

    assert any(const["type"] == "md5_h" for const in result["constants"])
    assert any(algo["algorithm"] == "BCrypt" for algo in result["algorithms"])
    assert any(pat["type"] == "XOR Operations" for pat in result["suspicious_patterns"])


def test_yara_analyzer_scan(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "simple.yar"
    rule_file.write_text('rule MatchHello { strings: $a = "hello" condition: $a }')

    sample_file = tmp_path / "sample.bin"
    sample_file.write_text("hello world")

    config = ConfigStub(yara_path=str(rules_dir))
    analyzer = YaraAnalyzer(FakeR2(cmdj_map={"ij": {"core": {"file": str(sample_file)}}}), config)

    matches = analyzer.scan(custom_rules_path=str(rules_dir))
    assert len(matches) == 1
    assert matches[0]["rule"] == "MatchHello"
