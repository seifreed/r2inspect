import io
import sys

from rich.console import Console

from r2inspect.cli import interactive


def _sample_results():
    return {
        "file_info": {
            "size": 1,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "PE",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86-64",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.95,
            },
        },
        "pe_info": {"compile_time": "2026-01-30", "imphash": "imphash", "is_executable": True},
        "security": {"aslr": True, "dep": True, "seh": False},
        "ssdeep": {"available": True, "hash_value": "ss", "method_used": "python"},
        "tlsh": {"available": False, "error": "nope"},
        "telfhash": {"available": True, "is_elf": False},
        "rich_header": {"available": True, "is_pe": False},
        "impfuzzy": {"available": False, "error": "nope", "library_available": False},
        "ccbhash": {"available": False, "error": "nope"},
        "binlex": {"available": False, "error": "nope"},
        "binbloom": {"available": False, "error": "nope"},
        "simhash": {"available": False, "error": "nope"},
        "bindiff": {"available": False, "error": "nope"},
    }


class InspectorStub:
    def analyze(self, **kwargs):
        return _sample_results()

    def get_strings(self):
        return ["alpha", "beta"]

    def get_file_info(self):
        return {"Format": "PE", "Size": 1}

    def get_pe_info(self):
        return {"Imphash": "imphash"}

    def get_imports(self):
        return ["KERNEL32!CreateFileA"]

    def get_exports(self):
        return ["Exported"]

    def get_sections(self):
        return [
            {"name": ".text", "size": 1, "entropy": 4.0, "permissions": "r-x"},
            {"name": ".data", "size": 1, "entropy": 3.0, "permissions": "rw-"},
        ]


def test_run_interactive_mode_all_commands():
    console = Console(record=True, width=120)
    interactive.console = console

    input_stream = io.StringIO(
        "help\n\nstrings\ninfo\npe\nimports\nexports\nsections\nunknown\nanalyze\nquit\n"
    )
    original_stdin = sys.stdin
    try:
        sys.stdin = input_stream
        interactive.run_interactive_mode(InspectorStub(), options={})
    finally:
        sys.stdin = original_stdin

    output = console.export_text()
    assert "Interactive Mode" in output
    assert "Available commands" in output
    assert "Unknown command" in output
    assert "alpha" in output
    assert "Imphash" in output
    assert "Exiting interactive mode" in output
