import hashlib
import json
from pathlib import Path

from r2inspect.application.forensic import create_forensic_bundle
from tests.helpers import env_vars


class _Config:
    def to_dict(self):
        return {"virustotal": {"api_key": "must-not-leak"}}


class _Adapter:
    def command_log(self):
        return [{"command": "ij", "status": "completed"}]


def test_forensic_bundle_preserves_and_hashes_evidence(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(bytes(range(128)))
    results = {
        "packer": {
            "findings": [
                {"finding_id": "packed", "locations": [{"offset": 4}], "warnings": ["note"]}
            ]
        },
        "capa": {"native_output": {"stdout": '{"rules": {}}\n', "stderr": ""}},
        "floss": {"native_output": {"stdout": '{"strings": {}}\n', "stderr": ""}},
        "yara_matches": [{"rule": "demo"}],
    }

    with env_vars(R2INSPECT_EVIDENCE_DIR=str(tmp_path / "evidence")):
        bundle = create_forensic_bundle(
            sample=sample,
            adapter=_Adapter(),
            config=_Config(),
            options={"profile": "forensic", "preserve_artifacts": True},
            results=results,
            started_at="2026-09-04T00:00:00+00:00",
        )

    manifest_path = Path(bundle["manifest_path"])
    manifest = json.loads(manifest_path.read_text())
    assert manifest["schema_version"] == "r2inspect.forensic/v1"
    assert manifest["effective_configuration"]["runtime"]["virustotal"]["api_key"] == "[redacted]"
    assert manifest["byte_snippets"][0]["bytes_hex"].startswith("04050607")
    assert {item["name"] for item in manifest["artifacts"]} >= {
        "analysis-results.json",
        "capa.raw.json",
        "floss.raw.json",
        "yara.raw.json",
    }
    for artifact in manifest["artifacts"]:
        data = (manifest_path.parent / artifact["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == artifact["sha256"]
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == bundle["manifest_sha256"]
