from pathlib import Path

from scripts.check_docs_links import check_docs


def test_check_docs_reports_only_missing_local_targets(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (tmp_path / "README.md").write_text(
        "[valid](docs/valid.md) [anchor](#section) "
        "[external](https://example.com) [missing](docs/missing.md)\n",
        encoding="utf-8",
    )
    (docs / "valid.md").write_text("# Valid\n", encoding="utf-8")

    assert check_docs(tmp_path) == ["README.md: missing docs/missing.md"]
