"""Security tests for ACL2 MCP server."""

from pathlib import Path

import pytest

from acl2_mcp.server import validate_timeout, xdoc_corpus_search


def test_validate_timeout_clamps_max() -> None:
    """Test that timeout is clamped to maximum."""
    assert validate_timeout(1000) == 300


def test_validate_timeout_clamps_min() -> None:
    """Test that timeout is clamped to minimum."""
    assert validate_timeout(0) == 1
    assert validate_timeout(-10) == 1


def test_validate_timeout_handles_float() -> None:
    """Test that float timeouts are converted to int."""
    assert validate_timeout(5.7) == 5


def test_validate_timeout_handles_invalid_type() -> None:
    """Test that invalid types return default."""
    assert validate_timeout("invalid") == 30  # type: ignore


def test_xdoc_full_text_query_starting_with_dash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full-text query starting with "-" is searched for, not parsed as grep options."""
    corpus = tmp_path / "corpus"
    (corpus / "topics").mkdir(parents=True)
    (corpus / "index.tsv").write_text(
        "dash\tACL2____DASH\tHas a dash.\nplain\tACL2____PLAIN\tNo dash.\n"
    )
    (corpus / "topics" / "ACL2____DASH.txt").write_text("Pass -v to be verbose.\n")
    (corpus / "topics" / "ACL2____PLAIN.txt").write_text("Nothing to see.\n")
    # Treated as an option, "-v" made grep search the working directory.
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "decoy.txt").write_text("decoy -v line\n")
    monkeypatch.setenv("ACL2_XDOC_CORPUS", str(corpus))
    monkeypatch.chdir(cwd)

    out = xdoc_corpus_search("-v", full_text=True, max_results=20)
    assert "ACL2____DASH" in out
    assert "ACL2____PLAIN" not in out
    assert "decoy" not in out

    out = xdoc_corpus_search("--version", full_text=True, max_results=20)
    assert "grep" not in out.lower()
