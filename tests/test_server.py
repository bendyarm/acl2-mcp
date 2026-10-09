"""Tests for the ACL2 MCP server."""

import asyncio
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from acl2_mcp.server import call_tool, list_tools, xdoc_corpus_show


@pytest.mark.asyncio
async def test_session_id_required_wherever_accepted() -> None:
    """Every tool that takes a session_id must require it.

    Without a session there is no ACL2 world to run in, so a forgotten
    session_id must be rejected rather than silently doing something else.
    """
    for tool in await list_tools():
        schema = tool.inputSchema
        if "session_id" in schema.get("properties", {}):
            assert "session_id" in schema.get("required", []), tool.name


@pytest.mark.asyncio
async def test_call_tool_evaluate(session_id: str) -> None:
    """Test the evaluate tool."""
    arguments: dict[str, Any] = {
        "code": "(+ 5 7)",
        "timeout": 10,
        "session_id": session_id,
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "12" in result[0].text


@pytest.mark.asyncio
async def test_call_tool_evaluate_with_definition(session_id: str) -> None:
    """Test evaluating code with definitions."""
    arguments: dict[str, Any] = {
        "code": """
(defun square (x)
  (* x x))

(square 4)
""",
        "timeout": 10,
        "session_id": session_id,
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "16" in result[0].text


@pytest.mark.asyncio
async def test_call_tool_unknown_tool() -> None:
    """Test calling an unknown tool raises an error."""
    with pytest.raises(ValueError, match="Unknown tool"):
        await call_tool("nonexistent_tool", {})


@pytest.mark.asyncio
async def test_call_tool_default_timeout(session_id: str) -> None:
    """Test that default timeout is used when not specified."""
    arguments: dict[str, Any] = {
        "code": "(+ 1 1)",
        "session_id": session_id,
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "2" in result[0].text


@pytest.mark.asyncio
async def test_call_tool_certify_book_nonexistent() -> None:
    """Test certify_book with nonexistent file."""
    arguments: dict[str, Any] = {
        "file_path": "/tmp/nonexistent_acl2_book",
    }

    result = await call_tool("certify_book", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()


def slow_book(directory: Path) -> str:
    """Write a book that takes a minute to certify; return its name.

    The name is unique, so that its cert.pl jobs can be found with ps.
    """
    name = f"slow{uuid.uuid4().hex[:8]}"
    (directory / f"{name}.lisp").write_text(
        '(in-package "ACL2")\n(value-triple (sleep 60))\n')
    return name


def cert_jobs_running(name: str) -> bool:
    """Is any cert.pl job (make helper, its shell script) for book NAME running?"""
    ps = subprocess.run(["ps", "-A", "-o", "command"],
                        capture_output=True, text=True).stdout
    return any(name in line for line in ps.splitlines())


@pytest.mark.asyncio
async def test_certify_book_timeout_stops_everything(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A certify_book timeout stops cert.pl and every job it started, at once.

    It used to kill only cert.pl: make and ACL2 went on and certified the
    book, and since they held cert.pl's output open, the call returned
    only when they had finished.
    """
    monkeypatch.chdir(tmp_path)  # cert.pl writes Makefile-tmp here
    name = slow_book(tmp_path)
    start = time.monotonic()
    result = await call_tool("certify_book", {
        "file_path": str(tmp_path / name), "jobs": 1, "timeout": 5})
    assert time.monotonic() - start < 15
    assert "timed out after 5 seconds" in result[0].text
    assert not cert_jobs_running(name)
    await asyncio.sleep(2)
    assert not (tmp_path / f"{name}.cert").exists()


@pytest.mark.asyncio
async def test_certify_book_cancel_stops_everything(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling a certify_book call (as an MCP client does) stops cert.pl
    and every job it started."""
    monkeypatch.chdir(tmp_path)
    name = slow_book(tmp_path)
    call = asyncio.create_task(call_tool("certify_book", {
        "file_path": str(tmp_path / name), "jobs": 1}))
    for _ in range(100):
        if cert_jobs_running(name):
            break
        await asyncio.sleep(0.1)
    assert cert_jobs_running(name)

    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    assert not cert_jobs_running(name)
    await asyncio.sleep(2)
    assert not (tmp_path / f"{name}.cert").exists()


@pytest.fixture
def tiny_corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A five-topic xdoc corpus laid out like the real one."""
    corpus = tmp_path / "corpus"
    (corpus / "topics").mkdir(parents=True)
    topics = {
        "ACL2____BVPLUS": ("bvplus", "Bit-vector sum."),
        "COMMON-LISP____DEFUN": ("defun", "Define a function symbol"),
        "FTY____DEFBITSTRUCT": ("fty::defbitstruct", "Define a bitvector type."),
        "ABNF____PARSE": ("abnf::parse", "ABNF parser."),
        "PFCS____PARSE": ("pfcs::parse", "PFCS parser."),
    }
    (corpus / "index.tsv").write_text(
        "".join(f"{nat}\t{key}\t{short}\n" for key, (nat, short) in topics.items())
    )
    for key, (nat, short) in topics.items():
        (corpus / "topics" / f"{key}.txt").write_text(f"# {nat}\nKey: {key}\n\n{short}\n")
    monkeypatch.setenv("ACL2_XDOC_CORPUS", str(corpus))
    return corpus


@pytest.mark.parametrize("name, key", [
    ("bvplus", "ACL2____BVPLUS"),
    ("acl2::bvplus", "ACL2____BVPLUS"),
    ("ACL2::BVPLUS", "ACL2____BVPLUS"),
    ("acl2::defun", "COMMON-LISP____DEFUN"),
    ("common-lisp::defun", "COMMON-LISP____DEFUN"),
    ("ACL2____DEFUN", "COMMON-LISP____DEFUN"),
    ("ACL2____DEFBITSTRUCT", "FTY____DEFBITSTRUCT"),
    ("defbitstruct", "FTY____DEFBITSTRUCT"),
])
def test_xdoc_show_resolves_names(tiny_corpus: Path, name: str, key: str) -> None:
    """Package-prefixed names and wrong-package keys find the topic."""
    assert f"Key: {key}\n" in xdoc_corpus_show(name, 1000)


def test_xdoc_show_wrong_package_key_ambiguous(tiny_corpus: Path) -> None:
    """A wrong-package key matching several topics lists the candidates."""
    out = xdoc_corpus_show("ACL2____PARSE", 1000)
    assert out.startswith("Ambiguous")
    assert "ABNF____PARSE" in out and "PFCS____PARSE" in out
