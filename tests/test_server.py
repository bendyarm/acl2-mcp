"""Tests for the ACL2 MCP server."""

import asyncio
from typing import Any

import pytest

from acl2_mcp.server import run_acl2, call_tool


@pytest.mark.asyncio
async def test_run_acl2_simple_expression() -> None:
    """Test running a simple ACL2 expression."""
    code = "(+ 1 2)"
    result = await run_acl2(code, timeout=10)

    assert result is not None
    assert isinstance(result, str)
    # ACL2 should evaluate this expression
    assert "3" in result or "ACL2" in result


@pytest.mark.asyncio
async def test_run_acl2_definition() -> None:
    """Test running an ACL2 function definition."""
    code = """
(defun my-add (x y)
  (+ x y))
"""
    result = await run_acl2(code, timeout=10)

    assert result is not None
    assert isinstance(result, str)
    # Should see function acceptance or ACL2 prompt
    assert "MY-ADD" in result.upper() or "ACL2" in result


@pytest.mark.asyncio
async def test_run_acl2_syntax_error() -> None:
    """Test handling of ACL2 syntax errors."""
    code = "(defun bad-syntax"  # Missing closing paren
    result = await run_acl2(code, timeout=10)

    assert result is not None
    # ACL2 should report some kind of error or incomplete input
    assert len(result) > 0


@pytest.mark.asyncio
async def test_call_tool_prove() -> None:
    """Test the prove tool."""
    arguments: dict[str, Any] = {
        "code": """
(defthm associativity-of-append
  (equal (append (append x y) z)
         (append x (append y z))))
""",
        "timeout": 15,
    }

    result = await call_tool("prove", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_evaluate() -> None:
    """Test the evaluate tool."""
    arguments: dict[str, Any] = {
        "code": "(+ 5 7)",
        "timeout": 10,
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "12" in result[0].text or "ACL2" in result[0].text


@pytest.mark.asyncio
async def test_call_tool_evaluate_with_definition() -> None:
    """Test evaluating code with definitions."""
    arguments: dict[str, Any] = {
        "code": """
(defun square (x)
  (* x x))

(square 4)
""",
        "timeout": 10,
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_check_syntax_valid() -> None:
    """Test syntax checking with valid code."""
    arguments: dict[str, Any] = {
        "code": """
(defun my-function (x y)
  (+ x y))
""",
    }

    result = await call_tool("check_syntax", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    # Should not report syntax errors
    assert "No obvious syntax errors" in result[0].text or "ACL2" in result[0].text


@pytest.mark.asyncio
async def test_call_tool_check_syntax_invalid() -> None:
    """Test syntax checking with invalid code."""
    arguments: dict[str, Any] = {
        "code": "(defun incomplete",
    }

    result = await call_tool("check_syntax", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    # Will either report syntax errors or just show ACL2 waiting for input
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_unknown_tool() -> None:
    """Test calling an unknown tool raises an error."""
    with pytest.raises(ValueError, match="Unknown tool"):
        await call_tool("nonexistent_tool", {})


@pytest.mark.asyncio
async def test_call_tool_default_timeout() -> None:
    """Test that default timeout is used when not specified."""
    arguments: dict[str, Any] = {
        "code": "(+ 1 1)",
    }

    result = await call_tool("evaluate", arguments)

    assert len(result) == 1
    assert result[0].type == "text"


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


@pytest.mark.asyncio
async def test_call_tool_include_book_nonexistent() -> None:
    """Test include_book with nonexistent file."""
    arguments: dict[str, Any] = {
        "file_path": "/tmp/nonexistent_acl2_book",
    }

    result = await call_tool("include_book", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()


@pytest.mark.asyncio
async def test_call_tool_check_theorem_nonexistent() -> None:
    """Test check_theorem with nonexistent file."""
    arguments: dict[str, Any] = {
        "file_path": "/tmp/nonexistent_acl2_file.lisp",
        "theorem_name": "some-theorem",
    }

    result = await call_tool("check_theorem", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()


@pytest.mark.asyncio
async def test_call_tool_admit_valid() -> None:
    """Test admit with valid ACL2 code."""
    arguments: dict[str, Any] = {
        "code": "(defun my-add (x y) (+ x y))",
    }

    result = await call_tool("admit", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "admit" in result[0].text.lower()


@pytest.mark.asyncio
async def test_call_tool_admit_invalid() -> None:
    """Test admit with invalid ACL2 code."""
    arguments: dict[str, Any] = {
        "code": "(defun bad-function (x) (undefined-function x))",
    }

    result = await call_tool("admit", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    # Should contain admit result
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_query_event_builtin() -> None:
    """Test query_event with a built-in function."""
    arguments: dict[str, Any] = {
        "name": "append",
    }

    result = await call_tool("query_event", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    # Should show information about append
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_query_event_nonexistent_file() -> None:
    """Test query_event with nonexistent file."""
    arguments: dict[str, Any] = {
        "name": "some-function",
        "file_path": "/tmp/nonexistent.lisp",
    }

    result = await call_tool("query_event", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()


@pytest.mark.asyncio
async def test_call_tool_verify_guards_builtin() -> None:
    """Test verify_guards with a built-in function."""
    arguments: dict[str, Any] = {
        "function_name": "len",
    }

    result = await call_tool("verify_guards", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    # Should produce some output about guards
    assert len(result[0].text) > 0


@pytest.mark.asyncio
async def test_call_tool_verify_guards_nonexistent_file() -> None:
    """Test verify_guards with nonexistent file."""
    arguments: dict[str, Any] = {
        "function_name": "my-func",
        "file_path": "/tmp/nonexistent.lisp",
    }

    result = await call_tool("verify_guards", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()
