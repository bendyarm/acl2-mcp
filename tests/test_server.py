"""Tests for the ACL2 MCP server."""

from typing import Any

import pytest

from acl2_mcp.server import call_tool, list_tools


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
async def test_call_tool_prove(session_id: str) -> None:
    """Test the prove tool."""
    arguments: dict[str, Any] = {
        "code": """
(defthm associativity-of-append
  (equal (append (append x y) z)
         (append x (append y z))))
""",
        "timeout": 15,
        "session_id": session_id,
    }

    result = await call_tool("prove", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "Q.E.D." in result[0].text


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


@pytest.mark.asyncio
async def test_call_tool_include_book_nonexistent(session_id: str) -> None:
    """Test include_book with nonexistent file."""
    arguments: dict[str, Any] = {
        "file_path": "/tmp/nonexistent_acl2_book",
        "session_id": session_id,
    }

    result = await call_tool("include_book", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "not found" in result[0].text.lower()


@pytest.mark.asyncio
async def test_call_tool_query_event_builtin(session_id: str) -> None:
    """Test query_event with a built-in function."""
    arguments: dict[str, Any] = {
        "name": "append",
        "session_id": session_id,
    }

    result = await call_tool("query_event", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "APPEND" in result[0].text.upper()
