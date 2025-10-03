"""Security tests for ACL2 MCP server."""

from pathlib import Path
from typing import Any

import pytest

from acl2_mcp.server import (
    validate_timeout,
    validate_acl2_identifier,
    escape_acl2_string,
    validate_file_path,
    call_tool,
)


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


def test_validate_acl2_identifier_rejects_quotes() -> None:
    """Test that identifiers with quotes are rejected."""
    with pytest.raises(ValueError, match="Invalid ACL2 identifier"):
        validate_acl2_identifier('malicious")(+ 1 1)')


def test_validate_acl2_identifier_rejects_parens() -> None:
    """Test that identifiers with parens are rejected."""
    with pytest.raises(ValueError, match="Invalid ACL2 identifier"):
        validate_acl2_identifier("malicious)(+ 1 1)")


def test_validate_acl2_identifier_rejects_empty() -> None:
    """Test that empty identifiers are rejected."""
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_acl2_identifier("")


def test_validate_acl2_identifier_accepts_valid() -> None:
    """Test that valid identifiers are accepted."""
    assert validate_acl2_identifier("my-function") == "my-function"
    assert validate_acl2_identifier("my_function") == "my_function"
    assert validate_acl2_identifier("my-function-123") == "my-function-123"


def test_escape_acl2_string_escapes_quotes() -> None:
    """Test that quotes are properly escaped."""
    assert escape_acl2_string('test"quote') == 'test\\"quote'


def test_escape_acl2_string_escapes_backslashes() -> None:
    """Test that backslashes are properly escaped."""
    assert escape_acl2_string('test\\path') == 'test\\\\path'


def test_escape_acl2_string_escapes_both() -> None:
    """Test that both backslashes and quotes are escaped."""
    assert escape_acl2_string('test\\"path') == 'test\\\\\\"path'


def test_validate_file_path_rejects_empty() -> None:
    """Test that empty paths are rejected."""
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_file_path("")


def test_validate_file_path_rejects_nonexistent() -> None:
    """Test that nonexistent files are rejected."""
    with pytest.raises(ValueError, match="not found"):
        validate_file_path("/tmp/nonexistent_file_12345.lisp")


def test_validate_file_path_rejects_directory(tmp_path: Any) -> None:
    """Test that directories are rejected."""
    with pytest.raises(ValueError, match="not a file"):
        validate_file_path(str(tmp_path))


def test_validate_file_path_accepts_valid_file(tmp_path: Any) -> None:
    """Test that valid files are accepted."""
    test_file = tmp_path / "test.lisp"
    test_file.write_text("(+ 1 1)")

    result = validate_file_path(str(test_file))
    assert result.exists()
    assert result.is_file()


@pytest.mark.asyncio
async def test_code_length_limit() -> None:
    """Test that extremely long code is rejected."""
    long_code = "a" * 2_000_000  # 2MB of code

    result = await call_tool("evaluate", {"code": long_code})

    assert len(result) == 1
    assert "exceeds maximum length" in result[0].text


@pytest.mark.asyncio
async def test_query_event_injection_protection() -> None:
    """Test that query_event protects against code injection."""
    malicious_name = 'append")(+ 1 1)'

    result = await call_tool("query_event", {"name": malicious_name})

    assert len(result) == 1
    assert "Error" in result[0].text
    assert "Invalid" in result[0].text


@pytest.mark.asyncio
async def test_verify_guards_injection_protection() -> None:
    """Test that verify_guards protects against code injection."""
    malicious_name = 'len)(+ 1 1)'

    result = await call_tool("verify_guards", {"function_name": malicious_name})

    assert len(result) == 1
    assert "Error" in result[0].text
    assert "Invalid" in result[0].text


@pytest.mark.asyncio
async def test_check_theorem_injection_protection(tmp_path: Any) -> None:
    """Test that check_theorem protects against code injection."""
    # Create a valid file
    test_file = tmp_path / "test.lisp"
    test_file.write_text("(defthm test-thm (equal (+ 1 1) 2))")

    malicious_theorem = 'test-thm")(+ 1 1)'

    result = await call_tool(
        "check_theorem",
        {"file_path": str(test_file), "theorem_name": malicious_theorem},
    )

    assert len(result) == 1
    assert "Error" in result[0].text
    assert "Invalid" in result[0].text
