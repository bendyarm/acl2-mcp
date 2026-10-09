"""Security tests for ACL2 MCP server."""

from acl2_mcp.server import validate_timeout


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
