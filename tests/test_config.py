"""Tests for acl2-mcp runtime configuration."""

from io import StringIO
from pathlib import Path
from typing import Any

import pytest

import acl2_mcp.server as server
from acl2_mcp.config import ServerConfig, ToolOutputConfig, load_config
from acl2_mcp.server import elide_large_output


def test_load_config_missing_file_uses_defaults() -> None:
    """Missing config files should silently use built-in defaults."""
    warning_output = StringIO()

    config = load_config(Path("/tmp/acl2-mcp-config-does-not-exist.toml"), stderr=warning_output)

    assert config == ServerConfig()
    assert warning_output.getvalue() == ""


def test_load_config_valid_file_overrides_defaults(tmp_path: Path) -> None:
    """Valid TOML settings should override the built-in defaults."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[session_log]\n"
        "view_log_in_terminal = false\n",
        encoding="utf-8",
    )

    config = load_config(config_path, stderr=StringIO())

    assert config.session_log.view_log_in_terminal is False


def test_load_config_warns_per_invalid_setting_and_keeps_valid_ones(tmp_path: Path) -> None:
    """Unknown and invalid settings should be ignored individually."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[session_log]\n"
        "view_log_in_terminal = false\n"
        "extra_setting = true\n"
        "\n"
        "[unknown_section]\n"
        "value = true\n",
        encoding="utf-8",
    )
    warning_output = StringIO()

    config = load_config(config_path, stderr=warning_output)

    assert config.session_log.view_log_in_terminal is False
    warnings = warning_output.getvalue()
    assert "session_log.extra_setting" in warnings
    assert "unknown_section" in warnings


def test_load_config_malformed_toml_falls_back_to_defaults(tmp_path: Path) -> None:
    """Malformed TOML should cause the whole file to be ignored."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[session_log\n"
        "view_log_in_terminal = true\n",
        encoding="utf-8",
    )
    warning_output = StringIO()

    config = load_config(config_path, stderr=warning_output)

    assert config == ServerConfig()
    assert "failed to parse config" in warning_output.getvalue()


@pytest.mark.asyncio
async def test_start_session_tool_uses_new_parameter_names() -> None:
    """The public tool schema should advertise the renamed log viewer settings."""
    tools = await server.list_tools()
    start_session_tool = next(tool for tool in tools if tool.name == "start_session")
    properties = start_session_tool.inputSchema["properties"]

    assert "view_log_in_terminal" in properties
    assert "bring_to_front" not in properties
    assert "enable_log_viewer" not in properties
    assert properties["view_log_in_terminal"]["default"] is True


@pytest.mark.asyncio
async def test_call_tool_start_session_forwards_new_log_viewer_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """call_tool should forward the renamed start_session arguments."""
    captured_args: dict[str, Any] = {}

    async def fake_start_session(*args: Any) -> tuple[str, str]:
        captured_args["args"] = args
        return "session-123", "Session started successfully. ID: session-123"

    monkeypatch.setattr(server.session_manager, "start_session", fake_start_session)

    result = await server.call_tool(
        "start_session",
        {
            "name": "demo",
            "enable_logging": True,
            "view_log_in_terminal": False,
            "log_tail_lines": 25,
            "cwd": "/tmp",
        },
    )

    assert len(result) == 1
    assert "Session started successfully" in result[0].text
    assert captured_args["args"] == ("demo", True, False, 25, "/tmp")


def test_load_config_tool_output_overrides_defaults(tmp_path: Path) -> None:
    """Valid tool_output settings should override the built-in defaults."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[tool_output]\n"
        "max_output_chars = 10000\n"
        "head_chars = 800\n"
        "tail_chars = 8000\n",
        encoding="utf-8",
    )

    config = load_config(config_path, stderr=StringIO())

    assert config.tool_output.max_output_chars == 10000
    assert config.tool_output.head_chars == 800
    assert config.tool_output.tail_chars == 8000


def test_elide_large_output_short_output_unchanged() -> None:
    """Output within the limit should be returned unchanged."""
    config = ToolOutputConfig(max_output_chars=100, head_chars=20, tail_chars=50)
    output = "short output"

    result = elide_large_output(output, config, None)

    assert result == output


def test_elide_large_output_long_output_elided() -> None:
    """Output exceeding the limit should be elided with head, warning, and tail."""
    config = ToolOutputConfig(max_output_chars=100, head_chars=10, tail_chars=20)
    output = "A" * 200

    result = elide_large_output(output, config, Path("/tmp/test.log"))

    assert result.startswith("A" * 10)
    assert "[WARNING: Large output elided (200 chars)" in result
    assert "/tmp/test.log" in result
    assert result.endswith("A" * 20)
