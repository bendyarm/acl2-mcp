"""Runtime configuration for acl2-mcp."""

from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Any, TextIO

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "acl2-mcp" / "config.toml"


@dataclass(frozen=True)
class SessionLogConfig:
    """Session log viewer defaults."""

    view_log_in_terminal: bool = True
    close_log_on_end: bool = True


@dataclass(frozen=True)
class ToolOutputConfig:
    """Tool output size limits."""

    max_output_chars: int = 5000
    head_chars: int = 400
    tail_chars: int = 4000


@dataclass(frozen=True)
class ServerConfig:
    """Top-level server configuration."""

    session_log: SessionLogConfig = field(default_factory=SessionLogConfig)
    tool_output: ToolOutputConfig = field(default_factory=ToolOutputConfig)
    debug_logging: bool = False


def load_config(
    config_path: Path | None = None,
    stderr: TextIO | None = None,
) -> ServerConfig:
    """
    Load runtime configuration from TOML.

    Missing config files are ignored. Malformed TOML falls back to built-in
    defaults. Validation errors are reported per setting and valid settings are
    still applied.
    """
    resolved_path = config_path or DEFAULT_CONFIG_PATH
    warning_stream = stderr if stderr is not None else sys.stderr
    defaults = ServerConfig()

    if not resolved_path.exists():
        return defaults

    try:
        with resolved_path.open("rb") as config_handle:
            raw_config = tomllib.load(config_handle)
    except tomllib.TOMLDecodeError as exc:
        _warn(
            warning_stream,
            f"failed to parse config {resolved_path}: {exc}. "
            "Ignoring config and using built-in defaults.",
        )
        return defaults
    except OSError as exc:
        _warn(
            warning_stream,
            f"failed to read config {resolved_path}: {exc}. "
            "Ignoring config and using built-in defaults.",
        )
        return defaults

    if not isinstance(raw_config, dict):
        _warn(
            warning_stream,
            f"ignoring config {resolved_path}: expected a TOML table at the top level. "
            "Using built-in defaults.",
        )
        return defaults

    return _merge_config(defaults, raw_config, resolved_path, warning_stream)


def _merge_config(
    defaults: ServerConfig,
    raw_config: dict[str, Any],
    config_path: Path,
    warning_stream: TextIO,
) -> ServerConfig:
    session_log = defaults.session_log

    known_top_level_keys = {"session_log", "tool_output", "debug_logging"}
    for key in raw_config:
        if key not in known_top_level_keys:
            _warn(
                warning_stream,
                f"ignoring unknown config section '{key}' in {config_path}.",
            )

    raw_session_log = raw_config.get("session_log")
    if raw_session_log is not None:
        if not isinstance(raw_session_log, dict):
            _warn(
                warning_stream,
                f"ignoring invalid config section 'session_log' in {config_path}: "
                "expected a TOML table.",
            )
        else:
            session_log = SessionLogConfig(
                view_log_in_terminal=_read_bool_setting(
                    raw_session_log,
                    "session_log",
                    "view_log_in_terminal",
                    session_log.view_log_in_terminal,
                    config_path,
                    warning_stream,
                ),
                close_log_on_end=_read_bool_setting(
                    raw_session_log,
                    "session_log",
                    "close_log_on_end",
                    session_log.close_log_on_end,
                    config_path,
                    warning_stream,
                ),
            )
            for key in raw_session_log:
                if key not in {"view_log_in_terminal", "close_log_on_end"}:
                    _warn(
                        warning_stream,
                        f"ignoring unknown config key 'session_log.{key}' in {config_path}.",
                    )

    tool_output = defaults.tool_output

    raw_tool_output = raw_config.get("tool_output")
    if raw_tool_output is not None:
        if not isinstance(raw_tool_output, dict):
            _warn(
                warning_stream,
                f"ignoring invalid config section 'tool_output' in {config_path}: "
                "expected a TOML table.",
            )
        else:
            tool_output = ToolOutputConfig(
                max_output_chars=_read_int_setting(
                    raw_tool_output, "tool_output", "max_output_chars",
                    tool_output.max_output_chars, config_path, warning_stream,
                ),
                head_chars=_read_int_setting(
                    raw_tool_output, "tool_output", "head_chars",
                    tool_output.head_chars, config_path, warning_stream,
                ),
                tail_chars=_read_int_setting(
                    raw_tool_output, "tool_output", "tail_chars",
                    tool_output.tail_chars, config_path, warning_stream,
                ),
            )
            for key in raw_tool_output:
                if key not in {"max_output_chars", "head_chars", "tail_chars"}:
                    _warn(
                        warning_stream,
                        f"ignoring unknown config key 'tool_output.{key}' in {config_path}.",
                    )

    debug_logging = defaults.debug_logging
    raw_debug_logging = raw_config.get("debug_logging")
    if raw_debug_logging is not None:
        if isinstance(raw_debug_logging, bool):
            debug_logging = raw_debug_logging
        else:
            _warn(
                warning_stream,
                f"ignoring invalid value for 'debug_logging' in {config_path}: "
                "expected boolean.",
            )

    return ServerConfig(session_log=session_log, tool_output=tool_output, debug_logging=debug_logging)


def _read_bool_setting(
    table: dict[str, Any],
    section_name: str,
    key: str,
    default: bool,
    config_path: Path,
    warning_stream: TextIO,
) -> bool:
    if key not in table:
        return default

    value = table[key]
    if isinstance(value, bool):
        return value

    _warn(
        warning_stream,
        f"ignoring invalid value for '{section_name}.{key}' in {config_path}: "
        "expected boolean.",
    )
    return default


def _read_int_setting(
    table: dict[str, Any],
    section_name: str,
    key: str,
    default: int,
    config_path: Path,
    warning_stream: TextIO,
) -> int:
    if key not in table:
        return default

    value = table[key]
    if isinstance(value, int) and not isinstance(value, bool):
        if value > 0:
            return value
        _warn(
            warning_stream,
            f"ignoring invalid value for '{section_name}.{key}' in {config_path}: "
            "expected positive integer.",
        )
        return default

    _warn(
        warning_stream,
        f"ignoring invalid value for '{section_name}.{key}' in {config_path}: "
        "expected integer.",
    )
    return default


def _warn(warning_stream: TextIO, message: str) -> None:
    print(f"Warning: {message}", file=warning_stream)
