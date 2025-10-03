# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that provides tools for interacting with the ACL2 theorem prover. The server enables AI assistants to work with ACL2 through 15 different tools, supporting both one-off execution and persistent sessions for incremental development.

## Architecture

### Core Components

- **[acl2_mcp/server.py](acl2_mcp/server.py)**: Main server implementation containing:
  - Tool definitions and handlers (`list_tools()`, `call_tool()`)
  - ACL2 execution functions (`run_acl2()`, `run_acl2_file()`)
  - Session management (`SessionManager`, `ACL2Session`)
  - Security validation functions (timeout, file path, identifiers, etc.)

### Execution Modes

1. **One-off execution** (default): Each tool call creates a fresh ACL2 process
   - Code written to temp `.lisp` file
   - ACL2 process started with code as input
   - Output captured and returned
   - Resources cleaned up

2. **Persistent sessions**: Long-running ACL2 processes for incremental work
   - Managed by `SessionManager` (singleton: `session_manager`)
   - Each session has stdin/stdout pipes for bidirectional communication
   - Sessions maintain ACL2 world state across commands
   - Auto-cleanup after 30 minutes inactivity
   - Max 50 concurrent sessions

### Session Communication

Sessions use a marker-based protocol to detect command completion:
- Commands sent via stdin
- Cryptographically random marker sent after each command: `___MARKER_{uuid}_{uuid}___`
- Reads stdout until marker appears or timeout
- True total timeout (not per-line) prevents DoS

### Security Features

Security validation is extensive (see `SECURITY.md`):
- Input validation: code length (1MB max), timeout (1-300s), file paths, identifiers
- Path traversal prevention: all paths resolved to absolute
- Command injection prevention: ACL2 strings escaped, identifiers validated
- DoS prevention: session limits, timeout enforcement, checkpoint limits
- No internal error details leaked to clients

## Development Commands

### Setup
```bash
# Create virtual environment and install
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Running the Server
```bash
# Direct execution
acl2-mcp

# Via Python module
python -m acl2_mcp.server
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
python -m pytest tests/test_server.py -v

# Run with verbose output and short traceback
python -m pytest tests/ -v --tb=short
```

### Type Checking
```bash
# Type check with mypy (strict mode enabled)
python -m mypy acl2_mcp/
```

## Testing Architecture

Test organization:
- **[tests/test_server.py](tests/test_server.py)**: Core functionality tests (tools, ACL2 execution)
- **[tests/test_security.py](tests/test_security.py)**: Security validation tests
- **[tests/test_sessions.py](tests/test_sessions.py)**: Session management tests

All tests use `pytest-asyncio` for async testing.

## Tool Implementation Pattern

When adding/modifying tools:

1. Add tool definition to `list_tools()` with:
   - Clear description (optimized for AI understanding)
   - Complete `inputSchema` with types and descriptions
   - Required fields marked in schema

2. Add handler in `call_tool()`:
   - Extract and validate all arguments
   - Use appropriate validation functions
   - Use session if `session_id` provided, otherwise one-off execution
   - Return `Sequence[TextContent]` (usually single-element list)

3. For session commands:
   - Check session exists: `session_manager.get_session(session_id)`
   - Send command: `await session.send_command(code, timeout)`
   - Session lock already handled by `send_command()`

## Key Constraints

- **ACL2 dependency**: Server requires ACL2 in PATH (exits gracefully if missing)
- **Python 3.10+**: Uses modern type hints (including `dict[str, X]` syntax)
- **Strict typing**: `mypy --strict` enforced in CI/development
- **File path conventions**:
  - Books: WITHOUT `.lisp` extension (certify_book, include_book)
  - Regular files: WITH `.lisp` extension (check_theorem, query_event)
- **Async throughout**: All I/O operations use asyncio
