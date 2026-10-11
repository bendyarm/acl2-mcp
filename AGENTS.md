# AGENTS.md

This file provides guidance to an agent **working on `acl2-mcp` itself**
(the MCP server source). It describes the architecture, build, and test
commands for this codebase.

If you are an end user *using* `acl2-mcp` to drive ACL2 from an agent —
not modifying the server — see `for-agents/AGENTS.md` instead.

This file should be kept consistent with `CLAUDE.md`, which provides the
same content for Claude Code.

## Project Overview

This is an MCP (Model Context Protocol) server that provides tools for interacting with the ACL2 theorem prover. The server enables AI assistants to work with ACL2 through persistent sessions for incremental development.

## Architecture

### Core Components

- **[acl2_mcp/server.py](acl2_mcp/server.py)**: Main server implementation containing:
  - Tool definitions and handlers (`list_tools()`, `call_tool()`)
  - Book certification (`certify_acl2_book()`, which runs `cert.pl`)
  - Session management (`SessionManager`, `ACL2Session`)
  - Security validation functions (timeout, session name, integer bounds)
- **[acl2_mcp/reader.py](acl2_mcp/reader.py)**: ACL2's reader syntax: a lexer and
  a splitter into top-level forms, following the ABNF grammar in the community
  books (`books/kestrel/acl2pl/grammar.abnf`) where it agrees with ACL2's reader

### Sessions

Every tool that runs ACL2 code runs it in a persistent session, a
long-running ACL2 process:
- Managed by `SessionManager` (singleton: `session_manager`)
- Uses PTY for bidirectional communication (see `docs/architecture.md` for architecture)
- Sessions maintain ACL2 world state across commands
- No idle cleanup (`SESSION_INACTIVITY_TIMEOUT = None`); sessions last until ended
- Max 50 concurrent sessions

For a throwaway clean world, a client starts a separate session and ends
it afterwards.

### Session Communication

Sessions use prompt detection to identify command completion:
- Commands are split into top-level forms (`acl2_mcp/reader.py`) and sent via
  the PTY master one form at a time, each once ACL2 has printed its prompt
  after the one before; unreadable code, and code with a C-c, C-\ or C-z
  (which the terminal would turn into a signal), is rejected before
  anything is sent
- Background reader continuously captures output to a buffer
- `send_command()` waits for prompt patterns to appear in output
- Prompt patterns match ACL2 (`.*>[ ]*$`, which covers break-rewrite,
  wormholes, and CCL's debugger and inspector), the proof builder (`->: `),
  ACL2 queries, walkabout (`:`), SBCL's debugger (`.*\] $`), and raw Lisp
  (`.*\* $` SBCL, `? ` CCL); on a timeout, an unknown prompt is adopted
- Based on Emacs `emacs-acl2.el` prompt detection
- See `docs/architecture.md` for full details

### Security Features

Security validation (see `SECURITY.md`):
- Input validation: code length (1MB max), timeout (1-300s), session names, integer bounds
- DoS prevention: session limits, timeout enforcement
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
- **[tests/test_reader.py](tests/test_reader.py)**: Tests of the reader module's interface
- **[tests/test_reader_vs_acl2.py](tests/test_reader_vs_acl2.py)**: Compares the reader
  with ACL2's own reader (runs `acl2` in batch), on snippets and on
  `books/kestrel/acl2pl/reader-tests.lisp` and `*.tests` when present

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
   - Tools that run ACL2 code take a required `session_id` (enforced by a test)
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
  - Books: WITHOUT `.lisp` extension (certify_book)
- **Async throughout**: All I/O operations use asyncio
