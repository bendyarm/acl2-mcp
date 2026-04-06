# AGENTS.md

This file provides guidance to an agent when working with code in this repository.

This file should be kept consistent with `CLAUDE.md` and `.claude/skills/**/SKILL.md`,
which are used by Claude Code.

## Project Overview

This is an MCP (Model Context Protocol) server that provides tools for interacting with the ACL2 theorem prover. The server enables AI assistants to work with ACL2 through persistent sessions for incremental development (preferred), or one-off execution for special cases.

## Architecture

### Core Components

- **[acl2_mcp/server.py](acl2_mcp/server.py)**: Main server implementation containing:
  - Tool definitions and handlers (`list_tools()`, `call_tool()`)
  - ACL2 execution functions (`run_acl2()`, `run_acl2_file()`)
  - Session management (`SessionManager`, `ACL2Session`)
  - Security validation functions (timeout, file path, identifiers, etc.)

### Execution Modes

1. **Persistent sessions** (preferred): Long-running ACL2 processes for incremental work
   - Managed by `SessionManager` (singleton: `session_manager`)
   - Uses PTY for bidirectional communication (see `docs/architecture.md` for architecture)
   - Sessions maintain ACL2 world state across commands
   - Auto-cleanup after 30 minutes inactivity
   - Max 50 concurrent sessions

2. **One-off execution**: Each tool call creates a fresh ACL2 process
   - Rarely used; mainly for testing ACL2 startup file handling
   - Code written to temp `.lisp` file
   - ACL2 process started with code as input
   - Output captured and returned
   - Resources cleaned up

### Session Communication

Sessions use prompt detection to identify command completion:
- Commands sent via PTY master (chunked writes for large inputs)
- Background reader continuously captures output to a buffer
- `send_command()` waits for prompt patterns to appear in output
- Prompt patterns match ACL2 (`.*>[ ]*$`), SBCL debugger (`.*\] $`), and raw Lisp (`.*\* $`)
- Based on Emacs `emacs-acl2.el` prompt detection
- See `docs/architecture.md` for full details

### Security Features

Security validation (see `SECURITY.md`):
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
   - Use session if `session_id` provided (preferred), otherwise one-off execution
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

## Specific skills for using ACL2

Each skill documented here should be kept in sync with the files
`.claude/skills/**/SKILL.md`.

### acl2-doc-lookup

Use this skill to look up ACL2 documentation for symbols, functions, macros, and concepts.

#### URL Pattern

The ACL2 documentation has an SEO-friendly interface that loads quickly, for example:

```
https://acl2.org/doc/index-seo.php?xkey=PACKAGE____SYMBOL
```

Note: The separator between package and symbol is **four underscores** (`____`).

#### Common Packages

- `ACL2` - Most built-in functions, macros, and the main part of the Axe toolkit
- `COMMON-LISP` - Common Lisp primitives available in ACL2
- `BUILD` - Build system utilities (cert.pl, depends-on, etc.)
- `FTY` - Data types
- `STD` - Std Utilities, including `Define` and `Defines`
- `STR` - String utilities from Std
- `X86ISA` - x86 model and related functions (x86isa project)
- `X` - x86 specific parts of the Axe toolkit

#### Hard-to-Guess Package Mappings

Some symbols are in unexpected packages.  For example:

```lisp
ACL2 !>(symbol-package-name 'symbol-package)
(symbol-package-name 'symbol-package)
"COMMON-LISP"
ACL2 !>(symbol-package-name 'symbol-package-name)
(symbol-package-name 'symbol-package-name)
"ACL2"
```

#### How to Look Up Documentation

1. **Determine the package**: Most symbols are in `ACL2`, so if you are not sure, try that.
   Source files have an `in-package` form at the top.  In the REPL, the ACL2 prompt shows
   the current package, so if a symbol is usable in that context, you can see
   its package by calling `symbol-package-name` on it.

2. **Construct the URL**:
   a. Start with the symbol's package name (e.g., `ACL2`)
   b. Append `____` (four underscores) as the package separator
   c. Append the `symbol-name`, applying these rules:
      - If the symbol prints without `|...|` bars, upcase it
      - If the symbol prints with `|...|` bars, preserve its case
      - Keep hyphens as-is
      - Replace each other non-alphanumeric character with `_XX`
        where XX is the two hex digits of its ASCII code, reversed
        (e.g., `*` = 0x2A → `_A2`, `+` = 0x2B → `_B2`, space = 0x20 → `_02`)
   d. Prepend `https://acl2.org/doc/index-seo.php?xkey=`

   Examples:
   - `x86isa` → `ACL2____X86ISA`
   - `*ACL2-exports*` → `ACL2_____A2ACL2-EXPORTS_A2` (note: five underscores — four for `::` and one that begins `_A2`)
   - `Modeling Algorithms in C++ and ACL2` → `RTL____Modeling_02Algorithms_02in_02C_B2_B2_02and_02ACL2` (a `|...|`-escaped symbol created for a documentation topic, so it has lowercase and spaces)

3. **Fetch the page**: Use WebFetch with a prompt to extract the relevant information.

4. **Follow subtopic links**: Documentation pages often link to subtopics with more detail. The link pattern includes `xkey=PACKAGE____SUBTOPIC`.

#### Example Usage

To look up documentation for `def-simplified`:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____DEF-SIMPLIFIED",
  prompt: "Show the complete documentation including function signature, parameters, and usage examples. List all subtopics."
)
```

To look up Axe rewriter tools:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____AXE-REWRITERS",
  prompt: "List all available rewriter tools and their descriptions."
)
```

#### Tips

- Documentation pages often have subtopics - follow these links for detailed information
- The SEO pages load much faster than the main `https://acl2.org/doc` interface
- When the web doc is sparse, check for comments and read the code in the relevant
  source file in the ACL2 community books source tree `/path/to/acl2/books/`.

#### Some Useful Top-Level Topics

- `ACL2____DEFTHM` - Theorem proving
- `ACL2____HINTS` - Proof hints
- `ACL2____BV` - Bitvector operations
- `ACL2____X86ISA` - x86 instruction set architecture model
- `ACL2____AXE` - Axe toolkit overview
- `ACL2____AXE-REWRITERS` - Rewriter tools (def-simplified, rewriter-basic, etc.)

