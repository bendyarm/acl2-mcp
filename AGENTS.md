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

### acl2-session-start

This skill starts a persistent ACL2 session using the Model Context Protocol (MCP) ACL2 server.

#### Instructions

1. **Check MCP ACL2 server availability**:
   - Attempt to use `mcp__acl2__list_sessions` to verify the MCP ACL2 server is available
   - **If the tool is not available or returns an error**:
     - Report: "Sorry, the MCP ACL2 server is not available. The MCP server must be configured properly."
     - **STOP** - do not continue with the remaining steps in this skill or any subsequent steps in any calling skill
   - **If successful**, proceed to step 2

2. **Determine working directory for ACL2**:
   - The `mcp__acl2__start_session` tool now accepts an optional `cwd` parameter
   - **If the user has specified a working directory** (e.g., for x86 lifting work in a specific examples directory):
     - Use that directory as the `cwd` parameter when starting the session
   - **Otherwise**:
     - Use `pwd` to check the current directory
     - This will be the ACL2 session's working directory (no need to pass `cwd`)

3. **Check for existing sessions**:
   - Use `mcp__acl2__list_sessions` to see if there are already active sessions
   - **If one existing session**:
     - Use AskUserQuestion to ask if they want to use the existing session
     - If yes, use that session_id (skip to step 6)
     - If no, proceed to start a new session (step 4)
   - **If multiple existing sessions**:
     - Use AskUserQuestion to ask which session to use, or if they want to start a new one
     - Show session names, IDs, and their ages/event counts to help the user decide
     - If they choose an existing session, use that session_id (skip to step 6)
     - If they choose to start new, proceed to step 4
   - **If no existing sessions**:
     - Proceed to start a new session (step 4)

4. **Start new session**:
   - Use `mcp__acl2__start_session` with `enable_logging: true` to create a new persistent ACL2 session
   - Provide a descriptive name parameter (optional but recommended)
     - For general work, use: "acl2-session" or similar

5. **Save session ID**:
   - The tool will return a `session_id`
   - Remember this ID for use in subsequent ACL2 operations
   - This ID is needed for:
     - `mcp__acl2__evaluate` (defining functions, evaluating expressions)
     - `mcp__acl2__prove` (proving theorems)
     - `mcp__acl2__include_book` (loading books)
     - Other MCP ACL2 tools

6. **Report success**:
   - Confirm which session is being used (existing or newly created)
   - Display the session ID
   - Display the log file path (if logging is enabled)
   - **Always** output this information to the user before proceeding with any other commands

#### Example

```
ACL2 session started. Session ID: abc123
Log file: /Users/user/.acl2-mcp/sessions/abc123-20260405-110632.log
```

#### Notes

- Sessions maintain state across multiple tool calls
- You can have multiple sessions active simultaneously
- The session ID is required for all subsequent ACL2 operations in that session

#### Session Lifecycle - Don't End Sessions Unnecessarily

**Important**: When something goes wrong (timeout, error, proof failure), the session is usually fine and can continue to be used. Do NOT end the session just because of an error.

**When to use keyboard interrupt** (not end session):
- ACL2 appears stuck with no prompt appearing
- A proof is churning with way too many subgoals
- Use `mcp__acl2__interrupt_session` to send Ctrl-C

**After sending an interrupt**, check if the session is responsive:
- Send an innocuous command like `t` or `(+ 1 1)` to verify ACL2 is responding, or if there is a session log, you can tail it to see the current status.
- **NEVER** use `:good-bye`, `:q`, or `(quit)` to "check" status - these will exit ACL2!
- If the session responds, you can continue working
- If it doesn't respond, you may need to end the session and start fresh

**When ending a session is appropriate** (rare):
- You're completely done with ACL2 work
- You need to start fresh with a clean ACL2 state
- The session process has actually crashed (not just timed out)

**On timeout**: Check the session log (`tail -20 <log-file>`) to see if ACL2 actually responded. A timeout often means the MCP server missed the prompt, not that ACL2 is stuck. You can usually just continue with the next command.

#### Monitoring Long-Running Operations

**Use `tail` on the session log** instead of repeatedly calling `mcp__acl2__evaluate` with `t` or using `mcp__acl2__get_world_state` to monitor progress. The session log shows actual ACL2 output in real-time.

```bash
# See recent output (last 100 lines)
tail -100 /path/to/session-log.log

# Follow output in real-time (for very long operations)
tail -f /path/to/session-log.log
```

The log file path is returned when starting the session. This approach is:
- More efficient (no round-trips to ACL2)
- Shows actual errors and warnings
- Displays proof progress and subgoal information
- Works even if the MCP tool times out
