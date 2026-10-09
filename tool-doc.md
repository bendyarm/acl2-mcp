# ACL2 MCP Server - Tool Reference

> **Note**: This documentation was automatically extracted from the tool definitions in `acl2_mcp/server.py` on 2025-11-03. The source of truth for tool behavior is the Python code itself.

This document provides detailed reference documentation for all 9 tools provided by the ACL2 MCP server.

## Table of Contents

- [Session Management Tools](#session-management-tools)
  - [start_session](#start_session)
  - [end_session](#end_session)
  - [list_sessions](#list_sessions)
  - [interrupt_session](#interrupt_session)
  - [show_session_log](#show_session_log)
- [Code-based Tools](#code-based-tools)
  - [evaluate](#evaluate)
- [File-based Tools](#file-based-tools)
  - [certify_book](#certify_book)
- [Documentation Tools](#documentation-tools)
  - [xdoc_search](#xdoc_search)
  - [xdoc_show](#xdoc_show)

---

## Session Management Tools

### start_session

Start a new persistent ACL2 session. This creates a long-running ACL2 process that maintains state across multiple tool calls. Use this when you want to incrementally build up definitions and theorems without having to wrap everything in progn.

**Parameters:**

- `name` (optional): Optional human-readable name for the session. Example: 'natural-numbers-proof'
- `enable_logging` (optional): If true, log all I/O to a session file in ~/.acl2-mcp/sessions/ (default: true)
- `view_log_in_terminal` (optional): If true, open a terminal window showing the session log. If not specified, uses the config default (built-in default: true).
- `bring_to_front` (optional): If true, bring the session log Terminal window to the foreground. If not specified, uses the config default (built-in default: true).
- `log_tail_lines` (optional): Number of lines to show in log viewer (default: 50)
- `cwd` (optional): Optional working directory for the ACL2 process. If not specified, uses the current directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'

---

### end_session

End a persistent ACL2 session and clean up resources. Use this when you're done with incremental development.

**Parameters:**

- `session_id` (required): ID of the session to end

---

### list_sessions

List all active ACL2 sessions with their IDs, names, age, and idle time. Use this to see which sessions are available and their current state.

**Parameters:**

None

---

### interrupt_session

Send SIGINT (Ctrl-C) to interrupt a running ACL2 command in a session. Use this when ACL2 gets stuck in an infinite loop or a proof attempt is taking too long. This is equivalent to pressing Ctrl-C in an interactive ACL2 session.

**Parameters:**

- `session_id` (required): ID of the session to interrupt

---

### show_session_log

Show the session log in a terminal window. If a Terminal window is already tailing this session's log, it is activated and brought to the foreground. If not, a new Terminal window is opened. Requires logging to be enabled for the session.

**Parameters:**

- `session_id` (required): ID of the session whose log to show
- `log_tail_lines` (optional): Number of lines to show initially if opening a new window (default: 50)

---

## Code-based Tools

### evaluate

Evaluate ACL2 expressions or define functions (defun). Use this for: 1) Defining functions, 2) Computing values, 3) Testing expressions. Example: (defun factorial (n) (if (zp n) 1 (* n (factorial (- n 1))))) or (+ 1 2). Returns the ACL2 evaluation result.

**Parameters:**

- `code` (required): ACL2 code to evaluate
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)
- `session_id` (required): ID of the session to use

---

## File-based Tools

### certify_book

Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Book path can be relative or absolute, WITHOUT .lisp extension (e.g., 'books/kestrel/axe/top' not 'books/kestrel/axe/top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.

**Parameters:**

- `file_path` (required): Path to the book WITHOUT .lisp extension. Can be relative (e.g., 'books/kestrel/axe/top') or absolute. Relative paths are relative to current directory.
- `jobs` (optional): Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

## Documentation Tools

### xdoc_search

Search the local xdoc agent corpus (the built manual as one plain-text file per topic plus an index; produced by the acl2-docker project, shipped in the acl2-allcerts image at $ACL2_ROOT/books/doc/agent-corpus or named by the ACL2_XDOC_CORPUS environment variable) for topics matching a query.  Millisecond name/summary search; optional full-text body search.  Needs no ACL2 session.  Follow up with xdoc_show.

**Parameters:**

- `query` (required): Case-insensitive substring. Examples: 'tail recursion', 'bvplus'
- `full_text` (optional): Also search topic bodies (slower: ~1 s). Default false.
- `max_results` (optional): Maximum results (default 20).

---

### xdoc_show

Show one topic from the local xdoc agent corpus by natural name ('bvplus', 'fty::defbitstruct', 'acl2::defun') or xdoc key ('ACL2____BVPLUS'); a key with the wrong package is matched by its name part.  Covers every topic in the built manual, but NOT topics defined in the current session (use :doc via evaluate for those).  Needs no ACL2 session.

**Parameters:**

- `name` (required): Topic to show.
- `max_chars` (optional): Truncation limit for very large topics (default 20000).

---

## General Notes

### Sessions
- Sessions do **not** auto-timeout by default (SESSION_INACTIVITY_TIMEOUT = None)
- Maximum of 50 concurrent sessions server-wide
- Each session maintains its own ACL2 world state
- Sessions are isolated from each other

### Timeouts
- All timeouts are clamped to the range 1-300 seconds (5 minutes max)
- If no timeout is specified, operations run until completion (no timeout)
- Use timeouts to prevent infinite loops or very long-running operations

### Security Constraints
- **Maximum code length**: 1MB (1,000,000 characters) per request
- **Session names**: Alphanumeric characters, hyphens, underscores, and spaces allowed
  - Validated with pattern: `^[a-zA-Z0-9_\- ]+$`

### Execution

Every tool that runs ACL2 code runs it in a session:
- Uses existing ACL2 process via PTY
- Maintains state across commands
- Much faster for repeated operations (no startup cost)
- Enables incremental development workflow
- For a throwaway experiment in a clean world, start a second session and end it afterwards

### Background I/O and Logging

When `enable_logging=true` (default for sessions):
- All I/O is logged to `~/.acl2-mcp/sessions/SESSION_ID-TIMESTAMP.log`
- Background tasks continuously capture stdout and stderr
- Input commands are logged in natural format (appear after ACL2 prompt)
- Timestamps mark when inputs are sent and when interrupts occur
- Logs are written asynchronously using non-blocking I/O
- Log files persist after session termination for later review

---
