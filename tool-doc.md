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

Start a persistent ACL2 session, whose world (definitions, theorems, included books) lasts across evaluate calls. All ACL2 evaluation happens in a session. For a clean world, start a separate session and end it when done. Returns the session ID and the session log's path.

**Parameters:**

- `name` (optional): Optional human-readable name for the session. Example: 'natural-numbers-proof'
- `enable_logging` (optional): If true, log all I/O to a session file in ~/.acl2-mcp/sessions/ (default: true)
- `view_log_in_terminal` (optional): If true, open a terminal window tailing the session log and bring it to the foreground. If not specified, uses the config default (built-in default: true).
- `log_tail_lines` (optional): Number of lines to show in log viewer (default: 50)
- `cwd` (optional): Optional working directory for the ACL2 process; relative include-book and ld paths are resolved against it. If not specified, uses the MCP server's working directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'

---

### end_session

End an ACL2 session; its world is lost (a busy ACL2 is killed). Don't end a session just because a command timed out or failed; the session is usually fine (see interrupt_session).

**Parameters:**

- `session_id` (required): ID of the session to end

---

### list_sessions

List all active ACL2 sessions with their IDs, names, age, and idle time. Use this to see which sessions are available and their current state.

**Parameters:**

None

---

### interrupt_session

Interrupt ACL2 like Ctrl-C: aborts the form being evaluated and discards any part of the command ACL2 hasn't read yet. The session and its world remain. Use it when a proof or computation takes too long, rather than ending the session. Returns once the interrupt is sent; ACL2's abort message appears at the start of the next evaluate reply.

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

Send code to an ACL2 session as if typed at its prompt: events (defun, defthm, include-book, deflabel), expressions, and keyword commands (:pe, :pbt, :u, :ubu). Several forms per call are fine. Returns ACL2's output up to its next prompt; look in it for 'ACL2 Error' or 'FAILED' (a failed event changes nothing). Long output is shortened; the session log has all of it.

**Parameters:**

- `code` (required): ACL2 code to evaluate
- `timeout` (optional): Seconds to wait for the whole command (no limit if not given). On a timeout ACL2 is not interrupted: it keeps working (a command not yet fully sent is still sent), and its later output appears in the session log and at the start of the next reply. Check the log, then wait or call interrupt_session; don't end the session.
- `session_id` (required): ID of the session to use

---

## File-based Tools

### certify_book

Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Runs cert.pl as a separate process; sessions are not affected. Book path WITHOUT .lisp extension (e.g., '/path/to/books/kestrel/axe/top' not '.../top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.

**Parameters:**

- `file_path` (required): Path to the book WITHOUT .lisp extension. Use an absolute path: a relative one is resolved against the MCP server's working directory, not a session's.
- `jobs` (optional): Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified). Unlike evaluate's timeout, this stops cert.pl and the jobs it started; the reply ends with cert.pl's last output.

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
- `evaluate` timeouts are clamped to the range 1-300 seconds (5 minutes max); `certify_book` timeouts are not
- If no timeout is specified, operations run until completion (no timeout)
- An `evaluate` timeout only stops waiting: ACL2 keeps working, and `interrupt_session` stops it.  A `certify_book` timeout, or cancelling the call, stops cert.pl and the jobs it started.

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
