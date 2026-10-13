# ACL2 MCP Server - Tool Reference

> **Note**: The tool sections of this file are generated from the tool definitions in `acl2_mcp/server.py` by `scripts/gen_tool_doc.py`: change a description there, then run `python scripts/gen_tool_doc.py`.  The General Notes section at the end is written by hand.

This document describes the 9 tools of the ACL2 MCP server, as an agent sees them: each tool's description and parameters.

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
- [General Notes](#general-notes)

---

## Session Management Tools

### start_session

Start a persistent ACL2 session, whose world (definitions, theorems, included books) lasts across evaluate calls. All ACL2 evaluation happens in a session. For a clean world, start a separate session and end it when done. Returns the session ID and the session log's path.

**Parameters:**

- `name` (string, optional): Optional human-readable name for the session. Example: 'natural-numbers-proof'
- `enable_logging` (boolean, optional): If true, log all I/O to a session file in ~/.acl2-mcp/sessions/ (default: true)
- `view_log_in_terminal` (boolean, optional): If true, open a terminal window tailing the session log and bring it to the foreground. If not specified, uses the config default (built-in default: true).
- `log_tail_lines` (number, optional): Number of lines to show in log viewer (default: 50)
- `cwd` (string, optional): Optional working directory for the ACL2 process; relative include-book and ld paths are resolved against it. If not specified, uses the MCP server's working directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'

---

### end_session

End an ACL2 session; its world is lost (a busy ACL2 is killed). Don't end a session just because a command timed out or failed; the session is usually fine (see interrupt_session).

**Parameters:**

- `session_id` (string, required): ID of the session to end

---

### list_sessions

List all active ACL2 sessions with their IDs, names, age, and idle time, marking any whose ACL2 has exited. Use this to see which sessions are available and their current state.

**Parameters:**

None

---

### interrupt_session

Interrupt ACL2 like Ctrl-C: aborts the form being evaluated and discards any part of the command ACL2 hasn't read yet. The session and its world remain. Use it when a proof or computation takes too long, rather than ending the session. Waits up to 5 seconds for ACL2 to get back to its prompt, and returns what ACL2 printed (its abort message). In a proof, the first interrupt may only ask ACL2 to stop at its next check: if the reply says ACL2 isn't back at its prompt, call interrupt_session again.

**Parameters:**

- `session_id` (string, required): ID of the session to interrupt

---

### show_session_log

Show the session log in a terminal window. If a Terminal window is already tailing this session's log, it is activated and brought to the foreground. If not, a new Terminal window is opened. Requires logging to be enabled for the session.

**Parameters:**

- `session_id` (string, required): ID of the session whose log to show
- `log_tail_lines` (number, optional): Number of lines to show initially if opening a new window (default: 50)

---

## Code-based Tools

### evaluate

Send code to an ACL2 session as if typed at its prompt: events (defun, defthm, include-book, deflabel), expressions, and keyword commands (:pe, :pbt, :u, :ubu). Several forms per call are fine: each is sent once ACL2 has finished the one before, and the reply is ACL2's output up to its prompt after the last; look in it for 'ACL2 Error' or 'FAILED' (a failed event changes nothing). Code that ACL2 can't read, such as a form missing its ), is rejected and none of it is sent. Long output is shortened; the session log has all of it.

**Parameters:**

- `code` (string, required): ACL2 code to evaluate
- `timeout` (number, optional): Seconds to wait for the whole command (default 300, the most allowed). A timeout costs nothing: ACL2 is not interrupted, but keeps working (the rest of a command not yet fully sent is still sent), and the next evaluate waits for it to finish and shows its output first. So prefer a short timeout, such as 30: a runaway proof usually shows in the session log within 30 seconds. Give more only to a command known to take long, such as a hard proof or a lift. On a timeout, check the session log, then wait or call interrupt_session; don't end the session.
- `session_id` (string, required): ID of the session to use
- `as_is` (boolean, optional): Send the code exactly as given, in one piece, without reading it as ACL2 code: for a program that reads its own kind of input (default false).

---

## File-based Tools

### certify_book

Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Runs cert.pl as a separate process; sessions are not affected. Book path WITHOUT .lisp extension (e.g., '/path/to/books/kestrel/axe/top' not '.../top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.

**Parameters:**

- `file_path` (string, required): Path to the book WITHOUT .lisp extension. Use an absolute path: a relative one is resolved against the MCP server's working directory, not a session's.
- `jobs` (number, optional): Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.
- `timeout` (number, optional): Timeout in seconds (optional, no timeout if not specified). Unlike evaluate's timeout, this stops cert.pl and the jobs it started; the reply ends with cert.pl's last output.

---

## Documentation Tools

### xdoc_search

Search the local xdoc agent corpus (every manual topic as plain text; see the acl2-docker project's tools/DESIGN.md) for topics matching a query.  Fast (milliseconds) and works with no ACL2 session.  Searches topic names and one-line summaries by default; set full_text to search topic bodies too.  The corpus is found via the ACL2_XDOC_CORPUS environment variable, or at $ACL2_ROOT/books/doc/agent-corpus (present in the acl2-allcerts Docker image).  Use xdoc_show to read a found topic.

**Parameters:**

- `query` (string, required): Case-insensitive substring to search for. Examples: 'tail recursion', 'bvplus', 'measure'
- `full_text` (boolean, optional): Also search topic bodies, not just names and summaries (slower: ~1 s). Default false.
- `max_results` (number, optional): Maximum results to return (default 20).

---

### xdoc_show

Show a topic from the local xdoc agent corpus by name.  Accepts a natural name ('bvplus', 'fty::defbitstruct', 'acl2::defun') or an xdoc key ('ACL2____BVPLUS'); a key with the wrong package is matched by its name part.  Fast and needs no ACL2 session; covers every topic in the built manual, but NOT topics defined in your own session (use :doc via evaluate for those).  Corpus location: see xdoc_search.

**Parameters:**

- `name` (string, required): Topic to show. Examples: 'bvplus', 'fty::defbitstruct', 'ACL2____DEFTHM-STP'
- `max_chars` (number, optional): Truncate the topic body beyond this many characters (default 20000; some topics, e.g. release notes, are very large).

---

## General Notes

### Sessions
- Sessions do **not** auto-timeout by default (SESSION_INACTIVITY_TIMEOUT = None)
- Maximum of 50 concurrent sessions server-wide
- Each session maintains its own ACL2 world state
- Sessions are isolated from each other

### Timeouts
- `evaluate` timeouts are clamped to the range 1-300 seconds (5 minutes max), and default to 300
- `certify_book` timeouts are not clamped, and there is none unless one is given
- An `evaluate` timeout only stops waiting: ACL2 keeps working, the next `evaluate` waits for it, and `interrupt_session` stops it.  Cancelling an `evaluate` call interrupts ACL2.  A `certify_book` timeout, or cancelling the call, stops cert.pl and the jobs it started.

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
