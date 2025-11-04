# ACL2 MCP Server - Tool Reference

> **Note**: This documentation was automatically extracted from the tool definitions in `acl2_mcp/server.py` on 2025-11-03. The source of truth for tool behavior is the Python code itself.

This document provides detailed reference documentation for all 17 tools provided by the ACL2 MCP server.

## Table of Contents

- [Session Management Tools](#session-management-tools)
  - [start_session](#start_session)
  - [end_session](#end_session)
  - [list_sessions](#list_sessions)
  - [interrupt_session](#interrupt_session)
- [Code-based Tools](#code-based-tools)
  - [prove](#prove)
  - [evaluate](#evaluate)
  - [check_syntax](#check_syntax)
  - [admit](#admit)
- [File-based Tools](#file-based-tools)
  - [certify_book](#certify_book)
  - [include_book](#include_book)
  - [check_theorem](#check_theorem)
- [Query and Verification Tools](#query-and-verification-tools)
  - [query_event](#query_event)
  - [verify_guards](#verify_guards)
- [Session State Management Tools](#session-state-management-tools)
  - [undo](#undo)
  - [save_checkpoint](#save_checkpoint)
  - [restore_checkpoint](#restore_checkpoint)
  - [get_world_state](#get_world_state)
  - [retry_proof](#retry_proof)

---

## Session Management Tools

### start_session

Start a new persistent ACL2 session. This creates a long-running ACL2 process that maintains state across multiple tool calls. Use this when you want to incrementally build up definitions and theorems without having to wrap everything in progn.

**Parameters:**

- `name` (optional): Optional human-readable name for the session. Example: 'natural-numbers-proof'
- `enable_logging` (optional): If true, log all I/O to a session file in ~/.acl2-mcp/sessions/ (default: true)
- `enable_log_viewer` (optional): If true, open a terminal window showing the session log (default: false)
- `log_tail_lines` (optional): Number of lines to show in log viewer (default: 50)
- `cwd` (optional): Optional working directory for the ACL2 process. If not specified, uses the current directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'

---

### end_session

End a persistent ACL2 session and clean up resources. Use this when you're done with incremental development.

**Parameters:**

- `session_id` (required): ID of the session to end

---

### list_sessions

List all active ACL2 sessions with their IDs, names, age, idle time, and event count. Use this to see which sessions are available and their current state.

**Parameters:**

None

---

### interrupt_session

Send SIGINT (Ctrl-C) to interrupt a running ACL2 command in a session. Use this when ACL2 gets stuck in an infinite loop or a proof attempt is taking too long. This is equivalent to pressing Ctrl-C in an interactive ACL2 session.

**Parameters:**

- `session_id` (required): ID of the session to interrupt

---

## Code-based Tools

### prove

Submit an ACL2 theorem (defthm) for proof. Use this to prove mathematical properties. Example: (defthm append-nil (implies (true-listp x) (equal (append x nil) x))). The theorem will be proven and added to the ACL2 world. Returns detailed ACL2 proof output. Can optionally use a persistent session for incremental development.

**Parameters:**

- `code` (required): ACL2 code to prove (e.g., defthm form)
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)
- `session_id` (optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

---

### evaluate

Evaluate ACL2 expressions or define functions (defun). Use this for: 1) Defining functions, 2) Computing values, 3) Testing expressions. Example: (defun factorial (n) (if (zp n) 1 (* n (factorial (- n 1))))) or (+ 1 2). Returns the ACL2 evaluation result. Can optionally use a persistent session for incremental development.

**Parameters:**

- `code` (required): ACL2 code to evaluate
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)
- `session_id` (optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

---

### check_syntax

Quickly check ACL2 code for syntax errors without full execution. Use this before 'admit' or 'prove' to catch basic errors. Faster than full evaluation but less thorough.

**Parameters:**

- `code` (required): ACL2 code to check

---

### admit

Test if an ACL2 event would be accepted WITHOUT saving it permanently. Use this to validate definitions/theorems before adding them to files. Faster than 'prove' for testing. Returns success/failure. Example use case: testing if a function definition is valid before committing to a file. Can optionally use a persistent session to test in context of existing definitions.

**Parameters:**

- `code` (required): Single ACL2 event to test. Example: (defun my-func (x) (+ x 1)) or (defthm my-thm (equal (+ 1 1) 2))
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)
- `session_id` (optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

---

## File-based Tools

### certify_book

Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Book path can be relative or absolute, WITHOUT .lisp extension (e.g., 'books/kestrel/axe/top' not 'books/kestrel/axe/top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.

**Parameters:**

- `file_path` (required): Path to the book WITHOUT .lisp extension. Can be relative (e.g., 'books/kestrel/axe/top') or absolute. Relative paths are relative to current directory.
- `jobs` (optional): Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

### include_book

Load a certified ACL2 book to use its definitions and theorems. Use this to import existing ACL2 libraries before proving new theorems. Optionally run additional code after loading. IMPORTANT: Provide path WITHOUT .lisp extension.

**Parameters:**

- `file_path` (required): Path to the book WITHOUT .lisp extension. Example: 'std/lists/append' for ACL2 standard library, or 'arithmetic/top' for system books
- `code` (optional): Optional ACL2 code to run after loading the book. Example: (thm (equal (+ 1 1) 2))
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)
- `session_id` (optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.
- `use_system_dir` (optional): If true, use :dir :system for ACL2 system books (books in the ACL2 books directory). Default: false

---

### check_theorem

Verify a specific theorem from a file. Use this to re-check a single theorem after making changes, without re-proving everything in the file. The file is loaded first, then the named theorem is proven. File path INCLUDES .lisp extension.

**Parameters:**

- `file_path` (required): Full path to the .lisp file (WITH extension). Example: '/path/to/theorems.lisp'
- `theorem_name` (required): Exact name of the theorem to check. Example: 'append-associative'
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

## Query and Verification Tools

### query_event

Look up the definition and properties of an ACL2 function, theorem, or macro. Use this to understand what's already defined before writing new code, or to check the signature of existing functions. Works with built-in ACL2 functions (e.g., 'append', 'len') or user-defined ones. Uses ACL2's :pe (print-event) command.

**Parameters:**

- `name` (required): Name of function/theorem to query. Examples: 'append', 'len', 'my-custom-function'
- `file_path` (optional): Optional: Load this file first (WITH .lisp extension) before querying. Use if the event is defined in a specific file.
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

### verify_guards

Verify that a function's guards are satisfied, enabling efficient execution in raw Common Lisp. Guards are conditions that ensure a function is called with valid inputs. Use this after defining a function to enable faster execution. Common workflow: 1) Define function with 'evaluate', 2) Verify guards with this tool. Example: After defining (defun my-div (x y) (/ x y)), verify guards to ensure y is never zero.

**Parameters:**

- `function_name` (required): Name of the function to verify. Example: 'my-div'
- `file_path` (optional): Optional: File containing the function (WITH .lisp extension). Load this first before verifying.
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

## Session State Management Tools

### undo

Undo the last ACL2 event in a persistent session. This removes the most recent definition, theorem, or command from the session's world. Use this to backtrack and try alternative approaches. Uses ACL2's :ubt (undo-back-through) command. Only works with persistent sessions.

**Parameters:**

- `session_id` (required): ID of the session to undo in
- `count` (optional): Number of events to undo (default: 1)

---

### save_checkpoint

Save a named checkpoint of the current ACL2 world state in a session. You can later restore to this checkpoint to try alternative proof strategies. Use this before attempting risky proof steps or when you want to preserve a known-good state.

**Parameters:**

- `session_id` (required): ID of the session
- `checkpoint_name` (required): Name for this checkpoint. Example: 'before-induction-proof'

---

### restore_checkpoint

Restore a session to a previously saved checkpoint. This undoes all events that occurred after the checkpoint was created. Use this to backtrack to a known-good state and try a different approach.

**Parameters:**

- `session_id` (required): ID of the session
- `checkpoint_name` (required): Name of the checkpoint to restore

---

### get_world_state

Display the current ACL2 world state in a session, showing all definitions, theorems, and events. Use this to see what's currently defined in your session. Uses ACL2's :pbt (print-back-through) command.

**Parameters:**

- `session_id` (required): ID of the session
- `limit` (optional): Maximum number of recent events to show (default: 20)

---

### retry_proof

Retry the last proof attempt in a session with different hints or strategies. This is useful for interactive proof debugging - when a proof fails, you can try again with modified hints without re-submitting the entire theorem. The previous failed proof attempt is undone first.

**Parameters:**

- `session_id` (required): ID of the session with the failed proof
- `code` (required): New proof attempt with different hints. Example: (defthm my-thm (equal x y) :hints (("Goal" :use (:instance lemma))))
- `timeout` (optional): Timeout in seconds (optional, no timeout if not specified)

---

## General Notes

### Sessions
- Sessions do **not** auto-timeout by default (SESSION_INACTIVITY_TIMEOUT = None)
- Maximum of 50 concurrent sessions server-wide
- Each session maintains its own ACL2 world state
- Sessions are isolated from each other
- Maximum of 50 checkpoints per session

### Timeouts
- All timeouts are clamped to the range 1-300 seconds (5 minutes max)
- If no timeout is specified, operations run until completion (no timeout)
- Use timeouts to prevent infinite loops or very long-running operations

### Security Constraints
- **Maximum code length**: 1MB (1,000,000 characters) per request
- **Session names**: Alphanumeric characters, hyphens, underscores, and spaces allowed
  - Validated with pattern: `^[a-zA-Z0-9_\- ]+$`
- **Checkpoint names**: Alphanumeric characters, hyphens, and underscores only (no spaces)
  - Maximum length: 100 characters
  - Validated with pattern: `^[a-zA-Z0-9_-]+$`
- **File paths**: Must exist and be files (not directories) when required

### Execution Modes

**One-off Execution** (no session_id):
- Creates fresh ACL2 process for each command
- Executes code in clean environment
- Returns output
- Terminates ACL2 process after completion
- Use for isolated proofs or evaluations

**Session Execution** (with session_id):
- Uses existing ACL2 process
- Maintains state across commands
- Much faster for repeated operations (no startup cost)
- Enables incremental development workflow
- Use for building up definitions and theorems incrementally

### Background I/O and Logging

When `enable_logging=true` (default for sessions):
- All I/O is logged to `~/.acl2-mcp/sessions/SESSION_ID-TIMESTAMP.log`
- Background tasks continuously capture stdout and stderr
- Input commands are logged in natural format (appear after ACL2 prompt)
- Timestamps mark when inputs are sent and when interrupts occur
- Logs are written asynchronously using non-blocking I/O
- Log files persist after session termination for later review

---
