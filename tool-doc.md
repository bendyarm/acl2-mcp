# ACL2 MCP Server - Tool Reference

> **Note**: This documentation was automatically extracted from the tool definitions in `acl2_mcp/server.py` on 2025-10-14. The source of truth for tool behavior is the Python code itself.

This document provides detailed reference documentation for all 15 tools provided by the ACL2 MCP server.

## Table of Contents

- [Session Management Tools](#session-management-tools)
  - [start_session](#start_session)
  - [end_session](#end_session)
  - [list_sessions](#list_sessions)
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

**Description**: Start a new persistent ACL2 session. This creates a long-running ACL2 process that maintains state across multiple tool calls. Use this when you want to incrementally build up definitions and theorems without having to wrap everything in progn. Sessions auto-timeout after 30 minutes of inactivity.

**Parameters**:
- `name` (string, optional): Optional human-readable name for the session. Example: 'natural-numbers-proof'

**Returns**: Session ID string (UUID format, e.g., "a1b2c3d4-...")

**Example**:
```
Arguments:
  name: "natural-numbers-proof"
Returns: Session ID: a1b2c3d4-5678-90ab-cdef-1234567890ab
```

---

### end_session

**Description**: End a persistent ACL2 session and clean up resources. Use this when you're done with incremental development. Sessions also auto-cleanup after 30 minutes of inactivity.

**Parameters**:
- `session_id` (string, **required**): ID of the session to end

**Returns**: Success message

**Example**:
```
Arguments:
  session_id: "a1b2c3d4-..."
Returns: Session a1b2c3d4-... ended successfully
```

---

### list_sessions

**Description**: List all active ACL2 sessions with their IDs, names, age, idle time, and event count. Use this to see which sessions are available and their current state.

**Parameters**: None

**Returns**: Formatted list of active sessions with statistics

**Example**:
```
Returns:
  Active sessions:
    a1b2c3d4-... (my-proof): age=120s, idle=30s, events=5
    e5f6g7h8-... (test): age=60s, idle=10s, events=2
```

---

## Code-based Tools

### prove

**Description**: Submit an ACL2 theorem (defthm) for proof. Use this to prove mathematical properties. Example: `(defthm append-nil (implies (true-listp x) (equal (append x nil) x)))`. The theorem will be proven and added to the ACL2 world. Returns detailed ACL2 proof output. Can optionally use a persistent session for incremental development.

**Parameters**:
- `code` (string, **required**): ACL2 code to prove (e.g., defthm form)
- `timeout` (number, optional, default: 30): Timeout in seconds
- `session_id` (string, optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

**Returns**: ACL2 proof output (success or failure with details)

**Example**:
```lisp
Arguments:
  code: "(defthm append-nil
          (implies (true-listp x)
                   (equal (append x nil) x)))"
  timeout: 60
  session_id: "a1b2c3d4-..."
```

---

### evaluate

**Description**: Evaluate ACL2 expressions or define functions (defun). Use this for: 1) Defining functions, 2) Computing values, 3) Testing expressions. Example: `(defun factorial (n) (if (zp n) 1 (* n (factorial (- n 1)))))` or `(+ 1 2)`. Returns the ACL2 evaluation result. Can optionally use a persistent session for incremental development.

**Parameters**:
- `code` (string, **required**): ACL2 code to evaluate
- `timeout` (number, optional, default: 30): Timeout in seconds
- `session_id` (string, optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

**Returns**: ACL2 evaluation output

**Example**:
```lisp
Arguments:
  code: "(defun factorial (n)
          (if (zp n) 1 (* n (factorial (- n 1)))))"
  session_id: "a1b2c3d4-..."
```

---

### check_syntax

**Description**: Quickly check ACL2 code for syntax errors without full execution. Use this before 'admit' or 'prove' to catch basic errors. Faster than full evaluation but less thorough.

**Parameters**:
- `code` (string, **required**): ACL2 code to check

**Returns**: Syntax error report or success message

**Example**:
```lisp
Arguments:
  code: "(defun my-function (x y) (+ x y))"
```

**Note**: This tool uses a short timeout (5 seconds) and checks for common error patterns in the output.

---

### admit

**Description**: Test if an ACL2 event would be accepted WITHOUT saving it permanently. Use this to validate definitions/theorems before adding them to files. Faster than 'prove' for testing. Returns success/failure. Example use case: testing if a function definition is valid before committing to a file. Can optionally use a persistent session to test in context of existing definitions.

**Parameters**:
- `code` (string, **required**): Single ACL2 event to test. Example: `(defun my-func (x) (+ x 1))` or `(defthm my-thm (equal (+ 1 1) 2))`
- `timeout` (number, optional, default: 30): Timeout in seconds
- `session_id` (string, optional): Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.

**Returns**: Success/failure message with ACL2 output

**Example**:
```lisp
Arguments:
  code: "(defun my-func (x) (+ x 1))"
  session_id: "a1b2c3d4-..."
```

---

## File-based Tools

### certify_book

**Description**: Certify an ACL2 book (a collection of definitions and theorems in a .lisp file). This verifies all proofs and creates a certificate for the book. Use this after creating a complete ACL2 book file. **IMPORTANT**: Provide path WITHOUT the .lisp extension (e.g., 'mybook' not 'mybook.lisp').

**Parameters**:
- `file_path` (string, **required**): Path to the book WITHOUT .lisp extension. Example: '/path/to/mybook' for file '/path/to/mybook.lisp'
- `timeout` (number, optional, default: 120): Timeout in seconds

**Returns**: ACL2 certification output

**Example**:
```
Arguments:
  file_path: "/Users/me/acl2/books/my-library/my-book"
  timeout: 300
```

**Implementation Note**: Uses ACL2's `(certify-book "path" ?)` command.

---

### include_book

**Description**: Load a certified ACL2 book to use its definitions and theorems. Use this to import existing ACL2 libraries before proving new theorems. Optionally run additional code after loading. **IMPORTANT**: Provide path WITHOUT .lisp extension.

**Parameters**:
- `file_path` (string, **required**): Path to the book WITHOUT .lisp extension. Example: 'std/lists/append' for ACL2 standard library
- `code` (string, optional): Optional ACL2 code to run after loading the book. Example: `(thm (equal (+ 1 1) 2))`
- `timeout` (number, optional, default: 60): Timeout in seconds

**Returns**: ACL2 output from loading the book and executing optional code

**Example**:
```
Arguments:
  file_path: "std/lists/append"
  code: "(thm (equal (append nil x) x))"
  timeout: 60
```

---

### check_theorem

**Description**: Verify a specific theorem from a file. Use this to re-check a single theorem after making changes, without re-proving everything in the file. The file is loaded first, then the named theorem is proven. File path INCLUDES .lisp extension.

**Parameters**:
- `file_path` (string, **required**): Full path to the .lisp file (WITH extension). Example: '/path/to/theorems.lisp'
- `theorem_name` (string, **required**): Exact name of the theorem to check. Example: 'append-associative'
- `timeout` (number, optional, default: 60): Timeout in seconds

**Returns**: ACL2 proof output for the specified theorem

**Example**:
```
Arguments:
  file_path: "/Users/me/acl2/my-theorems.lisp"
  theorem_name: "append-associative"
  timeout: 120
```

---

## Query and Verification Tools

### query_event

**Description**: Look up the definition and properties of an ACL2 function, theorem, or macro. Use this to understand what's already defined before writing new code, or to check the signature of existing functions. Works with built-in ACL2 functions (e.g., 'append', 'len') or user-defined ones. Uses ACL2's `:pe` (print-event) command.

**Parameters**:
- `name` (string, **required**): Name of function/theorem to query. Examples: 'append', 'len', 'my-custom-function'
- `file_path` (string, optional): Optional: Load this file first (WITH .lisp extension) before querying. Use if the event is defined in a specific file.
- `timeout` (number, optional, default: 30): Timeout in seconds

**Returns**: ACL2 output showing the event definition and properties

**Example**:
```
Arguments:
  name: "append"

Or with file:
Arguments:
  name: "my-helper-function"
  file_path: "/Users/me/acl2/my-utils.lisp"
```

---

### verify_guards

**Description**: Verify that a function's guards are satisfied, enabling efficient execution in raw Common Lisp. Guards are conditions that ensure a function is called with valid inputs. Use this after defining a function to enable faster execution. Common workflow: 1) Define function with 'evaluate', 2) Verify guards with this tool. Example: After defining `(defun my-div (x y) (/ x y))`, verify guards to ensure y is never zero.

**Parameters**:
- `function_name` (string, **required**): Name of the function to verify. Example: 'my-div'
- `file_path` (string, optional): Optional: File containing the function (WITH .lisp extension). Load this first before verifying.
- `timeout` (number, optional, default: 60): Timeout in seconds

**Returns**: ACL2 guard verification output (success or failure with details)

**Example**:
```
Arguments:
  function_name: "my-div"
  file_path: "/Users/me/acl2/my-functions.lisp"
  timeout: 90
```

---

## Session State Management Tools

### undo

**Description**: Undo the last ACL2 event in a persistent session. This removes the most recent definition, theorem, or command from the session's world. Use this to backtrack and try alternative approaches. Uses ACL2's `:ubt` (undo-back-through) command. **Only works with persistent sessions.**

**Parameters**:
- `session_id` (string, **required**): ID of the session to undo in
- `count` (number, optional, default: 1): Number of events to undo (default: 1)

**Returns**: ACL2 output showing what was undone

**Example**:
```
Arguments:
  session_id: "a1b2c3d4-..."
  count: 2
```

**Note**: Valid count range is 1-10000.

---

### save_checkpoint

**Description**: Save a named checkpoint of the current ACL2 world state in a session. You can later restore to this checkpoint to try alternative proof strategies. Use this before attempting risky proof steps or when you want to preserve a known-good state.

**Parameters**:
- `session_id` (string, **required**): ID of the session
- `checkpoint_name` (string, **required**): Name for this checkpoint. Example: 'before-induction-proof'

**Returns**: Success message with event number

**Example**:
```
Arguments:
  session_id: "a1b2c3d4-..."
  checkpoint_name: "before-induction"
```

**Constraints**:
- Maximum 50 checkpoints per session
- Checkpoint names can only contain letters, numbers, hyphens, and underscores
- Maximum name length: 100 characters

---

### restore_checkpoint

**Description**: Restore a session to a previously saved checkpoint. This undoes all events that occurred after the checkpoint was created. Use this to backtrack to a known-good state and try a different approach.

**Parameters**:
- `session_id` (string, **required**): ID of the session
- `checkpoint_name` (string, **required**): Name of the checkpoint to restore

**Returns**: ACL2 output showing restoration to the checkpoint state

**Example**:
```
Arguments:
  session_id: "a1b2c3d4-..."
  checkpoint_name: "before-induction"
```

---

### get_world_state

**Description**: Display the current ACL2 world state in a session, showing all definitions, theorems, and events. Use this to see what's currently defined in your session. Uses ACL2's `:pbt` (print-back-through) command.

**Parameters**:
- `session_id` (string, **required**): ID of the session
- `limit` (number, optional, default: 20): Maximum number of recent events to show (default: 20)

**Returns**: ACL2 output showing recent events in the session

**Example**:
```
Arguments:
  session_id: "a1b2c3d4-..."
  limit: 50
```

**Note**: Valid limit range is 1-1000.

---

### retry_proof

**Description**: Retry the last proof attempt in a session with different hints or strategies. This is useful for interactive proof debugging - when a proof fails, you can try again with modified hints without re-submitting the entire theorem. The previous failed proof attempt is undone first.

**Parameters**:
- `session_id` (string, **required**): ID of the session with the failed proof
- `code` (string, **required**): New proof attempt with different hints. Example: `(defthm my-thm (equal x y) :hints (("Goal" :use (:instance lemma))))`
- `timeout` (number, optional, default: 60): Timeout in seconds

**Returns**: ACL2 proof output for the retry attempt

**Example**:
```lisp
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defthm plus-commutative
          (equal (plus x y) (plus y x))
          :hints ((\"Goal\" :induct (plus x y))))"
  timeout: 120
```

**Behavior**: Automatically undoes the last event before retrying, so the session state is clean for the new proof attempt.

---

## General Notes

### Sessions
- Sessions auto-timeout after 30 minutes of inactivity
- Maximum of 50 concurrent sessions server-wide
- Each session maintains its own ACL2 world state
- Sessions are isolated from each other

### Timeouts
- All timeouts are clamped to the range 1-300 seconds (5 minutes max)
- Default timeouts vary by operation:
  - Code operations: 30 seconds
  - File operations: 60 seconds
  - Book certification: 120 seconds

### Security Constraints
- Maximum code length: 1MB per request
- ACL2 identifiers validated (no quotes or parentheses allowed)
- File paths validated (must exist and be files, not directories)
- Checkpoint and session names restricted to alphanumeric characters, hyphens, underscores (and spaces for session names)

### Execution Modes
**One-off Execution** (no session_id):
- Creates fresh ACL2 process
- Executes code
- Returns output
- Terminates ACL2

**Session Execution** (with session_id):
- Uses existing ACL2 process
- Maintains state across commands
- Faster for repeated operations
- Enables incremental development
