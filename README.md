# ACL2 MCP Server

> ⚠️ **Early Beta - Development in Progress**
> This is an early beta version that was rapidly developed. While functional and tested, expect rough edges, potential bugs, and breaking changes. Use at your own risk in production environments.

A Model Context Protocol (MCP) server that provides tools for interacting with the ACL2 theorem prover.

## Features

This MCP server exposes 15 tools for working with ACL2, including support for persistent sessions that enable incremental development:

### Session Management Tools
- **start_session**: Create a persistent ACL2 session for incremental development
- **end_session**: End a persistent session and clean up resources
- **list_sessions**: List all active sessions with their status

### Code-based Tools
- **prove**: Submit ACL2 theorems (defthm) for proof
- **evaluate**: Evaluate arbitrary ACL2 expressions and definitions
- **check_syntax**: Check ACL2 code for syntax errors
- **admit**: Test if an ACL2 event would be admitted without error

All code-based tools support an optional `session_id` parameter for incremental development.

### File-based Tools
- **certify_book**: Certify an ACL2 book file (loads and verifies all definitions and theorems)
- **include_book**: Load an ACL2 book and optionally evaluate additional code
- **check_theorem**: Check a specific theorem in an ACL2 file by name

### Query and Verification Tools
- **query_event**: Query information about a defined function, theorem, or event (uses :pe)
- **verify_guards**: Verify guards for a function to ensure efficient execution

### Session State Management Tools
- **undo**: Undo the last N events in a session
- **save_checkpoint**: Save a named checkpoint of the current session state
- **restore_checkpoint**: Restore a session to a previously saved checkpoint
- **get_world_state**: Display current session state (recent definitions and theorems)
- **retry_proof**: Retry a failed proof with different hints

## Prerequisites

- Python 3.10 or later
- ACL2 installed and available in PATH as `acl2`
  - If installed via package manager (e.g., `brew install acl2`): already configured
  - If built from source: add `/path/to/acl2/bin` to your PATH (this directory contains the `acl2` wrapper script)
- ACL2 books build tools (cert.pl) available in PATH
  - Add `/path/to/acl2/books/build` to your PATH for book certification support

## Installation

```bash
# Clone the repository
cd acl2-mcp

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .
```

## Usage

### Running the Server

Claude Desktop and Claude Code, when properly configured (see below), will automatically start the server. However, if you want to start it separately for development or testing purposes:

```bash
acl2-mcp
```

### Configuring Claude Desktop to use acl2-mcp

Add this to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "acl2": {
      "command": "/path/to/acl2-mcp/venv/bin/acl2-mcp"
    }
  }
}
```

Replace `/path/to/acl2-mcp` with the actual path to your installation directory.

We do not know if Claude Desktop works on Linux, so if you have that
configuration, you will need to find the appropriate json file and update it
similarly to the macOS example.

### Configuring Claude Code to use acl2-mcp

Claude Code provides a CLI command to add MCP servers. Choose the configuration that fits your workflow:

**Project-specific configuration** (recommended for ACL2 development):

From your ACL2 project directory, run:
```bash
claude mcp add acl2 /path/to/acl2-mcp/venv/bin/acl2-mcp
```

This makes acl2-mcp available only when working in that specific project directory. Good for teams with per-project tool configurations.

**Global configuration** (for system-wide availability):

From any directory, run:
```bash
claude mcp add acl2 /path/to/acl2-mcp/venv/bin/acl2-mcp --global
```

This makes acl2-mcp available in all Claude Code sessions regardless of directory. Good if you want ACL2 tools everywhere.

### Example Tool Usage

#### Persistent Session Workflow (Recommended for Interactive Development)

For incremental development where you build up definitions and theorems step-by-step, use persistent sessions:

**1. Start a session:**
```
Tool: start_session
Arguments:
  name: "natural-numbers-proof"  (optional, for easy identification)

Returns: Session ID (e.g., "a1b2c3d4-...")
```

**2. Define functions incrementally:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defun plus (x y) (if (zp x) y (plus (1- x) (1+ y))))"

Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(plus 2 3)"  // Test the function
```

**3. Build on previous definitions:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defun times (x y) (if (zp y) 0 (plus x (times x (1- y)))))"
```

**4. Prove theorems interactively:**
```lisp
Tool: prove
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defthm plus-commutative (equal (plus x y) (plus y x)))"
```

**5. If proof fails, retry with hints:**
```lisp
Tool: retry_proof
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defthm plus-commutative
          (equal (plus x y) (plus y x))
          :hints ((\"Goal\" :induct (plus x y))))"
```

**6. Save checkpoints before risky steps:**
```lisp
Tool: save_checkpoint
Arguments:
  session_id: "a1b2c3d4-..."
  checkpoint_name: "before-induction"
```

**7. Restore if needed:**
```lisp
Tool: restore_checkpoint
Arguments:
  session_id: "a1b2c3d4-..."
  checkpoint_name: "before-induction"
```

**8. Inspect session state:**
```lisp
Tool: get_world_state
Arguments:
  session_id: "a1b2c3d4-..."
  limit: 20  (show last 20 events)
```

**9. Undo mistakes:**
```lisp
Tool: undo
Arguments:
  session_id: "a1b2c3d4-..."
  count: 1  (undo last event)
```

**10. End session when done:**
```
Tool: end_session
Arguments:
  session_id: "a1b2c3d4-..."
```

**Benefits of persistent sessions:**

- ✅ No need to wrap everything in `progn`
- ✅ Test functions immediately after defining them
- ✅ Build complex proofs incrementally
- ✅ Try different proof strategies without re-submitting entire files
- ✅ Save/restore checkpoints for experimentation
- ⚡ Sessions auto-timeout after 30 minutes of inactivity

#### Code-based Tools (One-off Execution)

**Prove a Theorem:**
```lisp
(defthm append-nil
  (implies (true-listp x)
           (equal (append x nil) x)))
```

**Evaluate Expressions:**
```lisp
(defun factorial (n)
  (if (zp n)
      1
    (* n (factorial (- n 1)))))

(factorial 5)
```

**Check Syntax:**
```lisp
(defun my-function (x y)
  (+ x y))
```

#### File-based Tools

**Certify a Book:**
```
Tool: certify_book
Arguments:
  file_path: "path/to/mybook"  (without .lisp extension)
  timeout: 120  (optional)
```

**Include a Book and Run Code:**
```
Tool: include_book
Arguments:
  file_path: "path/to/mybook"  (without .lisp extension)
  code: "(thm (equal (+ 1 1) 2))"  (optional)
  timeout: 60  (optional)
  use_system_dir: true  (optional, use :dir :system for ACL2 system books)
```

For system books (books in the ACL2 books directory), set `use_system_dir: true`:
```
Tool: include_book
Arguments:
  file_path: "arithmetic/top"
  use_system_dir: true
```

**Check a Specific Theorem:**
```
Tool: check_theorem
Arguments:
  file_path: "path/to/myfile.lisp"
  theorem_name: "my-theorem-name"
  timeout: 60  (optional)
```

#### Query and Verification Tools

**Admit an Event:**
```
Tool: admit
Arguments:
  code: "(defun my-func (x) (+ x 1))"
  timeout: 30  (optional)

Returns whether the event would be admitted successfully.
```

**Query an Event:**
```
Tool: query_event
Arguments:
  name: "append"
  file_path: "path/to/file.lisp"  (optional, if function is in a file)
  timeout: 30  (optional)

Returns the definition and properties of the named event.
```

**Verify Guards:**
```
Tool: verify_guards
Arguments:
  function_name: "my-function"
  file_path: "path/to/file.lisp"  (optional, if function is in a file)
  timeout: 60  (optional)

Verifies that the function's guards are satisfied.
```

## Development

### Type Checking

This project uses strict static typing with mypy:

```bash
mypy acl2_mcp/
```

### Running Tests

```bash
pytest
```

## How It Works

The server supports two execution modes:

### One-off Execution (Default)
When no `session_id` is provided, each tool call:
1. Writes ACL2 code to a temporary `.lisp` file
2. Starts a fresh ACL2 process with the code as input
3. Captures and returns stdout/stderr
4. Cleans up the temporary file and terminates ACL2

### Persistent Sessions (Incremental Development)
When using sessions:
1. `start_session` creates a long-running ACL2 process with persistent stdin/stdout pipes
2. Each tool call sends commands to the existing process and reads responses
3. The ACL2 world state accumulates across multiple commands
4. Sessions auto-cleanup after 30 minutes of inactivity or when explicitly ended
5. Up to 50 concurrent sessions are supported

Default timeout is 30 seconds per command, configurable per request.

## License

BSD 3-Clause License - See [LICENSE](LICENSE) for details.
