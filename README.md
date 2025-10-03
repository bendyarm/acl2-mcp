# ACL2 MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting with the ACL2 theorem prover.

## Features

This MCP server exposes nine tools for working with ACL2:

### Code-based Tools
- **prove**: Submit ACL2 theorems (defthm) for proof
- **evaluate**: Evaluate arbitrary ACL2 expressions and definitions
- **check_syntax**: Check ACL2 code for syntax errors
- **admit**: Test if an ACL2 event would be admitted without error

### File-based Tools
- **certify_book**: Certify an ACL2 book file (loads and verifies all definitions and theorems)
- **include_book**: Load an ACL2 book and optionally evaluate additional code
- **check_theorem**: Check a specific theorem in an ACL2 file by name

### Query and Verification Tools
- **query_event**: Query information about a defined function, theorem, or event (uses :pe)
- **verify_guards**: Verify guards for a function to ensure efficient execution

## Prerequisites

- Python 3.10 or later
- ACL2 installed and available in PATH

## Installation

```bash
# Clone the repository
cd acl2-mcp

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .
```

## Usage

### Running the Server

The server can be run directly:

```bash
acl2-mcp
```

Or via Python:

```bash
python -m acl2_mcp.server
```

### Configuring in Claude Desktop

Add this to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

### Configuring in Claude Code

Add this to your Claude Code MCP settings file:

**macOS/Linux**: `~/.config/claude-code/mcp_settings.json`
**Windows**: `%APPDATA%\claude-code\mcp_settings.json`

```json
{
  "mcpServers": {
    "acl2": {
      "command": "python",
      "args": [
        "-m",
        "acl2_mcp.server"
      ],
      "cwd": "/path/to/acl2-mcp",
      "env": {
        "PYTHONPATH": "/path/to/acl2-mcp"
      }
    }
  }
}
```

Replace `/path/to/acl2-mcp` with the actual path to your installation directory.

**Note**: Make sure to activate the virtual environment or install the package globally if not using the venv python path directly. Alternatively, you can specify the full path to the venv python:

```json
{
  "mcpServers": {
    "acl2": {
      "command": "/path/to/acl2-mcp/venv/bin/python",
      "args": [
        "-m",
        "acl2_mcp.server"
      ]
    }
  }
}
```

### Example Tool Usage

#### Code-based Tools

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

The server creates temporary files containing your ACL2 code, executes ACL2 with the code as input, and returns the output. Each tool call:

1. Writes ACL2 code to a temporary `.lisp` file
2. Executes ACL2 with the code as input
3. Captures and returns stdout/stderr
4. Cleans up the temporary file

Default timeout is 30 seconds, configurable per request.

## License

MIT
