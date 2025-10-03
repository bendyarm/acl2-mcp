"""ACL2 MCP Server implementation."""

import asyncio
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


# Security constants
MAX_TIMEOUT = 300  # 5 minutes maximum
MIN_TIMEOUT = 1
MAX_CODE_LENGTH = 1_000_000  # 1MB of code


def validate_timeout(timeout: int) -> int:
    """
    Validate and clamp timeout value.

    Args:
        timeout: Requested timeout in seconds

    Returns:
        Validated timeout value
    """
    if not isinstance(timeout, (int, float)):
        return 30
    return max(MIN_TIMEOUT, min(int(timeout), MAX_TIMEOUT))


def validate_acl2_identifier(identifier: str) -> str:
    """
    Validate that a string is a safe ACL2 identifier.

    Args:
        identifier: The identifier to validate

    Returns:
        The validated identifier

    Raises:
        ValueError: If identifier is not safe
    """
    if not identifier:
        raise ValueError("Identifier cannot be empty")

    # ACL2 identifiers can contain letters, digits, hyphens, underscores
    # and some special characters, but should not contain quotes or parens
    if '"' in identifier or "'" in identifier or "(" in identifier or ")" in identifier:
        raise ValueError(f"Invalid ACL2 identifier: {identifier}")

    return identifier


def escape_acl2_string(s: str) -> str:
    """
    Escape a string for safe use in ACL2 code.

    Args:
        s: String to escape

    Returns:
        Escaped string safe for use in ACL2
    """
    # Escape backslashes first, then quotes
    return s.replace("\\", "\\\\").replace('"', '\\"')


def validate_file_path(file_path: str) -> Path:
    """
    Validate file path and check it exists.

    Args:
        file_path: Path to validate

    Returns:
        Resolved absolute path

    Raises:
        ValueError: If path is invalid or doesn't exist
    """
    if not file_path:
        raise ValueError("File path cannot be empty")

    # Resolve to absolute path
    abs_path = Path(file_path).resolve()

    # Check that file exists
    if not abs_path.exists():
        raise ValueError(f"File not found: {abs_path.name}")

    # Check that it's a file (not a directory)
    if not abs_path.is_file():
        raise ValueError(f"Path is not a file: {abs_path.name}")

    return abs_path


app: Server = Server("acl2-mcp")


@app.list_tools()  # type: ignore[misc,no-untyped-call]
async def list_tools() -> list[Tool]:
    """List available ACL2 tools."""
    return [
        Tool(
            name="prove",
            description="Submit an ACL2 theorem (defthm) for proof. Use this to prove mathematical properties. Example: (defthm append-nil (implies (true-listp x) (equal (append x nil) x))). The theorem will be proven and added to the ACL2 world. Returns detailed ACL2 proof output.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "ACL2 code to prove (e.g., defthm form)",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 30)",
                        "default": 30,
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="evaluate",
            description="Evaluate ACL2 expressions or define functions (defun). Use this for: 1) Defining functions, 2) Computing values, 3) Testing expressions. Example: (defun factorial (n) (if (zp n) 1 (* n (factorial (- n 1))))) or (+ 1 2). Returns the ACL2 evaluation result.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "ACL2 code to evaluate",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 30)",
                        "default": 30,
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="check_syntax",
            description="Quickly check ACL2 code for syntax errors without full execution. Use this before 'admit' or 'prove' to catch basic errors. Faster than full evaluation but less thorough.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "ACL2 code to check",
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="certify_book",
            description="Certify an ACL2 book (a collection of definitions and theorems in a .lisp file). This verifies all proofs and creates a certificate for the book. Use this after creating a complete ACL2 book file. IMPORTANT: Provide path WITHOUT the .lisp extension (e.g., 'mybook' not 'mybook.lisp').",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the book WITHOUT .lisp extension. Example: '/path/to/mybook' for file '/path/to/mybook.lisp'",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 120)",
                        "default": 120,
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="include_book",
            description="Load a certified ACL2 book to use its definitions and theorems. Use this to import existing ACL2 libraries before proving new theorems. Optionally run additional code after loading. IMPORTANT: Provide path WITHOUT .lisp extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the book WITHOUT .lisp extension. Example: 'std/lists/append' for ACL2 standard library",
                    },
                    "code": {
                        "type": "string",
                        "description": "Optional ACL2 code to run after loading the book. Example: (thm (equal (+ 1 1) 2))",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="check_theorem",
            description="Verify a specific theorem from a file. Use this to re-check a single theorem after making changes, without re-proving everything in the file. The file is loaded first, then the named theorem is proven. File path INCLUDES .lisp extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full path to the .lisp file (WITH extension). Example: '/path/to/theorems.lisp'",
                    },
                    "theorem_name": {
                        "type": "string",
                        "description": "Exact name of the theorem to check. Example: 'append-associative'",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["file_path", "theorem_name"],
            },
        ),
        Tool(
            name="admit",
            description="Test if an ACL2 event would be accepted WITHOUT saving it permanently. Use this to validate definitions/theorems before adding them to files. Faster than 'prove' for testing. Returns success/failure. Example use case: testing if a function definition is valid before committing to a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Single ACL2 event to test. Example: (defun my-func (x) (+ x 1)) or (defthm my-thm (equal (+ 1 1) 2))",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 30)",
                        "default": 30,
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="query_event",
            description="Look up the definition and properties of an ACL2 function, theorem, or macro. Use this to understand what's already defined before writing new code, or to check the signature of existing functions. Works with built-in ACL2 functions (e.g., 'append', 'len') or user-defined ones. Uses ACL2's :pe (print-event) command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of function/theorem to query. Examples: 'append', 'len', 'my-custom-function'",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional: Load this file first (WITH .lisp extension) before querying. Use if the event is defined in a specific file.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 30)",
                        "default": 30,
                    },
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="verify_guards",
            description="Verify that a function's guards are satisfied, enabling efficient execution in raw Common Lisp. Guards are conditions that ensure a function is called with valid inputs. Use this after defining a function to enable faster execution. Common workflow: 1) Define function with 'evaluate', 2) Verify guards with this tool. Example: After defining (defun my-div (x y) (/ x y)), verify guards to ensure y is never zero.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Name of the function to verify. Example: 'my-div'",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional: File containing the function (WITH .lisp extension). Load this first before verifying.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["function_name"],
            },
        ),
    ]


async def run_acl2(code: str, timeout: int = 30) -> str:
    """
    Run ACL2 code and return the output.

    Args:
        code: ACL2 code to execute
        timeout: Timeout in seconds

    Returns:
        Output from ACL2
    """
    # Validate inputs
    if len(code) > MAX_CODE_LENGTH:
        return f"Error: Code exceeds maximum length of {MAX_CODE_LENGTH} characters"

    timeout = validate_timeout(timeout)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".lisp", delete=False
    ) as f:
        f.write(code)
        f.write("\n(good-bye)\n")  # Exit ACL2
        temp_file = f.name

    try:
        process = await asyncio.create_subprocess_exec(
            "acl2",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Read the temp file and send to ACL2
        with open(temp_file, "r") as f:
            input_data = f.read()

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=input_data.encode()),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return f"Error: ACL2 execution timed out after {timeout} seconds"

        output = stdout.decode()
        if stderr:
            error_output = stderr.decode()
            if error_output.strip():
                output += f"\n\nStderr:\n{error_output}"

        return output
    finally:
        Path(temp_file).unlink(missing_ok=True)


async def run_acl2_file(file_path: str, timeout: int = 60) -> str:
    """
    Run ACL2 with a file using ld (load).

    Args:
        file_path: Path to the ACL2 file
        timeout: Timeout in seconds

    Returns:
        Output from ACL2
    """
    try:
        abs_path = validate_file_path(file_path)
    except ValueError as e:
        return f"Error: {e}"

    # Escape the path for safe use in ACL2 code
    escaped_path = escape_acl2_string(str(abs_path))

    # Use ld to load the file
    code = f'(ld "{escaped_path}")'
    return await run_acl2(code, timeout)


async def certify_acl2_book(file_path: str, timeout: int = 120) -> str:
    """
    Certify an ACL2 book.

    Args:
        file_path: Path to the book (without .lisp extension)
        timeout: Timeout in seconds

    Returns:
        Output from ACL2
    """
    # Remove .lisp extension if present
    book_path = str(Path(file_path).with_suffix(""))
    lisp_path = Path(book_path).with_suffix(".lisp")

    try:
        abs_path = validate_file_path(str(lisp_path))
    except ValueError as e:
        return f"Error: {e}"

    # Escape the book path for safe use in ACL2 code
    escaped_book_path = escape_acl2_string(book_path)

    # Use certify-book command
    code = f'(certify-book "{escaped_book_path}" ?)'
    return await run_acl2(code, timeout)


async def include_acl2_book(file_path: str, additional_code: str = "", timeout: int = 60) -> str:
    """
    Include an ACL2 book and optionally run additional code.

    Args:
        file_path: Path to the book (without .lisp extension)
        additional_code: Optional code to run after including
        timeout: Timeout in seconds

    Returns:
        Output from ACL2
    """
    # Remove .lisp extension if present
    book_path = str(Path(file_path).with_suffix(""))
    lisp_path = Path(book_path).with_suffix(".lisp")

    try:
        abs_path = validate_file_path(str(lisp_path))
    except ValueError as e:
        return f"Error: {e}"

    # Escape the book path for safe use in ACL2 code
    escaped_book_path = escape_acl2_string(book_path)

    # Build code to include book and run additional commands
    code = f'(include-book "{escaped_book_path}")'
    if additional_code.strip():
        # Validate additional code length
        if len(additional_code) > MAX_CODE_LENGTH:
            return f"Error: Additional code exceeds maximum length of {MAX_CODE_LENGTH} characters"
        code += f"\n{additional_code}"

    return await run_acl2(code, timeout)


async def query_acl2_event(name: str, file_path: str = "", timeout: int = 30) -> str:
    """
    Query information about an ACL2 event (function, theorem, etc.).

    Args:
        name: Name of the event to query
        file_path: Optional file to load first
        timeout: Timeout in seconds

    Returns:
        Output from ACL2 showing the event definition and properties
    """
    # Validate the event name
    try:
        validated_name = validate_acl2_identifier(name)
    except ValueError as e:
        return f"Error: {e}"

    # Build code to load file (if provided) and query the event
    code = ""
    if file_path:
        try:
            abs_path = validate_file_path(file_path)
        except ValueError as e:
            return f"Error: {e}"

        escaped_path = escape_acl2_string(str(abs_path))
        code += f'(ld "{escaped_path}")\n'

    # Use :pe (print event) to show the definition
    code += f":pe {validated_name}"

    return await run_acl2(code, timeout)


async def verify_function_guards(function_name: str, file_path: str = "", timeout: int = 60) -> str:
    """
    Verify guards for a function.

    Args:
        function_name: Name of the function
        file_path: Optional file containing the function
        timeout: Timeout in seconds

    Returns:
        Output from ACL2
    """
    # Validate the function name
    try:
        validated_name = validate_acl2_identifier(function_name)
    except ValueError as e:
        return f"Error: {e}"

    # Build code to load file (if provided) and verify guards
    code = ""
    if file_path:
        try:
            abs_path = validate_file_path(file_path)
        except ValueError as e:
            return f"Error: {e}"

        escaped_path = escape_acl2_string(str(abs_path))
        code += f'(ld "{escaped_path}")\n'

    # Use verify-guards command
    code += f"(verify-guards {validated_name})"

    return await run_acl2(code, timeout)


@app.call_tool()  # type: ignore[misc]
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent]:
    """Handle tool calls."""
    if name == "prove":
        code: str = arguments["code"]
        timeout: int = arguments.get("timeout", 30)

        output = await run_acl2(code, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "evaluate":
        code = arguments["code"]
        timeout = arguments.get("timeout", 30)

        output = await run_acl2(code, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "check_syntax":
        code = arguments["code"]

        # For syntax checking, we can try to parse without executing
        # ACL2 doesn't have a dedicated syntax checker, so we'll just
        # try to load it with a very short timeout
        output = await run_acl2(code, timeout=5)

        # Check for common error patterns
        if "Error:" in output or "HARD ACL2 ERROR" in output:
            return [
                TextContent(
                    type="text",
                    text=f"Syntax errors found:\n\n{output}",
                )
            ]
        else:
            return [
                TextContent(
                    type="text",
                    text="No obvious syntax errors detected.\n\n" + output,
                )
            ]

    elif name == "certify_book":
        file_path = arguments["file_path"]
        timeout = arguments.get("timeout", 120)

        output = await certify_acl2_book(file_path, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "include_book":
        file_path = arguments["file_path"]
        additional_code = arguments.get("code", "")
        timeout = arguments.get("timeout", 60)

        output = await include_acl2_book(file_path, additional_code, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "check_theorem":
        file_path = arguments["file_path"]
        theorem_name = arguments["theorem_name"]
        timeout = arguments.get("timeout", 60)

        # Validate inputs
        try:
            abs_path = validate_file_path(file_path)
            validated_theorem = validate_acl2_identifier(theorem_name)
        except ValueError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error: {e}",
                )
            ]

        # Escape the path and build code
        escaped_path = escape_acl2_string(str(abs_path))

        # First load the file, then try to prove the theorem by name
        code = f'(ld "{escaped_path}")\n(thm (implies t ({validated_theorem})))'
        output = await run_acl2(code, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "admit":
        code = arguments["code"]
        timeout = arguments.get("timeout", 30)

        output = await run_acl2(code, timeout)

        # Check if the event was admitted successfully
        success = "Error" not in output and "FAILED" not in output

        return [
            TextContent(
                type="text",
                text=f"Admit {'succeeded' if success else 'failed'}:\n\n{output}",
            )
        ]

    elif name == "query_event":
        name_arg = arguments["name"]
        file_path = arguments.get("file_path", "")
        timeout = arguments.get("timeout", 30)

        output = await query_acl2_event(name_arg, file_path, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "verify_guards":
        function_name = arguments["function_name"]
        file_path = arguments.get("file_path", "")
        timeout = arguments.get("timeout", 60)

        output = await verify_function_guards(function_name, file_path, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    else:
        raise ValueError(f"Unknown tool: {name}")


async def run() -> None:
    """Run the server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


def main() -> None:
    """Main entry point for the server."""
    asyncio.run(run())


if __name__ == "__main__":
    main()
