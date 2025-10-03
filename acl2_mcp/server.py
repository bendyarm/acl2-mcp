"""ACL2 MCP Server implementation."""

import asyncio
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


app: Server = Server("acl2-mcp")


@app.list_tools()  # type: ignore[misc,no-untyped-call]
async def list_tools() -> list[Tool]:
    """List available ACL2 tools."""
    return [
        Tool(
            name="prove",
            description="Submit an ACL2 theorem or defthm for proof. Returns the ACL2 output.",
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
            description="Evaluate arbitrary ACL2 expressions or definitions. Returns the ACL2 output.",
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
            description="Check ACL2 code for syntax errors without executing it.",
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
            description="Certify an ACL2 book file (.lisp). This loads and verifies all definitions and theorems in the file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .lisp file to certify (without .lisp extension)",
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
            description="Load an ACL2 book file and optionally evaluate additional code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .lisp file to include (without .lisp extension)",
                    },
                    "code": {
                        "type": "string",
                        "description": "Optional additional ACL2 code to evaluate after including the book",
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
            description="Check a specific theorem in an ACL2 file by name. Loads the file and attempts to prove the named theorem.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .lisp file containing the theorem",
                    },
                    "theorem_name": {
                        "type": "string",
                        "description": "Name of the theorem to check",
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
            description="Test if an ACL2 event (defun, defthm, etc.) would be admitted without error. Returns success/failure without persisting to world.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "ACL2 event to test (e.g., defun or defthm form)",
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
            description="Query information about a defined function, theorem, or other event by name. Returns the definition and properties.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the function, theorem, or event to query",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional: file to load first before querying",
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
            description="Verify guards for a function, ensuring it can execute efficiently in raw Lisp.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Name of the function to verify guards for",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional: file containing the function definition to load first",
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
    # Normalize path
    abs_path = Path(file_path).resolve()

    if not abs_path.exists():
        return f"Error: File not found: {abs_path}"

    # Use ld to load the file
    code = f'(ld "{abs_path}")'
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
    abs_path = Path(book_path).with_suffix(".lisp").resolve()

    if not abs_path.exists():
        return f"Error: File not found: {abs_path}"

    # Use certify-book command
    code = f'(certify-book "{book_path}" ?)'
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
    abs_path = Path(book_path).with_suffix(".lisp").resolve()

    if not abs_path.exists():
        return f"Error: File not found: {abs_path}"

    # Build code to include book and run additional commands
    code = f'(include-book "{book_path}")'
    if additional_code.strip():
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
    # Build code to load file (if provided) and query the event
    code = ""
    if file_path:
        abs_path = Path(file_path).resolve()
        if not abs_path.exists():
            return f"Error: File not found: {abs_path}"
        code += f'(ld "{abs_path}")\n'

    # Use :pe (print event) to show the definition
    code += f":pe {name}"

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
    # Build code to load file (if provided) and verify guards
    code = ""
    if file_path:
        abs_path = Path(file_path).resolve()
        if not abs_path.exists():
            return f"Error: File not found: {abs_path}"
        code += f'(ld "{abs_path}")\n'

    # Use verify-guards command
    code += f"(verify-guards {function_name})"

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

        # Load the file and then re-prove the specific theorem
        abs_path = Path(file_path).resolve()
        if not abs_path.exists():
            return [
                TextContent(
                    type="text",
                    text=f"Error: File not found: {abs_path}",
                )
            ]

        # First load the file, then try to prove the theorem by name
        code = f'(ld "{abs_path}")\n(thm (implies t ({theorem_name})))'
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
