"""ACL2 MCP Server implementation."""

import asyncio
import os
import re
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Sequence, Optional
from dataclasses import dataclass, field

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


# Security constants
MAX_TIMEOUT = 300  # 5 minutes maximum
MIN_TIMEOUT = 1
MAX_CODE_LENGTH = 1_000_000  # 1MB of code
SESSION_INACTIVITY_TIMEOUT = 1800  # 30 minutes
MAX_SESSIONS = 50  # Maximum concurrent sessions
MAX_CHECKPOINT_NAME_LENGTH = 100  # Maximum checkpoint name length
MAX_CHECKPOINTS_PER_SESSION = 50  # Maximum checkpoints per session
MAX_SESSION_NAME_LENGTH = 100  # Maximum session name length


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


def validate_checkpoint_name(name: str) -> str:
    """
    Validate checkpoint name for safety.

    Args:
        name: Checkpoint name to validate

    Returns:
        Validated checkpoint name

    Raises:
        ValueError: If name is invalid
    """
    if not name:
        raise ValueError("Checkpoint name cannot be empty")

    if len(name) > MAX_CHECKPOINT_NAME_LENGTH:
        raise ValueError(f"Checkpoint name exceeds maximum length of {MAX_CHECKPOINT_NAME_LENGTH}")

    # Only allow alphanumeric, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Checkpoint name can only contain letters, numbers, hyphens, and underscores")

    return name


def validate_session_name(name: str) -> str:
    """
    Validate session name for safety.

    Args:
        name: Session name to validate

    Returns:
        Validated session name

    Raises:
        ValueError: If name is invalid
    """
    if not name:
        return name

    if len(name) > MAX_SESSION_NAME_LENGTH:
        raise ValueError(f"Session name exceeds maximum length of {MAX_SESSION_NAME_LENGTH}")

    # Only allow alphanumeric, hyphens, underscores, spaces
    if not re.match(r'^[a-zA-Z0-9_\- ]+$', name):
        raise ValueError("Session name can only contain letters, numbers, hyphens, underscores, and spaces")

    return name


def validate_integer_parameter(value: int, min_value: int, max_value: int, name: str) -> int:
    """
    Validate integer parameter is within bounds.

    Args:
        value: Value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        name: Parameter name for error messages

    Returns:
        Validated integer

    Raises:
        ValueError: If value is out of bounds
    """
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value < min_value or value > max_value:
        raise ValueError(f"{name} must be between {min_value} and {max_value}")

    return value


@dataclass
class SessionCheckpoint:
    """Represents a saved checkpoint in an ACL2 session."""
    name: str
    event_number: int
    timestamp: float


@dataclass
class ACL2Session:
    """Represents a persistent ACL2 session."""
    session_id: str
    name: Optional[str]
    process: asyncio.subprocess.Process
    created_at: float
    last_activity: float
    checkpoints: dict[str, SessionCheckpoint] = field(default_factory=dict)
    event_counter: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send_command(self, command: str, timeout: int = 30) -> str:
        """
        Send a command to the ACL2 session and get response.

        Args:
            command: ACL2 command to execute
            timeout: Timeout in seconds

        Returns:
            Output from ACL2
        """
        async with self.lock:
            self.last_activity = time.time()

            if self.process.stdin is None or self.process.stdout is None:
                return "Error: Session process has no stdin/stdout"

            # SECURITY: Validate code length to prevent memory exhaustion
            if len(command) > MAX_CODE_LENGTH:
                return f"Error: Command exceeds maximum length of {MAX_CODE_LENGTH} characters"

            # SECURITY: Validate timeout
            timeout = validate_timeout(timeout)

            try:
                # Send command
                try:
                    self.process.stdin.write(f"{command}\n".encode())
                    await self.process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    return "Error: Session connection lost (broken pipe)"

                # Read response with timeout
                output_lines = []
                # SECURITY: Use cryptographically random marker to prevent injection
                marker = f"___MARKER_{uuid.uuid4().hex}_{uuid.uuid4().hex}___"

                # Send a marker to know when we're done
                try:
                    self.process.stdin.write(f'(cw "~%{marker}~%")\n'.encode())
                    await self.process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    return "Error: Session connection lost (broken pipe)"

                # SECURITY: Implement true total timeout, not per-line timeout
                start_time = time.time()
                marker_found = False

                try:
                    while time.time() - start_time < timeout:
                        remaining = timeout - (time.time() - start_time)
                        if remaining <= 0:
                            break

                        try:
                            line = await asyncio.wait_for(
                                self.process.stdout.readline(),
                                timeout=min(remaining, 1.0)
                            )
                            if not line:  # EOF
                                return "Error: Session process terminated unexpectedly"
                            decoded_line = line.decode()
                            output_lines.append(decoded_line)

                            if marker in decoded_line:
                                marker_found = True
                                break
                        except asyncio.TimeoutError:
                            # Continue reading until total timeout
                            continue

                    if not marker_found and (time.time() - start_time) >= timeout:
                        return f"Error: Command execution timed out after {timeout} seconds"

                except Exception:
                    return "Error: Session communication failed"

                self.event_counter += 1
                return "".join(output_lines).replace(marker, "").strip()

            except (BrokenPipeError, ConnectionResetError):
                # SECURITY: Don't leak internal details in error messages
                return "Error: Session connection lost (broken pipe)"
            except Exception:
                # SECURITY: Don't leak internal details in error messages
                return "Error: Failed to execute command in session"

    async def terminate(self) -> None:
        """Terminate the ACL2 session."""
        try:
            if self.process.stdin:
                try:
                    self.process.stdin.write(b"(good-bye)\n")
                    await self.process.stdin.drain()
                    self.process.stdin.close()
                except (BrokenPipeError, ConnectionResetError):
                    # Process already dead, ignore
                    pass
            await asyncio.wait_for(self.process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        except Exception:
            self.process.kill()
            await self.process.wait()


class SessionManager:
    """Manages persistent ACL2 sessions."""

    def __init__(self) -> None:
        self.sessions: dict[str, ACL2Session] = {}
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    async def start_session(self, name: Optional[str] = None) -> tuple[str, str]:
        """
        Start a new persistent ACL2 session.

        Args:
            name: Optional human-readable name for the session

        Returns:
            Tuple of (session_id, message)
        """
        if len(self.sessions) >= MAX_SESSIONS:
            return "", f"Error: Maximum number of sessions ({MAX_SESSIONS}) reached"

        # SECURITY: Validate session name
        if name:
            try:
                name = validate_session_name(name)
            except ValueError as e:
                return "", f"Error: Invalid session name - {e}"

        session_id = str(uuid.uuid4())

        try:
            process = await asyncio.create_subprocess_exec(
                "acl2",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            session = ACL2Session(
                session_id=session_id,
                name=name,
                process=process,
                created_at=time.time(),
                last_activity=time.time(),
            )

            self.sessions[session_id] = session

            # Start cleanup task if not already running
            if self._cleanup_task is None:
                self._cleanup_task = asyncio.create_task(self._cleanup_inactive_sessions())

            return session_id, f"Session started successfully. ID: {session_id}"

        except Exception:
            # SECURITY: Don't leak internal error details
            return "", "Error: Failed to start session"

    async def end_session(self, session_id: str) -> str:
        """
        End a persistent ACL2 session.

        Args:
            session_id: ID of the session to end

        Returns:
            Status message
        """
        session = self.sessions.get(session_id)
        if not session:
            return f"Error: Session {session_id} not found"

        await session.terminate()
        del self.sessions[session_id]

        return f"Session {session_id} ended successfully"

    def list_sessions(self) -> str:
        """
        List all active sessions.

        Returns:
            Formatted list of sessions
        """
        if not self.sessions:
            return "No active sessions"

        lines = ["Active sessions:"]
        for session_id, session in self.sessions.items():
            age = time.time() - session.created_at
            idle = time.time() - session.last_activity
            name_str = f" ({session.name})" if session.name else ""
            lines.append(
                f"  {session_id}{name_str}: "
                f"age={age:.0f}s, idle={idle:.0f}s, events={session.event_counter}"
            )

        return "\n".join(lines)

    def get_session(self, session_id: str) -> Optional[ACL2Session]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    async def cleanup_all(self) -> None:
        """Clean up all sessions."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Terminate all sessions concurrently to avoid blocking
        session_list = list(self.sessions.values())
        if session_list:
            await asyncio.gather(
                *[session.terminate() for session in session_list],
                return_exceptions=True  # Don't let one failure stop others
            )
        self.sessions.clear()

    async def _cleanup_inactive_sessions(self) -> None:
        """Background task to clean up inactive sessions."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                now = time.time()
                to_remove = []

                # SECURITY: Create snapshot to avoid race conditions
                sessions_snapshot = list(self.sessions.items())

                for session_id, session in sessions_snapshot:
                    if now - session.last_activity > SESSION_INACTIVITY_TIMEOUT:
                        to_remove.append((session_id, session))

                # SECURITY: Check if session still exists before removing
                for session_id, session in to_remove:
                    if session_id in self.sessions:
                        try:
                            await session.terminate()
                            del self.sessions[session_id]
                        except Exception:
                            # Log failure but continue cleanup
                            pass

            except asyncio.CancelledError:
                break
            except Exception:
                # Continue cleanup loop even if there's an error
                pass


# Global session manager
session_manager = SessionManager()

app: Server = Server("acl2-mcp")


@app.list_tools()  # type: ignore[misc,no-untyped-call]
async def list_tools() -> list[Tool]:
    """List available ACL2 tools."""
    return [
        Tool(
            name="start_session",
            description="Start a new persistent ACL2 session. This creates a long-running ACL2 process that maintains state across multiple tool calls. Use this when you want to incrementally build up definitions and theorems without having to wrap everything in progn. Sessions auto-timeout after 30 minutes of inactivity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional human-readable name for the session. Example: 'natural-numbers-proof'",
                    },
                },
            },
        ),
        Tool(
            name="end_session",
            description="End a persistent ACL2 session and clean up resources. Use this when you're done with incremental development. Sessions also auto-cleanup after 30 minutes of inactivity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session to end",
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="list_sessions",
            description="List all active ACL2 sessions with their IDs, names, age, idle time, and event count. Use this to see which sessions are available and their current state.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="prove",
            description="Submit an ACL2 theorem (defthm) for proof. Use this to prove mathematical properties. Example: (defthm append-nil (implies (true-listp x) (equal (append x nil) x))). The theorem will be proven and added to the ACL2 world. Returns detailed ACL2 proof output. Can optionally use a persistent session for incremental development.",
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
                    "session_id": {
                        "type": "string",
                        "description": "Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.",
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="evaluate",
            description="Evaluate ACL2 expressions or define functions (defun). Use this for: 1) Defining functions, 2) Computing values, 3) Testing expressions. Example: (defun factorial (n) (if (zp n) 1 (* n (factorial (- n 1))))) or (+ 1 2). Returns the ACL2 evaluation result. Can optionally use a persistent session for incremental development.",
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
                    "session_id": {
                        "type": "string",
                        "description": "Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.",
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
                    "session_id": {
                        "type": "string",
                        "description": "Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.",
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
            description="Test if an ACL2 event would be accepted WITHOUT saving it permanently. Use this to validate definitions/theorems before adding them to files. Faster than 'prove' for testing. Returns success/failure. Example use case: testing if a function definition is valid before committing to a file. Can optionally use a persistent session to test in context of existing definitions.",
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
                    "session_id": {
                        "type": "string",
                        "description": "Optional: ID of persistent session to use. If not provided, creates a fresh ACL2 session for this command only.",
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
        Tool(
            name="undo",
            description="Undo the last ACL2 event in a persistent session. This removes the most recent definition, theorem, or command from the session's world. Use this to backtrack and try alternative approaches. Uses ACL2's :ubt (undo-back-through) command. Only works with persistent sessions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session to undo in",
                    },
                    "count": {
                        "type": "number",
                        "description": "Number of events to undo (default: 1)",
                        "default": 1,
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="save_checkpoint",
            description="Save a named checkpoint of the current ACL2 world state in a session. You can later restore to this checkpoint to try alternative proof strategies. Use this before attempting risky proof steps or when you want to preserve a known-good state.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session",
                    },
                    "checkpoint_name": {
                        "type": "string",
                        "description": "Name for this checkpoint. Example: 'before-induction-proof'",
                    },
                },
                "required": ["session_id", "checkpoint_name"],
            },
        ),
        Tool(
            name="restore_checkpoint",
            description="Restore a session to a previously saved checkpoint. This undoes all events that occurred after the checkpoint was created. Use this to backtrack to a known-good state and try a different approach.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session",
                    },
                    "checkpoint_name": {
                        "type": "string",
                        "description": "Name of the checkpoint to restore",
                    },
                },
                "required": ["session_id", "checkpoint_name"],
            },
        ),
        Tool(
            name="get_world_state",
            description="Display the current ACL2 world state in a session, showing all definitions, theorems, and events. Use this to see what's currently defined in your session. Uses ACL2's :pbt (print-back-through) command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session",
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of recent events to show (default: 20)",
                        "default": 20,
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="retry_proof",
            description="Retry the last proof attempt in a session with different hints or strategies. This is useful for interactive proof debugging - when a proof fails, you can try again with modified hints without re-submitting the entire theorem. The previous failed proof attempt is undone first.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session with the failed proof",
                    },
                    "code": {
                        "type": "string",
                        "description": "New proof attempt with different hints. Example: (defthm my-thm (equal x y) :hints ((\"Goal\" :use (:instance lemma))))",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["session_id", "code"],
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


def build_include_book_command(file_path: str, additional_code: str = "") -> tuple[str, str]:
    """
    Build include-book command for ACL2.

    Args:
        file_path: Path to the book (without .lisp extension)
        additional_code: Optional code to run after including

    Returns:
        Tuple of (command_string, error_message). If error_message is non-empty, command_string is empty.
    """
    # Remove .lisp extension if present
    book_path = str(Path(file_path).with_suffix(""))
    lisp_path = Path(book_path).with_suffix(".lisp")

    try:
        abs_path = validate_file_path(str(lisp_path))
    except ValueError as e:
        return "", f"Error: {e}"

    # Escape the book path for safe use in ACL2 code
    escaped_book_path = escape_acl2_string(book_path)

    # Build code to include book and run additional commands
    code = f'(include-book "{escaped_book_path}")'
    if additional_code.strip():
        # Validate additional code length
        if len(additional_code) > MAX_CODE_LENGTH:
            return "", f"Error: Additional code exceeds maximum length of {MAX_CODE_LENGTH} characters"
        code += f"\n{additional_code}"

    return code, ""


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
    code, error = build_include_book_command(file_path, additional_code)
    if error:
        return error

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
    if name == "start_session":
        session_name = arguments.get("name")
        session_id, message = await session_manager.start_session(session_name)
        return [
            TextContent(
                type="text",
                text=message,
            )
        ]

    elif name == "end_session":
        session_id = arguments["session_id"]
        message = await session_manager.end_session(session_id)
        return [
            TextContent(
                type="text",
                text=message,
            )
        ]

    elif name == "list_sessions":
        message = session_manager.list_sessions()
        return [
            TextContent(
                type="text",
                text=message,
            )
        ]

    elif name == "undo":
        session_id = arguments["session_id"]
        count = arguments.get("count", 1)

        # SECURITY: Validate count parameter
        try:
            count = validate_integer_parameter(count, 1, 10000, "count")
        except ValueError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error: {e}",
                )
            ]

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]

        # Use ACL2's :ubt to undo
        # SECURITY: Ensure undo_count is within valid range
        undo_count = max(0, min(session.event_counter - count, session.event_counter))
        if undo_count < 0:
            undo_count = 0

        output = await session.send_command(f":ubt {undo_count}")
        session.event_counter = undo_count

        return [
            TextContent(
                type="text",
                text=f"Undone {count} event(s):\n\n{output}",
            )
        ]

    elif name == "save_checkpoint":
        session_id = arguments["session_id"]
        checkpoint_name = arguments["checkpoint_name"]

        # SECURITY: Validate checkpoint name
        try:
            checkpoint_name = validate_checkpoint_name(checkpoint_name)
        except ValueError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error: {e}",
                )
            ]

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]

        # SECURITY: Limit number of checkpoints per session
        if len(session.checkpoints) >= MAX_CHECKPOINTS_PER_SESSION:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Maximum number of checkpoints ({MAX_CHECKPOINTS_PER_SESSION}) reached for this session",
                )
            ]

        new_checkpoint = SessionCheckpoint(
            name=checkpoint_name,
            event_number=session.event_counter,
            timestamp=time.time(),
        )
        session.checkpoints[checkpoint_name] = new_checkpoint

        return [
            TextContent(
                type="text",
                text=f"Checkpoint '{checkpoint_name}' saved at event {session.event_counter}",
            )
        ]

    elif name == "restore_checkpoint":
        session_id = arguments["session_id"]
        checkpoint_name = arguments["checkpoint_name"]

        # SECURITY: Validate checkpoint name
        try:
            checkpoint_name = validate_checkpoint_name(checkpoint_name)
        except ValueError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error: {e}",
                )
            ]

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]

        checkpoint: Optional[SessionCheckpoint] = session.checkpoints.get(checkpoint_name)
        if checkpoint is None:
            available = ", ".join(session.checkpoints.keys()) if session.checkpoints else "none"
            return [
                TextContent(
                    type="text",
                    text=f"Error: Checkpoint '{checkpoint_name}' not found. Available: {available}",
                )
            ]

        # Restore to checkpoint by undoing to that event number
        output = await session.send_command(f":ubt {checkpoint.event_number}")
        session.event_counter = checkpoint.event_number

        return [
            TextContent(
                type="text",
                text=f"Restored to checkpoint '{checkpoint_name}' (event {checkpoint.event_number}):\n\n{output}",
            )
        ]

    elif name == "get_world_state":
        session_id = arguments["session_id"]
        limit = arguments.get("limit", 20)

        # SECURITY: Validate limit parameter to prevent DoS
        try:
            limit = validate_integer_parameter(limit, 1, 1000, "limit")
        except ValueError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error: {e}",
                )
            ]

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]

        # Use ACL2's :pbt to show recent events
        # SECURITY: Ensure start_event is non-negative
        start_event = max(0, session.event_counter - limit)
        output = await session.send_command(f":pbt {start_event}")

        return [
            TextContent(
                type="text",
                text=f"World state (last {limit} events):\n\n{output}",
            )
        ]

    elif name == "retry_proof":
        session_id = arguments["session_id"]
        code = arguments["code"]
        timeout = arguments.get("timeout", 60)

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]

        # Undo the last failed proof attempt
        if session.event_counter > 0:
            await session.send_command(f":ubt {session.event_counter - 1}")
            session.event_counter -= 1

        # Try the new proof
        output = await session.send_command(code, timeout)

        return [
            TextContent(
                type="text",
                text=f"Retry proof result:\n\n{output}",
            )
        ]

    elif name == "prove":
        code = arguments["code"]
        timeout = arguments.get("timeout", 30)
        session_id = arguments.get("session_id")

        if session_id:
            session = session_manager.get_session(session_id)
            if not session:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: Session {session_id} not found",
                    )
                ]
            output = await session.send_command(code, timeout)
        else:
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
        session_id = arguments.get("session_id")

        if session_id:
            session = session_manager.get_session(session_id)
            if not session:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: Session {session_id} not found",
                    )
                ]
            output = await session.send_command(code, timeout)
        else:
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
        session_id = arguments.get("session_id")

        # Build the command (same logic for both session and non-session)
        code, error = build_include_book_command(file_path, additional_code)
        if error:
            return [
                TextContent(
                    type="text",
                    text=error,
                )
            ]

        if session_id:
            session = session_manager.get_session(session_id)
            if not session:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: Session {session_id} not found",
                    )
                ]
            output = await session.send_command(code, timeout)
        else:
            output = await run_acl2(code, timeout)

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
        session_id = arguments.get("session_id")

        if session_id:
            session = session_manager.get_session(session_id)
            if not session:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: Session {session_id} not found",
                    )
                ]
            output = await session.send_command(code, timeout)
        else:
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
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    finally:
        # Clean up all sessions on shutdown
        await session_manager.cleanup_all()


def main() -> None:
    """Main entry point for the server."""
    # Ignore SIGPIPE to prevent broken pipe errors when clients disconnect
    # This is safe on Unix-like systems; on Windows SIGPIPE doesn't exist
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    asyncio.run(run())


if __name__ == "__main__":
    main()
