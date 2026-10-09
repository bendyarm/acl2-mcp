"""ACL2 MCP Server implementation."""

import aiofiles
import asyncio
import errno
import fcntl
import os
import platform
import pty
import re
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid
from pathlib import Path
from typing import Any, Sequence, Optional, IO, Callable, Awaitable
from dataclasses import dataclass, field

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from acl2_mcp.config import ServerConfig, ToolOutputConfig, load_config


# Security constants
MAX_TIMEOUT = 300  # 5 minutes maximum
MIN_TIMEOUT = 1
MAX_CODE_LENGTH = 1_000_000  # 1MB of code
SESSION_INACTIVITY_TIMEOUT = None  # Disabled by default - sessions don't auto-timeout
MAX_SESSIONS = 50  # Maximum concurrent sessions
MAX_SESSION_NAME_LENGTH = 100  # Maximum session name length

_DEBUG_LOG_PATH = Path.home() / ".acl2-mcp" / "debug.log"
_debug_logging_enabled = False


def _init_debug_logging(enabled: bool) -> None:
    """Initialize debug logging.  If enabled, remove any stale log file."""
    global _debug_logging_enabled
    _debug_logging_enabled = enabled
    if enabled:
        try:
            _DEBUG_LOG_PATH.unlink(missing_ok=True)
        except Exception:
            pass


def _debug_log(message: str) -> None:
    """Append a timestamped debug message to ~/.acl2-mcp/debug.log."""
    if not _debug_logging_enabled:
        return
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(_DEBUG_LOG_PATH, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def elide_large_output(output: str, config: ToolOutputConfig, log_file: Path | None) -> str:
    """Elide output that exceeds the configured max size.

    Returns the original output if within limits.  Otherwise returns
    the first head_chars, an elision warning, and the last tail_chars.
    """
    if len(output) <= config.max_output_chars:
        return output

    head = output[:config.head_chars]
    tail = output[-config.tail_chars:]
    log_msg = f"  See session log: {log_file}" if log_file else ""
    elision = f"\n[WARNING: Large output elided ({len(output)} chars).{log_msg}]\n"
    return head + elision + tail


# How long to wait (seconds) after seeing a potential prompt before confirming
# it.  If more PTY data arrives within this window the candidate is
# re-absorbed into normal output processing, avoiding false positives on
# output lines that happen to match a prompt pattern.
PROMPT_SETTLE_SECONDS = 0.2

# Prompt patterns for detecting command completion.
#
# These are the "positive" patterns from emacs-acl2.el *acl2-insert-pats*
# (commented-out alternative in that file).  Each pattern matches a line
# (with no trailing newline) that could be a Lisp or ACL2 prompt.
#
# Because these patterns are broad (especially ".*>[ ]*$" and ".*\* $"),
# prompt detection uses a settle delay (PROMPT_SETTLE_SECONDS) to
# distinguish real prompts from mid-output lines that happen to match.
PROMPT_PATTERNS = [
    re.compile(r'.*>[ ]*$'),      # ACL2, GCL, CLISP, LispWorks, CCL debugger
    re.compile(r'.*\] $'),        # SBCL debugger
    re.compile(r'.*\* $'),        # CMUCL, SBCL
]
# Other Lisp prompts not included: ".*[?] $" (CCL), ".*): $" (Allegro CL)


def prompt_depth(text: str) -> int:
    """Return the LD nesting depth from an ACL2 prompt.

    Counts trailing '>' characters (before optional spaces).
    'ACL2 !>'   → 1   (top-level)
    'ACL2 !>>'  → 2   (inside one LD)
    'ACL2 !>>>' → 3   (nested LD)
    Non-'>' prompts (SBCL debugger '0] ', raw Lisp '* ') → 0.
    """
    stripped = text.rstrip()
    count = 0
    for ch in reversed(stripped):
        if ch == '>':
            count += 1
        else:
            break
    return count


def matches_prompt_pattern(text: str) -> bool:
    """Check if text matches any known prompt pattern."""
    for pattern in PROMPT_PATTERNS:
        if pattern.match(text):
            return True
    return False


def validate_timeout(timeout: int | None) -> int | None:
    """
    Validate and clamp timeout value.

    Args:
        timeout: Requested timeout in seconds, or None for no timeout

    Returns:
        Validated timeout value, or None for no timeout
    """
    if timeout is None:
        return None
    if not isinstance(timeout, (int, float)):
        return None
    return max(MIN_TIMEOUT, min(int(timeout), MAX_TIMEOUT))


def detect_optimal_jobs() -> tuple[int | None, str]:
    """
    Detect optimal number of jobs based on CPU count and current load.
    Works on macOS, Linux, and WSL2.

    Returns:
        Tuple of (optimal_jobs, info_message)
        - optimal_jobs: Recommended number of jobs, or None if user should specify
        - info_message: Information about CPU and load for user
    """
    try:
        # Get total CPU/thread count
        cpu_count = os.cpu_count()
        if cpu_count is None:
            return None, "Unable to determine CPU count"

        # Get current load average (1-minute load)
        # Works on Unix-like systems: macOS, Linux, WSL2
        load_avg = os.getloadavg()[0]

        # Calculate available threads
        available = cpu_count - load_avg

        info = f"System has {cpu_count} threads, current load: {load_avg:.2f}, available: {available:.2f}"

        if available >= 1.0:
            # Use available threads, rounded down to nearest integer
            optimal_jobs = max(1, int(available))
            return optimal_jobs, info
        else:
            # Not enough available, ask user
            return None, info

    except Exception as e:
        return None, f"Unable to detect system load: {e}"


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
class ACL2Session:
    """
    Represents a persistent ACL2 session with background I/O handling via PTY.

    Architecture:
    - Uses a pseudo-terminal (pty) for bidirectional communication with ACL2
    - Event-driven reader (loop.add_reader) continuously reads from pty master
    - Raw bytes are written to a rolling ring buffer for pattern matching
    - Lines are tagged with monotonic timestamps and sequence IDs
    - A merge queue collects all output lines
    - A logger task writes lines to the log file in timestamp order
    - send_command waits for prompts by checking the ring buffer
    - PTY makes SBCL think it's interactive, ensuring unbuffered output
    - Matches Emacs shell-mode behavior (echoed input, prompts, carriage returns)
    """
    session_id: str
    name: Optional[str]
    process: asyncio.subprocess.Process
    created_at: float
    last_activity: float
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    log_file: Optional[Path] = None
    log_handle: Optional[IO[str]] = None
    tool_output_config: ToolOutputConfig = field(default_factory=ToolOutputConfig)

    # PTY infrastructure
    master_fd: Optional[int] = None
    reader_registered: bool = False  # Track whether loop.add_reader was called
    ring_buffer: bytearray = field(default_factory=bytearray)
    max_ring_buffer_size: int = 65536  # 64KB rolling buffer
    # Accumulates incomplete line/prompt bytes across chunks
    partial_line_buffer: bytearray = field(default_factory=bytearray)

    # Background I/O infrastructure
    # Unbounded queue to prevent blocking when output is very fast (e.g., Axe simplification)
    merge_queue: asyncio.Queue[tuple[float, int, str, str]] = field(default_factory=lambda: asyncio.Queue(maxsize=0))  # (timestamp, seq_id, stream_type, line)
    output_buffer: list[tuple[int, str]] = field(default_factory=list)  # (seq_id, line) for send_command
    sequence_counter: int = 0  # Atomic counter for tie-breaking
    sequence_lock: asyncio.Lock = field(default_factory=asyncio.Lock)  # Protects sequence_counter

    # Prompt detection — sequenced to avoid stale-event corruption.
    # _flush_prompt increments prompt_seq and notifies via prompt_condition.
    # send_command captures prompt_seq before sending and waits for it to
    # increase, so stale confirmations from earlier commands are ignored.
    _prompt_flush_handle: Optional[asyncio.TimerHandle] = field(default=None, repr=False)
    prompt_seq: int = 0
    last_prompt_text: str = ""
    _confirm_max_depth: int = 1  # Only confirm prompts at this depth or less
    prompt_condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    # Serializes access to partial_line_buffer and _prompt_flush_handle
    # across concurrent _process_pty_chunk / _flush_prompt coroutines.
    _chunk_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # Background task references
    # Note: PTY reader uses loop.add_reader() callback (event-driven, tracked via reader_registered)
    logger_task: Optional[asyncio.Task[None]] = None

    # Shutdown coordination
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    _end_marker_written: bool = False

    async def send_command(self, command: str, timeout: int | None = None) -> str:
        """
        Send a command to the ACL2 session and get response.

        Uses background logging infrastructure - does not read from stdout directly.
        Instead, waits for prompt to appear in the output_buffer populated by logger task.

        Args:
            command: ACL2 command to execute
            timeout: Timeout in seconds, or None for no timeout

        Returns:
            Output from ACL2
        """
        async with self.lock:
            self.last_activity = time.time()

            if self.master_fd is None:
                return "Error: Session PTY master is not available"

            # SECURITY: Validate code length to prevent memory exhaustion
            if len(command) > MAX_CODE_LENGTH:
                return f"Error: Command exceeds maximum length of {MAX_CODE_LENGTH} characters"

            # SECURITY: Validate timeout
            validated_timeout = validate_timeout(timeout)

            try:
                # Capture sequence counters BEFORE adding anything to queues or
                # writing to PTY.  During the await calls below, the event loop
                # can run _logger_task / _flush_prompt, which append to
                # output_buffer and increment prompt_seq.  If we capture these
                # after those awaits, we might miss the response entirely.
                start_seq_id = self.sequence_counter
                start_prompt_seq = self.prompt_seq
                # Set the max depth for prompt confirmation.  Only prompts
                # at this depth or less will be confirmed.  This prevents
                # intermediate LD prompts (deeper) from triggering early
                # return, while still allowing responses at the current
                # depth (e.g., inside interactive LD).
                self._confirm_max_depth = prompt_depth(self.last_prompt_text) or 1

                # Log input followed by an INPUT timestamp marker for easier auditing
                timestamp_mono = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                # Input line (command)
                await self.merge_queue.put((timestamp_mono, seq_id, "stdin", f"{command}\n"))
                # Timestamp after input (preserve original format)
                seq_id = await self._get_next_sequence_id()
                current_time = time.strftime("%Y-%m-%d %H:%M:%S")
                timestamp_line = f"[{current_time} INPUT]\n"
                await self.merge_queue.put((timestamp_mono, seq_id, "stdin", timestamp_line))

                # Send command to ACL2 via PTY master
                # Use chunked writes to avoid PTY buffer saturation. On macOS,
                # PIPE_BUF is only 512 bytes, and writing large inputs in one
                # os.write() call can cause partial writes or deadlocks when
                # the PTY output buffer fills with echoed input. By writing in
                # small chunks and yielding to the event loop between chunks,
                # we allow the PTY reader to drain ACL2's output and prevent
                # buffer backpressure.
                try:
                    command_bytes = f"{command}\n".encode()
                    loop = asyncio.get_event_loop()
                    chunk_size = 512  # macOS PIPE_BUF size
                    total_written = 0

                    for i in range(0, len(command_bytes), chunk_size):
                        chunk = command_bytes[i:i + chunk_size]
                        written = await loop.run_in_executor(
                            None,
                            os.write,
                            self.master_fd,
                            chunk
                        )
                        if written < len(chunk):
                            return "Error: Failed to write complete command to session"
                        total_written += written
                        # Yield to event loop to allow PTY output to be drained
                        # This prevents buffer saturation when ACL2 echoes input
                        # A small delay is needed to give the reader time to process
                        await asyncio.sleep(0.001)

                except OSError as e:
                    if e.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                        return "Error: Session connection lost"
                    raise

                # Wait for a confirmed prompt from the chunk processor.
                # The chunk processor detects potential prompts in partial
                # buffers and waits PROMPT_SETTLE_SECONDS before confirming,
                # then increments prompt_seq and notifies via prompt_condition.
                #
                # We capture prompt_seq *before* sending so that stale
                # confirmations from earlier commands (e.g., LD intermediate
                # prompts still being flushed) are ignored.
                start_time = time.time()
                _debug_log(f"send_command: start_seq_id={start_seq_id}, start_prompt_seq={start_prompt_seq}, output_buffer_len={len(self.output_buffer)}")

                try:
                    async with self.prompt_condition:
                        while self.prompt_seq <= start_prompt_seq:
                            # Compute wait timeout
                            if validated_timeout is not None:
                                elapsed = time.time() - start_time
                                if elapsed >= validated_timeout:
                                    # On timeout, check if there's an
                                    # unconfirmed prompt in the partial
                                    # buffer and adopt it as the current
                                    # prompt.  This allows subsequent
                                    # commands to use the correct depth
                                    # (e.g., after (ld *standard-oi*)
                                    # produces a depth-2 prompt).
                                    self._adopt_pending_prompt()
                                    return f"Error: Command execution timed out after {validated_timeout} seconds"
                                remaining = max(0.1, validated_timeout - elapsed)
                                wait_timeout = min(remaining, 1.0)
                            else:
                                wait_timeout = 1.0

                            try:
                                await asyncio.wait_for(
                                    self.prompt_condition.wait(),
                                    timeout=wait_timeout,
                                )
                            except asyncio.TimeoutError:
                                pass

                            # Check if session has been shutdown
                            if self.shutdown_event.is_set():
                                return "Error: Session terminated during command execution"

                except Exception as e:
                    _debug_log(f"send_command exception: {type(e).__name__}: {e}")
                    return f"Error: Session communication failed ({type(e).__name__}: {e})"

                _debug_log(f"send_command: prompt confirmed, prompt_seq={self.prompt_seq}, last_prompt='{self.last_prompt_text}'")

                # Give the logger task a moment to flush the prompt from
                # the merge queue into output_buffer.
                await asyncio.sleep(0.05)

                # Collect output lines produced after the command was sent,
                # identified by seq_id.  This is robust against buffer
                # trimming since we match on monotonic IDs, not positions.
                output_lines = [line for sid, line in self.output_buffer if sid > start_seq_id]

                # Detect if trimming lost some of our output
                if self.output_buffer and self.output_buffer[0][0] > start_seq_id + 1:
                    _debug_log(f"send_command: output truncated, earliest retained seq_id={self.output_buffer[0][0]}, start_seq_id={start_seq_id}")

                _debug_log(f"send_command: collected {len(output_lines)} lines (start_seq_id={start_seq_id})")

                # Return collected output, eliding if too large
                output = "".join(output_lines).strip()
                return elide_large_output(output, self.tool_output_config, self.log_file)

            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                    return "Error: Session connection lost"
                return "Error: Failed to execute command in session"
            except Exception:
                # SECURITY: Don't leak internal details in error messages
                return "Error: Failed to execute command in session"

    async def interrupt(self) -> str:
        """
        Interrupt a running command in this session by sending Ctrl-C via PTY.

        This mimics a user pressing Ctrl-C in a terminal. The PTY's controlling
        terminal setup ensures the interrupt is delivered correctly to ACL2/SBCL.

        Returns:
            Status message indicating success or failure
        """
        try:
            if self.master_fd is None:
                return "Error: Session PTY master is not available"

            if self.process.returncode is not None:
                return "Error: Session process has already terminated"

            # Primary method: Send Ctrl-C (0x03) through the PTY
            # This is how a terminal delivers interrupts - the line discipline
            # converts it to SIGINT for the foreground process group
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    os.write,
                    self.master_fd,
                    b"\x03"  # Ctrl-C
                )

                # Log the interrupt in the session
                timestamp = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                interrupt_time = time.strftime("%Y-%m-%d %H:%M:%S")
                marker = f"[{interrupt_time} INTERRUPT SENT]\n"
                await self.merge_queue.put((timestamp, seq_id, "stdout", marker))

                return "Interrupt signal sent via PTY"

            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                    # PTY write failed, try fallback method
                    pass
                else:
                    raise

            # Fallback method: Send SIGINT to the process group
            # This is needed if the PTY write fails for some reason
            try:
                # Get the process group ID and send SIGINT
                pgid = os.getpgid(self.process.pid)
                os.killpg(pgid, signal.SIGINT)

                # Log the interrupt
                timestamp = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                interrupt_time = time.strftime("%Y-%m-%d %H:%M:%S")
                marker = f"[{interrupt_time} INTERRUPT SENT (FALLBACK)]\n"
                await self.merge_queue.put((timestamp, seq_id, "stdout", marker))

                return "Interrupt signal sent via SIGINT (fallback)"

            except (ProcessLookupError, PermissionError) as e:
                return f"Error: Failed to interrupt session: {e}"

        except Exception as e:
            return f"Error: Failed to interrupt session: {e}"

    async def _get_next_sequence_id(self) -> int:
        """Get the next sequence ID for ordering output lines."""
        async with self.sequence_lock:
            seq_id = self.sequence_counter
            self.sequence_counter += 1
            return seq_id

    def _on_pty_readable(self) -> None:
        """
        Synchronous callback invoked by event loop when PTY master has data.
        Reads available data, updates ring buffer, processes lines, and schedules
        async work via ensure_future.

        This is NOT a coroutine - it's a synchronous callback for loop.add_reader.
        """
        if self.master_fd is None:
            return

        # Don't process new data if shutdown is in progress
        if self.shutdown_event.is_set():
            return

        try:
            # Read all available data (master_fd is non-blocking)
            while True:
                try:
                    chunk = os.read(self.master_fd, 4096)
                    if not chunk:
                        # EOF - PTY master closed
                        # Schedule async cleanup
                        asyncio.ensure_future(self._handle_pty_eof())
                        return

                    # Add to ring buffer (maintain max size)
                    self.ring_buffer.extend(chunk)
                    if len(self.ring_buffer) > self.max_ring_buffer_size:
                        # Trim from the beginning to maintain size limit
                        excess = len(self.ring_buffer) - self.max_ring_buffer_size
                        self.ring_buffer = self.ring_buffer[excess:]

                    # Schedule async processing of the chunk
                    asyncio.ensure_future(self._process_pty_chunk(chunk))

                except BlockingIOError:
                    # No more data available right now
                    break
                except OSError as e:
                    if e.errno in (errno.EIO, errno.EBADF):
                        # EIO: I/O error (master closed), EBADF: bad fd
                        asyncio.ensure_future(self._handle_pty_eof())
                        return
                    raise

        except Exception as e:
            print(f"Error in PTY reader callback: {e}", file=sys.stderr)
            asyncio.ensure_future(self._handle_pty_error(e))

    async def _process_pty_chunk(self, chunk: bytes) -> None:
        """
        Process a chunk of data from the PTY.
        Tags lines with timestamps, pushes to merge queue for logging.

        Uses _chunk_lock to serialize access to partial_line_buffer and
        _prompt_flush_handle.  Multiple _process_pty_chunk coroutines can
        be scheduled concurrently (via ensure_future from _on_pty_readable),
        so the lock prevents interleaving that could corrupt state.

        Args:
            chunk: Raw bytes from PTY (may contain partial lines, carriage returns, etc.)
        """
        async with self._chunk_lock:
            try:
                # Cancel any pending prompt flush — new data arrived, so the
                # partial buffer we were about to flush as a prompt was actually
                # mid-output.
                if self._prompt_flush_handle is not None:
                    self._prompt_flush_handle.cancel()
                    self._prompt_flush_handle = None

                # Process complete lines and detect partial prompts, preserving
                # incomplete bytes across chunks via partial_line_buffer.
                if self.partial_line_buffer:
                    buffer = self.partial_line_buffer + chunk
                    self.partial_line_buffer.clear()
                else:
                    buffer = chunk

                while buffer:
                    newline_idx = buffer.find(b'\n')

                    if newline_idx >= 0:
                        # Extract complete line (including newline)
                        line = buffer[:newline_idx + 1]
                        buffer = buffer[newline_idx + 1:]

                        # Normalize CRLF -> LF for consistency
                        if line.endswith(b"\r\n"):
                            line = line[:-2] + b"\n"

                        # Tag and push to queue
                        timestamp = time.monotonic()
                        seq_id = await self._get_next_sequence_id()
                        decoded_line = line.decode(errors='replace')
                        await self.merge_queue.put((timestamp, seq_id, "stdout", decoded_line))
                    else:
                        # Remaining buffer has no newline — could be a prompt or
                        # mid-output.  Store it in partial_line_buffer either way.
                        # If it looks like a prompt, schedule a delayed flush; if
                        # more data arrives before the delay fires, the flush is
                        # cancelled and the partial buffer is re-processed with
                        # the new chunk.
                        self.partial_line_buffer.extend(buffer)

                        try:
                            decoded_buffer = buffer.decode(errors='replace')
                            prompt_candidate = decoded_buffer.rstrip('\r')
                            if matches_prompt_pattern(prompt_candidate):
                                self._schedule_prompt_flush()
                        except UnicodeDecodeError:
                            pass  # Partial UTF-8; wait for more bytes

                        break

            except Exception as e:
                print(f"Error processing PTY chunk: {e}", file=sys.stderr)

    def _schedule_prompt_flush(self) -> None:
        """Schedule a delayed flush of the partial_line_buffer as a prompt.

        If no new PTY data arrives within PROMPT_SETTLE_SECONDS, the partial
        buffer is flushed as a prompt line.  If new data does arrive, the
        timer is cancelled in _process_pty_chunk and the partial buffer is
        re-processed normally.
        """
        loop = asyncio.get_event_loop()
        self._prompt_flush_handle = loop.call_later(
            PROMPT_SETTLE_SECONDS,
            lambda: asyncio.ensure_future(self._flush_prompt()),
        )

    def _adopt_pending_prompt(self) -> None:
        """Adopt an unconfirmed prompt as the current prompt level.

        Called on timeout.  Checks both partial_line_buffer (prompt not
        yet flushed) and the last line in output_buffer (prompt flushed
        to log but not confirmed).  Updates last_prompt_text so that
        subsequent commands use the correct depth for
        _confirm_max_depth.  This handles the case where
        (ld *standard-oi*) produces a depth-2 prompt that was never
        confirmed.
        """
        # Check partial_line_buffer first
        if self.partial_line_buffer:
            try:
                decoded = bytes(self.partial_line_buffer).decode(errors='replace')
                candidate = decoded.rstrip('\r')
                if matches_prompt_pattern(candidate):
                    self.last_prompt_text = candidate
                    _debug_log(f"_adopt_pending_prompt: adopted from partial_line_buffer '{candidate}'")
                    return
            except Exception:
                pass

        # Check the last line in output_buffer (prompt was flushed but not confirmed)
        if self.output_buffer:
            _seq_id, last_line = self.output_buffer[-1]
            candidate = last_line.rstrip('\n').rstrip('\r')
            if matches_prompt_pattern(candidate):
                self.last_prompt_text = candidate
                _debug_log(f"_adopt_pending_prompt: adopted from output_buffer '{candidate}'")

    async def _flush_prompt(self) -> None:
        """Flush the partial_line_buffer as a confirmed prompt.

        Called after the settle delay (PROMPT_SETTLE_SECONDS) with no
        new data.  Depth-1 prompts (top-level) are confirmed immediately.
        Depth-2+ prompts (inside LD) are NOT confirmed here — they are
        left in partial_line_buffer.  If ACL2 continues processing the
        next form, new data will arrive and _process_pty_chunk will
        absorb the buffer.  If LD finishes, the depth-1 final prompt
        will be confirmed normally.  If the command times out,
        send_command handles that independently.

        Uses _chunk_lock to serialize with _process_pty_chunk.
        """
        async with self._chunk_lock:
            self._prompt_flush_handle = None
            if not self.partial_line_buffer:
                return

            try:
                decoded = bytes(self.partial_line_buffer).decode(errors='replace')
                prompt_candidate = decoded.rstrip('\r')
                if not matches_prompt_pattern(prompt_candidate):
                    return

                depth = prompt_depth(prompt_candidate)
                if depth > self._confirm_max_depth:
                    # Deeper than the starting depth — likely an
                    # intermediate prompt during LD.  Don't confirm
                    # (don't increment prompt_seq or notify), but DO
                    # flush to the log/output_buffer so the prompt
                    # appears in the correct position in the log.
                    self.partial_line_buffer.clear()
                    timestamp = time.monotonic()
                    seq_id = await self._get_next_sequence_id()
                    await self.merge_queue.put((timestamp, seq_id, "stdout", prompt_candidate))
                    _debug_log(f"_flush_prompt: depth-{depth} prompt '{prompt_candidate}' — flushed to log but not confirming (deeper than max {self._confirm_max_depth})")
                    return

                self.partial_line_buffer.clear()
                timestamp = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                await self.merge_queue.put((timestamp, seq_id, "stdout", prompt_candidate))
                self.last_prompt_text = prompt_candidate
                self.prompt_seq += 1
                async with self.prompt_condition:
                    self.prompt_condition.notify_all()
                _debug_log(f"_flush_prompt: confirmed prompt '{prompt_candidate}' (seq={self.prompt_seq})")
            except Exception as e:
                print(f"Error flushing prompt: {e}", file=sys.stderr)

    async def _handle_pty_eof(self) -> None:
        """Handle EOF from PTY master (session ended)."""
        try:
            # Flush any remaining partial bytes as a final line before end marker
            if self.partial_line_buffer:
                try:
                    decoded = self.partial_line_buffer.decode(errors='replace')
                    timestamp = time.monotonic()
                    seq_id = await self._get_next_sequence_id()
                    await self.merge_queue.put((timestamp, seq_id, "stdout", decoded))
                finally:
                    self.partial_line_buffer.clear()
            # Only write SESSION ENDED if end_session hasn't already written one.
            if not self._end_marker_written:
                timestamp = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                end_time = time.strftime("%Y-%m-%d %H:%M:%S")
                end_marker = f"\n[{end_time} SESSION ENDED]\n"
                await self.merge_queue.put((timestamp, seq_id, "stdout", end_marker))
        except Exception as e:
            print(f"Error handling PTY EOF: {e}", file=sys.stderr)
        finally:
            self.shutdown_event.set()

    async def _handle_pty_error(self, error: Exception) -> None:
        """Handle errors from PTY reader."""
        print(f"PTY error: {error}", file=sys.stderr)
        self.shutdown_event.set()

    async def _logger_task(self) -> None:
        """
        Background task that reads from merge queue and writes to log file.
        Maintains timestamp ordering and updates output_buffer for send_command.
        """
        try:
            if not self.log_file:
                return

            # Open log file with aiofiles for non-blocking async I/O
            async with aiofiles.open(self.log_file, "a", buffering=1) as log_handle:
                while not self.shutdown_event.is_set():
                    try:
                        # Get next line from merge queue with timeout
                        timestamp, seq_id, stream_type, line = await asyncio.wait_for(
                            self.merge_queue.get(),
                            timeout=1.0  # Check shutdown event periodically
                        )

                        # Write to log file
                        await log_handle.write(line)
                        await log_handle.flush()

                        # Also store in output_buffer for send_command to collect output
                        self.output_buffer.append((seq_id, line))

                        # Check if buffer is getting too large (keep last 50000 lines)
                        if len(self.output_buffer) > 50000:
                            self.output_buffer = self.output_buffer[-50000:]
                            print(f"Warning: Output buffer trimmed for session {self.session_id}", file=sys.stderr)

                    except asyncio.TimeoutError:
                        # No data in queue, continue checking shutdown
                        continue
                    except Exception as e:
                        print(f"Error in logger task: {e}", file=sys.stderr)
                        break

                # Drain remaining items in queue before shutting down
                while not self.merge_queue.empty():
                    try:
                        timestamp, seq_id, stream_type, line = self.merge_queue.get_nowait()
                        await log_handle.write(line)
                        await log_handle.flush()
                        self.output_buffer.append((seq_id, line))
                    except asyncio.QueueEmpty:
                        break
                    except Exception as e:
                        print(f"Error draining queue: {e}", file=sys.stderr)
                        break

        except Exception as e:
            print(f"Fatal error in logger task: {e}", file=sys.stderr)

    async def terminate(self) -> None:
        """
        Terminate the ACL2 session and stop all background tasks.
        Ensures all output is logged before shutdown.
        """
        try:
            # Remove the event loop reader first
            if self.reader_registered and self.master_fd is not None:
                loop = asyncio.get_event_loop()
                try:
                    loop.remove_reader(self.master_fd)
                except (ValueError, OSError):
                    # Reader wasn't registered or fd invalid
                    pass
                self.reader_registered = False

            # Send good-bye command to ACL2 via PTY
            if self.master_fd is not None:
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        os.write,
                        self.master_fd,
                        b"(good-bye)\n"
                    )
                    # Give ACL2 a moment to process goodbye
                    await asyncio.sleep(0.5)
                except OSError:
                    # PTY already closed or other error, ignore
                    pass

            # Wait for process to terminate
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
            except Exception:
                self.process.kill()
                await self.process.wait()

        finally:
            # Signal background tasks to shut down
            self.shutdown_event.set()

            # Remove reader if not already removed
            if self.reader_registered and self.master_fd is not None:
                try:
                    loop = asyncio.get_event_loop()
                    loop.remove_reader(self.master_fd)
                except Exception:
                    pass
                self.reader_registered = False

            # Close PTY master file descriptor
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                    self.master_fd = None
                except OSError:
                    # Already closed, ignore
                    pass

            # Clear ring buffer
            if hasattr(self, 'ring_buffer'):
                self.ring_buffer.clear()

            # Wait for background tasks to complete (with timeout)
            tasks_to_cancel = []
            if self.logger_task:
                tasks_to_cancel.append(self.logger_task)

            if tasks_to_cancel:
                try:
                    # Wait for tasks to finish gracefully (they check shutdown_event)
                    await asyncio.wait_for(
                        asyncio.gather(*tasks_to_cancel, return_exceptions=True),
                        timeout=3.0
                    )
                except asyncio.TimeoutError:
                    # Force cancel if they don't finish in time
                    for task in tasks_to_cancel:
                        task.cancel()
                    # Wait for cancellation to complete
                    await asyncio.gather(*tasks_to_cancel, return_exceptions=True)


def _session_window_title(session_id: str) -> str:
    """Return the Terminal custom title for a session's log viewer window."""
    short_id = session_id.split("-")[0]
    return f"ACL2 Log {short_id}"


def _elisp_escape(value: str) -> str:
    """Escape a string for inclusion in an Emacs Lisp double-quoted literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _emacsclient_eval(form: str) -> None:
    """Best-effort: evaluate an Emacs Lisp FORM in the running Emacs via emacsclient.

    Like the other viewers, this fails silently if emacsclient or the Emacs
    server is unavailable.
    """
    try:
        subprocess.Popen(
            ["emacsclient", "-n", "--eval", form],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def open_log_viewer(
    log_file: Path, lines: int = 50, session_id: str = "", viewer: str = "auto"
) -> None:
    """
    Open a viewer tailing the log file and bring it to the foreground.

    The viewer backend is selected by ``viewer``:
      - "emacs": tail the log in Emacs via emacsclient (acl2-mcp-show-log)
      - "none": do nothing
      - "auto"/"terminal": open a terminal window (platform-specific)

    Args:
        log_file: Path to the log file to view
        lines: Number of lines to show initially (default: 50)
        session_id: Session ID, used to set a unique window title
        viewer: Viewer backend ("auto", "emacs", "terminal", or "none")
    """
    if viewer == "none":
        return
    if viewer == "emacs":
        _emacsclient_eval(f'(acl2-mcp-show-log "{_elisp_escape(str(log_file))}")')
        return

    system = platform.system()

    try:
        if system == "Darwin":  # macOS
            quoted_log_file = shlex.quote(str(log_file))
            window_title = _session_window_title(session_id)
            script = (
                'tell application "Terminal"\n'
                f'    do script "tail -n {lines} -f {quoted_log_file}"\n'
                f'    set custom title of front window to "{window_title}"\n'
                "    activate\n"
                "end tell\n"
            )
            subprocess.Popen(["osascript", "-e", script])

        elif system == "Linux":
            # Try different terminal emulators
            terminals = [
                ["gnome-terminal", "--", "tail", f"-n{lines}", "-f", str(log_file)],
                ["xterm", "-e", "tail", f"-n{lines}", "-f", str(log_file)],
                ["konsole", "-e", "tail", f"-n{lines}", "-f", str(log_file)],
            ]
            for cmd in terminals:
                try:
                    subprocess.Popen(cmd)
                    break
                except FileNotFoundError:
                    continue

        elif system == "Windows":
            # Use PowerShell
            cmd = f'powershell -Command "Get-Content -Path \'{log_file}\' -Wait -Tail {lines}"'
            subprocess.Popen(["cmd", "/c", "start", "cmd", "/k", cmd])

    except Exception:
        # Silently fail if we can't open the viewer
        # The log file will still be created and can be viewed manually
        pass


def show_session_log(
    log_file: Path, lines: int = 50, session_id: str = "", viewer: str = "auto"
) -> None:
    """
    Show the session log in a viewer and bring it to the foreground.

    If a Terminal window for this session is already open, activate it.
    Otherwise, open a new viewer tailing the log file.

    Args:
        log_file: Path to the log file to view
        lines: Number of lines to show initially if opening a new window (default: 50)
        session_id: Session ID, used to find or create the correct window
        viewer: Viewer backend ("auto", "emacs", "terminal", or "none")
    """
    if viewer == "none":
        return
    if viewer == "emacs":
        # Re-displaying is idempotent: acl2-mcp-show-log reuses the buffer.
        _emacsclient_eval(f'(acl2-mcp-show-log "{_elisp_escape(str(log_file))}")')
        return

    system = platform.system()

    try:
        if system == "Darwin":  # macOS
            quoted_log_file = shlex.quote(str(log_file))
            window_title = _session_window_title(session_id)
            script = (
                'tell application "Terminal"\n'
                '    set foundWindow to false\n'
                '    repeat with w in windows\n'
                '        try\n'
                f'            if custom title of w is "{window_title}" then\n'
                '                set frontmost of w to true\n'
                '                set foundWindow to true\n'
                '                exit repeat\n'
                '            end if\n'
                '        end try\n'
                '    end repeat\n'
                '    if foundWindow is false then\n'
                f'        do script "tail -n {lines} -f {quoted_log_file}"\n'
                f'        set custom title of front window to "{window_title}"\n'
                '    end if\n'
                '    activate\n'
                'end tell\n'
            )
            subprocess.Popen(["osascript", "-e", script])

        elif system == "Linux":
            # On Linux, just open a new viewer (no easy way to find existing windows)
            open_log_viewer(log_file, lines, session_id)

        elif system == "Windows":
            open_log_viewer(log_file, lines, session_id)

    except Exception:
        pass


def close_log_viewer(
    session_id: str, log_file: Path | None = None, viewer: str = "auto"
) -> None:
    """Close the viewer for a session's log.

    For the "emacs" backend, kills the tail buffer/process and removes its
    window via acl2-mcp-close-log.  For the terminal backend, kills the tail
    process following the log file (so Terminal won't show a "terminate
    running processes?" dialog), then closes the window by its custom title.
    Silently does nothing if the window or process doesn't exist.
    """
    if viewer == "emacs":
        if log_file:
            _emacsclient_eval(f'(acl2-mcp-close-log "{_elisp_escape(str(log_file))}")')
        return

    system = platform.system()

    try:
        if system == "Darwin":
            # To close the Terminal window without a "terminate running
            # processes?" dialog, we need to exit the shell cleanly.
            # The window runs "tail -f <logfile>" as a foreground
            # process.  We kill tail via pkill, wait for the shell to
            # return to a prompt, send "exit" to exit the shell, then
            # close the window.
            window_title = _session_window_title(session_id)
            if log_file:
                try:
                    subprocess.run(
                        ["pkill", "-f", f"tail.*{log_file.name}"],
                        capture_output=True, timeout=2,
                    )
                except Exception:
                    pass

            script = (
                'delay 0.3\n'
                'tell application "Terminal"\n'
                '    repeat with w in windows\n'
                '        try\n'
                f'            if custom title of w is "{window_title}" then\n'
                '                do script "exec true" in w\n'
                '                exit repeat\n'
                '            end if\n'
                '        end try\n'
                '    end repeat\n'
                'end tell\n'
                'delay 0.5\n'
                'tell application "Terminal"\n'
                '    repeat with w in windows\n'
                '        try\n'
                f'            if custom title of w is "{window_title}" then\n'
                '                close w\n'
                '                exit repeat\n'
                '            end if\n'
                '        end try\n'
                '    end repeat\n'
                'end tell\n'
            )
            subprocess.Popen(["osascript", "-e", script])
    except Exception:
        pass


class SessionManager:
    """Manages persistent ACL2 sessions."""

    def __init__(self, config: ServerConfig | None = None) -> None:
        self.config = config or ServerConfig()
        self.sessions: dict[str, ACL2Session] = {}
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    async def start_session(
        self,
        name: Optional[str] = None,
        enable_logging: bool = True,
        view_log_in_terminal: bool | None = None,
        log_tail_lines: int = 50,
        cwd: Optional[str] = None
    ) -> tuple[str, str]:
        """
        Start a new persistent ACL2 session.

        Args:
            name: Optional human-readable name for the session
            enable_logging: If True, log all I/O to a session file (default: True)
            view_log_in_terminal: If True, open a terminal window tailing the session
                log and bring it to the foreground (default: True)
            log_tail_lines: Number of lines to show in log viewer (default: 50)
            cwd: Optional working directory for the ACL2 process (default: None, uses current directory)

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

        effective_view_log_in_terminal = (
            self.config.session_log.view_log_in_terminal
            if view_log_in_terminal is None
            else view_log_in_terminal
        )

        session_id = str(uuid.uuid4())

        try:
            # Create pseudo-terminal (pty) for ACL2 process
            # This makes SBCL think it's running interactively, ensuring unbuffered output
            master_fd, slave_fd = pty.openpty()

            # Set terminal size (80 columns x 24 rows) to avoid issues with programs
            # that query terminal dimensions
            winsize = struct.pack("HHHH", 24, 80, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

            # Make master_fd non-blocking for event-driven async I/O
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Configure terminal attributes for raw mode (no line editing, no echo processing)
            # This prevents the PTY from interpreting control characters and provides
            # clean echoed input like Emacs shell-mode
            try:
                attrs = termios.tcgetattr(slave_fd)
                # Use raw mode but keep some minimal processing
                # ECHO is handled by ACL2/SBCL, so we disable it at PTY level
                attrs[3] = attrs[3] & ~termios.ECHO  # Disable echo (ACL2 handles its own)
                termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
            except termios.error:
                # If termios setup fails, continue anyway - not critical
                pass

            # Define preexec_fn to set up controlling terminal properly
            def setup_controlling_tty():
                """
                Make the child process a session leader with the PTY slave as controlling terminal.
                This is critical for proper signal handling (Ctrl-C) and terminal behavior.

                Required on macOS for TIOCSCTTY to work.
                """
                os.setsid()  # Create new session, become session leader
                # Set the slave PTY as the controlling terminal for this session
                # This is what makes Ctrl-C and other terminal signals work correctly
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

            # Set up environment for ACL2 process
            env = os.environ.copy()
            env["TERM"] = "dumb"  # Like Emacs comint - simple terminal without fancy features
            env["COLUMNS"] = "80"
            env["LINES"] = "24"

            # Spawn ACL2 process with slave as stdin/stdout/stderr
            # Note: We call 'acl2' directly, no wrapper script needed
            process = await asyncio.create_subprocess_exec(
                "acl2",
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd,
                env=env,
                preexec_fn=setup_controlling_tty,  # Critical for proper terminal setup
            )

            # Close slave_fd in parent process (child inherited it)
            os.close(slave_fd)

            # Set up logging first if enabled
            log_file = None
            if enable_logging:
                # Create log directory
                log_dir = Path.home() / ".acl2-mcp" / "sessions"
                log_dir.mkdir(parents=True, exist_ok=True)

                # Create log file with timestamp in name for uniqueness
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                log_filename = f"{session_id}-{timestamp}.log"
                log_file = log_dir / log_filename

            session = ACL2Session(
                session_id=session_id,
                name=name,
                process=process,
                created_at=time.time(),
                last_activity=time.time(),
                log_file=log_file,
                master_fd=master_fd,
                ring_buffer=bytearray(),
                tool_output_config=self.config.tool_output,
            )

            # Start background I/O tasks immediately
            # Use event-driven reader for PTY master
            loop = asyncio.get_event_loop()
            loop.add_reader(master_fd, session._on_pty_readable)
            session.reader_registered = True
            session.logger_task = asyncio.create_task(session._logger_task())

            # Write session start marker to log
            if log_file:
                header_time = time.strftime("%Y-%m-%d %H:%M:%S")
                start_marker = f"[{header_time} SESSION STARTED]\n"
                timestamp_mono = time.monotonic()
                seq_id = await session._get_next_sequence_id()
                await session.merge_queue.put((timestamp_mono, seq_id, "session", start_marker))

            # Wait for ACL2 startup by checking for prompt in output_buffer
            # (populated by background tasks)
            start_time = time.time()
            startup_complete = False
            while time.time() - start_time < 10.0:  # 10 second timeout
                # Check if we've seen the ACL2 prompt
                for _sid, line in session.output_buffer:
                    if "ACL2 !>" in line:
                        startup_complete = True
                        break
                if startup_complete:
                    break
                await asyncio.sleep(0.1)  # Check every 100ms

            # Open log viewer if requested
            if effective_view_log_in_terminal and log_file:
                open_log_viewer(
                    log_file, log_tail_lines, session_id,
                    viewer=self.config.session_log.viewer,
                )

            self.sessions[session_id] = session

            # Start cleanup task if not already running
            if self._cleanup_task is None:
                self._cleanup_task = asyncio.create_task(self._cleanup_inactive_sessions())

            message = f"Session started successfully. ID: {session_id}"
            if enable_logging:
                message += f"\nLog file: {session.log_file}"
            return session_id, message

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

        # Write end marker to log before terminating.
        # Set _end_marker_written so _handle_pty_eof doesn't write a
        # duplicate marker when the PTY closes during terminate().
        session._end_marker_written = True
        if session.log_file:
            header_time = time.strftime("%Y-%m-%d %H:%M:%S")
            end_marker = f"\n[{header_time} SESSION ENDED]\n"
            seq_id = await session._get_next_sequence_id()
            await session.merge_queue.put((time.monotonic(), seq_id, "session", end_marker))
            # Give the logger task a moment to flush
            await asyncio.sleep(0.1)

        await session.terminate()
        del self.sessions[session_id]

        # Close the log viewer if configured
        if self.config.session_log.close_log_on_end:
            close_log_viewer(
                session_id, session.log_file,
                viewer=self.config.session_log.viewer,
            )

        return f"Session {session_id} ended successfully"

    async def interrupt_session(self, session_id: str) -> str:
        """
        Send SIGINT to interrupt a running ACL2 command in the session.

        Args:
            session_id: The session ID to interrupt

        Returns:
            Status message
        """
        session = self.sessions.get(session_id)
        if not session:
            return f"Error: Session {session_id} not found"

        return await session.interrupt()

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
                f"age={age:.0f}s, idle={idle:.0f}s"
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

                # Only cleanup inactive sessions if timeout is enabled
                if SESSION_INACTIVITY_TIMEOUT is not None:
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
server_config = load_config()
_init_debug_logging(server_config.debug_logging)
session_manager = SessionManager(server_config)

app: Server = Server("acl2-mcp")


@app.list_tools()  # type: ignore[misc,no-untyped-call]
async def list_tools() -> list[Tool]:
    """List available ACL2 tools."""
    return [
        Tool(
            name="start_session",
            description="Start a new persistent ACL2 session. This creates a long-running ACL2 process that maintains state across multiple tool calls. Use this when you want to incrementally build up definitions and theorems without having to wrap everything in progn.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional human-readable name for the session. Example: 'natural-numbers-proof'",
                    },
                    "enable_logging": {
                        "type": "boolean",
                        "description": "If true, log all I/O to a session file in ~/.acl2-mcp/sessions/ (default: true)",
                        "default": True,
                    },
                    "view_log_in_terminal": {
                        "type": "boolean",
                        "description": "If true, open a terminal window tailing the session log and bring it to the foreground. If not specified, uses the config default (built-in default: true).",
                        "default": True,
                    },
                    "log_tail_lines": {
                        "type": "number",
                        "description": "Number of lines to show in log viewer (default: 50)",
                        "default": 50,
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Optional working directory for the ACL2 process. If not specified, uses the current directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'",
                    },
                },
            },
        ),
        Tool(
            name="end_session",
            description="End a persistent ACL2 session and clean up resources. Use this when you're done with incremental development.",
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
            description="List all active ACL2 sessions with their IDs, names, age, and idle time. Use this to see which sessions are available and their current state.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="show_session_log",
            description="Show the session log in a terminal window. If a Terminal window is already tailing this session's log, it is activated and brought to the foreground. If not, a new Terminal window is opened. Requires logging to be enabled for the session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session whose log to show",
                    },
                    "log_tail_lines": {
                        "type": "number",
                        "description": "Number of lines to show initially if opening a new window (default: 50)",
                        "default": 50,
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="interrupt_session",
            description="Send SIGINT (Ctrl-C) to interrupt a running ACL2 command in a session. Use this when ACL2 gets stuck in an infinite loop or a proof attempt is taking too long. This is equivalent to pressing Ctrl-C in an interactive ACL2 session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session to interrupt",
                    },
                },
                "required": ["session_id"],
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
                        "description": "Timeout in seconds (optional, no timeout if not specified)",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session to use",
                    },
                },
                "required": ["code", "session_id"],
            },
        ),
        Tool(
            name="certify_book",
            description="Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Book path can be relative or absolute, WITHOUT .lisp extension (e.g., 'books/kestrel/axe/top' not 'books/kestrel/axe/top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the book WITHOUT .lisp extension. Can be relative (e.g., 'books/kestrel/axe/top') or absolute. Relative paths are relative to current directory.",
                    },
                    "jobs": {
                        "type": "number",
                        "description": "Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (optional, no timeout if not specified)",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="xdoc_search",
            description="Search the local xdoc agent corpus (all ~77,000 manual topics as plain text; see the acl2-docker project's tools/DESIGN.md) for topics matching a query.  Fast (milliseconds) and works with no ACL2 session.  Searches topic names and one-line summaries by default; set full_text to search topic bodies too.  The corpus is found via the ACL2_XDOC_CORPUS environment variable, or at $ACL2_ROOT/books/doc/agent-corpus (present in the acl2-allcerts Docker image).  Use xdoc_show to read a found topic.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Case-insensitive substring to search for. Examples: 'tail recursion', 'bvplus', 'measure'",
                    },
                    "full_text": {
                        "type": "boolean",
                        "description": "Also search topic bodies, not just names and summaries (slower: ~1 s). Default false.",
                    },
                    "max_results": {
                        "type": "number",
                        "description": "Maximum results to return (default 20).",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="xdoc_show",
            description="Show a topic from the local xdoc agent corpus by name.  Accepts a natural name ('bvplus', 'fty::defbitstruct') or an xdoc key ('ACL2____BVPLUS').  Fast and needs no ACL2 session; covers every topic in the built manual, but NOT topics defined in your own session (use :doc via evaluate for those).  Corpus location: see xdoc_search.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Topic to show. Examples: 'bvplus', 'fty::defbitstruct', 'ACL2____DEFTHM-STP'",
                    },
                    "max_chars": {
                        "type": "number",
                        "description": "Truncate the topic body beyond this many characters (default 20000; some topics, e.g. release notes, are very large).",
                    },
                },
                "required": ["name"],
            },
        ),
    ]


async def certify_acl2_book(
    file_path: str,
    timeout: int | None = None,
    jobs: int = 12,
    progress_callback: Optional[Callable[[str], Awaitable[None]]] = None
) -> str:
    """
    Certify an ACL2 book using cert.pl.

    Args:
        file_path: Path to the book (can be relative or absolute, without .lisp extension)
        timeout: Timeout in seconds (None = no timeout)
        jobs: Number of parallel jobs for cert.pl (default: 12)
        progress_callback: Optional async callback to report progress messages (e.g., command being run)

    Returns:
        Success/failure message with error details if failed
    """
    # Remove .lisp extension if present
    book_path = str(Path(file_path).with_suffix(""))

    # Build cert.pl command with -j flag
    cmd_args = ["cert.pl", f"-j{jobs}", book_path]

    # Format command for display (used by progress_callback if provided)
    cmd_display = " ".join(cmd_args)

    # Send progress notification with command if callback provided
    if progress_callback:
        await progress_callback(f"Running: {cmd_display}")

    # Use cert.pl to certify the book
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,  # Combine stderr into stdout
            # Note: Consider passing an appropriate directory here.
            # Right now we assume the MCP server was started in the ACL2 directory
            # but if not then the errors can be confusing.
            # cwd="/path/to/working/directory/"
        )

        try:
            if timeout is not None:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            else:
                stdout, _ = await process.communicate()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return f"Error: cert.pl execution timed out after {timeout} seconds"

        output = stdout.decode()
        exit_code = process.returncode

        # Check for success: exit code 0 AND no "***" in output
        has_error_marker = "***" in output

        if exit_code == 0 and not has_error_marker:
            return "Success: Book certification completed successfully"
        else:
            # Certification failed - extract error details
            error_msg = "Error: Book certification failed\n\n"

            if exit_code != 0:
                error_msg += f"Exit code: {exit_code}\n\n"

            if has_error_marker:
                error_msg += "Error markers found in output:\n"
                # Extract lines containing "***"
                error_lines = [line for line in output.split('\n') if '***' in line]
                error_msg += '\n'.join(error_lines[:20])  # Limit to first 20 error lines
                if len(error_lines) > 20:
                    error_msg += f"\n... and {len(error_lines) - 20} more error lines"
            else:
                # No error markers but non-zero exit - show last 50 lines
                lines = output.split('\n')
                error_msg += "Last 50 lines of output:\n"
                error_msg += '\n'.join(lines[-50:])

            return error_msg

    except FileNotFoundError:
        return "Error: cert.pl not found in PATH. Make sure ACL2 books build tools are installed."
    except Exception as e:
        return f"Error: Failed to run cert.pl: {e}"


# ---------------------------------------------------------------------------
# Local xdoc agent corpus (xdoc_search / xdoc_show)
#
# The corpus is the built ACL2 manual converted to one plain-text file per
# topic plus an index.tsv (natural-name <TAB> KEY <TAB> short).  It is
# produced by the acl2-docker project (tools/xdoc_extract.py; see its
# tools/DESIGN.md), ships in the acl2-allcerts Docker image at
# $ACL2_ROOT/books/doc/agent-corpus, and is also distributed as a tarball
# on that project's rolling "xdoc-corpus" release.  These tools are thin
# conveniences over it: everything they do can also be done with grep.

_XDOC_NO_CORPUS_MSG = (
    "No local xdoc corpus found.  Set the ACL2_XDOC_CORPUS environment "
    "variable to a corpus directory (one containing index.tsv and topics/), "
    "or run in an environment that has one at "
    "$ACL2_ROOT/books/doc/agent-corpus (e.g. the acl2-allcerts Docker "
    "image).  A corpus tarball is published on the acl2-docker project's "
    "'xdoc-corpus' release.  Without a corpus, use :doc in an ACL2 session "
    "(via the evaluate tool) for topics whose books are loaded."
)


def find_xdoc_corpus() -> Path | None:
    """Locate the local xdoc agent corpus, or None if unavailable."""
    candidates = []
    env_dir = os.environ.get("ACL2_XDOC_CORPUS")
    if env_dir:
        candidates.append(Path(env_dir))
    acl2_root = os.environ.get("ACL2_ROOT")
    if acl2_root:
        candidates.append(Path(acl2_root) / "books" / "doc" / "agent-corpus")
    for cand in candidates:
        if (cand / "index.tsv").is_file() and (cand / "topics").is_dir():
            return cand
    return None


def _xdoc_index_rows(corpus: Path) -> list[tuple[str, str, str]]:
    """Parse index.tsv into (natural-name, key, short) rows."""
    rows = []
    with open(corpus / "index.tsv", encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                rows.append((parts[0], parts[1], parts[2]))
    return rows


def xdoc_corpus_search(query: str, full_text: bool, max_results: int) -> str:
    corpus = find_xdoc_corpus()
    if corpus is None:
        return _XDOC_NO_CORPUS_MSG
    max_results = validate_integer_parameter(max_results, 1, 200, "max_results")
    q = query.lower()

    hits = [(nat, key, short) for (nat, key, short) in _xdoc_index_rows(corpus)
            if q in nat.lower() or q in short.lower()]
    lines = [f"{nat}\t{short}" for (nat, key, short) in hits[:max_results]]
    out = ""
    if lines:
        out += (f"{len(hits)} name/summary match(es)"
                f"{' (first ' + str(max_results) + ')' if len(hits) > max_results else ''}"
                f" -- read one with xdoc_show:\n" + "\n".join(lines))

    if full_text:
        try:
            proc = subprocess.run(
                ["grep", "-r", "-i", "-m", "1", "-F", query,
                 str(corpus / "topics")],
                capture_output=True, text=True, timeout=60)
            body_lines = []
            for line in proc.stdout.splitlines():
                path, _, match = line.partition(":")
                topic_key = Path(path).stem
                body_lines.append(f"{topic_key}\t{match.strip()[:120]}")
                if len(body_lines) >= max_results:
                    break
            if body_lines:
                out += ("\n\nfull-text match(es) (topic key, first matching "
                        "line):\n" + "\n".join(body_lines))
        except (OSError, subprocess.TimeoutExpired) as e:
            out += f"\n\n(full-text search unavailable: {e})"

    if not out:
        out = (f"No matches for {query!r} in topic names, summaries, or bodies."
               if full_text else
               f"No matches for {query!r} in topic names or summaries."
               "  Try again with full_text: true to search topic bodies.")
    return out


def xdoc_corpus_show(name: str, max_chars: int) -> str:
    corpus = find_xdoc_corpus()
    if corpus is None:
        return _XDOC_NO_CORPUS_MSG
    max_chars = validate_integer_parameter(max_chars, 200, 2_000_000, "max_chars")

    def read_topic(key: str) -> str:
        text = (corpus / "topics" / f"{key}.txt").read_text(encoding="utf-8")
        if len(text) > max_chars:
            text = (text[:max_chars]
                    + f"\n\n[... truncated at {max_chars} characters; "
                    f"pass a larger max_chars for more]")
        return text

    # 1. Treat the argument as an xdoc KEY / corpus file name.
    if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        if (corpus / "topics" / f"{name}.txt").is_file():
            return read_topic(name)
        upper = name.upper()
        if (corpus / "topics" / f"{upper}.txt").is_file():
            return read_topic(upper)

    # 2. Resolve as a natural name via the index.
    rows = _xdoc_index_rows(corpus)
    lname = name.lower()
    exact = [(nat, key) for (nat, key, _s) in rows if nat.lower() == lname]
    if not exact:
        # A bare name may match a package-qualified topic (defbitstruct ->
        # fty::defbitstruct).
        exact = [(nat, key) for (nat, key, _s) in rows
                 if nat.lower().endswith("::" + lname)]
    if len(exact) == 1:
        return read_topic(exact[0][1])
    if len(exact) > 1:
        listing = "\n".join(f"{nat}  (key: {key})" for (nat, key) in exact)
        return (f"Ambiguous topic {name!r}; candidates:\n{listing}\n"
                f"Call xdoc_show again with one of these keys.")

    close = [nat for (nat, _k, _s) in rows if lname in nat.lower()][:10]
    if close:
        return (f"No topic named {name!r}.  Close matches:\n"
                + "\n".join(close))
    return (f"No topic named {name!r} in the corpus.  Use xdoc_search to "
            f"look for it, or :doc in a session for session-defined topics.")


@app.call_tool()  # type: ignore[misc]
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent]:
    """Handle tool calls."""
    if name == "start_session":
        session_name = arguments.get("name")
        enable_logging = arguments.get("enable_logging", True)
        view_log_in_terminal = arguments.get("view_log_in_terminal")
        log_tail_lines = arguments.get("log_tail_lines", 50)
        cwd = arguments.get("cwd")
        session_id, message = await session_manager.start_session(
            session_name,
            enable_logging,
            view_log_in_terminal,
            log_tail_lines,
            cwd
        )
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

    elif name == "show_session_log":
        session_id = arguments["session_id"]
        log_tail_lines = arguments.get("log_tail_lines", 50)
        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]
        if not session.log_file:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} does not have logging enabled",
                )
            ]
        show_session_log(
            session.log_file, log_tail_lines, session_id,
            viewer=session_manager.config.session_log.viewer,
        )
        return [
            TextContent(
                type="text",
                text=f"Opened session log: {session.log_file}",
            )
        ]

    elif name == "interrupt_session":
        session_id = arguments["session_id"]
        message = await session_manager.interrupt_session(session_id)
        return [
            TextContent(
                type="text",
                text=message,
            )
        ]

    elif name == "evaluate":
        code = arguments["code"]
        timeout = arguments.get("timeout")
        session_id = arguments["session_id"]

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Session {session_id} not found",
                )
            ]
        output = await session.send_command(code, timeout)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "certify_book":
        file_path = arguments["file_path"]
        timeout = arguments.get("timeout")

        # Progress notification support for displaying command line before execution
        #
        # The MCP protocol supports optional progress notifications where the client
        # sends a progressToken in the request metadata, and the server can send
        # asynchronous progress updates via notifications/progress messages.
        #
        # CURRENT STATUS (2025-11-06): Claude Code does not appear to send progress
        # tokens to MCP servers. However, this code is structured to support progress
        # notifications for when that capability is added.
        #
        # HOW IT WORKS:
        # - If progressToken is present: Send command line as async progress notification
        #   (appears in Claude Code immediately, before cert.pl completes)
        # - If no progressToken: Capture command line and include in final return message
        #   (appears after cert.pl completes)
        #
        # BENEFIT: With progress notifications, users see the exact cert.pl command
        # being executed immediately, providing better visibility into long-running
        # operations.
        #
        # TO ENABLE (when Claude Code supports progress tokens):
        # 1. Uncomment the progress_callback setup code below
        # 2. Pass progress_callback to certify_acl2_book calls
        # 3. Include command_info in return messages
        #
        # context = app.request_context
        # progress_token = context.meta.progressToken if context.meta else None
        #
        # # Track command for display
        # command_info: list[str] = []
        #
        # # Create progress callback if token is available
        # progress_callback = None
        # if progress_token:
        #     # Progress token available - send async notification
        #     async def send_progress(message: str) -> None:
        #         await context.session.send_progress_notification(
        #             progress_token=progress_token,
        #             progress=0,
        #             total=1,
        #             message=message
        #         )
        #     progress_callback = send_progress
        # else:
        #     # No progress token - capture command for inclusion in return message
        #     async def capture_command(message: str) -> None:
        #         command_info.append(message)
        #     progress_callback = capture_command

        # Determine number of jobs
        if "jobs" in arguments:
            # User explicitly specified jobs
            jobs = arguments["jobs"]
        else:
            # Auto-detect optimal jobs based on system load
            optimal_jobs, info = detect_optimal_jobs()
            if optimal_jobs is not None:
                jobs = optimal_jobs
                # Prepend info to output
                output = await certify_acl2_book(file_path, timeout, jobs)
                return [
                    TextContent(
                        type="text",
                        text=f"Auto-detected jobs: {jobs} ({info})\n\n{output}",
                    )
                ]
            else:
                # Unable to auto-detect or insufficient resources
                return [
                    TextContent(
                        type="text",
                        text=f"Unable to auto-detect optimal job count.\n{info}\n\nPlease retry with explicit 'jobs' parameter.",
                    )
                ]

        output = await certify_acl2_book(file_path, timeout, jobs)

        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "xdoc_search":
        query = arguments["query"]
        full_text = bool(arguments.get("full_text", False))
        max_results = int(arguments.get("max_results", 20))
        try:
            output = xdoc_corpus_search(query, full_text, max_results)
        except ValueError as e:
            output = f"Error: {e}"
        return [
            TextContent(
                type="text",
                text=output,
            )
        ]

    elif name == "xdoc_show":
        topic_name = arguments["name"]
        max_chars = int(arguments.get("max_chars", 20000))
        try:
            output = xdoc_corpus_show(topic_name, max_chars)
        except ValueError as e:
            output = f"Error: {e}"
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
