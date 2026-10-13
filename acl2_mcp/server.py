"""ACL2 MCP Server implementation."""

import aiofiles
import asyncio
import errno
import fcntl
import functools
import os
import platform
import pty
import queue
import re
import shlex
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Sequence, Optional, IO, Callable, Awaitable
from dataclasses import dataclass, field

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from acl2_mcp import reader
from acl2_mcp.config import ServerConfig, ToolOutputConfig, load_config


# Security constants
MAX_TIMEOUT = 300  # 5 minutes maximum
MIN_TIMEOUT = 1
# How long evaluate waits when no timeout is given: then a runaway command
# leaves the agent able to look at the log, wait more, or interrupt
EVALUATE_DEFAULT_TIMEOUT = MAX_TIMEOUT
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

# On a timeout, output that ends with an unfinished line and has been
# quiet this long is taken for a prompt that PROMPT_PATTERNS doesn't know
# (see _adopt_pending_prompt).
UNKNOWN_PROMPT_SECONDS = 1.0

# How long interrupt_session waits for ACL2's prompt after the interrupt.
# An abort takes well under a second; in a proof, the first interrupt only
# asks ACL2 to stop at its next check, which may take longer or never come.
INTERRUPT_WAIT_SECONDS = 5

# Prompt patterns for detecting command completion.
#
# These are the "positive" patterns from emacs-acl2.el *acl2-insert-pats*
# (commented-out alternative in that file).  Each pattern matches a line
# (with no trailing newline) that could be a Lisp or ACL2 prompt.
#
# Because these patterns are broad (especially ".*>[ ]*$" and ".*\* $"),
# prompt detection uses a settle delay (PROMPT_SETTLE_SECONDS) to
# distinguish real prompts from mid-output lines that happen to match.
# ACL2's proof builder: "->: ", nested "-->: " (the default pc-prompt)
_PROOF_BUILDER_PROMPT = re.compile(r'-+>: $')
# An ACL2 query (acl2-query): "ACL2 Query (:ID):  ...  (Y, N or Q):  "
_QUERY_PROMPT = re.compile(r'.*\):  $')
# ACL2's walkabout, which prints the current object, then ":" on a line
_WALKABOUT_PROMPT = re.compile(r':$')

PROMPT_PATTERNS = [
    re.compile(r'.*>[ ]*$'),      # ACL2 (also break-rewrite "1 ACL2 >"), GCL,
                                  # CLISP, LispWorks, CCL debugger "1 > "
    re.compile(r'.*\] $'),        # SBCL debugger
    re.compile(r'.*\* $'),        # CMUCL, SBCL
    re.compile(r'\? $'),          # CCL
    _PROOF_BUILDER_PROMPT,
    _QUERY_PROMPT,
    _WALKABOUT_PROMPT,
]
# Other Lisp prompts not included: ".*): $" (Allegro CL)

# An ACL2 read-eval-print loop prompt (default-print-prompt): package,
# "(r)" in ACL2(r), a space, mode (! s p, or P in raw mode), and a > per LD
# level; after "N " in break-rewrite and "Wormhole " in a wormhole.  ACL2
# package names have no lower case letters (defpkg disallows them), which
# rules out the prompts of most other programs' read loops ("calc > ");
# and the package must have a non-digit, which rules out the CCL
# debugger's "1 > ".
_ACL2_PROMPT = re.compile(
    r'(?:Wormhole )?(?:\d+ )?(?=\S*[^\d\s])[^\sa-z]+(?:\(r\))? ([!psP]*)>+ *')


def prompt_mode(text: str) -> str:
    """How input is read at the prompt TEXT: "acl2" (by ACL2's reader),
    "raw-acl2" (in ACL2's raw mode: ACL2's reader, but with no check of
    the objects read), or "lisp" (by the host Lisp's reader, in raw Lisp
    or a debugger)."""
    if not text:
        return "acl2"  # no prompt seen yet; ACL2 starts in its loop
    m = _ACL2_PROMPT.fullmatch(text)
    if m:
        return "raw-acl2" if "P" in m.group(1) else "acl2"
    if any(p.fullmatch(text) for p in (_PROOF_BUILDER_PROMPT, _QUERY_PROMPT,
                                       _WALKABOUT_PROMPT)):
        return "acl2"  # these read with read-object
    return "lisp"


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


# What the characters that ACL2's terminal turns into signals (ISIG) would
# do to ACL2, by their termios index (see ACL2Session.signal_characters)
_SIGNAL_EFFECTS = {
    termios.VINTR: "interrupt ACL2",
    termios.VQUIT: "send ACL2 SIGQUIT, which can end the session",
    termios.VSUSP: "suspend ACL2, leaving the session hung",
}


def _session_not_found(session_id: str) -> str:
    """The error for a tool call naming SESSION_ID, which isn't a session."""
    return (f"Error: Session {session_id} not found (list_sessions shows "
            f"the active sessions)")


# What the next reply says before the output of a command whose evaluate
# call timed out, or was cancelled (see ACL2Session._take_unreported_output)
TIMED_OUT_HEADING = "Output of the earlier command that timed out:"
CANCELLED_HEADING = ("The earlier command's evaluate call was cancelled, so ACL2 "
                     "was interrupted, and the part of the command not yet sent "
                     "was discarded.  Its output:")


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
    slave_path: Optional[str] = None  # e.g. /dev/pts/3; see _flush_pty_input
    interrupt_count: int = 0  # Incremented by interrupt(); see _write_input
    # Finishes a command whose evaluate call timed out (see _finish_command),
    # or waits for ACL2's prompt after one that was cancelled (_cancel_command)
    _pending_send: Optional["asyncio.Task[None]"] = field(default=None, repr=False)
    # Output of a command that timed out or was cancelled, from this
    # sequence ID on, which no reply has shown yet, and what to say about it
    # (see _take_unreported_output)
    _unreported_from: Optional[int] = None
    _unreported_heading: str = ""
    # The host Lisp's reader syntax (see start_session)
    syntax: reader.Syntax = reader.SBCL
    # The characters that ACL2's terminal turns into signals, and what
    # each would do (see _signal_character)
    signal_characters: dict[bytes, str] = field(default_factory=lambda: {
        b"\x03": _SIGNAL_EFFECTS[termios.VINTR],
        b"\x1c": _SIGNAL_EFFECTS[termios.VQUIT],
        b"\x1a": _SIGNAL_EFFECTS[termios.VSUSP]})
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

    # Sending a command one form at a time (see _send_units).  A prompt
    # candidate is output that ends with a prompt, before it settles;
    # candidate_seq counts those at an allowed depth, each once (by where
    # it starts in the output).  _sends counts the forms sent: a prompt
    # seen before the latest send can't be the prompt after that form, so
    # _flush_prompt doesn't confirm it.
    candidate_seq: int = 0
    _sends: int = 0
    _candidate_offset: int = -1
    _candidate_sends: int = -1
    # The latest output that ended with a prompt, at any depth, as
    # (start, end, sends, text); see _adopt_pending_prompt
    _last_prompt_like: Optional[tuple[int, int, int, str]] = None
    _total_bytes: int = 0  # bytes of output processed so far
    # When output last arrived (time.monotonic()), and _sends then
    _last_output_time: float = 0.0
    _last_output_sends: int = 0
    _unknown_prompt_adopted: bool = False  # see _adopt_pending_prompt

    # Background task references
    # Note: PTY reader uses loop.add_reader() callback (event-driven, tracked via reader_registered)
    logger_task: Optional[asyncio.Task[None]] = None

    # Shutdown coordination
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    _end_marker_written: bool = False
    # Closes the session log's viewer; set when one is opened (see
    # SessionManager.log_viewer_opened), called once when the session ends
    close_viewer: Optional[Callable[[], None]] = field(default=None, repr=False)

    async def send_command(self, command: str, timeout: int | None = None,
                           as_is: bool = False) -> str:
        """
        Send a command to the ACL2 session and get response.

        The command is sent one top-level form at a time, each once ACL2
        has finished the one before (see _plan_units and _send_units), and
        the reply is ACL2's output up to its prompt after the last form.
        Code that ACL2's reader would reject is not sent at all.  AS_IS:
        send the command exactly as given, in one piece, without reading
        it as ACL2 code (for a program that reads its own kind of input).

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

            if self.exited or self.master_fd is None:
                return self._exited_message()

            # SECURITY: Validate code length to prevent memory exhaustion
            if len(command) > MAX_CODE_LENGTH:
                return f"Error: Command exceeds maximum length of {MAX_CODE_LENGTH} characters"

            # SECURITY: Validate timeout
            validated_timeout = validate_timeout(timeout)

            # The timeout covers the whole command: waiting for an earlier
            # command to finish, sending this one, and evaluating it.
            start_time = time.time()
            deadline = (None if validated_timeout is None
                        else start_time + validated_timeout)
            log_hint = (f"  Session log: {self.log_file}"
                        if self.log_file else "")
            # Whether some of this command may have reached ACL2, which
            # hasn't finished it: if the call is cancelled, ACL2 is
            # interrupted (see _cancel_command)
            busy = False
            start_seq_id: Optional[int] = None

            try:
                # An earlier command whose evaluate call timed out may still
                # be running (see _finish_command).  Wait for it, so that
                # each reply shows its own command's output.
                pending = self._pending_send
                if pending is not None and not pending.done():
                    remaining = (None if deadline is None
                                 else max(0.0, deadline - time.time()))
                    try:
                        await asyncio.wait_for(asyncio.shield(pending), remaining)
                    except asyncio.TimeoutError:
                        return ("Error: Command not sent: ACL2 is still busy "
                                "with an earlier command (whose evaluate call "
                                "timed out or was cancelled).  Wait and try "
                                "again, or call interrupt_session." + log_hint)
                if self._unreported_from is not None:
                    await asyncio.sleep(0.05)  # let the logger catch up
                earlier = self._take_unreported_output()

                data = f"{command}\n".encode()
                refusal = self._signal_character(data)
                plan = ([len(data)] if as_is or refusal
                        else self._plan_units(data))

                # Capture the output sequence counter BEFORE adding anything
                # to queues or writing to PTY.  During the await calls below,
                # the event loop can run _logger_task, which appends to
                # output_buffer.  If we capture it after those awaits, we
                # might miss the response entirely.
                start_seq_id = self.sequence_counter
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
                if refusal or isinstance(plan, str) or not plan:
                    reason = refusal or plan or "only comments and whitespace"
                    await self.merge_queue.put((
                        timestamp_mono, seq_id, "stdin",
                        f"[{current_time} NOT SENT: {reason}]\n"))
                    if refusal:
                        return (earlier + f"Error: Nothing was sent, because "
                                f"{refusal}.  (To interrupt ACL2, call "
                                f"interrupt_session.  In ACL2 code, "
                                f"(code-char N) is the character with code N.)")
                    if not plan:
                        return (earlier + "Nothing to evaluate: the code has "
                                "only comments and whitespace.")
                    return (earlier + f"Error: Nothing was sent, because "
                            f"ACL2 couldn't read the code: {plan}.  (If it "
                            f"is input for a program that reads its own kind "
                            f"of input, send it with as_is.)")
                timestamp_line = f"[{current_time} INPUT]\n"
                await self.merge_queue.put((timestamp_mono, seq_id, "stdin", timestamp_line))
                cuts = plan

                # Send the command to ACL2 via the PTY master, one form at a
                # time (see _send_units)
                interrupts = self.interrupt_count
                busy = True
                unit, written, mark, outcome = await self._send_units(
                    data, cuts, 0, 0, self.candidate_seq, deadline, interrupts)
                sent = min((cuts[unit - 1] if unit else 0) + written, len(data))
                if outcome == "closed":
                    return earlier + await self._exited_reply(start_seq_id)
                if outcome == "timeout":
                    # As for any timeout, leave ACL2 working; send it the
                    # rest of the command as it finishes each form.
                    if not written and await self._adopt_and_log_prompt():
                        # ACL2 waits for input at a prompt that doesn't
                        # count, such as the deeper one of
                        # (ld *standard-oi*): go on from there
                        self._confirm_max_depth = max(
                            self._confirm_max_depth,
                            prompt_depth(self.last_prompt_text))
                        self.candidate_seq += 1
                    self._pending_send = asyncio.create_task(
                        self._finish_command(data, cuts, unit, written, mark,
                                             interrupts, None))
                    self._unreported_from = start_seq_id
                    self._unreported_heading = TIMED_OUT_HEADING
                    return (earlier + f"Error: Command execution timed out "
                            f"after {validated_timeout} seconds.  ACL2 is "
                            f"still busy, and not all of the command has been "
                            f"sent yet ({sent} of {len(data)} bytes); the rest "
                            f"will be sent as it finishes each form.  The next "
                            f"evaluate waits for it to finish and shows its "
                            f"output first; to stop it instead, call "
                            f"interrupt_session.{log_hint}")
                note = ""
                if outcome == "interrupted":
                    await self._log_input_cut_short(sent, len(data))
                    note = (f"Note: interrupted before the whole command was "
                            f"sent ({sent} of {len(data)} bytes); the rest "
                            f"was discarded.\n")

                # Wait for a confirmed prompt from the chunk processor.
                # The chunk processor detects potential prompts in partial
                # buffers and waits PROMPT_SETTLE_SECONDS before confirming,
                # then increments prompt_seq and notifies via prompt_condition.
                #
                # We capture prompt_seq only now that the last form has been
                # sent, so that earlier confirmations are ignored: stale ones
                # from earlier commands (e.g., LD intermediate prompts still
                # being flushed).  A prompt seen before the last form was
                # sent is never confirmed (see _flush_prompt).
                start_prompt_seq = self.prompt_seq
                _debug_log(f"send_command: start_seq_id={start_seq_id}, start_prompt_seq={start_prompt_seq}, output_buffer_len={len(self.output_buffer)}")

                outcome = await self._wait_for_prompt(start_prompt_seq, deadline,
                                                      None)
                busy = outcome == "timeout"  # (ACL2 is still working)
                if outcome == "closed":
                    return earlier + note + await self._exited_reply(start_seq_id)
                if outcome == "timeout":
                    self._unreported_from = start_seq_id
                    self._unreported_heading = TIMED_OUT_HEADING
                    # If ACL2's output ends with a prompt that doesn't
                    # count, such as the deeper one of (ld *standard-oi*),
                    # ACL2 waits for input: take that as the current prompt
                    # for later commands.  Otherwise ACL2 is still working.
                    if await self._adopt_and_log_prompt():
                        return (earlier + note + f"Error: Command execution "
                                f"timed out after {validated_timeout} seconds.  "
                                f"ACL2 seems to be waiting for input at "
                                f"{self.last_prompt_text.strip()!r}; later "
                                f"commands are sent there.{log_hint}")
                    self._pending_send = asyncio.create_task(
                        self._finish_command(data, cuts, len(cuts), 0, mark,
                                             interrupts, start_prompt_seq))
                    return (earlier + note + f"Error: Command execution timed "
                            f"out after {validated_timeout} seconds.  ACL2 is "
                            f"still working on it; the next evaluate waits for "
                            f"it to finish and shows its output first.  To stop "
                            f"it instead, call interrupt_session.{log_hint}")

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
                return (earlier + note
                        + elide_large_output(output, self.tool_output_config,
                                             self.log_file))

            except asyncio.CancelledError:
                # The client cancelled the call, perhaps because the user
                # interrupted the agent: stop the command, as a cancelled
                # certify_book stops cert.pl
                if busy and start_seq_id is not None:
                    await self._cancel_command(start_seq_id)
                raise
            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                    return self._exited_message()  # (the terminal is gone)
                return self._internal_error_message()
            except Exception:
                # SECURITY: Don't leak internal details in error messages
                return self._internal_error_message()

    @property
    def exited(self) -> bool:
        """Has ACL2 exited (or its terminal gone)?"""
        return self.shutdown_event.is_set() or self.process.returncode is not None

    def _exited_message(self) -> str:
        """The error for a command or interrupt in a session whose ACL2 has
        exited."""
        log = (f"  The session log has ACL2's last output: {self.log_file}"
               if self.log_file else "")
        return ("Error: ACL2 has exited in this session, so the session's "
                "world is gone and nothing more can run in it.  Start a new "
                f"session (end_session removes this one).{log}")

    async def _exited_reply(self, start_seq_id: int) -> str:
        """The reply to a command during which ACL2 exited: its output after
        sequence ID START_SEQ_ID (an error message, say), then why nothing
        more can run in the session."""
        await asyncio.sleep(0.05)  # let the logger catch up
        output = "".join(line for sid, line in self.output_buffer
                         if sid > start_seq_id).strip()
        output = elide_large_output(output, self.tool_output_config, self.log_file)
        return (output + "\n\n" if output else "") + self._exited_message()

    def _internal_error_message(self) -> str:
        """The error for a command that acl2-mcp itself failed on."""
        log = f"  Session log: {self.log_file}" if self.log_file else ""
        return ("Error: acl2-mcp failed while sending the command (an internal "
                "error), and some of it may have reached ACL2.  Check the "
                f"session log before going on.{log}")

    def _signal_character(self, data: bytes) -> str:
        """Why DATA can't be sent, if it has a character that ACL2's
        terminal turns into a signal (C-c, C-\\ or C-z); otherwise ""."""
        found = [(data.find(char), char) for char in self.signal_characters
                 if char in data]
        if not found:
            return ""
        position, char = min(found)
        line = data.count(b"\n", 0, position) + 1
        column = position - (data.rfind(b"\n", 0, position) + 1) + 1
        return (f"the code has a C-{chr(char[0] ^ 0x40).lower()} character "
                f"(code {char[0]}) at line {line}, column {column}, which the "
                f"terminal would turn into a signal that would "
                f"{self.signal_characters[char]}")

    def _plan_units(self, data: bytes) -> list[int] | str:
        """Where to split DATA, a command ending with a newline, into units
        sent one at a time: a list of the units' ends (offsets in DATA),
        or why ACL2 couldn't read it.

        A unit is a top-level form with the text before it, except that a
        keyword command such as ":pe foo" takes the rest of its line:
        ACL2 reads the command's arguments after it, as many as it takes
        in ACL2's world.  The last unit takes the rest of DATA.  DATA is
        one unit at a raw Lisp or debugger prompt, where the host Lisp
        reads it with its own syntax, and when syntax the reader doesn't
        handle (or a top-level feature conditional, whose form may be
        skipped) leaves the forms uncertain.
        """
        whole = [len(data)]
        mode = prompt_mode(self.last_prompt_text)
        if mode == "lisp":
            return whole
        code = data[:-1]
        try:
            forms = reader.read_forms(code, self.syntax,
                                      check_objects=(mode == "acl2"))
        except reader.ReadError as e:
            if e.kind == "unsupported":
                return whole
            if e.incomplete:
                return f"it ends inside a form, string or comment: {e}"
            return str(e)
        if any(form.kind == "conditional" for form in forms):
            return whole
        cuts = []
        k = 0
        while k < len(forms):
            end = forms[k].end
            if forms[k].kind == "keyword":
                while (k + 1 < len(forms)
                       and b"\n" not in code[end:forms[k + 1].start]):
                    k += 1
                    end = forms[k].end
            cuts.append(end)
            k += 1
        if cuts:
            cuts[-1] = len(data)
        return cuts

    async def _send_units(self, data: bytes, cuts: list[int], unit: int,
                          written: int, mark: int, deadline: Optional[float],
                          interrupts: int) -> tuple[int, int, int, str]:
        """Send the units of DATA that end at CUTS (see _plan_units), from
        UNIT on (WRITTEN bytes of which were already sent), each once ACL2
        has finished the one before.

        ACL2 has finished a unit when a prompt appears after it was sent:
        candidate_seq passes MARK, its value when the unit was sent.  A
        unit other than the last gets a newline, to end its last token;
        the last one ends with DATA's newline.

        Returns the unit being sent (len(CUTS) when all were), the bytes of
        it sent, MARK, and why sending stopped, as for _write_input.
        """
        while unit < len(cuts):
            text = data[cuts[unit - 1] if unit else 0:cuts[unit]]
            if unit < len(cuts) - 1:
                text += b"\n"
            if not written:
                if unit:
                    outcome = await self._wait_for_candidate(mark, deadline,
                                                             interrupts)
                    if outcome != "ready":
                        return unit, 0, mark, outcome
                # No prompt seen from now on can be an earlier unit's
                self._sends += 1
                mark = self.candidate_seq
            written, outcome = await self._write_input(
                memoryview(text), written, deadline, interrupts)
            if outcome != "done":
                return unit, written, mark, outcome
            unit, written = unit + 1, 0
        return unit, 0, mark, "done"

    async def _wait_for_candidate(self, mark: int, deadline: Optional[float],
                                  interrupts: int) -> str:
        """Wait for a prompt candidate after MARK (see _send_units).
        Returns "ready", "timeout", "interrupted" or "closed"."""
        async with self.prompt_condition:
            while self.candidate_seq <= mark:
                if self.interrupt_count != interrupts:
                    return "interrupted"
                if self.shutdown_event.is_set() or self.master_fd is None:
                    return "closed"
                wait = 1.0
                if deadline is not None:
                    wait = min(wait, deadline - time.time())
                    if wait <= 0:
                        return "timeout"
                try:
                    await asyncio.wait_for(self.prompt_condition.wait(), wait)
                except asyncio.TimeoutError:
                    pass
        return "ready"

    async def _wait_for_prompt(self, mark: int, deadline: Optional[float],
                               interrupts: Optional[int]) -> str:
        """Wait for a prompt confirmed after MARK (a value of prompt_seq).

        Returns "ready", "timeout", "closed", or "interrupted" (only if
        INTERRUPTS is given and interrupt() was called since it was read).
        """
        async with self.prompt_condition:
            while self.prompt_seq <= mark:
                if interrupts is not None and self.interrupt_count != interrupts:
                    return "interrupted"
                if self.shutdown_event.is_set():
                    return "closed"
                wait = 1.0
                if deadline is not None:
                    wait = min(wait, deadline - time.time())
                    if wait <= 0:
                        return "timeout"
                try:
                    await asyncio.wait_for(self.prompt_condition.wait(), wait)
                except asyncio.TimeoutError:
                    pass
        return "ready"

    async def _finish_command(self, data: bytes, cuts: list[int], unit: int,
                              written: int, mark: int, interrupts: int,
                              prompt_mark: Optional[int]) -> None:
        """Finish a command whose evaluate call timed out: send the rest of
        it as ACL2 finishes each form (see _send_units), then wait for the
        prompt after the last form (confirmed after PROMPT_MARK, if all of
        it was already sent).

        Runs as a task (_pending_send) after send_command has returned.
        send_command waits for it before sending another command, and
        interrupt() stops it.
        """
        try:
            if unit < len(cuts):
                unit, written, mark, outcome = await self._send_units(
                    data, cuts, unit, written, mark, None, interrupts)
                if outcome == "interrupted":
                    await self._log_input_cut_short(
                        min((cuts[unit - 1] if unit else 0) + written,
                            len(data)),
                        len(data))
                if outcome != "done":
                    return
                prompt_mark = self.prompt_seq
            assert prompt_mark is not None
            await self._wait_for_prompt(prompt_mark, None, interrupts)
        except OSError:
            return

    def _take_unreported_output(self) -> str:
        """The output of a command whose evaluate call timed out or was
        cancelled, which no reply has shown yet, to put before the next
        reply."""
        start = self._unreported_from
        if start is None:
            return ""
        self._unreported_from = None
        output = "".join(line for sid, line in self.output_buffer
                         if sid > start).strip()
        if not output:
            return ""
        return (self._unreported_heading + "\n"
                + elide_large_output(output, self.tool_output_config,
                                     self.log_file)
                + "\n\nOutput of this command:\n")

    async def _cancel_command(self, start_seq_id: int) -> None:
        """Stop a command whose evaluate call was cancelled: interrupt ACL2
        (which discards the part of the command it hasn't read, half a
        form included), and have the next reply say so and show ACL2's
        output from START_SEQ_ID on.  The next command waits for ACL2's
        prompt after the interrupt (see _pending_send)."""
        prompt_mark = self.prompt_seq
        try:
            await self._send_interrupt("CALL CANCELLED")
        except OSError:
            return
        self._unreported_from = start_seq_id
        self._unreported_heading = CANCELLED_HEADING

        async def wait_for_prompt() -> None:
            await self._wait_for_prompt(prompt_mark, None, None)

        self._pending_send = asyncio.create_task(wait_for_prompt())

    async def _write_input(self, data: memoryview, written: int,
                           deadline: Optional[float],
                           interrupts: int) -> tuple[int, str]:
        """Write DATA[WRITTEN:] to the PTY, waiting for room as ACL2 reads.

        The PTY holds only so much unread input (about 1 KB on macOS and
        20 KB on Linux).  While ACL2 is busy with an earlier form of the
        same command, the queue fills up and a write fails with EAGAIN.
        That is not an error: wait for ACL2 to read more, and retry.

        Returns the number of bytes of DATA written so far and why writing
        stopped: "done"; "timeout" (DEADLINE passed); "interrupted"
        (interrupt() was called since INTERRUPTS was read from
        interrupt_count; the rest must not follow it); or "closed".
        """
        delay = 0.001
        while written < len(data):
            if self.interrupt_count != interrupts:
                return written, "interrupted"
            fd = self.master_fd
            if fd is None:
                return written, "closed"
            try:
                written += os.write(fd, data[written:])
                delay = 0.001
                if written < len(data):
                    # Let the reader drain ACL2's output
                    await asyncio.sleep(0)
            except BlockingIOError:
                if deadline is not None and time.time() >= deadline:
                    return written, "timeout"
                await asyncio.sleep(delay)
                delay = min(2 * delay, 0.05)
        return written, "done"

    async def _log_input_cut_short(self, written: int, total: int) -> None:
        """Note in the session log that a command was not sent in full."""
        seq_id = await self._get_next_sequence_id()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        marker = (f"[{now} INPUT CUT SHORT: {written} of {total} bytes sent, "
                  f"the rest discarded]\n")
        await self.merge_queue.put((time.monotonic(), seq_id, "stdin", marker))

    def _flush_pty_input(self) -> None:
        """Discard input written to the PTY that ACL2 has not read yet."""
        if self.slave_path is None:
            return
        # Flush on the slave side, opened by name.  A flush through the
        # master fd differs by platform: TCIFLUSH there discards this input
        # on macOS but ACL2's pending output on Linux.
        try:
            fd = os.open(self.slave_path,
                         os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            finally:
                os.close(fd)
        except (OSError, termios.error):
            pass

    async def interrupt(self) -> str:
        """
        Interrupt a running command in this session by sending Ctrl-C via PTY.

        This mimics a user pressing Ctrl-C in a terminal. The PTY's controlling
        terminal setup ensures the interrupt is delivered correctly to ACL2/SBCL.

        ACL2's unread input is discarded first, as the Ctrl-C would discard
        it anyway.  If the Ctrl-C still cannot be written, send SIGINT to
        the process group.

        Then wait up to INTERRUPT_WAIT_SECONDS for ACL2's prompt, and return
        what ACL2 printed in response (its abort message).  An evaluate
        call that timed out has already returned, so no other reply would
        show it.

        Returns:
            Status message and ACL2's response, or an error message
        """
        try:
            if self.exited or self.master_fd is None:
                return self._exited_message()

            # Output and prompts from here on are ACL2's response.  It
            # shows in this reply, so an earlier timed-out command's
            # output needn't come with the next one.
            start_seq_id = self.sequence_counter
            start_prompt_seq = self.prompt_seq
            try:
                sent = await self._send_interrupt()
            except OSError as e:
                return f"Error: Failed to interrupt session: {e}"
            self._unreported_from = None

            at_prompt = await self._wait_for_prompt(
                start_prompt_seq, time.time() + INTERRUPT_WAIT_SECONDS,
                None) == "ready"
            # Let the logger task move the prompt into output_buffer
            await asyncio.sleep(0.05)
            output = "".join(line for sid, line in self.output_buffer
                             if sid >= start_seq_id).strip()
            output = elide_large_output(output, self.tool_output_config,
                                        self.log_file)
            if at_prompt:
                return f"{sent}; ACL2 is back at its prompt:\n\n{output}"
            return (f"{sent}, but ACL2 has not returned to its prompt within "
                    f"{INTERRUPT_WAIT_SECONDS} seconds.  In a proof, the first "
                    f"interrupt only asks ACL2 to stop at its next check; call "
                    f"interrupt_session again to abort at once.  Output so "
                    f"far:\n\n{output}")

        except Exception as e:
            return f"Error: Failed to interrupt session: {e}"

    async def _send_interrupt(self, note: str = "") -> str:
        """Interrupt ACL2 like Ctrl-C, and log it (with NOTE).  Returns what
        was sent; raises OSError if nothing could be."""
        if self.master_fd is None:
            raise OSError("the session's terminal is closed")

        # Stop any command still being written (see _write_input), and
        # one finishing in the background (_finish_command): the rest
        # must not follow the interrupt.
        self.interrupt_count += 1
        async with self.prompt_condition:
            self.prompt_condition.notify_all()

        # On Linux the terminal acts on an input byte only once the
        # input ahead of it has been read, so a Ctrl-C behind unread
        # input would wait until ACL2 had finished its current form and
        # read the rest.  Discarding that input first also makes room
        # for the Ctrl-C when the input queue is full.
        self._flush_pty_input()

        # Primary method: Send Ctrl-C (0x03) through the PTY
        # This is how a terminal delivers interrupts - the line discipline
        # converts it to SIGINT for the foreground process group
        try:
            os.write(self.master_fd, b"\x03")  # non-blocking fd
            sent, marker = "Interrupt sent", "INTERRUPT SENT"
        except OSError:
            # PTY write failed (say, the flush failed and the input
            # queue is still full).  Fallback method: Send SIGINT to
            # the process group
            os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            sent = "Interrupt sent (as SIGINT)"
            marker = "INTERRUPT SENT (FALLBACK)"

        # Log the interrupt in the session
        if note:
            marker = f"{marker} ({note})"
        timestamp = time.monotonic()
        seq_id = await self._get_next_sequence_id()
        interrupt_time = time.strftime("%Y-%m-%d %H:%M:%S")
        await self.merge_queue.put(
            (timestamp, seq_id, "stdout", f"[{interrupt_time} {marker}]\n"))
        return sent

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
                        self._stop_reading()
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
                        self._stop_reading()
                        asyncio.ensure_future(self._handle_pty_eof())
                        return
                    raise

        except Exception as e:
            print(f"Error in PTY reader callback: {e}", file=sys.stderr)
            asyncio.ensure_future(self._handle_pty_error(e))

    def _stop_reading(self) -> None:
        """Remove the event loop reader for the PTY master.

        Once ACL2's side of the PTY is closed, the master stays readable
        (EOF or EIO), so a reader left registered would be called in a
        busy loop.
        """
        if self.reader_registered and self.master_fd is not None:
            try:
                asyncio.get_event_loop().remove_reader(self.master_fd)
            except (ValueError, OSError):
                # Reader wasn't registered or fd invalid
                pass
        self.reader_registered = False

    def _close_viewer(self) -> None:
        """Close the session log's viewer, if one is open.

        Called when ACL2 exits (_handle_pty_eof) and when the session is
        ended (terminate), whichever comes first.
        """
        close, self.close_viewer = self.close_viewer, None
        if close is not None:
            close()

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
            self._total_bytes += len(chunk)
            self._last_output_time = time.monotonic()
            self._last_output_sends = self._sends
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
                    buffer = bytes(self.partial_line_buffer) + chunk
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
                                await self._note_prompt_candidate(prompt_candidate)
                                self._schedule_prompt_flush()
                        except UnicodeDecodeError:
                            pass  # Partial UTF-8; wait for more bytes

                        break

            except Exception as e:
                print(f"Error processing PTY chunk: {e}", file=sys.stderr)

    async def _note_prompt_candidate(self, text: str) -> None:
        """Note that the output (so far) ends with TEXT, which looks like
        a prompt, in partial_line_buffer.  Counts it in candidate_seq if it
        is at an allowed depth and wasn't counted already (see _send_units).
        Called with _chunk_lock held."""
        end = self._total_bytes
        start = end - len(self.partial_line_buffer)
        self._last_prompt_like = (start, end, self._sends, text)
        if (prompt_depth(text) <= self._confirm_max_depth
                and start != self._candidate_offset):
            self._candidate_offset = start
            self._candidate_sends = self._sends
            self.candidate_seq += 1
            async with self.prompt_condition:
                self.prompt_condition.notify_all()

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

    def _adopt_pending_prompt(self) -> bool:
        """Adopt an unconfirmed prompt as the current prompt level.

        Called on timeout.  If ACL2's output ends with a prompt that
        appeared after the latest form was sent but wasn't confirmed (such
        as the depth-2 prompt of (ld *standard-oi*)), ACL2 is waiting for
        input there: make it last_prompt_text, so that later commands use
        its depth for _confirm_max_depth.

        Likewise if the output ends with an unfinished line, printed after
        the latest form was sent, and nothing more has come for
        UNKNOWN_PROMPT_SECONDS: almost surely a prompt of some read loop
        that PROMPT_PATTERNS doesn't know.  Taking it as the prompt lets
        the next command be sent (whole, since prompt_mode doesn't know
        how it reads), where waiting for the earlier command to finish
        would block the session.  Returns whether it adopted a prompt.
        """
        if self._last_prompt_like is not None:
            _start, end, sends, text = self._last_prompt_like
            if end == self._total_bytes and sends == self._sends:
                self.last_prompt_text = text
                _debug_log(f"_adopt_pending_prompt: adopted '{text}'")
                return True
        if (self.partial_line_buffer and self._last_output_sends == self._sends
                and time.monotonic() - self._last_output_time
                >= UNKNOWN_PROMPT_SECONDS):
            text = bytes(self.partial_line_buffer).decode(errors="replace")
            self.last_prompt_text = text.rstrip("\r")
            _debug_log(f"_adopt_pending_prompt: adopted unknown prompt '{text}'")
            # The caller logs it now (_flush_partial_line), as the timed-out
            # command's output; a known prompt is logged when it settles
            self._unknown_prompt_adopted = True
            return True
        return False

    async def _adopt_and_log_prompt(self) -> bool:
        """_adopt_pending_prompt, and log an adopted unknown prompt at once,
        as the output of the command that timed out."""
        self._unknown_prompt_adopted = False
        adopted = self._adopt_pending_prompt()
        if self._unknown_prompt_adopted:
            await self._flush_partial_line()
        return adopted

    async def _flush_partial_line(self) -> None:
        """Move the unfinished line of output to the log and output_buffer."""
        async with self._chunk_lock:
            if not self.partial_line_buffer:
                return
            text = bytes(self.partial_line_buffer).decode(errors="replace")
            self.partial_line_buffer.clear()
            seq_id = await self._get_next_sequence_id()
            await self.merge_queue.put((time.monotonic(), seq_id, "stdout", text))

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
                start = self._total_bytes - len(self.partial_line_buffer)
                stale = (start != self._candidate_offset
                         or self._candidate_sends != self._sends)
                if depth > self._confirm_max_depth or stale:
                    # Deeper than the starting depth — likely an
                    # intermediate prompt during LD — or seen before the
                    # latest form was sent, so not the prompt after it
                    # (see _send_units).  Don't confirm
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
            # Only write SESSION ENDED if terminate() hasn't already written one.
            if not self._end_marker_written:
                self._end_marker_written = True
                timestamp = time.monotonic()
                seq_id = await self._get_next_sequence_id()
                end_time = time.strftime("%Y-%m-%d %H:%M:%S")
                end_marker = f"\n[{end_time} SESSION ENDED]\n"
                await self.merge_queue.put((timestamp, seq_id, "stdout", end_marker))
        except Exception as e:
            print(f"Error handling PTY EOF: {e}", file=sys.stderr)
        finally:
            self.shutdown_event.set()
            self._close_viewer()

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

    async def _wait_for_exit(self, timeout: float) -> bool:
        """Wait up to TIMEOUT seconds for the ACL2 process to exit."""
        try:
            await asyncio.wait_for(self.process.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def terminate(self) -> None:
        """
        Terminate the ACL2 session and stop all background tasks.
        Ensures all output is logged before shutdown.

        ACL2's output is read until the process has exited.  Besides
        logging it, this keeps the exit from hanging: on macOS a session
        leader's exit waits until its terminal output has been read.
        Every wait here is bounded.
        """
        try:
            # Stop sending the rest of a timed-out command, so that
            # (good-bye) doesn't land in the middle of it and nothing is
            # written after the master fd is closed.
            if self._pending_send is not None:
                self._pending_send.cancel()
                await asyncio.gather(self._pending_send, return_exceptions=True)

            # Ask ACL2 to exit.  The write fails if the input queue is full
            # (ACL2 is busy and hasn't read the last command), in which case
            # ACL2 couldn't see the request anyway.  It is sent even if the
            # acl2 process has died, since the Lisp that an acl2 script
            # starts may still be reading.
            goodbye_sent = False
            if self.master_fd is not None:
                try:
                    os.write(self.master_fd, b"(good-bye)\n")
                    goodbye_sent = True
                except OSError:
                    pass

            if self.process.returncode is None:
                if not (goodbye_sent and await self._wait_for_exit(5.0)):
                    # Kill the whole process group, which includes the Lisp
                    # that an acl2 script starts.  The group ID is the acl2
                    # process's PID (it called setsid), which can't be
                    # reused until we reap that process.
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    await self._wait_for_exit(5.0)

        finally:
            # Log the end marker after ACL2's last output, unless
            # _handle_pty_eof has already logged it
            if self.log_file and not self._end_marker_written:
                self._end_marker_written = True
                # Let output chunks already read reach the queue first
                await asyncio.sleep(0.1)
                end_time = time.strftime("%Y-%m-%d %H:%M:%S")
                end_marker = f"\n[{end_time} SESSION ENDED]\n"
                seq_id = await self._get_next_sequence_id()
                await self.merge_queue.put(
                    (time.monotonic(), seq_id, "session", end_marker))

            # Signal background tasks to shut down
            self.shutdown_event.set()

            self._stop_reading()

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

            self._close_viewer()


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


def _terminal_tail_command(log_file: Path, lines: int) -> str:
    """The command a Terminal log window runs: tail -f LOG_FILE in a sh
    wrapper that, on SIGTERM (or Ctrl-C, or the window closing), stops
    tail and exits 0.  close_log_viewer signals the wrapper, and closes
    the window once nothing runs on its tty (see _stop_terminal_tail)."""
    wrapper = (f"trap 'kill $! 2>/dev/null; exit 0' TERM INT HUP; "
               f'tail -n {lines} -f "$0" & wait')
    return f"exec /bin/sh -c {shlex.quote(wrapper)} {shlex.quote(str(log_file))}"


def _terminal_wrapper_pattern(log_file: Path) -> str:
    """A pkill -f pattern for the wrapper that _terminal_tail_command runs.
    Anchored at the start of the command line, so that it can't match the
    osascript processes, whose arguments mention the log too."""
    return f"^/bin/sh -c trap .*tail -n .*{log_file.name}"


def _terminal_tail_script(log_file: Path, lines: int, window_title: str) -> str:
    """AppleScript (inside tell application "Terminal") that opens a window
    running _terminal_tail_command and titles its tab WINDOW_TITLE: the tab
    that do script returns, not the front window, which may be another."""
    command = _terminal_tail_command(log_file, lines)
    quoted = '"' + command.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return (
        f"    set t to do script {quoted}\n"
        f'    set custom title of t to "{window_title}"\n'
        "    activate\n"
    )


# The Terminal log window AppleScripts waiting to run, as (window title,
# script); see _osascript.  The worker thread that runs them shares the
# state below with _stop_terminal_tail, under _viewer_lock.
_osascript_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
_osascript_worker: Optional[threading.Thread] = None
_viewer_lock = threading.Condition()
_osascript_running: Optional[str] = None  # the title of the running script
_windows_opened: dict[str, int] = {}  # by title: windows the scripts may have opened
_windows_closing: set[str] = set()  # the titles whose windows are closed


def _osascript(window_title: str, script: str) -> None:
    """Run SCRIPT, which opens or shows the log window titled WINDOW_TITLE
    (and returns "shown" if it only shows one), in the background, once the
    scripts queued before it have finished.  (show_session_log called
    right after start_session must find the window that start_session's
    script opens.)  It is dropped if, by then, that window is being closed:
    otherwise a window would be opened for a session that has ended."""
    global _osascript_worker
    _osascript_queue.put((window_title, script))
    if _osascript_worker is None:
        _osascript_worker = threading.Thread(target=_run_osascripts, daemon=True)
        _osascript_worker.start()


def _run_osascripts() -> None:
    """Run the queued viewer AppleScripts, one at a time.  Runs in a thread."""
    global _osascript_running
    while True:
        window_title, script = _osascript_queue.get()
        with _viewer_lock:
            if window_title in _windows_closing:
                continue
            _osascript_running = window_title
        # Count a window unless the script only showed one: a script that
        # failed or timed out (Terminal not answering) may have opened one
        shown = _run(["osascript", "-e", script]).strip() == "shown"
        with _viewer_lock:
            if not shown:
                _windows_opened[window_title] = _windows_opened.get(window_title, 0) + 1
            _osascript_running = None
            _viewer_lock.notify_all()


def _linux_tail_command(log_file: Path, lines: int) -> list[str]:
    """The command a Linux terminal log window runs.  Stopping it closes
    the window (see _stop_linux_tail)."""
    return ["tail", f"-n{lines}", "-f", str(log_file)]


def _linux_tail_pattern(log_file: Path) -> str:
    """A pkill -f pattern for the command that _linux_tail_command makes.
    Anchored at the start of the command line, so that it can't match
    another command that mentions the log."""
    return f"^tail -n[0-9]+ -f .*{log_file.name}$"


# The logs that Linux terminal windows were opened for (see close_log_viewer)
_linux_viewer_logs: set[str] = set()


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
            window_title = _session_window_title(session_id)
            _osascript(window_title, 'tell application "Terminal"\n'
                       + _terminal_tail_script(log_file, lines, window_title)
                       + "end tell\n")

        elif system == "Linux":
            # Without a display (a remote server, say) no window can open
            if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
                return
            # Try different terminal emulators.  None of them gets the
            # server's stdin, stdout or stderr: they carry the MCP
            # messages, which a warning from the emulator would corrupt.
            tail = _linux_tail_command(log_file, lines)
            terminals = [
                ["gnome-terminal", "--", *tail],
                ["xterm", "-e", *tail],
                ["konsole", "-e", *tail],
            ]
            for cmd in terminals:
                try:
                    subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                    _linux_viewer_logs.add(str(log_file))
                    break
                except FileNotFoundError:
                    continue

        elif system == "Windows":
            # Use PowerShell
            powershell = f'powershell -Command "Get-Content -Path \'{log_file}\' -Wait -Tail {lines}"'
            subprocess.Popen(["cmd", "/c", "start", "cmd", "/k", powershell])

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
            window_title = _session_window_title(session_id)
            # Bring this session's window to the front if there is one
            # still running something (its shell may not have started
            # tail yet); otherwise open one.  (Over windows by id: see
            # _stop_terminal_wrapper.)
            script = (
                'tell application "Terminal"\n'
                '    repeat with w in (get every window)\n'
                '        repeat with t in (get every tab of w)\n'
                '            try\n'
                f'                if custom title of t is "{window_title}" and (count of processes of t) > 0 then\n'
                '                    set frontmost of w to true\n'
                '                    activate\n'
                '                    return "shown"\n'
                '                end if\n'
                '            end try\n'
                '        end repeat\n'
                '    end repeat\n'
                + _terminal_tail_script(log_file, lines, window_title)
                + 'end tell\n'
            )
            _osascript(window_title, script)

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
    window via acl2-mcp-close-log.  For the macOS Terminal backend, stops
    the window's tail wrapper and closes the window (see
    _stop_terminal_tail).  On Linux, stops the windows' tail, which closes
    them (see _stop_linux_tail).
    Silently does nothing if the window or process doesn't exist.
    """
    if viewer == "none":
        return
    if viewer == "emacs":
        if log_file:
            _emacsclient_eval(f'(acl2-mcp-close-log "{_elisp_escape(str(log_file))}")')
        return

    system = platform.system()

    try:
        if system == "Darwin":
            if log_file is None:
                return
            # In a thread: the window's shell may not have started the
            # wrapper yet, and the caller is the event loop
            thread = threading.Thread(
                target=_stop_terminal_tail,
                args=(_terminal_wrapper_pattern(log_file),
                      _session_window_title(session_id)),
                daemon=True)
            _viewer_closers.add(thread)
            thread.start()
        elif system == "Linux":
            if log_file is None or str(log_file) not in _linux_viewer_logs:
                return
            _linux_viewer_logs.discard(str(log_file))
            thread = threading.Thread(
                target=_stop_linux_tail,
                args=(_linux_tail_pattern(log_file),), daemon=True)
            _viewer_closers.add(thread)
            thread.start()
    except Exception:
        pass


def _stop_linux_tail(pattern: str) -> None:
    """Stop the tail processes matching PATTERN (see _linux_tail_pattern):
    a terminal emulator closes its window when its command exits.  Runs in
    a thread.  A window can take a while to start tail, so this tries for
    up to 15 seconds."""
    try:
        deadline = time.time() + 15.0
        while True:
            try:
                if subprocess.run(["pkill", "-f", pattern], capture_output=True,
                                  timeout=10).returncode == 0:
                    break
            except Exception:
                pass
            if time.time() >= deadline:
                break
            time.sleep(0.25)
    finally:
        _viewer_closers.discard(threading.current_thread())


# Threads closing log windows (see wait_for_viewer_closers)
_viewer_closers: set[threading.Thread] = set()


def _stop_terminal_tail(pattern: str, window_title: str) -> None:
    """Stop the Terminal log windows' tail wrappers matching PATTERN (see
    _terminal_tail_command), and close their windows.  Runs in a thread.

    Terminal asks "terminate running processes?" when asked to close a
    window that still runs a process, and what it reports for a tab (its
    tty, its processes) can be stale.  So each wrapper's tty comes from
    ps; the window is found by its title and that tty while the wrapper
    still runs; and it is closed (by id) only once the processes that ran
    on that tty have exited and Terminal has noticed: the last line of the
    window's history is "[Process completed]".  (Closed as soon as ps
    showed the tty idle, a window could still bring up the dialog.)  When
    in doubt, the window is left open.

    The scripts that open windows for WINDOW_TITLE and haven't run yet are
    dropped, and one that is running is waited for, so the number of
    windows is known.  A window's shell can take a while to start the
    wrapper, so this looks for the wrappers for up to 15 seconds.
    """
    try:
        with _viewer_lock:
            _windows_closing.add(window_title)
            _viewer_lock.wait_for(lambda: _osascript_running != window_title, 15.0)
            windows = _windows_opened.pop(window_title, 0)
        deadline = time.time() + 15.0
        stopped: set[int] = set()
        while True:
            pids = [int(pid) for pid in _run(["pgrep", "-f", pattern]).split()]
            pids = [pid for pid in pids if pid not in stopped]
            for pid in pids:
                stopped.add(pid)
                _stop_terminal_wrapper(pid, window_title)
            if not pids:
                if len(stopped) >= windows or time.time() >= deadline:
                    break
                time.sleep(0.25)
        if len(stopped) < windows:
            _debug_log(f"close_log_viewer: found {len(stopped)} of {windows} "
                       f"wrappers for {window_title}")
    finally:
        _viewer_closers.discard(threading.current_thread())


def _stop_terminal_wrapper(pid: int, window_title: str) -> None:
    """Stop the Terminal log window wrapper PID, and close its window titled
    WINDOW_TITLE (see _stop_terminal_tail)."""
    tty = _run(["ps", "-o", "tty=", "-p", str(pid)]).strip()
    window = ""
    processes = ""
    if re.fullmatch(r"ttys\d+", tty):
        # The window's processes (login, the wrapper, tail), waited for
        # below.  Not whatever runs on the tty then: once they have
        # exited, Terminal gives the tty to the next window it opens.
        processes = ",".join(_run(["ps", "-t", tty, "-o", "pid="]).split())
        # Over (get every window), a list of windows by id: "repeat with w
        # in windows" names them by position, which shifts when another
        # window closes meanwhile, so "id of w" could be another window's
        window = _run(["osascript", "-e", (
            'tell application "Terminal"\n'
            '    repeat with w in (get every window)\n'
            '        try\n'
            '            if (count of tabs of w) is 1 then\n'
            f'                if tty of tab 1 of w is "/dev/{tty}" and custom title of tab 1 of w is "{window_title}" then return id of w\n'
            '            end if\n'
            '        end try\n'
            '    end repeat\n'
            '    return ""\n'
            'end tell\n')]).strip()
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not window.isdigit():
        _debug_log(f"close_log_viewer: no window found for {window_title}, tty {tty!r}")
        return
    deadline = time.time() + 10.0  # login can take seconds to exit
    lines: list[str] = []
    while time.time() < deadline:
        time.sleep(0.2)
        if processes and _run(["ps", "-p", processes, "-o", "pid="]).strip():
            continue
        # The end of the history, not the contents: a window in the
        # background doesn't update its contents
        history = _run(["osascript", "-e", (
            'tell application "Terminal"\n'
            f'    set h to history of tab 1 of window id {window}\n'
            'end tell\n'
            'if length of h > 400 then set h to text -400 thru -1 of h\n'
            'return h\n')])
        lines = [line for line in history.splitlines() if line.strip()]
        if lines and lines[-1].strip() == "[Process completed]":
            _run(["osascript", "-e",
                  f'tell application "Terminal" to close window id {window}'])
            _debug_log(f"close_log_viewer: closed {window_title} (window {window})")
            return
    _debug_log(f"close_log_viewer: left {window_title} open (window {window}), "
               f"last line {lines[-1] if lines else ''!r}, still running: "
               f"{_run(['ps', '-p', processes, '-o', 'pid=,command=']).strip()!r}")


def _run(command: list[str]) -> str:
    """Run COMMAND and return its output ("" if it fails)."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except Exception as e:
        _debug_log(f"_run {command[0]}: {e}")
        return ""
    # (Not ps's errors: ps -t fails once a window's tty is gone, as it should)
    if result.returncode != 0 and command[0] == "osascript":
        _debug_log(f"_run osascript: {result.stderr.strip()}")
    return result.stdout


def wait_for_viewer_closers(timeout: float) -> None:
    """Wait up to TIMEOUT seconds for log windows being closed (before the
    server exits)."""
    deadline = time.time() + timeout
    for thread in list(_viewer_closers):
        thread.join(max(0.0, deadline - time.time()))


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

        if cwd is not None and not os.path.isdir(cwd):
            problem = "not a directory" if os.path.exists(cwd) else "no such directory"
            return "", f"Error: Can't start a session in {cwd}: {problem}"

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

            # Pass input to ACL2 unchanged.  In canonical mode (ICANON)
            # the terminal holds input until a newline, truncates a longer
            # line (1024 bytes on macOS, 4096 on Linux), and edits lines:
            # DEL, C-u and C-w erase, and C-d ends input (at the start of
            # a line, ACL2 sees end of file).  IEXTEN (on macOS: C-o, C-v,
            # C-y) and IXON (C-s, C-q) would still make the terminal
            # swallow bytes of a command.  ISIG stays on: interrupt()
            # sends C-c, and send_command refuses code with C-c, C-\ or
            # C-z.  ECHO is off, so that the output is only ACL2's (the
            # input is logged separately).
            signal_characters: dict[bytes, str] | None = None
            try:
                attrs = termios.tcgetattr(slave_fd)
                attrs[0] &= ~termios.IXON
                attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN)
                attrs[6][termios.VMIN] = 1  # read() waits for one byte...
                attrs[6][termios.VTIME] = 0  # ...however long that takes
                termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
                signal_characters = {
                    attrs[6][index]: effect
                    for index, effect in _SIGNAL_EFFECTS.items()
                    if attrs[6][index] not in (b"\x00", b"\xff")}  # disabled
            except termios.error:
                # If termios setup fails, continue anyway - not critical
                pass

            # Define preexec_fn to set up controlling terminal properly
            def setup_controlling_tty() -> None:
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
            try:
                process = await asyncio.create_subprocess_exec(
                    "acl2",
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    cwd=cwd,
                    env=env,
                    preexec_fn=setup_controlling_tty,  # Critical for proper terminal setup
                )
            except FileNotFoundError:
                os.close(master_fd)
                os.close(slave_fd)
                return "", ("Error: Can't start ACL2: there is no acl2 command "
                            "in the MCP server's PATH")

            # Remember the slave's name for _flush_pty_input, then close
            # slave_fd in parent process (child inherited it)
            slave_path = os.ttyname(slave_fd)
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
                slave_path=slave_path,
                ring_buffer=bytearray(),
                tool_output_config=self.config.tool_output,
            )
            if signal_characters is not None:
                session.signal_characters = signal_characters

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

            # Wait for ACL2's first confirmed prompt: one that settles (see
            # _flush_prompt).  ACL2 loads an acl2-customization file after
            # printing a first prompt, in a nested LD, so a command sent at
            # that prompt would take the prompt after the file for its own.
            start_time = time.time()
            while (session.prompt_seq == 0 and time.time() - start_time < 30.0
                   and not session.exited):
                await asyncio.sleep(0.1)
            if session.exited:
                await session.terminate()
                log = f"  The session log has its output: {log_file}" if log_file else ""
                return "", f"Error: ACL2 exited while starting.{log}"

            # The host Lisp decides some of the reader's syntax
            if b"Welcome to Clozure Common Lisp" in session.ring_buffer:
                session.syntax = reader.CCL

            # Open log viewer if requested
            if effective_view_log_in_terminal and log_file:
                open_log_viewer(
                    log_file, log_tail_lines, session_id,
                    viewer=self.config.session_log.viewer,
                )
                self.log_viewer_opened(session)

            self.sessions[session_id] = session

            # Start cleanup task if not already running
            if self._cleanup_task is None:
                self._cleanup_task = asyncio.create_task(self._cleanup_inactive_sessions())

            message = f"Session started successfully. ID: {session_id}"
            if enable_logging:
                message += f"\nLog file: {session.log_file}"
            if session.prompt_seq == 0:
                message += ("\nNote: ACL2 hasn't shown its prompt within 30 "
                            "seconds; it may still be starting.  The session "
                            "log shows what it is doing.")
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
            return _session_not_found(session_id)

        # terminate() logs the SESSION ENDED marker and closes the log viewer
        await session.terminate()
        del self.sessions[session_id]

        return f"Session {session_id} ended successfully"

    def log_viewer_opened(self, session: ACL2Session) -> None:
        """Note that a viewer shows SESSION's log, so that it is closed when
        the session ends (if close_log_on_end is set)."""
        if self.config.session_log.close_log_on_end:
            session.close_viewer = functools.partial(
                close_log_viewer, session.session_id, session.log_file,
                viewer=self.config.session_log.viewer)

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
            return _session_not_found(session_id)

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
            exited = ("; ACL2 has exited, so nothing can run in it"
                      if session.exited else "")
            lines.append(
                f"  {session_id}{name_str}: "
                f"age={age:.0f}s, idle={idle:.0f}s{exited}"
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
                to_remove: list[tuple[str, ACL2Session]] = []

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


@app.list_tools()  # type: ignore[no-untyped-call]
async def list_tools() -> list[Tool]:
    """List available ACL2 tools."""
    return [
        Tool(
            name="start_session",
            description="Start a persistent ACL2 session, whose world (definitions, theorems, included books) lasts across evaluate calls. All ACL2 evaluation happens in a session. For a clean world, start a separate session and end it when done. Returns the session ID and the session log's path.",
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
                        "description": "Optional working directory for the ACL2 process; relative include-book and ld paths are resolved against it. If not specified, uses the MCP server's working directory. Example: '/Users/user/acl2/books/kestrel/axe/x86/examples/switch'",
                    },
                },
            },
        ),
        Tool(
            name="end_session",
            description="End an ACL2 session; its world is lost (a busy ACL2 is killed). Don't end a session just because a command timed out or failed; the session is usually fine (see interrupt_session).",
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
            description="List all active ACL2 sessions with their IDs, names, age, and idle time, marking any whose ACL2 has exited. Use this to see which sessions are available and their current state.",
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
            description="Interrupt ACL2 like Ctrl-C: aborts the form being evaluated and discards any part of the command ACL2 hasn't read yet. The session and its world remain. Use it when a proof or computation takes too long, rather than ending the session. Waits up to 5 seconds for ACL2 to get back to its prompt, and returns what ACL2 printed (its abort message). In a proof, the first interrupt may only ask ACL2 to stop at its next check: if the reply says ACL2 isn't back at its prompt, call interrupt_session again.",
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
            description="Send code to an ACL2 session as if typed at its prompt: events (defun, defthm, include-book, deflabel), expressions, and keyword commands (:pe, :pbt, :u, :ubu). Several forms per call are fine: each is sent once ACL2 has finished the one before, and the reply is ACL2's output up to its prompt after the last; look in it for 'ACL2 Error' or 'FAILED' (a failed event changes nothing). Code that ACL2 can't read, such as a form missing its ), is rejected and none of it is sent. Long output is shortened; the session log has all of it.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "ACL2 code to evaluate",
                    },
                    "timeout": {
                        "type": "number",
                        "description": f"Seconds to wait for the whole command (default {EVALUATE_DEFAULT_TIMEOUT}, the most allowed). A timeout costs nothing: ACL2 is not interrupted, but keeps working (the rest of a command not yet fully sent is still sent), and the next evaluate waits for it to finish and shows its output first. So prefer a short timeout, such as 30: a runaway proof usually shows in the session log within 30 seconds. Give more only to a command known to take long, such as a hard proof or a lift. On a timeout, check the session log, then wait or call interrupt_session; don't end the session.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "ID of the session to use",
                    },
                    "as_is": {
                        "type": "boolean",
                        "description": "Send the code exactly as given, in one piece, without reading it as ACL2 code: for a program that reads its own kind of input (default false).",
                    },
                },
                "required": ["code", "session_id"],
            },
        ),
        Tool(
            name="certify_book",
            description="Certify ACL2 books using cert.pl with parallel compilation. This verifies all proofs and creates certificates for books. Runs cert.pl as a separate process; sessions are not affected. Book path WITHOUT .lisp extension (e.g., '/path/to/books/kestrel/axe/top' not '.../top.lisp'). If jobs parameter is not specified, automatically detects optimal number based on CPU count and current system load.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the book WITHOUT .lisp extension. Use an absolute path: a relative one is resolved against the MCP server's working directory, not a session's.",
                    },
                    "jobs": {
                        "type": "number",
                        "description": "Number of parallel jobs for cert.pl. If not specified, automatically detects based on available CPU threads and current load.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout in seconds (optional, no timeout if not specified). Unlike evaluate's timeout, this stops cert.pl and the jobs it started; the reply ends with cert.pl's last output.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="xdoc_search",
            description="Search the local xdoc agent corpus (every manual topic as plain text; see the acl2-docker project's tools/DESIGN.md) for topics matching a query.  Fast (milliseconds) and works with no ACL2 session.  Searches topic names and one-line summaries by default; set full_text to search topic bodies too.  The corpus is found via the ACL2_XDOC_CORPUS environment variable, or at $ACL2_ROOT/books/doc/agent-corpus (present in the acl2-allcerts Docker image).  Use xdoc_show to read a found topic.",
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
            description="Show a topic from the local xdoc agent corpus by name.  Accepts a natural name ('bvplus', 'fty::defbitstruct', 'acl2::defun') or an xdoc key ('ACL2____BVPLUS'); a key with the wrong package is matched by its name part.  Fast and needs no ACL2 session; covers every topic in the built manual, but NOT topics defined in your own session (use :doc via evaluate for those).  Corpus location: see xdoc_search.",
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


# cert.pl processes still running, so that they can be stopped when the
# server exits (they run in process groups of their own, so they would
# outlive it).
_running_certifications: set["asyncio.subprocess.Process"] = set()


async def _stop_certification(process: "asyncio.subprocess.Process") -> None:
    """Stop cert.pl and everything it started.

    cert.pl execs make, which runs a helper script, a shell, and ACL2 for
    each book, all in cert.pl's process group, whose ID is cert.pl's PID.
    SIGTERM makes make remove the target it was building; anything still
    running 5 seconds later gets SIGKILL.  The group is signalled only
    while process.wait() hasn't returned, that is, while cert.pl or a
    process sharing its output is still alive, so the group ID is still in
    use and can't have been reused.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except (ProcessLookupError, PermissionError):
            break
        try:
            await asyncio.wait_for(process.wait(), 5.0)
            break
        except asyncio.TimeoutError:
            pass
    # Not reached if this was cancelled; stop_all_certifications() then
    # finishes the job at server exit.
    _running_certifications.discard(process)


async def stop_all_certifications() -> None:
    """Stop every cert.pl still running (at server exit)."""
    await asyncio.gather(
        *(_stop_certification(p) for p in list(_running_certifications)),
        return_exceptions=True)


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
    book_file = Path(book_path + ".lisp")
    if not book_file.is_file():
        where = ("" if book_file.is_absolute() else
                 f" (a relative path is resolved against the MCP server's "
                 f"working directory, {os.getcwd()})")
        return f"Error: Book not found: no file {book_file}{where}"

    # Build cert.pl command with -j flag
    cmd_args = ["cert.pl", f"-j{jobs}", book_path]

    # Format command for display (used by progress_callback if provided)
    cmd_display = " ".join(cmd_args)

    # Send progress notification with command if callback provided
    if progress_callback:
        await progress_callback(f"Running: {cmd_display}")

    # Use cert.pl to certify the book.  It runs in a process group of its
    # own, so that a timeout or a cancelled tool call can stop everything
    # it starts (see _stop_certification).
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,  # Combine stderr into stdout
            start_new_session=True,
            # Note: Consider passing an appropriate directory here.
            # Right now we assume the MCP server was started in the ACL2 directory
            # but if not then the errors can be confusing.
            # cwd="/path/to/working/directory/"
        )
        _running_certifications.add(process)

        # Collect the output as it arrives, so that a timeout can report
        # how far cert.pl got.  It ends when cert.pl and everything it
        # started have exited, since they all share its stdout.
        chunks: list[bytes] = []

        async def collect_output() -> None:
            assert process.stdout is not None
            while chunk := await process.stdout.read(65536):
                chunks.append(chunk)

        collector = asyncio.create_task(collect_output())
        try:
            await asyncio.wait_for(asyncio.shield(collector), timeout)
            await process.wait()
            _running_certifications.discard(process)
        except asyncio.TimeoutError:
            await _stop_certification(process)
            await asyncio.wait({collector}, timeout=1.0)
            output = b"".join(chunks).decode(errors="replace")
            tail = "\n".join(output.splitlines()[-20:])
            return (f"Error: cert.pl timed out after {timeout} seconds; it "
                    f"and the jobs it started were stopped.\n\n"
                    f"Last output:\n{tail}")
        except asyncio.CancelledError:
            # The client cancelled the tool call, or the server is exiting
            await _stop_certification(process)
            raise
        finally:
            collector.cancel()

        output = b"".join(chunks).decode(errors="replace")
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
            # -e keeps a query that starts with "-" from being parsed as
            # grep options.
            proc = subprocess.run(
                ["grep", "-r", "-i", "-m", "1", "-F", "-e", query,
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
    # The index lists ACL2 symbols and the Common Lisp symbols imported into
    # ACL2 without a package prefix (acl2::bvplus as bvplus, acl2::defun as
    # defun), the way they print from the ACL2 package.
    for prefix in ("acl2::", "common-lisp::"):
        if lname.startswith(prefix):
            lname = lname[len(prefix):]
            break
    exact = [(nat, key) for (nat, key, _s) in rows if nat.lower() == lname]
    if not exact:
        # A bare name may match a package-qualified topic (defbitstruct ->
        # fty::defbitstruct).
        exact = [(nat, key) for (nat, key, _s) in rows
                 if nat.lower().endswith("::" + lname)]
    if not exact and "____" in name:
        # A key with the wrong package, e.g. ACL2____DEFUN for
        # COMMON-LISP____DEFUN: match on the part after the package.
        part = name.partition("____")[2].lower()
        exact = [(nat, key) for (nat, key, _s) in rows
                 if key.partition("____")[2].lower() == part]
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


@app.call_tool()
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
                    text=_session_not_found(session_id),
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
        session_manager.log_viewer_opened(session)
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
        timeout = arguments.get("timeout", EVALUATE_DEFAULT_TIMEOUT)
        session_id = arguments["session_id"]
        as_is = arguments.get("as_is", False) is True

        session = session_manager.get_session(session_id)
        if not session:
            return [
                TextContent(
                    type="text",
                    text=_session_not_found(session_id),
                )
            ]
        output = await session.send_command(code, timeout, as_is)

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
    # MCP clients stop a server by closing its input, then sending SIGTERM
    # if it hasn't exited (it waits for tool calls still running, such as a
    # long certification).  A client running in a terminal starts the
    # server in its own process group, so when the terminal goes away (a
    # closed window, a killed tmux pane) the server gets SIGHUP as well.
    # The default action of either signal would kill it at once, skipping
    # the cleanup and leaving certifications running.  Instead, cancel the
    # running tool calls, clean up, and exit.  The cleanup runs in a task
    # of its own because run() may never get to its finally: if stdin is
    # still open, the MCP library's thread reading it stays blocked in
    # read(), and the library waits for that thread.
    main_task = asyncio.current_task()
    cleaning_up = False
    exit_tasks: list["asyncio.Task[None]"] = []

    async def clean_up() -> None:
        await asyncio.gather(session_manager.cleanup_all(),
                             stop_all_certifications())
        # Let log windows finish closing
        await asyncio.get_running_loop().run_in_executor(
            None, wait_for_viewer_closers, 10.0)

    async def clean_up_and_exit() -> None:
        await clean_up()
        os._exit(0)

    def on_signal() -> None:
        nonlocal cleaning_up
        if cleaning_up:
            return  # the server is already shutting down
        cleaning_up = True
        if main_task is not None:
            main_task.cancel()
        exit_tasks.append(asyncio.create_task(clean_up_and_exit()))

    for sig in (signal.SIGTERM, signal.SIGHUP):
        asyncio.get_running_loop().add_signal_handler(sig, on_signal)
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    finally:
        # Clean up all sessions and certifications on shutdown
        if not cleaning_up:
            cleaning_up = True
            await clean_up()
        elif exit_tasks:
            # After SIGTERM or SIGHUP: let its cleanup finish (it exits the
            # process)
            await exit_tasks[0]


def main() -> None:
    """Main entry point for the server."""
    # Ignore SIGPIPE to prevent broken pipe errors when clients disconnect
    # This is safe on Unix-like systems; on Windows SIGPIPE doesn't exist
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    asyncio.run(run())


if __name__ == "__main__":
    main()
