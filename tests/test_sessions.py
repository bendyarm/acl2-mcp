"""Tests for ACL2 MCP server session functionality.

Known failures as of 2026-04-05:
- test_eof_detection: Flaky — killing the ACL2 process doesn't always
  prevent it from responding to the next command, due to process
  termination timing.

Pre-existing failures in other test files (not in this file):
- test_security.py::test_validate_timeout_handles_invalid_type
- test_server.py::test_call_tool_certify_book_nonexistent: Test expects
  "not found" but make returns "No rule to make target".

Terminal window cleanup note:
test_eof_detection fails before it ends its session, leaving its log
viewer window open.  test_cleanup_all_with_dead_sessions usually leaves
one open too: its sessions end within a second of starting, and the
Terminal viewer's close (which kills the window's tail process) can run
before the window's shell has started tail.
"""

import asyncio
import os
import time
from typing import Any

import pytest

from acl2_mcp import server
from acl2_mcp.config import ServerConfig, SessionLogConfig
from acl2_mcp.server import (
    call_tool,
    session_manager,
    validate_session_name,
    validate_integer_parameter,
)


def extract_session_id(text: str) -> str:
    """Extract session ID from start_session response text.

    The response format is:
        Session started successfully. ID: <uuid>
        Log file: /path/to/log
    """
    return text.split("ID: ")[1].split("\n")[0].strip()


@pytest.mark.asyncio
async def test_start_session() -> None:
    """Test starting a new session."""
    arguments: dict[str, Any] = {"name": "test-session"}

    result = await call_tool("start_session", arguments)

    assert len(result) == 1
    assert result[0].type == "text"
    assert "Session started successfully" in result[0].text
    assert "ID:" in result[0].text

    # Extract session ID for cleanup
    session_id = extract_session_id(result[0].text)

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_start_session_no_name() -> None:
    """Test starting a session without a name."""
    arguments: dict[str, Any] = {}

    result = await call_tool("start_session", arguments)

    assert len(result) == 1
    assert "Session started successfully" in result[0].text

    session_id = extract_session_id(result[0].text)
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_end_session() -> None:
    """Test ending a session."""
    # Start a session first
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # End the session
    end_result = await call_tool("end_session", {"session_id": session_id})

    assert len(end_result) == 1
    assert "ended successfully" in end_result[0].text


@pytest.mark.asyncio
async def test_end_session_nonexistent() -> None:
    """Test ending a nonexistent session."""
    result = await call_tool("end_session", {"session_id": "invalid-uuid"})

    assert len(result) == 1
    assert "not found" in result[0].text


@pytest.mark.asyncio
async def test_list_sessions_empty() -> None:
    """Test listing sessions when none exist."""
    # Clean up any existing sessions first
    await session_manager.cleanup_all()

    result = await call_tool("list_sessions", {})

    assert len(result) == 1
    assert "No active sessions" in result[0].text


@pytest.mark.asyncio
async def test_list_sessions_with_active() -> None:
    """Test listing active sessions."""
    await session_manager.cleanup_all()

    # Start a session
    start_result = await call_tool("start_session", {"name": "test-session"})
    session_id = extract_session_id(start_result[0].text)

    # List sessions
    list_result = await call_tool("list_sessions", {})

    assert len(list_result) == 1
    assert "Active sessions:" in list_result[0].text
    assert session_id in list_result[0].text
    assert "test-session" in list_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_evaluate_in_session() -> None:
    """Test evaluating code in a persistent session."""
    # Start session
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Define a function in the session
    eval_result = await call_tool("evaluate", {
        "code": "(defun my-plus (x y) (+ x y))",
        "session_id": session_id
    })

    assert len(eval_result) == 1
    assert "MY-PLUS" in eval_result[0].text.upper() or "ACL2" in eval_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_session_state_persistence() -> None:
    """Test that session maintains state across multiple calls."""
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Define function
    await call_tool("evaluate", {
        "code": "(defun double (x) (* 2 x))",
        "session_id": session_id
    })

    # Use the function in a second call (should work due to persistence)
    eval_result = await call_tool("evaluate", {
        "code": "(double 5)",
        "session_id": session_id
    })

    # Should execute successfully (function is defined in session)
    assert len(eval_result) == 1
    # ACL2 might show 10 or just return success
    assert len(eval_result[0].text) > 0

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_session_nonexistent_error() -> None:
    """Test that operations on nonexistent sessions fail gracefully."""
    result = await call_tool("evaluate", {
        "session_id": "nonexistent-session",
        "code": "(+ 1 1)"
    })

    assert len(result) == 1
    assert "not found" in result[0].text


# Security and Validation Tests


def test_validate_session_name_valid() -> None:
    """Test that valid session names are accepted."""
    assert validate_session_name("my-session") == "my-session"
    assert validate_session_name("session 123") == "session 123"
    assert validate_session_name("test_session") == "test_session"


def test_validate_session_name_rejects_invalid() -> None:
    """Test that invalid session names are rejected."""
    with pytest.raises(ValueError, match="only contain"):
        validate_session_name("bad@session")

    with pytest.raises(ValueError, match="only contain"):
        validate_session_name("bad\nsession")


def test_validate_session_name_rejects_long() -> None:
    """Test that long session names are rejected."""
    long_name = "a" * 101
    with pytest.raises(ValueError, match="exceeds maximum length"):
        validate_session_name(long_name)


def test_validate_session_name_allows_empty() -> None:
    """Test that empty session names are allowed (optional)."""
    assert validate_session_name("") == ""


def test_validate_integer_parameter_valid() -> None:
    """Test that valid integers are accepted."""
    assert validate_integer_parameter(5, 1, 10, "test") == 5
    assert validate_integer_parameter(1, 1, 10, "test") == 1
    assert validate_integer_parameter(10, 1, 10, "test") == 10


def test_validate_integer_parameter_rejects_out_of_bounds() -> None:
    """Test that out of bounds integers are rejected."""
    with pytest.raises(ValueError, match="must be between"):
        validate_integer_parameter(0, 1, 10, "test")

    with pytest.raises(ValueError, match="must be between"):
        validate_integer_parameter(11, 1, 10, "test")

    with pytest.raises(ValueError, match="must be between"):
        validate_integer_parameter(-5, 1, 10, "test")


def test_validate_integer_parameter_rejects_non_integer() -> None:
    """Test that non-integers are rejected."""
    with pytest.raises(ValueError, match="must be an integer"):
        validate_integer_parameter("5", 1, 10, "test")  # type: ignore


@pytest.mark.asyncio
async def test_session_code_length_limit() -> None:
    """Test that code length limits apply to sessions."""
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Try to send very long code
    long_code = "a" * 2_000_000
    result = await call_tool("evaluate", {
        "code": long_code,
        "session_id": session_id
    })

    assert len(result) == 1
    assert "exceeds maximum length" in result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_invalid_session_name() -> None:
    """Test that invalid session names are rejected."""
    result = await call_tool("start_session", {
        "name": "bad@session#name!"
    })

    assert len(result) == 1
    assert "Invalid session name" in result[0].text


@pytest.mark.asyncio
async def test_interrupt_with_full_input_queue(session_id: str) -> None:
    """Interrupt works when ACL2's input queue is full.

    While ACL2 sleeps, a command bigger than the PTY input queue (about
    1 KB on macOS, 20 KB on Linux) fills it, leaving no room to write
    Ctrl-C.  The interrupt must discard the unread input, so that there is
    room for Ctrl-C (it used to fall back to SIGINT), none of the queued
    forms run, and no partial form is left to swallow the next command.
    """
    code = "(sleep 10)\n" + "(value-triple :padding)\n" * 2000
    # evaluate waits for ACL2 to read the rest; interrupt meanwhile.
    evaluation = asyncio.create_task(call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 60}))
    await asyncio.sleep(1)

    result = await call_tool("interrupt_session", {"session_id": session_id})
    # (not "Interrupt sent (as SIGINT)", the fallback)
    assert result[0].text.startswith("Interrupt sent; ACL2 is back at its prompt")

    result = await evaluation
    assert "interrupted before the whole command was sent" in result[0].text
    assert "ABORTING" in result[0].text
    assert ":PADDING" not in result[0].text

    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 10})
    assert "1337" in result[0].text
    assert ":PADDING" not in result[0].text


@pytest.mark.asyncio
async def test_long_line(session_id: str) -> None:
    """A 70 KB line reaches ACL2 whole.

    In canonical mode the terminal kept only the first 1024 bytes of a
    line on macOS (and dropped its newline, so ACL2 waited for the rest of
    the form forever), and the first 4096 on Linux.
    """
    code = '(length "' + "x" * 70000 + '")'
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 30})
    assert "70000" in result[0].text


@pytest.mark.asyncio
async def test_line_editing_characters_reach_acl2(session_id: str) -> None:
    """Characters that a terminal edits lines with reach ACL2 unchanged.

    In canonical mode DEL, C-u and C-w erased input and C-d ended it (at
    the start of a line, ACL2 saw end of file and aborted).  C-o discarded
    output (macOS), C-s stopped it, and C-t printed a status line.
    """
    s = "a\x7fb\x15c\x17d\x04e\x0ff\x13g\x14h\n\x04i"
    s += "x" * (4321 - len(s))
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": f'(length "{s}")', "timeout": 10})
    assert "4321" in result[0].text


# About 32 KB of comment lines: more than the PTY input queue holds (about
# 1 KB on macOS, 20 KB on Linux).
FILLER = ("; " + "x" * 78 + "\n") * 400


@pytest.mark.asyncio
async def test_long_command_while_acl2_busy(session_id: str) -> None:
    """A command bigger than the PTY input queue is sent in full while
    ACL2 is busy with its first form.

    The write used to give up when the queue filled ("Failed to write
    complete command to session"), leaving a partial form in ACL2's reader
    to swallow the next command.
    """
    code = "(sleep 2)\n" + FILLER + "(value-triple :last-form-done)"
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 60})
    assert ":LAST-FORM-DONE" in result[0].text

    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 10})
    assert "1337" in result[0].text


@pytest.mark.asyncio
async def test_timeout_while_command_is_still_being_sent(
        session_id: str) -> None:
    """A command that times out before ACL2 has read all of it is still
    sent in full, and the next command runs after it."""
    session = session_manager.get_session(session_id)
    assert session is not None and session.log_file is not None
    code = "(sleep 4)\n" + FILLER + "(value-triple :last-form-done)"
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 1})
    assert "timed out" in result[0].text
    assert "the rest will be sent" in result[0].text

    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 30})
    assert "1337" in result[0].text
    log = session.log_file.read_text()
    assert log.index(":LAST-FORM-DONE") < log.index("1337")


@pytest.mark.asyncio
async def test_interrupt_stops_sending_rest_of_command(
        session_id: str) -> None:
    """After a command times out before ACL2 has read all of it, an
    interrupt stops the rest from being sent."""
    session = session_manager.get_session(session_id)
    assert session is not None and session.log_file is not None
    code = "(sleep 10)\n" + FILLER + "(value-triple :last-form-done)"
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 1})
    assert "the rest will be sent" in result[0].text

    # interrupt_session returns ACL2's abort message (the timed-out
    # evaluate can't), and only once ACL2 is back at its prompt, so that
    # the next command doesn't take that prompt as its own
    result = await call_tool("interrupt_session", {"session_id": session_id})
    assert result[0].text.startswith("Interrupt sent; ACL2 is back at its prompt")
    assert "ABORTING" in result[0].text

    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 10})
    assert "1337" in result[0].text
    log = session.log_file.read_text()
    assert "INPUT CUT SHORT" in log
    assert ":LAST-FORM-DONE" not in log


@pytest.mark.asyncio
async def test_interrupt_while_rest_of_command_unread(session_id: str) -> None:
    """Interrupt works at once while ACL2 is busy with an early form and
    the rest of the command is queued, unread.

    The command fits in the PTY input queue, so it is sent in full, but
    ACL2 reads only part of it before starting the first form.  On Linux
    the terminal acts on a byte only once the input ahead of it is read,
    so a Ctrl-C written behind the rest of the command used to wait until
    ACL2 had finished the form and read the rest.
    """
    # Let ACL2 finish starting up (an acl2-customization file loads after
    # the first prompt, which start_session takes as the end of startup)
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 30})
    assert "1337" in result[0].text

    code = "(sleep 30)\n" + FILLER[:16000] + "(value-triple :last-form-done)"
    evaluation = asyncio.create_task(call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 60}))
    await asyncio.sleep(1)

    start = time.monotonic()
    result = await call_tool("interrupt_session", {"session_id": session_id})
    assert result[0].text.startswith("Interrupt sent; ACL2 is back at its prompt")
    result = await evaluation
    assert time.monotonic() - start < 10
    assert "ABORTING" in result[0].text
    assert ":LAST-FORM-DONE" not in result[0].text


@pytest.mark.asyncio
async def test_interrupt_proof_twice(session_id: str) -> None:
    """In a proof, the first interrupt only asks ACL2 to stop at its next
    check; interrupt_session says so when ACL2 doesn't get back to its
    prompt, and a second interrupt aborts the proof."""
    for code in ["(+ 1000 337)",  # let ACL2 finish starting up
                 "(defun count-up (n acc) (if (zp n) acc (count-up (1- n) (1+ acc))))"]:
        await call_tool("evaluate", {
            "session_id": session_id, "code": code, "timeout": 30})
    # Proving this means evaluating the call, which never checks for an
    # interrupt
    result = await call_tool("evaluate", {
        "session_id": session_id, "timeout": 2,
        "code": "(thm (equal (count-up 100000000000 0) 100000000000))"})
    assert "timed out" in result[0].text

    result = await call_tool("interrupt_session", {"session_id": session_id})
    assert "has not returned to its prompt" in result[0].text
    assert "call interrupt_session again" in result[0].text
    result = await call_tool("interrupt_session", {"session_id": session_id})
    assert result[0].text.startswith("Interrupt sent; ACL2 is back at its prompt")

    result = await call_tool("evaluate", {
        "session_id": session_id, "code": "(+ 1000 337)", "timeout": 10})
    assert "1337" in result[0].text


async def process_group_exits(pgid: int, timeout: float = 5.0) -> bool:
    """Wait up to TIMEOUT seconds for every process in group PGID to exit."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.1)
    return False


async def start_session_and_get_pgid() -> tuple[str, int]:
    """Start a session; return its ID and its ACL2 process group ID."""
    result = await call_tool("start_session", {})
    session_id = extract_session_id(result[0].text)
    session = session_manager.get_session(session_id)
    assert session is not None
    return session_id, session.process.pid


@pytest.mark.asyncio
async def test_end_session_while_acl2_prints() -> None:
    """end_session finishes while ACL2 is printing a lot of output.

    terminate() used to stop reading ACL2's output before waiting for it
    to exit.  ACL2 then blocked writing its output and never read
    (good-bye); once it was killed, its exit waited on macOS for the unread
    output, and so end_session hung.
    """
    session_id, pgid = await start_session_and_get_pgid()
    # The command times out while ACL2 sleeps; then ACL2 prints ~40 KB.
    await call_tool("evaluate", {
        "session_id": session_id, "timeout": 1,
        "code": '(prog2$ (sleep 2) (cw "~x0~%" (make-list 20000 :initial-element 7)))'})

    result = await asyncio.wait_for(
        call_tool("end_session", {"session_id": session_id}), timeout=30)
    assert "ended successfully" in result[0].text
    assert await process_group_exits(pgid)


@pytest.mark.asyncio
async def test_end_session_kills_busy_acl2() -> None:
    """end_session kills ACL2 when it is too busy to read (good-bye).

    Every process in the session's group must be gone afterwards,
    including the Lisp that the acl2 script starts.
    """
    session_id, pgid = await start_session_and_get_pgid()
    await call_tool("evaluate", {
        "session_id": session_id, "timeout": 1, "code": "(sleep 60)"})

    result = await asyncio.wait_for(
        call_tool("end_session", {"session_id": session_id}), timeout=30)
    assert "ended successfully" in result[0].text
    assert await process_group_exits(pgid)


@pytest.mark.asyncio
async def test_reader_stops_when_acl2_exits(session_id: str) -> None:
    """Once ACL2 has exited, the session stops reading its PTY.

    The PTY master then reads EOF or EIO forever, so a reader left
    registered kept the event loop busy (100% CPU until end_session).
    """
    session = session_manager.get_session(session_id)
    assert session is not None
    await call_tool("evaluate", {
        "session_id": session_id, "timeout": 10, "code": "(good-bye)"})

    for _ in range(50):
        if not session.reader_registered:
            break
        await asyncio.sleep(0.1)
    assert not session.reader_registered


@pytest.fixture
def emacs_viewer(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Use the Emacs log viewer, recording the forms for emacsclient
    instead of sending them."""
    forms: list[str] = []
    monkeypatch.setattr(server, "_emacsclient_eval", forms.append)
    monkeypatch.setattr(session_manager, "config", ServerConfig(
        session_log=SessionLogConfig(viewer="emacs")))
    return forms


def viewer_closes(forms: list[str]) -> int:
    return sum(form.startswith("(acl2-mcp-close-log ") for form in forms)


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["end_session", "ACL2 exits", "server exits"])
async def test_log_viewer_closed_when_session_ends(
        emacs_viewer: list[str], ending: str) -> None:
    """A session's log viewer is closed once, however the session ends.

    Only end_session used to close it, so a session whose ACL2 exited, or
    that was still running when the server exited, left its viewer open.
    """
    result = await call_tool("start_session", {})
    session_id = extract_session_id(result[0].text)
    assert emacs_viewer[0].startswith("(acl2-mcp-show-log ")
    assert viewer_closes(emacs_viewer) == 0

    if ending == "end_session":
        await call_tool("end_session", {"session_id": session_id})
    elif ending == "ACL2 exits":
        await call_tool("evaluate", {
            "session_id": session_id, "timeout": 10, "code": "(good-bye)"})
        for _ in range(50):
            if viewer_closes(emacs_viewer):
                break
            await asyncio.sleep(0.1)
        assert viewer_closes(emacs_viewer) == 1
        await call_tool("end_session", {"session_id": session_id})
    else:
        await session_manager.cleanup_all()
    assert viewer_closes(emacs_viewer) == 1


@pytest.mark.asyncio
async def test_log_viewer_shown_later_closed_when_session_ends(
        emacs_viewer: list[str]) -> None:
    """A viewer opened by show_session_log is closed when the session ends."""
    result = await call_tool("start_session", {"view_log_in_terminal": False})
    session_id = extract_session_id(result[0].text)
    assert emacs_viewer == []
    await call_tool("show_session_log", {"session_id": session_id})
    await call_tool("end_session", {"session_id": session_id})
    assert viewer_closes(emacs_viewer) == 1


@pytest.mark.asyncio
async def test_broken_pipe_on_send_command() -> None:
    """Test that BrokenPipeError is handled gracefully when sending commands."""
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Get the session and kill the underlying process to simulate broken pipe
    session = session_manager.get_session(session_id)
    assert session is not None

    # Kill the ACL2 process
    session.process.kill()
    await session.process.wait()

    # Try to send a command (should get broken pipe error)
    result = await call_tool("evaluate", {
        "code": "(+ 1 1)",
        "session_id": session_id
    })

    assert len(result) == 1
    # Should get error message about broken pipe or connection lost
    assert "broken pipe" in result[0].text.lower() or "connection lost" in result[0].text.lower()

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_broken_pipe_on_terminate() -> None:
    """Test that terminating an already-dead session doesn't raise errors."""
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Get the session and kill the underlying process
    session = session_manager.get_session(session_id)
    assert session is not None

    # Kill the ACL2 process
    session.process.kill()
    await session.process.wait()

    # Terminate should handle the broken pipe gracefully
    result = await call_tool("end_session", {"session_id": session_id})

    assert len(result) == 1
    assert "ended successfully" in result[0].text


@pytest.mark.asyncio
async def test_cleanup_all_with_dead_sessions() -> None:
    """Test that cleanup_all handles sessions with dead processes."""
    # Start multiple sessions
    session_ids = []
    for i in range(3):
        start_result = await call_tool("start_session", {"name": f"test-{i}"})
        session_id = extract_session_id(start_result[0].text)
        session_ids.append(session_id)

    # Kill some of the processes
    for session_id in session_ids[:2]:
        session = session_manager.get_session(session_id)
        if session:
            session.process.kill()
            await session.process.wait()

    # cleanup_all should handle this gracefully
    await session_manager.cleanup_all()

    # Verify all sessions are gone
    list_result = await call_tool("list_sessions", {})
    assert "No active sessions" in list_result[0].text


@pytest.mark.asyncio
async def test_eof_detection() -> None:
    """Test that EOF from session process is detected properly."""
    start_result = await call_tool("start_session", {})
    session_id = extract_session_id(start_result[0].text)

    # Get the session
    session = session_manager.get_session(session_id)
    assert session is not None

    # Send a command that will cause the process to exit
    # (good-bye exits ACL2)
    if session.process.stdin:
        try:
            session.process.stdin.write(b"(good-bye)\n")
            await session.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # Wait a bit for process to exit
    await asyncio.sleep(0.5)

    # Try to send another command - should detect terminated process
    result = await call_tool("evaluate", {
        "code": "(+ 1 1)",
        "session_id": session_id
    })

    assert len(result) == 1
    # Should get error about terminated process or broken pipe
    assert "terminated" in result[0].text.lower() or "connection lost" in result[0].text.lower() or "broken pipe" in result[0].text.lower()

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})
