"""Tests for ACL2 MCP server session functionality."""

import asyncio
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from acl2_mcp import server
from acl2_mcp.config import ServerConfig, SessionLogConfig
from acl2_mcp.server import (
    call_tool,
    matches_prompt_pattern,
    prompt_mode,
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



def test_linux_log_viewer_gets_no_server_stdio(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """On Linux the terminal emulator doesn't inherit the server's stdin,
    stdout and stderr, which carry the MCP messages; and without a display
    there is no emulator to start."""
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(server.platform, "system", lambda: "Linux")
    monkeypatch.setattr(server.subprocess, "Popen",
                        lambda cmd, **kwargs: calls.append((cmd, kwargs)))
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    server.open_log_viewer(tmp_path / "x.log", 50, "abc")
    assert not calls  # no display, no window
    monkeypatch.setenv("DISPLAY", ":0")
    server.open_log_viewer(tmp_path / "x.log", 50, "abc")
    [(cmd, kwargs)] = calls
    assert cmd[-4:] == ["tail", "-n50", "-f", str(tmp_path / "x.log")]
    for stream in ("stdin", "stdout", "stderr"):
        assert kwargs[stream] == server.subprocess.DEVNULL


def test_linux_log_viewer_closed(monkeypatch: pytest.MonkeyPatch,
                                 tmp_path: Path) -> None:
    """On Linux, closing a log viewer stops its tail (the emulator then
    closes its window), and only that tail."""
    log, other = tmp_path / "s1-x.log", tmp_path / "s2-x.log"
    log.write_text("")
    other.write_text("")
    tails = [subprocess.Popen(server._linux_tail_command(f, 50),
                              stdout=subprocess.DEVNULL) for f in (log, other)]
    try:
        time.sleep(0.5)
        monkeypatch.setattr(server.platform, "system", lambda: "Linux")
        monkeypatch.setattr(server, "_linux_viewer_logs", {str(log), str(other)})
        server.close_log_viewer("s1", log)
        server.wait_for_viewer_closers(20.0)
        assert tails[0].wait(timeout=5) is not None
        assert tails[1].poll() is None
    finally:
        for tail in tails:
            tail.kill()
            tail.wait()

@pytest.mark.asyncio
async def test_line_editing_characters_reach_acl2(session_id: str) -> None:
    """Characters that a terminal edits lines with reach ACL2 unchanged.

    In canonical mode DEL, C-u and C-w erased input and C-d ended it (at
    the start of a line, ACL2 saw end of file and aborted).  C-o discarded
    output (macOS), C-s stopped it, C-t printed a status line, and C-y
    suspended ACL2 when it read it (macOS).
    """
    s = "a\x7fb\x15c\x17d\x04e\x0ff\x13g\x14h\x19j\n\x04i"
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
    """Interrupt works at once while ACL2 is busy with an early form of a
    long command.

    When a command was sent all at once, it could be queued, unread,
    behind the form ACL2 was busy with.  On Linux the terminal acts on a
    byte only once the input ahead of it is read, so a Ctrl-C written
    behind the rest of the command used to wait until ACL2 had finished
    the form and read the rest.  (A command is now sent one form at a
    time, except at a raw Lisp prompt.)
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
        except (ProcessLookupError, PermissionError):
            # PermissionError: none of the group's processes are ours, so
            # its ID was reused (by a root-owned login, say)
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
@pytest.mark.skipif(server.platform.system() != "Darwin",
                    reason="Terminal log windows are macOS only")
async def test_terminal_log_window_closed_when_its_tty_is_reused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A Terminal log window is closed even if, once its processes have
    exited, another window has its tty.

    Terminal gives a new window the lowest free tty, often the one a log
    window has just freed.  The window used to be closed only once nothing
    ran on its tty, so when the next session's window got it, the window
    stayed open.  Here ps -t shows another window's process on the tty
    once the window's own are gone.
    """
    real_run = server._run

    def run(command: list[str]) -> str:
        out = real_run(command)
        if command[:2] == ["ps", "-t"] and not out.strip():
            out = "99999\n"  # the next window's login, say
        return out

    monkeypatch.setattr(server, "_run", run)
    monkeypatch.setattr(session_manager, "config", ServerConfig(
        session_log=SessionLogConfig(viewer="auto")))
    session_id, _ = await session_manager.start_session(view_log_in_terminal=True)
    await asyncio.sleep(1)  # (so that its window is open)
    await session_manager.end_session(session_id)
    await asyncio.to_thread(server.wait_for_viewer_closers, 30.0)
    names = real_run(["osascript", "-e",
                      'tell application "Terminal" to return name of every window'])
    assert f"ACL2 Log {session_id[:8]}" not in names


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
    assert "ACL2 has exited" in result[0].text

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
async def test_acl2_exit_reported(session_id: str) -> None:
    """When ACL2 exits, the reply says so, and so does every later call on
    the session: its world is gone, and a new session is needed.

    There used to be four messages for this ("Session terminated during
    command execution", "Session connection lost", ...), none saying what
    to do, and list_sessions listed the session like any other.
    """
    text = await evaluate(session_id, "(good-bye)")
    assert "ACL2 has exited" in text and "Start a new session" in text
    text = await evaluate(session_id, "(+ 1 1)")
    assert "ACL2 has exited" in text
    result = await call_tool("interrupt_session", {"session_id": session_id})
    assert "ACL2 has exited" in result[0].text
    result = await call_tool("list_sessions", {})
    line = next(line for line in result[0].text.splitlines() if session_id in line)
    assert "ACL2 has exited" in line


@pytest.mark.asyncio
async def test_start_session_in_missing_directory(tmp_path: Path) -> None:
    """A session asked to start in a directory that doesn't exist says so
    (the reply used to be "Failed to start session")."""
    result = await call_tool("start_session", {"cwd": str(tmp_path / "missing")})
    assert "no such directory" in result[0].text
    (tmp_path / "file").write_text("")
    result = await call_tool("start_session", {"cwd": str(tmp_path / "file")})
    assert "not a directory" in result[0].text
    result = await call_tool("list_sessions", {})
    assert "No active sessions" in result[0].text


async def evaluate(session_id: str, code: str, timeout: int = 30) -> str:
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": timeout})
    return result[0].text


@pytest.mark.asyncio
async def test_first_reply_has_no_startup_prompt(session_id: str) -> None:
    """start_session returns once ACL2 is ready, after any
    acl2-customization file, so the first reply is the command's own.

    It used to return at ACL2's first prompt, before the customization
    file was loaded; the first reply then started with the prompt after
    the file."""
    text = await evaluate(session_id, "(+ 1 2)")
    assert re.search(r"INPUT\]\s*3\s*\n", text), text


@pytest.mark.asyncio
async def test_reply_waits_for_every_form(session_id: str) -> None:
    """The reply to a command comes after its last form, even when a
    later form takes a while and prints nothing.

    The reply used to end at the first prompt that stayed quiet for 0.2
    seconds, so a later form that was slow and silent (a sleep, or a
    defthm proved without checkpoints) had its result in the next reply.
    """
    text = await evaluate(session_id, "(+ 1 2)\n(prog2$ (sleep 2) :second)")
    assert re.search(r"(^|>)3$", text, re.M) and ":SECOND" in text
    text = await evaluate(session_id, "(+ 1000 337)")
    assert "1337" in text and ":SECOND" not in text


@pytest.mark.asyncio
async def test_keyword_command_takes_rest_of_line(session_id: str) -> None:
    """A keyword command and its arguments on the same line are sent
    together, since ACL2 reads the arguments after the keyword."""
    text = await evaluate(session_id,
                          "(defun kw-test (x) x)\n:pe kw-test\n(+ 2 3)")
    # (A result that follows a prompt is on the prompt's line)
    assert "(DEFUN KW-TEST (X) X)" in text and re.search(r"(^|>)5$", text, re.M)


@pytest.mark.asyncio
async def test_command_after_a_timeout_waits_for_it(session_id: str) -> None:
    """After a command times out, the next one waits for it to finish, and
    its reply shows the earlier command's output first.

    The next command used to be sent at once, and its reply ended at the
    earlier command's prompt: each reply showed the previous command's
    result."""
    text = await evaluate(session_id, "(prog2$ (sleep 3) :first-done)", 1)
    assert "timed out" in text and "next evaluate waits" in text
    text = await evaluate(session_id, "(prog2$ (sleep 1) :second-done)")
    assert (text.index(":FIRST-DONE") < text.index("Output of this command")
            < text.index(":SECOND-DONE"))
    text = await evaluate(session_id, "(+ 2000 337)")
    assert "2337" in text and ":SECOND-DONE" not in text
    assert "earlier command" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix, symbol", [("", "nopkg::g"), ("#!nopkg ", "g")])
async def test_large_form_with_missing_package(
        session_id: str, prefix: str, symbol: str) -> None:
    """When ACL2 gives up reading a large form, as for a symbol in a
    package that doesn't exist, the part it hasn't read is discarded, not
    read as new commands, and later replies stay in step.

    ACL2 discards only what it has read.  The rest of an 80 KB defun used
    to come back as thousands of errors and prompts, which left later
    replies without their own results.
    """
    big = (f"{prefix}(defun h (x)\n  (list ({symbol} x)\n"
           + "".join(f"        (car (cons {i} x))\n" for i in range(3000))
           + "))")
    text = await evaluate(session_id, big)
    assert "NOPKG" in text and "stopped reading 1 form" in text
    assert len(text) < 10000
    for k in range(2):
        text = await evaluate(session_id, f"(value-triple :next-{k})")
        assert f":NEXT-{k}" in text and "Error" not in text


async def cancel_after(session_id: str, code: str, delay: float) -> None:
    """Start evaluating CODE, and cancel the call after DELAY seconds, as a
    client does when the user interrupts the agent."""
    call = asyncio.create_task(evaluate(session_id, code))
    await asyncio.sleep(delay)
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call


@pytest.mark.asyncio
async def test_cancelled_command_is_stopped(session_id: str) -> None:
    """Cancelling an evaluate call interrupts ACL2 and discards the part of
    the command not yet sent, and the next reply says so first.

    The rest of the command used to be dropped silently, while ACL2 went on
    with the form it had, whose output turned up unlabeled in the next
    reply.
    """
    await cancel_after(
        session_id, "(value-triple (sleep 4))\n(value-triple :second-form)", 1)
    start = time.monotonic()
    text = await evaluate(session_id, "(value-triple :next)")
    assert time.monotonic() - start < 3  # ACL2 was interrupted
    assert text.startswith("The earlier command's evaluate call was cancelled")
    earlier, this = text.split("Output of this command:")
    assert "ABORTING" in earlier and ":SECOND-FORM" not in text
    assert ":NEXT" in this
    text = await evaluate(session_id, "(value-triple :after)")
    assert ":AFTER" in text and "cancelled" not in text


@pytest.mark.asyncio
async def test_cancel_while_a_form_is_written(session_id: str) -> None:
    """A call cancelled while a large form is still being written (ACL2 is
    busy with the form before it) leaves no part of it for ACL2 to read
    as the start of the next command."""
    big = '(value-triple (length "' + "x" * 200000 + '"))'
    await cancel_after(session_id, "(value-triple (sleep 3))\n" + big, 1)
    text = await evaluate(session_id, "(value-triple :next)")
    assert ":NEXT" in text.split("Output of this command:")[1]
    assert "200000" not in text
    text = await evaluate(session_id, "(+ 1000 337)")
    assert "1337" in text and "cancelled" not in text


@pytest.mark.asyncio
async def test_unreadable_code_is_not_sent(session_id: str) -> None:
    """Code that ACL2 can't read is rejected, and none of it is sent:
    a form missing its ) would leave ACL2 waiting for the rest, which
    then swallowed the next command."""
    text = await evaluate(
        session_id, "(defun not-sent (x) x)\n(defthm not-sent-thm (equal (not-sent x) x)")
    assert "Nothing was sent" in text and "line 2" in text
    text = await evaluate(session_id, "(not-sent 3)")
    assert "ACL2 Error" in text  # the defun wasn't sent either
    text = await evaluate(session_id, "; only a comment")
    assert "Nothing to evaluate" in text


@pytest.mark.asyncio
@pytest.mark.parametrize("char", ["\x03", "\x1c", "\x1a"])
async def test_signal_characters_are_not_sent(session_id: str, char: str) -> None:
    """Code with a character that the terminal turns into a signal is
    rejected, as is or not: C-c would interrupt ACL2, C-\\ would send it
    SIGQUIT, which can end the session, and C-z would suspend it."""
    code = f'(defun not-sent () "a{char}b")'
    for text in (await evaluate(session_id, code),
                 await evaluate_as_is(session_id, code)):
        assert "Nothing was sent" in text and f"(code {ord(char)})" in text
    text = await evaluate(session_id, "(not-sent)")
    assert "ACL2 Error" in text
    text = await evaluate(session_id, "(+ 1000 337)")
    assert "1337" in text


@pytest.mark.asyncio
async def test_raw_lisp_code_is_sent_whole(session_id: str) -> None:
    """At a raw Lisp prompt the host Lisp reads the code, with its own
    syntax, so the code is sent as it is: a float, which ACL2 rejects,
    is fine there."""
    await evaluate(session_id, ":q")
    text = await evaluate(session_id, "(+ 1 2)\n(* 2 1.5)")
    assert "3.0" in text
    text = await evaluate(session_id, "(lp)")
    text = await evaluate(session_id, "(+ 1000 337)")
    assert "1337" in text


@pytest.mark.asyncio
async def test_proof_builder_prompt(session_id: str) -> None:
    """The proof builder's prompt ("->: ") ends a reply, and so does the
    query it asks when exiting with an event name ("... (Y, R, N or A):  ")."""
    start = time.monotonic()
    text = await evaluate(session_id, "(verify (equal (car (cons a b)) a))")
    assert text.rstrip().endswith("->:") and time.monotonic() - start < 10
    text = await evaluate(session_id, "prove")
    assert text.rstrip().endswith("->:")
    start = time.monotonic()
    text = await evaluate(session_id, "(exit pb-car-cons)")
    assert text.rstrip().endswith("(Y, R, N or A):") and time.monotonic() - start < 10
    text = await evaluate(session_id, "y")
    assert text.rstrip().endswith("ACL2 !>")
    text = await evaluate(session_id, ":pe pb-car-cons")
    assert "PB-CAR-CONS" in text


@pytest.mark.parametrize("prompt, mode", [
    ("ACL2 !>", "acl2"), ("ACL2 p!>", "acl2"), ("ACL2 >", "acl2"),
    ("ACL2 !>>", "acl2"), ("1 ACL2 >", "acl2"), ("Wormhole ACL2 !>", "acl2"),
    ("ACL2 P>", "raw-acl2"), ("->: ", "acl2"), (":", "acl2"),
    ("ACL2(r) !>", "acl2"), ("X86ISA p!>", "acl2"),
    # Other programs' prompts: lower case, which ACL2 packages don't have
    ("calc >", "lisp"), ("foo !>", "lisp"), ("remora> ", "lisp"),
    ("ACL2 Query (:EXIT):  Exit?  (Y, N or Q):  ", "acl2"),
    ("* ", "lisp"), ("? ", "lisp"), ("0] ", "lisp"), ("0[2] ", "lisp"),
    ("1 > ", "lisp"), ("2 > ", "lisp"), ("> ", "lisp"), ("Inspect> ", "lisp"),
    ("Inspect 1> ", "lisp"),
])
def test_prompts(prompt: str, mode: str) -> None:
    """Each prompt is recognized, and read with ACL2's reader or the host
    Lisp's."""
    assert matches_prompt_pattern(prompt)
    assert prompt_mode(prompt) == mode


@pytest.mark.asyncio
async def test_debugger_and_inspector_prompts(session_id: str) -> None:
    """Raw Lisp, the debugger, a nested debugger, and the inspector each end
    a reply with their own prompt, which differ between host Lisps (CCL's
    inspector prompt shows how deep in the object it is)."""
    session = session_manager.get_session(session_id)
    assert session is not None
    if session.syntax.name == "ccl":
        steps = [(":q", "?"), ("(car 3)", "1 >"), ("(car 4)", "2 >"),
                 (":pop", "1 >"), (":pop", "?"),
                 ("(inspect *package*)", "Inspect>"), ("1", "Inspect 1>"),
                 ("1", "Inspect 2>"), (":q", "?")]
    else:
        steps = [(":q", "*"), ("(car 3)", "0]"), ("(car 4)", "0[2]"),
                 ("0", "0]"), ("0", "*"),
                 ("(inspect *package*)", ">"), ("1", ">"), ("1", ">"),
                 ("q", "*")]
    for code, prompt in steps + [("(lp)", "ACL2 !>")]:
        start = time.monotonic()
        text = await evaluate(session_id, code, 10)
        assert time.monotonic() - start < 5, code
        assert text.strip().splitlines()[-1].strip() == prompt, (code, text)
    assert "1337" in await evaluate(session_id, "(+ 1000 337)")


async def last_line_after(session_id: str, code: str) -> str:
    """Evaluate CODE, which must reply within 5 seconds; return the reply's
    last line."""
    start = time.monotonic()
    text = await evaluate(session_id, code, 10)
    assert time.monotonic() - start < 5, (code, text)
    return text.strip().splitlines()[-1].strip()


@pytest.mark.asyncio
async def test_walkabout_prompt(session_id: str) -> None:
    """walkabout's prompt (":" on a line) ends a reply."""
    assert await last_line_after(session_id, "(walkabout '(a (b c) d) state)") == ":"
    assert await last_line_after(session_id, "1") == ":"
    assert await last_line_after(session_id, "up") == ":"
    assert await last_line_after(session_id, "q") == "ACL2 !>"


@pytest.mark.asyncio
async def test_wormhole_prompt(session_id: str) -> None:
    """An interactive wormhole's prompt ("Wormhole ACL2 !>") ends a reply."""
    code = "(wormhole 'demo '(lambda (whs) whs) nil '(quote (welcome!)))"
    assert await last_line_after(session_id, code) == "Wormhole ACL2 !>"
    assert await last_line_after(session_id, "(+ 1 2)") == "Wormhole ACL2 !>"
    assert await last_line_after(session_id, ":q") == "ACL2 !>"


@pytest.mark.asyncio
async def test_redefinition_query(session_id: str) -> None:
    """The query that redefinition asks after (redef) ends a reply."""
    await evaluate(session_id, "(defun redef-me (x) x)")
    await evaluate(session_id, "(redef)")
    line = await last_line_after(session_id, "(defun redef-me (x) (+ x 1))")
    assert line.endswith("?):"), line
    assert await last_line_after(session_id, "y") == "ACL2 !>"
    await evaluate(session_id, "(redef-)")
    assert re.search(r"(^|>)2$", await evaluate(session_id, "(redef-me 1)"), re.M)


@pytest.mark.asyncio
async def test_unknown_prompt(session_id: str) -> None:
    """When a command times out and ACL2's output ends with an unfinished
    line that has been quiet, that is taken for the prompt of a read loop
    acl2-mcp doesn't know, and later commands are sent there.

    Otherwise the next command would wait for the timed-out one, which
    can't finish without input, and the session would be stuck."""
    await evaluate(session_id, ":q")
    text = await evaluate(
        session_id, '(progn (princ "Your choice? ") (finish-output) (read))', 2)
    assert "waiting for input at 'Your choice?'" in text, text
    text = await evaluate(session_id, "42")
    assert text.index("Your choice?") < text.index("Output of this command")
    assert re.search(r"(^|[>*?] )42$", text, re.M), text
    await evaluate(session_id, "(lp)")
    assert "1337" in await evaluate(session_id, "(+ 1000 337)")


async def evaluate_as_is(session_id: str, code: str) -> str:
    result = await call_tool("evaluate", {
        "session_id": session_id, "code": code, "timeout": 10, "as_is": True})
    return result[0].text


@pytest.mark.asyncio
async def test_program_with_its_own_input(session_id: str) -> None:
    """Input for a program with its own read loop, which needn't be Lisp,
    gets through: with as_is when the program's prompt looks like ACL2's
    (so that the code would be read as ACL2 code), and as it is when the
    prompt is another program's."""
    def loop(prompt: str) -> str:
        return (f'(loop (princ "{prompt}") (finish-output) '
                '(let ((line (read-line))) (when (equal line "quit") (return)) '
                '(format t "got [~a]~%" line)))')
    await evaluate(session_id, ":q")
    assert (await evaluate(session_id, loop("CALC >"))).rstrip().endswith("CALC >")
    text = await evaluate(session_id, "x = (3")
    assert "Nothing was sent" in text and "as_is" in text
    text = await evaluate_as_is(session_id, "x = (3")
    assert "got [x = (3]" in text and text.rstrip().endswith("CALC >")
    await evaluate(session_id, "quit")
    assert (await evaluate(session_id, loop("calc > "))).rstrip().endswith("calc >")
    assert "got [3 + 4]" in await evaluate(session_id, "3 + 4")
    await evaluate(session_id, "quit")
    await evaluate(session_id, "(lp)")
    assert "1337" in await evaluate(session_id, "(+ 1000 337)")
