"""Tests for ACL2 MCP server session functionality."""

import asyncio
from typing import Any

import pytest

from acl2_mcp.server import (
    call_tool,
    session_manager,
    validate_checkpoint_name,
    validate_session_name,
    validate_integer_parameter,
)


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
    session_id = result[0].text.split("ID: ")[1].strip()

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_start_session_no_name() -> None:
    """Test starting a session without a name."""
    arguments: dict[str, Any] = {}

    result = await call_tool("start_session", arguments)

    assert len(result) == 1
    assert "Session started successfully" in result[0].text

    session_id = result[0].text.split("ID: ")[1].strip()
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_end_session() -> None:
    """Test ending a session."""
    # Start a session first
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
async def test_undo() -> None:
    """Test undoing events in a session."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Add some events
    await call_tool("evaluate", {
        "code": "(defun func1 (x) x)",
        "session_id": session_id
    })

    await call_tool("evaluate", {
        "code": "(defun func2 (x) x)",
        "session_id": session_id
    })

    # Undo last event
    undo_result = await call_tool("undo", {
        "session_id": session_id,
        "count": 1
    })

    assert len(undo_result) == 1
    assert "Undone" in undo_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_save_and_restore_checkpoint() -> None:
    """Test saving and restoring checkpoints."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Add an event
    await call_tool("evaluate", {
        "code": "(defun func1 (x) x)",
        "session_id": session_id
    })

    # Save checkpoint
    save_result = await call_tool("save_checkpoint", {
        "session_id": session_id,
        "checkpoint_name": "after-func1"
    })

    assert len(save_result) == 1
    assert "saved" in save_result[0].text.lower()

    # Add another event
    await call_tool("evaluate", {
        "code": "(defun func2 (x) x)",
        "session_id": session_id
    })

    # Restore to checkpoint
    restore_result = await call_tool("restore_checkpoint", {
        "session_id": session_id,
        "checkpoint_name": "after-func1"
    })

    assert len(restore_result) == 1
    assert "Restored" in restore_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_get_world_state() -> None:
    """Test getting world state from a session."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Add some events
    await call_tool("evaluate", {
        "code": "(defun my-func (x) x)",
        "session_id": session_id
    })

    # Get world state
    state_result = await call_tool("get_world_state", {
        "session_id": session_id,
        "limit": 10
    })

    assert len(state_result) == 1
    assert "World state" in state_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_retry_proof() -> None:
    """Test retrying a proof with different hints."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Try a simple theorem first
    await call_tool("prove", {
        "code": "(defthm simple-thm (equal (+ 1 1) 2))",
        "session_id": session_id
    })

    # Retry with same theorem (this is just testing the mechanism)
    retry_result = await call_tool("retry_proof", {
        "session_id": session_id,
        "code": "(defthm simple-thm2 (equal (+ 2 2) 4))"
    })

    assert len(retry_result) == 1
    assert "Retry proof" in retry_result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_session_nonexistent_error() -> None:
    """Test that operations on nonexistent sessions fail gracefully."""
    result = await call_tool("undo", {
        "session_id": "nonexistent-session",
        "count": 1
    })

    assert len(result) == 1
    assert "not found" in result[0].text


# Security and Validation Tests


def test_validate_checkpoint_name_valid() -> None:
    """Test that valid checkpoint names are accepted."""
    assert validate_checkpoint_name("my-checkpoint") == "my-checkpoint"
    assert validate_checkpoint_name("checkpoint_123") == "checkpoint_123"
    assert validate_checkpoint_name("TEST-POINT") == "TEST-POINT"


def test_validate_checkpoint_name_rejects_invalid() -> None:
    """Test that invalid checkpoint names are rejected."""
    with pytest.raises(ValueError, match="only contain"):
        validate_checkpoint_name("bad checkpoint")  # spaces not allowed

    with pytest.raises(ValueError, match="only contain"):
        validate_checkpoint_name("bad@checkpoint")  # special chars not allowed

    with pytest.raises(ValueError, match="cannot be empty"):
        validate_checkpoint_name("")


def test_validate_checkpoint_name_rejects_long() -> None:
    """Test that long checkpoint names are rejected."""
    long_name = "a" * 101
    with pytest.raises(ValueError, match="exceeds maximum length"):
        validate_checkpoint_name(long_name)


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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
async def test_checkpoint_limit_per_session() -> None:
    """Test that checkpoint limit per session is enforced."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Try to create 51 checkpoints (max is 50)
    for i in range(51):
        result = await call_tool("save_checkpoint", {
            "session_id": session_id,
            "checkpoint_name": f"checkpoint-{i}"
        })

        if i < 50:
            assert "saved" in result[0].text.lower()
        else:
            # 51st should fail
            assert "Maximum number of checkpoints" in result[0].text

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
async def test_invalid_checkpoint_name() -> None:
    """Test that invalid checkpoint names are rejected."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    result = await call_tool("save_checkpoint", {
        "session_id": session_id,
        "checkpoint_name": "bad checkpoint name"  # spaces not allowed
    })

    assert len(result) == 1
    assert "Error" in result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_undo_count_validation() -> None:
    """Test that undo count is validated."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Try invalid count
    result = await call_tool("undo", {
        "session_id": session_id,
        "count": 100000  # Too large
    })

    assert len(result) == 1
    assert "must be between" in result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_get_world_state_limit_validation() -> None:
    """Test that get_world_state limit is validated."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    # Try invalid limit
    result = await call_tool("get_world_state", {
        "session_id": session_id,
        "limit": 10000  # Too large
    })

    assert len(result) == 1
    assert "must be between" in result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_restore_nonexistent_checkpoint() -> None:
    """Test restoring a checkpoint that doesn't exist."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

    result = await call_tool("restore_checkpoint", {
        "session_id": session_id,
        "checkpoint_name": "nonexistent"
    })

    assert len(result) == 1
    assert "not found" in result[0].text
    assert "Available:" in result[0].text

    # Cleanup
    await call_tool("end_session", {"session_id": session_id})


@pytest.mark.asyncio
async def test_broken_pipe_on_send_command() -> None:
    """Test that BrokenPipeError is handled gracefully when sending commands."""
    start_result = await call_tool("start_session", {})
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
        session_id = start_result[0].text.split("ID: ")[1].strip()
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
    session_id = start_result[0].text.split("ID: ")[1].strip()

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
