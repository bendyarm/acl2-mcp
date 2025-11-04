#!/usr/bin/env python3
"""Quick test script for PTY-based ACL2 session."""

import asyncio
import sys
from pathlib import Path

# Add the module to path
sys.path.insert(0, str(Path(__file__).parent))

from acl2_mcp.server import SessionManager


async def main():
    """Test basic PTY session functionality."""
    print("=" * 60)
    print("Testing PTY-based ACL2 Session")
    print("=" * 60)

    manager = SessionManager()

    # Test 1: Start session
    print("\n[TEST 1] Starting ACL2 session...")
    session_id, message = await manager.start_session(
        name="test-session",
        enable_logging=True,
        enable_log_viewer=False
    )

    if not session_id:
        print(f"❌ FAILED to start session: {message}")
        return

    print(f"✓ Session started: {session_id}")
    print(f"  Message: {message}")

    session = manager.sessions.get(session_id)
    if not session:
        print("❌ Session not found in manager!")
        return

    # Give it a moment to start up
    await asyncio.sleep(2)

    # Test 2: Basic arithmetic
    print("\n[TEST 2] Testing basic command: (+ 1 2)")
    result = await session.send_command("(+ 1 2)", timeout=10)
    print(f"Result: {result}")

    # Check for proper ACL2 prompt at end (pattern: r'.*>[ ]*$', e.g., "ACL2 !>")
    has_result = "3" in result
    has_prompt = result.rstrip().endswith(">") or result.endswith("> ")

    if has_result and has_prompt:
        print("✓ Basic arithmetic works and ends with ACL2 prompt!")
    elif has_result:
        print("⚠ Got result '3' but no '>' prompt at end")
        print(f"  Last 20 chars: ...{repr(result[-20:])}")
    else:
        print(f"❌ Unexpected result: {result}")

    # Test 3: Check log file
    if session.log_file:
        print(f"\n[TEST 3] Checking log file: {session.log_file}")
        try:
            with open(session.log_file, 'r') as f:
                log_content = f.read()
                if "ACL2 !>" in log_content:
                    print("✓ Log file contains ACL2 prompt!")
                else:
                    print("❌ Log file missing ACL2 prompt")
                print(f"  Log size: {len(log_content)} bytes")
        except Exception as e:
            print(f"❌ Error reading log: {e}")

    # Test 4: Division by zero (THE CRITICAL TEST!)
    print("\n[TEST 4] THE CRITICAL TEST: Division by zero")
    print("  This tests if SBCL debugger output appears via PTY...")
    print("  Entering raw Lisp mode...")

    result = await session.send_command(":q", timeout=10)
    print(f"  :q result: {result[:100]}...")

    # Check for SBCL raw Lisp prompt at END of output (pattern: r'.*\* $')
    # Note: send_command() strips trailing whitespace, so we check for '*' at end
    # The actual prompt in the log file will have the space: '* '
    if result.endswith("*") or result.endswith("* "):
        print("✓ Entered raw Lisp mode (found '*' prompt at end)")
    elif "Exiting" in result:
        print("⚠ Saw 'Exiting' message but no '*' prompt at end")
        print(f"  Last 50 chars: ...{repr(result[-50:])}")
    else:
        print(f"❌ Did not find '*' prompt at end")
        print(f"  Last 50 chars: ...{repr(result[-50:])}")

    print("\n  Executing (/ 3 0)...")
    result = await session.send_command("(/ 3 0)", timeout=10)
    print(f"\n  Division by zero result ({len(result)} chars):")
    print("  " + "-" * 50)
    print(result)
    print("  " + "-" * 50)

    # Check if we got the debugger output AND proper prompt at end
    # SBCL debugger prompt pattern: r'.*\] $' (e.g., "0] ")
    # Note: send_command() strips trailing whitespace, so we check for ']' at end
    # The actual prompt in the log file will have the space: '0] '
    has_error = "DIVISION-BY-ZERO" in result
    has_debugger_msg = "debugger invoked" in result
    has_proper_prompt = result.endswith("]") or result.endswith("] ")

    # Extract what the actual ending is
    last_10_chars = repr(result[-10:]) if len(result) >= 10 else repr(result)

    print(f"\n  Checking output:")
    print(f"    ✓ Has DIVISION-BY-ZERO: {has_error}")
    print(f"    ✓ Has 'debugger invoked': {has_debugger_msg}")
    print(f"    ✓ Ends with ']' prompt: {has_proper_prompt}")
    print(f"    Last 10 chars: {last_10_chars}")

    if has_error and has_debugger_msg and has_proper_prompt:
        print(f"\n✓✓✓ SUCCESS! All checks passed!")
        print("✓✓✓ PTY implementation is working correctly!")
        print("    Note: send_command() strips trailing spaces from prompts")
        print("    But the log file contains the full prompts with spaces")
    else:
        print(f"\n❌ FAILED: Missing required elements")
        if not has_proper_prompt:
            print("❌ Most critical: debugger prompt ']' not at end of output")

    # Check the log file too
    if session.log_file:
        print("\n  Checking log file for complete debugger output...")
        try:
            with open(session.log_file, 'r') as f:
                log_content = f.read()
                # Check for proper prompt with space
                if "0] " in log_content:
                    print("✓ Log file contains debugger prompt '0] ' (with space)!")
                    print("✓ This confirms PTY solved the buffering problem!")
                elif "0]" in log_content:
                    print("⚠ Log file contains '0]' but without trailing space")
                else:
                    print("❌ Log file missing '0]' prompt")
        except Exception as e:
            print(f"  Error reading log: {e}")

    # Test 5: Interrupt to escape debugger
    print("\n[TEST 5] Testing interrupt to escape debugger...")
    interrupt_result = await session.interrupt()
    print(f"  Interrupt result: {interrupt_result}")

    await asyncio.sleep(1)

    # Try to return to ACL2
    print("\n  Returning to ACL2 with (lp)...")
    result = await session.send_command("(lp)", timeout=10)

    # Check for ACL2 prompt at end (pattern: r'.*>[ ]*$')
    if result.rstrip().endswith(">") or result.endswith("> "):
        print("✓ Successfully returned to ACL2 mode (prompt ends with '>')")
    elif "ACL2 !>" in result:
        print("⚠ Found 'ACL2 !>' in output but not at end")
        print(f"  Last 20 chars: ...{repr(result[-20:])}")
    else:
        print("❌ Did not return to ACL2 mode")
        print(f"  Last 50 chars: ...{repr(result[-50:])}")

    # Cleanup
    print("\n[CLEANUP] Ending session...")
    await manager.end_session(session_id)
    print("✓ Session ended")

    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
