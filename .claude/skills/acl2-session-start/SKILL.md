---
name: acl2-session-start
description: Start a persistent ACL2 session using the MCP ACL2 server for interactive theorem proving and evaluation
allowed-tools: mcp__acl2__start_session, mcp__acl2__list_sessions, AskUserQuestion, Bash
---

<!-- Keep in sync with the acl2-session-start section of AGENTS.md (after modifying Claude Code-specific sections) --> 

# ACL2 Session Start

This skill starts a persistent ACL2 session using the Model Context Protocol (MCP) ACL2 server.

## Instructions

1. **Check MCP ACL2 server availability**:
   - Attempt to use `mcp__acl2__list_sessions` to verify the MCP ACL2 server is available
   - **If the tool is not available or returns an error**:
     - Report: "Sorry, the MCP ACL2 server is not available. The MCP server must be configured in the directory from which Claude Code was started. Please run `/mcp` to check your MCP configuration or visit https://docs.claude.com/en/docs/claude-code/mcp to learn more."
     - **STOP** - do not continue with the remaining steps in this skill or any subsequent steps in any calling skill
   - **If successful**, proceed to step 2

2. **Determine working directory for ACL2**:
   - The `mcp__acl2__start_session` tool now accepts an optional `cwd` parameter
   - **If the user has specified a working directory** (e.g., for x86 lifting work in a specific examples directory):
     - Use that directory as the `cwd` parameter when starting the session
   - **Otherwise**:
     - Use `pwd` to check the current directory
     - This will be the ACL2 session's working directory (no need to pass `cwd`)

3. **Check for existing sessions**:
   - Use `mcp__acl2__list_sessions` to see if there are already active sessions
   - **If one existing session**:
     - Use AskUserQuestion to ask if they want to use the existing session
     - If yes, use that session_id (skip to step 6)
     - If no, proceed to start a new session (step 4)
   - **If multiple existing sessions**:
     - Use AskUserQuestion to ask which session to use, or if they want to start a new one
     - Show session names, IDs, and their ages/event counts to help the user decide
     - If they choose an existing session, use that session_id (skip to step 6)
     - If they choose to start new, proceed to step 4
   - **If no existing sessions**:
     - Proceed to start a new session (step 4)

4. **Start new session**:
   - Use `mcp__acl2__start_session` with `enable_logging: true` to create a new persistent ACL2 session
   - Provide a descriptive name parameter (optional but recommended)
     - For general work, use: "acl2-session" or similar

5. **Save session ID**:
   - The tool will return a `session_id`
   - Remember this ID for use in subsequent ACL2 operations
   - This ID is needed for:
     - `mcp__acl2__evaluate` (defining functions, evaluating expressions)
     - `mcp__acl2__prove` (proving theorems)
     - `mcp__acl2__include_book` (loading books)
     - Other MCP ACL2 tools

6. **Report success**:
   - Confirm which session is being used (existing or newly created)
   - Display the session ID
   - Display the log file path (if logging is enabled)
   - **Always** output this information to the user before proceeding with any other commands

## Example

```
ACL2 session started. Session ID: abc123
Log file: /Users/user/.acl2-mcp/sessions/abc123-20260405-110632.log
```

## Notes

- Sessions maintain state across multiple tool calls
- You can have multiple sessions active simultaneously
- The session ID is required for all subsequent ACL2 operations in that session

## Session Lifecycle - Don't End Sessions Unnecessarily

**Important**: When something goes wrong (timeout, error, proof failure), the session is usually fine and can continue to be used. Do NOT end the session just because of an error.

**When to use keyboard interrupt** (not end session):
- ACL2 appears stuck with no prompt appearing
- A proof is churning with way too many subgoals
- Use `mcp__acl2__interrupt_session` to send Ctrl-C

**After sending an interrupt**, check if the session is responsive:
- Send an innocuous command like `t` or `(+ 1 1)` to verify ACL2 is responding, or if there is a session log, you can tail it to see the current status.
- **NEVER** use `:good-bye`, `:q`, or `(quit)` to "check" status - these will exit ACL2!
- If the session responds, you can continue working
- If it doesn't respond, you may need to end the session and start fresh

**When ending a session is appropriate** (rare):
- You're completely done with ACL2 work
- You need to start fresh with a clean ACL2 state
- The session process has actually crashed (not just timed out)

**On timeout**: Check the session log (`tail -20 <log-file>`) to see if ACL2 actually responded. A timeout often means the MCP server missed the prompt, not that ACL2 is stuck. You can usually just continue with the next command.

## Monitoring Long-Running Operations

**Use `tail` on the session log** instead of repeatedly calling `mcp__acl2__evaluate` with `t` or using `mcp__acl2__get_world_state` to monitor progress. The session log shows actual ACL2 output in real-time.

```bash
# See recent output (last 100 lines)
tail -100 /path/to/session-log.log

# Follow output in real-time (for very long operations)
tail -f /path/to/session-log.log
```

The log file path is returned when starting the session. This approach is:
- More efficient (no round-trips to ACL2)
- Shows actual errors and warnings
- Displays proof progress and subgoal information
- Works even if the MCP tool times out
