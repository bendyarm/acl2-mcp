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
     - If you are in an environment where MCP servers cannot be registered with your tool harness (e.g. a Claude Cowork / cloud sandbox session), you can instead drive the server directly over stdio with `for-agents/mcp_stdio_client.py` in this repository; the same tools are then available via its `call` method, and the rest of this skill's guidance applies with that substitution.
     - Otherwise report: "Sorry, the MCP ACL2 server is not available. The MCP server must be configured in the directory from which Claude Code was started. Please run `/mcp` to check your MCP configuration or visit https://docs.claude.com/en/docs/claude-code/mcp to learn more."
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
     - Show session names, IDs, and their ages and idle times to help the user decide
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
     - `mcp__acl2__evaluate` (definitions, theorems, `include-book`, queries such as `:pe`, history commands such as `:pbt`)
     - `mcp__acl2__interrupt_session`, `mcp__acl2__show_session_log`, and `mcp__acl2__end_session`

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

## Scratch Sessions

For a throwaway experiment in a clean ACL2 world (for example, trying a
macro or checking what a book defines without touching your working
session), start a separate scratch session:

1. `mcp__acl2__start_session` with `name: "scratch"`, and the same `cwd` as
   your working session if relative paths matter
2. Run the experiment with `mcp__acl2__evaluate`, passing the scratch
   session's ID
3. `mcp__acl2__end_session` on the scratch session as soon as you are done

Keep using the working session's ID for everything else; the two worlds are
independent.  To try something on top of your current world instead, set a
`deflabel` checkpoint in the working session and return to it with `:ubu`
(see the acl2-session-history-management skill).

## Session Lifecycle - Don't End Sessions Unnecessarily

**Important**: When something goes wrong (timeout, error, proof failure), the session is usually fine and can continue to be used. Do NOT end the session just because of an error.

**When to use keyboard interrupt** (not end session):
- ACL2 appears stuck with no prompt appearing
- A proof is churning with way too many subgoals
- Use `mcp__acl2__interrupt_session` to send Ctrl-C

**After sending an interrupt**, read its reply, which shows ACL2's response:
- "ACL2 is back at its prompt": the session is fine; continue working.
- "has not returned to its prompt": in a proof, the first interrupt only asks ACL2 to stop at its next check, so call `mcp__acl2__interrupt_session` again. Otherwise, check the session log to see what ACL2 is doing.
- **NEVER** use `:good-bye`, `:q`, or `(quit)` to "check" status - these will exit ACL2!
- If ACL2 still doesn't get back to its prompt, you may need to end the session and start fresh

**When ending a session is appropriate** (rare):
- You're completely done with ACL2 work
- You need to start fresh with a clean ACL2 state
- The session process has actually crashed (not just timed out)
- You're done with a scratch session (see Scratch Sessions above)

**On timeout**: Check the session log (`tail -20 <log-file>`) to see if ACL2 actually responded. A timeout often means the MCP server missed the prompt, not that ACL2 is stuck. You can usually just continue with the next command.

## Monitoring Long-Running Operations

**Use `tail` on the session log** instead of repeatedly calling `mcp__acl2__evaluate` with `t` or `:pbt` to monitor progress. The session log shows actual ACL2 output in real-time.

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
