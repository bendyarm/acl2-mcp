# Changes — 2026-04-05

## Summary

- Large output from ACL2 is elided before being passed back to the model.
  This reduces the tokens needed to process the output, speeds up model
  response time, and avoids confusing warnings.

- Various bugs with prompt detection have been fixed.  The most obvious
  change is you will no longer see an ACL2 command finish quickly without
  the model knowing it is done.

- A TOML configuration system has been added.

- A configuration parameter lets you turn off automatic ACL2 session viewers,
  and if you do that but want to see a session later, there is a new acl2-mcp
  tool `show_session_log` to see it.

- ACL2 session viewer window automatically closes when the ACL2 session exits.

## Configuration System

Added an optional TOML configuration file at `~/.config/acl2-mcp/config.toml`.
The file is loaded once at server startup.  Missing files are silently
ignored.  Malformed files or invalid settings produce warnings and fall
back to built-in defaults.

Configurable settings:

- **`session_log.view_log_in_terminal`** (bool, default `true`):
  Whether to open a Terminal window tailing the session log when a
  session starts.

- **`session_log.close_log_on_end`** (bool, default `true`):
  Whether to close the session log Terminal window when the session ends.

- **`tool_output.max_output_chars`** (int, default `5000`),
  **`tool_output.head_chars`** (int, default `400`),
  **`tool_output.tail_chars`** (int, default `4000`):
  Controls output elision.  When a tool result exceeds `max_output_chars`,
  only the first `head_chars` and last `tail_chars` are returned, with
  an elision warning pointing to the session log.

- **`debug_logging`** (bool, default `false`):
  Enables diagnostic logging to `~/.acl2-mcp/debug.log`.  The log is
  cleared each time the server starts.

Explicit `start_session` tool arguments override config file defaults.

## Tool API Changes

- Renamed `enable_log_viewer` to `view_log_in_terminal` in the
  `start_session` tool schema.  (When true, the Terminal window is
  always brought to the foreground and Terminal.app steals the focus,
  but this is not a change in behavior.)

- Added **`show_session_log`** tool: opens (or activates) a Terminal
  window showing the session log on demand.  This is a way to see
  a session later even if you initially had `view_log_in_terminal = false`.
  Each session's Terminal window has a unique title based on the session
  ID, so multiple sessions can coexist.

## Prompt Detection Improvements

### Settle delay

Added a 0.2-second settle delay before confirming a prompt candidate.
If more PTY data arrives within that window, the candidate is cancelled
(it was mid-output, not a prompt).  This prevents false positives on
output lines that happen to match a prompt pattern — for example, lines
ending in `>` (package names, xdoc output).

### Prompt depth tracking

The server now parses the LD nesting depth from prompt text (counting
trailing `>` characters).  During `(ld "file.lisp")`, intermediate
prompts at deeper depth are flushed to the log but not confirmed as
command completion.  Only a prompt at the starting depth or shallower
triggers command completion.

This prevents `(ld "file.lisp")` from returning early when a slow form
(e.g., `include-book`) creates a gap longer than the settle delay.

Interactive LD (`(ld *standard-oi*)`) is also handled: the initial
`(ld ...)` times out (the depth-2 prompt is not confirmed), but
subsequent commands at depth 2 work correctly because the server adopts
the unconfirmed prompt's depth on timeout.

### Sequenced prompt confirmations

Replaced the single `asyncio.Event` with a monotonic `prompt_seq`
counter and `asyncio.Condition`.  `send_command` captures the counter
before sending and waits for it to increase.  This eliminates a race
where stale prompt confirmations from earlier commands (e.g., LD
intermediate prompts) caused subsequent commands to return empty or
with wrong output.

### Monotonic line IDs in output buffer

Changed the in-memory output buffer from `list[str]` to
`list[tuple[int, str]]`, where each line is tagged with a monotonic
sequence ID.  `send_command` collects lines by sequence ID rather than
positional index.  This is robust against buffer trimming (the 50,000-
line limit) — previously, trimming could shift indices and cause
commands after large output to return empty.

### Chunk processing lock

Added a lock (`_chunk_lock`) to serialize `_process_pty_chunk` and
`_flush_prompt`.  Multiple chunk-processing coroutines can be scheduled
concurrently during bursts of output; without serialization, interleaving
at `await` points could corrupt the partial line buffer and permanently
break prompt detection for the session.

## Session Log Improvements

- **SESSION ENDED marker**: The session log now includes a timestamped
  `[SESSION ENDED]` marker when a session ends, matching the existing
  `[SESSION STARTED]` marker.

- **Clean Terminal close on session end**: When `close_log_on_end` is
  `true` (the default), ending a session kills the `tail` process and
  closes the Terminal window cleanly, without a "terminate running
  processes?" dialog.

- **Unique window titles**: Each session's log viewer Terminal window
  gets a unique title (`ACL2 Log <short-id>`), allowing `show_session_log`
  to find the correct window among multiple sessions.

## Output Elision

Large tool output is now elided before returning to the caller.  When
output exceeds `max_output_chars`, the response includes the first
`head_chars`, an elision warning with the session log path, and the
last `tail_chars`.  This prevents Claude Code from hitting its tool
result size limit on large LD transcripts.

## Test Fixes

- Fixed session ID parsing in `test_sessions.py` to handle the
  multi-line `start_session` response (which now includes the log file
  path).

## Documentation

- Added configuration section to README.
