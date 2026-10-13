# Changes — 2026-10-13

## Summary

- Nine tools instead of 21.  Tools that were broken or misleading
  (`check_theorem`, `retry_proof`, the checkpoint tools, `admit`,
  `check_syntax`, `verify_guards`) and thin wrappers around `evaluate`
  are gone, and so is one-off execution: all ACL2 code runs through
  `evaluate` in a session, so every tool that runs ACL2 code takes a
  `session_id`.  For undoing and checkpoints, the
  `acl2-session-history-management` skill shows how to use `deflabel`
  and `:ubu` through `evaluate`.

- New `xdoc_search` and `xdoc_show` tools look up the ACL2 manual in a
  local xdoc corpus, offline and in milliseconds, with no ACL2 session.

- `evaluate` works reliably for any command:
  - A command is sent one top-level form at a time, so its reply ends
    at its own prompt, not at an earlier form's.
  - Code that ACL2 can't read (such as a form missing its `)`) is
    rejected before anything is sent.  A new ACL2 reader in Python
    (`acl2_mcp/reader.py`) does this; it has been checked against ACL2's
    own reader on SBCL and CCL, and on 389,000 forms from the books.
  - Lines of any length work, and line-editing characters (DEL, C-u,
    C-w, C-d, ...) reach ACL2 unchanged.  Code with a C-c, C-\ or C-z,
    which the terminal would turn into a signal, is refused.
  - A new `as_is` parameter sends the code exactly as given, for a
    program with its own read loop.
  - A timeout no longer loses anything: ACL2 keeps working, and the
    next `evaluate` waits for it and shows its output first.  The
    default timeout is 300 seconds (the maximum), and agents are advised
    to use a short one, such as 30.
  - A cancelled call (the user interrupted the agent) interrupts ACL2.
  - A large form with a symbol in a package that doesn't exist no
    longer comes back as thousands of errors.
  - Replies end correctly at the prompts of the proof builder, ACL2's
    queries, walkabout, raw Lisp, and SBCL's and CCL's debuggers and
    inspectors; on a timeout, an unknown prompt is taken as the one
    ACL2 is waiting at.

- `interrupt_session` works even when ACL2 has unread input queued (it
  used to do nothing on Linux), waits for ACL2's prompt, and returns
  ACL2's abort message; it says when a proof needs a second interrupt.

- `certify_book`: a timeout, a cancelled call, or the server exiting
  stops `cert.pl` and every job it started.  A book that doesn't exist
  is reported as such.

- Error messages say what happened and what to do: for example, when
  ACL2 has exited in a session, every call says so and says to start a
  new session, and `list_sessions` marks the session.

- Session log viewers:
  - A new Emacs viewer shows the log in an Emacs buffer, for working
    on a remote machine over ssh in tmux (see
    `INSTALL.remote-tmux-emacs.md`).
  - Viewers close whenever a session ends: by `end_session`, by ACL2
    exiting, or by the server exiting (also on SIGHUP, as when a tmux
    pane or terminal window is closed).
  - The macOS Terminal viewer closes its window without a "terminate
    running processes?" dialog, and never types into or closes another
    window.
  - On a Linux desktop, the viewer window closes when the session ends,
    and none is opened without a display.

- For agents:
  - `for-agents/mcp_stdio_client.py` drives the server directly over
    stdio, for an agent that can't register MCP servers (a cloud
    sandbox, say).
  - The skills and `for-agents/AGENTS.md` say how to choose a timeout,
    what to do after a timeout or an interrupt, and when (rarely) to
    end a session; the documentation lookup skill prefers the local
    xdoc corpus.
  - Instructions for registering the server with Codex, and security
    tips for Claude Code and Codex (`README-CLAUDE-CODE-SECURITY-TIPS.md`,
    `README-CODEX-SECURITY-TIPS.md`).

## Configuration

- **`session_log.viewer`** (`"auto"`, `"emacs"`, `"terminal"` or
  `"none"`, default `"auto"`): how session logs are shown.  `"auto"`
  and `"terminal"` open a terminal window (Terminal on macOS);
  `"emacs"` shows the log in Emacs via `emacsclient`.

## Development

- `tool-doc.md` is generated from the tool definitions by
  `scripts/gen_tool_doc.py`, and a test fails when it is out of date.
- `mypy --strict` reports no errors, and the test suite passes with no
  known failures (on macOS with SBCL and CCL, and on Linux with SBCL).
- `docs/architecture.md` describes the terminal settings, sending one
  form at a time, prompt detection, interrupts and cancelled calls, and
  the log viewers.

# Changes — 2026-05-24

- Improved the organization of the README.md installation instructions,
  and add instructions on how to instruct Claude Code and other
  agents to find skill information.

- Split agent-facing documentation by audience.  The repo-root
  `CLAUDE.md` and `AGENTS.md` are now strictly dev-facing (architecture,
  build, tests for contributors to `acl2-mcp` itself).  End-user
  guidance for driving ACL2 via `acl2-mcp` moved to a new `for-agents/`
  directory.

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
