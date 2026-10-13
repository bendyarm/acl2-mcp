# ACL2 MCP Server Architecture

This document describes the internal architecture of the ACL2 MCP server, focusing on session management and PTY-based communication.

## Overview

The ACL2 MCP server provides tools for interacting with the ACL2 theorem prover through the Model Context Protocol (MCP). The server supports persistent sessions for incremental development, using pseudo-terminals (PTY) to communicate with ACL2.

## PTY-Based Communication

### Why PTY?

ACL2 runs on SBCL (Steel Bank Common Lisp), which uses block-buffered output when connected to pipes. This causes debugger prompts and error messages to get stuck in buffers. By using a PTY, SBCL detects an interactive terminal (via `isatty()`) and uses unbuffered/line-buffered output instead.

This matches how Emacs shell-mode interacts with ACL2.

### Architecture Diagram

```
Python MCP Server <---> PTY master (read/write) <---> PTY slave <---> ACL2/SBCL
```

Key characteristics:
- PTY combines stdin/stdout/stderr into a single bidirectional channel
- SBCL sees a TTY and uses unbuffered output
- Matches Emacs shell-mode behavior exactly

## Session Management

### ACL2Session Class

Each persistent session is represented by an `ACL2Session` dataclass containing:

- **Process management**: `process`, `session_id`, `name`
- **PTY infrastructure**: `master_fd`, `ring_buffer`, `partial_line_buffer`
- **I/O handling**: `merge_queue`, `output_buffer`, `sequence_counter`
- **State**: `lock`
- **Logging**: `log_file`, `log_handle`

### Background I/O Architecture

```
PTY Master
    |
    v
_on_pty_readable() [event-driven callback]
    |
    v
Ring Buffer (64KB rolling) --> Pattern matching for prompts
    |
    v
merge_queue (async queue)
    |
    v
_logger_task() [background coroutine]
    |
    v
Log file + output_buffer
```

1. **Event-driven reader**: `loop.add_reader()` registers `_on_pty_readable()` callback
2. **Ring buffer**: Maintains last 64KB for efficient marker/prompt detection
3. **Merge queue**: Collects timestamped output lines from all sources
4. **Logger task**: Writes to log file and populates `output_buffer` for `send_command()`

### Prompt Detection

The server detects command completion by matching prompt patterns (based on Emacs `emacs-acl2.el`):

```python
PROMPT_PATTERNS = [
    r'.*>[ ]*$',    # ACL2 (also break-rewrite "1 ACL2 >"), GCL, CLISP,
                    # LispWorks, CCL debugger
    r'.*\] $',      # SBCL debugger (e.g., "0] ")
    r'.*\* $',      # CMUCL, SBCL raw Lisp (e.g., "* ")
    r'\? $',        # CCL raw Lisp
    r'-+>: $',      # ACL2 proof builder ("->: ", nested "-->: ")
    r'.*\):  $',    # ACL2 query ("ACL2 Query (:ID):  ...  (Y or N):  ")
    r':$',          # ACL2 walkabout
]
```

Other read loops these match: break-rewrite (`1 ACL2 >`), a wormhole
(`Wormhole ACL2 !>`), nested LD (`ACL2 !>>`), SBCL's nested debugger
(`0[2] `) and inspector (`> `), CCL's debugger (`1 > `, `2 > `) and
inspector (`Inspect> `, `Inspect 1> `).  A prompt none of them knows
costs a timeout: then, if ACL2's output ends with an unfinished line,
printed after the last form was sent and quiet for
`UNKNOWN_PROMPT_SECONDS`, `_adopt_pending_prompt` takes it for the
prompt, so later commands are sent there (whole).  A read with no
visible prompt can't be told from a slow, silent command;
`interrupt_session` gets out of it.

A prompt is a candidate when ACL2's output so far ends with it (no
newline after it).  It is confirmed once no more output arrives for
`PROMPT_SETTLE_SECONDS` (0.2), and only at a depth (count of trailing
`>`) no deeper than the prompt before the command, so that the prompts
of `(ld "file")` don't end a command.

`prompt_mode` tells how input is read at a prompt: by ACL2's reader at
an ACL2 loop prompt (`PKG MODE>`, also in break-rewrite and a wormhole),
the proof builder's, or a query's; by ACL2's reader without its object
check in raw mode (`ACL2 P>`); or by the host Lisp's own reader in raw
Lisp and debuggers.

## PTY Setup

### Terminal Configuration

When creating a session:

```python
master_fd, slave_fd = pty.openpty()

# Set terminal size (80x24)
winsize = struct.pack("HHHH", 24, 80, 0, 0)
fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

# Make master non-blocking for async I/O
flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

# Pass input to ACL2 unchanged (see Terminal Modes)
attrs = termios.tcgetattr(slave_fd)
attrs[0] &= ~termios.IXON
attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN)
attrs[6][termios.VMIN] = 1
attrs[6][termios.VTIME] = 0
termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
```

### Terminal Modes

The terminal passes a command to ACL2 unchanged, except for the
characters that send signals:

- **Canonical mode (`ICANON`) is off.**  In canonical mode the terminal
  holds input until a newline and limits the length of a line: on macOS
  it drops everything after 1024 bytes, newline included, so ACL2 waits
  forever for the rest of the form; on Linux it truncates the line to
  4096 bytes.  It also edits lines: DEL, C-u and C-w erase input, and C-d
  ends it, so a C-d at the start of a line makes ACL2 see end of file.
- **`IEXTEN` is off.**  Even without canonical mode, it makes macOS
  swallow C-o (which discards output), C-v (which quotes the next
  character) and C-y (a delayed suspend).
- **`IXON` is off.**  It makes the terminal swallow C-s and C-q, which
  stop and restart ACL2's output.
- **`ISIG` stays on**, so that `interrupt()` can send C-c.  A C-c, C-\
  or C-z in a command would signal ACL2 too (interrupt it, send it
  SIGQUIT, which can end the session, or suspend it), so `send_command`
  refuses a command that has one, sending none of it.  The characters
  come from the terminal's settings.
- **`ECHO` is off**, so the output holds only what ACL2 prints; the
  input is logged separately.

Without canonical mode, a read returns as soon as any input has arrived
(`VMIN` 1, `VTIME` 0).  SBCL and CCL buffer their input themselves and
read until they have a whole form, as they do from a pipe.

### Controlling Terminal Setup

The child process must be a session leader with the PTY slave as controlling terminal:

```python
def setup_controlling_tty():
    os.setsid()  # Create new session, become session leader
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)  # Set controlling terminal
```

This is critical for proper signal handling (Ctrl-C).

### Environment

```python
env["TERM"] = "dumb"    # Simple terminal, like Emacs comint
env["COLUMNS"] = "80"
env["LINES"] = "24"
```

## Sending Commands

### One Form at a Time

`send_command` sends a command one top-level form at a time, each once
ACL2 has finished the one before, and replies at the prompt after the
last.  Sent all at once, a command's reply ended at the first prompt
that settled: a later form that was slow and printed nothing (a
`(sleep 3)`, or a `defthm` proved without checkpoints) left its result
for the next reply.

- **Splitting** (`_plan_units`): `acl2_mcp/reader.py` reads the code's
  top-level forms with ACL2's syntax (see its docstring).  Each unit
  sent is a form with the text before it; a keyword command takes the
  rest of its line, since ACL2 reads as many arguments after it as the
  command takes in ACL2's world.  A newline after a unit ends its last
  token.
- **Rejection**: code that ACL2's reader would reject (a syntax error, a
  form missing its `)`, a float outside raw mode) is not sent at all;
  the reply says where, and the log shows the input with a `NOT SENT`
  marker.  A form left incomplete would otherwise have ACL2 wait for its
  rest and swallow the next command.
- **Whole**: at a raw Lisp or debugger prompt the host Lisp reads the
  code with its own syntax, so it is sent whole, as it is when a
  top-level `#+`/`#-` (whose form may be skipped) or syntax the reader
  doesn't handle (`#Y`, `#Z`, vectors) leaves the forms uncertain, and
  when `evaluate` is given `as_is`: input for a program with its own
  read loop needn't be Lisp at all.  Such a program's prompt is told
  from ACL2's by its package part, since ACL2 package names have no
  lower case letters; one that still looks like ACL2's needs `as_is`.
- **Stepping** (`_send_units`): a unit is finished when a prompt
  candidate appears after it was sent (`candidate_seq` counts them, each
  once, at an allowed depth).  No settle delay is needed there.
- **Stale prompts**: `_sends` counts the units sent.  A prompt seen
  before the latest send can't be that unit's, so `_flush_prompt`
  doesn't confirm it, even if it settles after the send.
- **Long units**: the PTY holds only so much input that ACL2 hasn't
  read: about 1 KB on macOS and 20 KB on Linux.  `_write_input` writes a
  unit as ACL2 reads, waiting on EAGAIN (backing off from 1 ms to 50 ms)
  and yielding to the event loop so the reader keeps draining output.

Sending stops early in three cases:

- **Timeout**: the command's timeout covers waiting for an earlier
  command, sending, and evaluation.  On a timeout ACL2 keeps working:
  a background task (`_pending_send`, `_finish_command`) sends the rest
  of the command as ACL2 finishes each form, then waits for the prompt
  after the last.  The next command waits for that task (within its own
  timeout), and its reply shows the earlier command's output first
  (`_unreported_from`, `_take_unreported_output`).  If ACL2's output ends
  with a prompt that doesn't count, such as the depth-2 prompt of
  `(ld *standard-oi*)`, ACL2 is waiting for input there:
  `_adopt_pending_prompt` makes it the current prompt.
- **Interrupt**: `interrupt()` increments `interrupt_count`; sending
  checks it before each write and stops, since the rest of a command
  must not follow an interrupt, and the log gets an `INPUT CUT SHORT`
  marker.
- **Session ended**: `terminate()` cancels a background send before
  sending `(good-bye)`.

## Interrupt Handling

Interrupts discard ACL2's unread input, then send Ctrl-C via the PTY,
with a SIGINT fallback:

```python
# Discard input ACL2 hasn't read yet
self._flush_pty_input()

# Primary: Send Ctrl-C through PTY
os.write(self.master_fd, b"\x03")

# Fallback: send SIGINT to process group
pgid = os.getpgid(self.process.pid)
os.killpg(pgid, signal.SIGINT)
```

Sending Ctrl-C matches terminal behavior exactly: the line discipline
discards ACL2's unread input and sends SIGINT.  Discarding the input
first matters in two cases where ACL2 is busy with an early form of a
long command and the rest is queued, unread:

- On Linux, the line discipline acts on an input byte only once the
  input ahead of it has been read.  A Ctrl-C written behind the rest of
  the command waits until ACL2 has finished the form and read the rest:
  `interrupt_session` reports success, but nothing is interrupted.
- When the input queue is full (about 1 KB on macOS, 20 KB on Linux),
  there is no room to write the Ctrl-C (EAGAIN).

The flush opens the slave by name (`slave_path`), because a `tcflush`
through the master fd discards the input on macOS but ACL2's pending
output on Linux.  The fallback is for a Ctrl-C that still can't be
written.

`interrupt()` then waits up to `INTERRUPT_WAIT_SECONDS` (5) for a prompt
confirmed after the interrupt, as `send_command` waits for its command's
prompt, and returns the output since the interrupt: ACL2's abort
message.  Usually the `evaluate` call being interrupted has already timed
out, so no other reply would show that message, and returning only at
the prompt keeps the next command from taking it as its own.  It doesn't
take the session lock, so an `evaluate` still waiting gets the abort
message too.  In a proof, the first interrupt only asks ACL2 to stop at
its next check (`:DOC abort-soft`); when no prompt comes, the reply says
to interrupt again.

### Cancelled Calls

An MCP client cancels a tool call when, say, the user interrupts the
agent.  A cancelled `evaluate` call stops its command, as a cancelled
`certify_book` call stops `cert.pl`: if any of the command may have
reached ACL2, `send_command` interrupts ACL2 as above
(`_cancel_command`), which also discards the part of the command ACL2
hasn't read, half a form included.  The call returns nothing, so the
next reply begins by saying that the earlier call was cancelled and
showing ACL2's output (its abort message), and the next command first
waits for ACL2's prompt after the interrupt, as after a timeout.
Without this, the rest of the command was dropped silently while ACL2
went on with the form it had, a half-written form was left for ACL2 to
read as the start of the next command, and the output turned up
unlabeled in the next reply.

## Session Lifecycle

### Start Session

1. Create PTY pair (`pty.openpty()`)
2. Configure terminal attributes
3. Spawn ACL2 process with slave as stdin/stdout/stderr
4. Close slave in parent (child inherited it)
5. Register event-driven reader on master
6. Start logger task
7. Wait for ACL2's first confirmed prompt (one that settles): an
   `acl2-customization` file loads after a first prompt, in a nested LD,
   and a command sent at that prompt would take the prompt after the
   file for its own
8. Take the reader's syntax from the host Lisp (CCL's banner says
   "Welcome to Clozure Common Lisp")

### Send Command

1. Acquire session lock
2. Wait for an earlier command that timed out, or was cancelled, to finish
3. Split the command into forms, or reject it (unreadable, or with a
   C-c, C-\ or C-z)
4. Log input with timestamp
5. Send the forms one at a time (see One Form at a Time)
6. Wait for the prompt after the last form
7. Return the earlier command's output, if any, and this one's

### End Session

1. Send `(good-bye)` to ACL2 and wait up to 5 seconds for it to exit
2. If it hasn't exited (it was busy, or its input queue was full), kill
   its process group with SIGKILL and wait up to 5 more seconds
3. Log the `SESSION ENDED` marker
4. Remove event loop reader
5. Close PTY master
6. Clean up buffers and tasks
7. Close the log viewer, if `close_log_on_end` is set

The reader stays registered until ACL2 has exited, so that its last
output is logged and its exit can't hang: on macOS, the exit of the
session leader (the `acl2` process) waits until its terminal output has
been read.  The reader also removes itself when it reads EOF or EIO,
since the master stays readable after ACL2's side closes.

A session also ends when ACL2 exits on its own (after `(good-bye)` or a
crash): the reader's EOF or EIO logs the `SESSION ENDED` marker and
closes the log viewer.  The viewer is closed once, whichever comes
first; `log_viewer_opened` arranges it when `start_session` or
`show_session_log` opens one.

On macOS the viewer is a Terminal window whose shell execs a `sh`
wrapper around `tail -f` that exits cleanly on SIGTERM.  The script
that opens it titles the tab that `do script` returns (not the front
window, which may be another).  The scripts that open and show windows
run one at a time, in order, in a thread, so that `show_session_log`
called right after `start_session` finds the window that
`start_session` opened.  `close_log_viewer` (in a thread) drops the
session's scripts that haven't run yet (they would open a window for an
ended session), waits for one that is running, and so knows how many
windows may have been opened (a script that failed, say because
Terminal didn't answer in time, may have opened one).  It finds their wrappers with `pgrep`, takes each
one's tty from `ps`, finds the window with that title and tty while the
wrapper still runs, stops the wrapper, and closes the window by its id
only once the processes that ran on that tty have exited (not whatever
runs on it then: Terminal gives a freed tty to the next window it
opens) and the window's history ends with "[Process completed]" (Terminal has noticed; a window
in the background doesn't update its `contents`, so the history is
read).  Terminal asks "terminate running processes?" when asked to
close a window that runs something, and what it reports about a tab
(its tty, its processes) can be stale, so none of that is trusted; when
in doubt the window stays open.  Nothing is ever typed into a window.
The wrapper's `pgrep` pattern is anchored at the start of the command
line, so that it can't match the `osascript` processes, whose arguments
mention the log too.

On Linux the viewer is the first of `gnome-terminal`, `xterm` and
`konsole` that is installed, running `tail -f` on the log; without a
display (neither `DISPLAY` nor `WAYLAND_DISPLAY` set) none is opened.
It gets none of the server's stdin, stdout and stderr, which carry the
MCP messages.  For a log whose window was opened, `close_log_viewer`
(in a thread) stops the `tail` with `pkill`, using a pattern anchored at
the start of the command line, and the emulator then closes its window.  The window isn't found or raised
again: `show_session_log` opens another, and closing stops them all.

## Book Certification

`certify_book` runs `cert.pl` as a separate process, not in a session.
`cert.pl` execs `make`, which runs a helper script, a shell, and ACL2 for
each book.  They all share `cert.pl`'s output pipe, and `cert.pl` is
started in a process group of its own (`start_new_session=True`), so that
`_stop_certification` can stop all of them: SIGTERM to the group (`make`
then removes the target it was building), then SIGKILL after 5 seconds.
This happens on a timeout, when the client cancels the tool call, and at
server exit (`_running_certifications`).  Killing only `cert.pl` would
leave the rest running, and the call would wait for them, since they
keep its output pipe open.

## Server Shutdown

An MCP client stops a stdio server by closing its stdin, then sending
SIGTERM if it hasn't exited, then SIGKILL.  A client running in a
terminal (Claude Code, say) starts the server in its own process group,
which gets SIGHUP when the terminal goes away: a closed Terminal window,
a killed tmux pane or session.  On stdin EOF the MCP library waits for
running tool calls to finish before `run()` returns and cleans up (ends
all sessions, closing their log viewers, and stops all certifications).
On SIGTERM or SIGHUP, `run()` cancels the running tool calls, cleans up
in a task of its own, and exits with `os._exit(0)`: if stdin is still
open, the library's thread reading it stays blocked in `read()`, and
the process would not otherwise exit.

## Platform Notes

- **macOS/Linux**: Full PTY support
- **Windows**: Not supported (PTY not available); use WSL
- **macOS-specific**: `TIOCSCTTY` requires `setsid()` first

## References

- Python pty module: https://docs.python.org/3/library/pty.html
- termios module: https://docs.python.org/3/library/termios.html
- SBCL manual: http://www.sbcl.org/manual/
- Emacs comint mode: https://www.gnu.org/software/emacs/manual/html_node/emacs/Shell-Mode.html
