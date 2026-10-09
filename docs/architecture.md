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
    r'.*>[ ]*$',    # ACL2, GCL, CLISP, LispWorks, CCL debugger
    r'.*\] $',      # SBCL debugger (e.g., "0] ")
    r'.*\* $',      # CMUCL, SBCL raw Lisp (e.g., "* ")
]
```

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

# Disable echo (ACL2 handles its own)
attrs = termios.tcgetattr(slave_fd)
attrs[3] = attrs[3] & ~termios.ECHO
termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
```

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

### Writing a Command

The PTY holds only so much input that ACL2 hasn't read: about 1 KB on
macOS and 20 KB on Linux.  ACL2 reads a command one form at a time, so
while it evaluates an early form of a long command, the queue fills and a
write to the (non-blocking) master fails with EAGAIN.  That is not an
error.  `_write_input` waits (backing off from 1 ms to 50 ms) and writes
more as ACL2 reads, yielding to the event loop between writes so the
reader keeps draining ACL2's output.

Writing stops early in three cases:

- **Timeout**: the command's timeout covers sending as well as
  evaluation.  If it expires before the whole command is sent,
  `evaluate` returns a timeout error that says how much was sent, and
  ACL2 keeps working, as for any timeout: a background task
  (`_pending_write`, `_finish_write`) sends the rest as ACL2 reads it.
  The next command waits for that task before writing, so commands never
  interleave.
- **Interrupt**: `interrupt()` increments `interrupt_count`; the writer
  checks it before each write and stops, since the rest of a command
  must not follow an interrupt.  The interrupt discards what ACL2 hasn't
  read, and the log gets an `INPUT CUT SHORT` marker.
- **Session ended**: `terminate()` cancels a background write before
  sending `(good-bye)`.

Prompt confirmations are counted only from when the whole command has
been sent: prompts after a long command's earlier forms can be confirmed
while the write is still waiting, and must not end the command.

### Known Limitation: Single-Line Length

Single lines longer than 1024 bytes cause the PTY to hang due to the canonical mode (`ICANON`) line buffer limit (`MAX_CANON`). This affects both the MCP server and Emacs shell-mode.

**Workaround**: Use multi-line inputs with lines shorter than 1024 bytes. This is typical for ACL2 code (e.g., mutual-recursion definitions).

**Potential fix**: Disable canonical mode (`~ICANON`), but this may affect ACL2's line editing and signal handling. Not yet implemented.

## Interrupt Handling

Interrupts are sent via PTY (preferred) with SIGINT fallback:

```python
# Primary: Send Ctrl-C through PTY
os.write(self.master_fd, b"\x03")

# Fallback: discard unread input, then send SIGINT to process group
self._flush_pty_input()
pgid = os.getpgid(self.process.pid)
os.killpg(pgid, signal.SIGINT)
```

The PTY method is preferred because it matches terminal behavior exactly:
the line discipline discards ACL2's unread input and sends SIGINT.  The
fallback does the same two steps itself.  It is needed when the Ctrl-C
cannot be written, usually because ACL2 is busy and the input queue is
full of a command it has not read yet (EAGAIN; the queue holds about 1 KB
on macOS and 20 KB on Linux).  The flush opens the slave by name
(`slave_path`), because a `tcflush` through the master fd discards the
input on macOS but ACL2's pending output on Linux.

## Session Lifecycle

### Start Session

1. Create PTY pair (`pty.openpty()`)
2. Configure terminal attributes
3. Spawn ACL2 process with slave as stdin/stdout/stderr
4. Close slave in parent (child inherited it)
5. Register event-driven reader on master
6. Start logger task
7. Wait for initial ACL2 prompt

### Send Command

1. Acquire session lock
2. Wait for any earlier command still being sent
3. Log input with timestamp
4. Write command to PTY master, waiting for room as ACL2 reads
5. Wait for prompt pattern in output buffer
6. Return captured output

### End Session

1. Send `(good-bye)` to ACL2 and wait up to 5 seconds for it to exit
2. If it hasn't exited (it was busy, or its input queue was full), kill
   its process group with SIGKILL and wait up to 5 more seconds
3. Log the `SESSION ENDED` marker
4. Remove event loop reader
5. Close PTY master
6. Clean up buffers and tasks

The reader stays registered until ACL2 has exited, so that its last
output is logged and its exit can't hang: on macOS, the exit of the
session leader (the `acl2` process) waits until its terminal output has
been read.  The reader also removes itself when it reads EOF or EIO,
since the master stays readable after ACL2's side closes.

## Platform Notes

- **macOS/Linux**: Full PTY support
- **Windows**: Not supported (PTY not available); use WSL
- **macOS-specific**: `TIOCSCTTY` requires `setsid()` first

## References

- Python pty module: https://docs.python.org/3/library/pty.html
- termios module: https://docs.python.org/3/library/termios.html
- SBCL manual: http://www.sbcl.org/manual/
- Emacs comint mode: https://www.gnu.org/software/emacs/manual/html_node/emacs/Shell-Mode.html
