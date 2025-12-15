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
- **State**: `checkpoints`, `event_counter`, `lock`
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

### Chunked Writes

Large inputs must be written in chunks to avoid PTY buffer issues:

```python
chunk_size = 512  # macOS PIPE_BUF size
for i in range(0, len(command_bytes), chunk_size):
    chunk = command_bytes[i:i + chunk_size]
    written = await loop.run_in_executor(None, os.write, self.master_fd, chunk)
    await asyncio.sleep(0.001)  # Allow output to drain
```

**Why chunking is necessary:**
- macOS `PIPE_BUF` is only 512 bytes (vs 4096 on Linux)
- Large single writes cause backpressure when echoed input fills the PTY buffer
- Inter-chunk delays allow the reader to drain output

### Known Limitation: Single-Line Length

Single lines longer than 1024 bytes cause the PTY to hang due to the canonical mode (`ICANON`) line buffer limit (`MAX_CANON`). This affects both the MCP server and Emacs shell-mode.

**Workaround**: Use multi-line inputs with lines shorter than 1024 bytes. This is typical for ACL2 code (e.g., mutual-recursion definitions).

**Potential fix**: Disable canonical mode (`~ICANON`), but this may affect ACL2's line editing and signal handling. Not yet implemented.

## Interrupt Handling

Interrupts are sent via PTY (preferred) with SIGINT fallback:

```python
# Primary: Send Ctrl-C through PTY
os.write(self.master_fd, b"\x03")

# Fallback: Send SIGINT to process group
pgid = os.getpgid(self.process.pid)
os.killpg(pgid, signal.SIGINT)
```

The PTY method is preferred because it matches terminal behavior exactly.

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
2. Log input with timestamp
3. Write command to PTY master (chunked)
4. Wait for prompt pattern in output buffer
5. Return captured output

### End Session

1. Remove event loop reader
2. Send `(good-bye)` to ACL2
3. Wait briefly for graceful exit
4. Terminate process if needed
5. Close PTY master
6. Clean up buffers and tasks

## Platform Notes

- **macOS/Linux**: Full PTY support
- **Windows**: Not supported (PTY not available); use WSL
- **macOS-specific**: `TIOCSCTTY` requires `setsid()` first

## References

- Python pty module: https://docs.python.org/3/library/pty.html
- termios module: https://docs.python.org/3/library/termios.html
- SBCL manual: http://www.sbcl.org/manual/
- Emacs comint mode: https://www.gnu.org/software/emacs/manual/html_node/emacs/Shell-Mode.html
