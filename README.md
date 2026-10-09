# ACL2 MCP Server

> ⚠️ **Use at your own Risk**
> While this is functional and tested with Claude, you should expect bugs and changes.  Do not use with sensitive data.  Currently the MCP server does not practically limit what ACL2 can do.

This Model Context Protocol (MCP) server provides tools for agentic interaction with the ACL2 theorem prover.

`acl2-mcp` has been tested most with Claude Code CLI, so the instructions are best for that platform.
There has been some use with Claude Desktop, so we believe that will work as well.
There is an `AGENTS.md` file that should work with other agentic models.  And, of course,
any client that can make use of the tools is welcome.  Feedback is appreciated.

A section near the end of this README describes how to register the MCP server with Codex.

## Features

This MCP server exposes 9 tools for working with ACL2, including support for persistent sessions that enable incremental development.
(Note: we are not sure these are all useful; the list may change.)

### Session Management Tools
- **start_session**: Create a persistent ACL2 session for incremental development
- **end_session**: End a persistent session and clean up resources
- **list_sessions**: List all active sessions with their status
- **interrupt_session**: Send Ctrl-C to a session that is stuck or churning
- **show_session_log**: Open or raise the terminal window tailing a session's log

### ACL2 Tools
- **evaluate**: Send any ACL2 form to a session: definitions, theorems, `include-book`, queries such as `:pe`, and history commands such as `:pbt` and `:ubt`. Requires a `session_id` from `start_session`.
- **certify_book**: Certify an ACL2 book file with `cert.pl` (loads and verifies all definitions and theorems)

### Documentation Tools
- **xdoc_search**: Search the local xdoc corpus (the ACL2 manual as plain text) by topic name or summary, optionally full text
- **xdoc_show**: Show one topic from the local xdoc corpus

## Prerequisites

- Python 3.10 or later
- ACL2 installed and available in PATH as `acl2`
  - If installed via package manager (e.g., `brew install acl2`): already configured
  - If built from source: add `/path/to/acl2/bin` to your PATH (this directory contains the `acl2` wrapper script)
  - If you are using your own script named `acl`, make sure it has a shebang as the first line: `#!/bin/bash`
- ACL2 books build tools (cert.pl) available in PATH
  - Add `/path/to/acl2/books/build` to your PATH for book certification support
- An MCP client.  These instructions include details on how to set up Claude Code
  to use `acl2-mcp`, but other clients can also be used.

## Installation

The steps below get you a working default setup with Claude Code.

For Claude Desktop or other configuration scopes, see
[Configuration](#configuration).

For a **remote, headless Linux server** (ssh/mosh + tmux + Emacs, no graphical
display), see [INSTALL.remote-tmux-emacs.md](INSTALL.remote-tmux-emacs.md): it sets
up the session log to tail live inside Emacs instead of a terminal window.

### 1. Install the package

Clone the repository, then `cd` into it:

```bash
git clone <repo-url>
cd acl2-mcp
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the package:

```bash
pip install -e .
```

### 2. Register with Claude Code

To make `acl2-mcp` start automatically when you run Claude Code,
follow these instructions.

It is important to realize that the directory you are in
when you run `claude` determines where Claude Code stores
per-project state (MCP server config, resume history, etc.).

For that reason, we recommend picking a directory
for starting `claude` and sticking to it.  One good choice
for such a directory is a specific `acl2` installation,
for example `~/claude-code/acl2/`.  When we mention
"your ACL2 directory", this is the directory we are
referring to.  (However, if you run `claude` from
some other directory, use that directory when
we say to use "your ACL2 directory".)

From your ACL2 directory, run:

```bash
claude mcp add acl2 /path/to/acl2-mcp/venv/bin/acl2-mcp
```

### 3. Install the ACL2 skills

The `for-agents/` directory in the cloned `acl2-mcp` repo ships
skills that help Claude use ACL2 effectively.

Claude Code looks in `~/.claude/skills/` and in `./.claude/skills/`
when it starts up.  These instructions presume you
leave `./.claude/skills/` in *your ACL2 directory*
free for the skills shipped with this distribution.
To install these skills, symlink the whole `skills`
directory as follows.

From your ACL2 directory, run:

```bash
mkdir .claude
ln -s /path/to/acl2-mcp/for-agents/.claude/skills .claude/skills
```

Use the absolute path of your `acl2-mcp` clone in the `ln -s` argument.

With this setup, after a `git pull` in `acl2-mcp`,
any new skills will be picked up by Claude Code automatically.

For non-Claude agent tools, copy `for-agents/AGENTS.md` to your working
directory's `AGENTS.md` instead — it contains the same skill content
inlined, since other agent frameworks don't have a skills mechanism.

That's it — start `claude` from your ACL2 directory and the ACL2 tools
will be available.

## Configuration

As you use `acl2-mcp`, you may wish to configure the
server's behavior.  For example, there are parameters controlling
the visibility of session transcript windows; see
[Configuring `acl2-mcp` via `config.toml`](#configure-acl2-mcp-via-configtoml) below.

Other topics cover optional and alternate setups: Claude Desktop, choosing
between project-scoped and user-wide Claude Code installs,
and running `acl2-mcp` standalone for development.

### Configure `acl2-mcp` via `config.toml`

`acl2-mcp` can load an optional config file from:

- `~/.config/acl2-mcp/config.toml`

We use `~/.config/` on both macOS and Linux instead of macOS
`~/Library/Application Support/` to keep the path consistent across
implementations and easier to type.

Currently supported settings:

```toml
[session_log]
# If true (the default), open a terminal window tailing the session log
# and bring it to the foreground when a session starts.
# Set to false to suppress the automatic terminal window.
# view_log_in_terminal = true

# If true (the default), close the session log viewer when the session
# ends: by end_session, by ACL2 exiting, or by acl2-mcp exiting.  Set to
# false to keep it open for review.
# close_log_on_end = true

# Which viewer opens the session log when a session starts:
#   "auto"     - default; a terminal window (platform-specific)
#   "emacs"    - tail the log inside a running Emacs via emacsclient, for
#                remote/headless servers (see INSTALL.remote-tmux-emacs.md)
#   "terminal" - force the terminal-window viewer
#   "none"     - do not open any viewer
# (view_log_in_terminal above is the on/off gate; viewer chooses the backend.)
# viewer = "auto"

[tool_output]
# Maximum characters returned by a tool call before output is elided.
# When exceeded, the first head_chars and last tail_chars are kept,
# with an elision warning in between pointing to the session log.
# max_output_chars = 5000
# head_chars = 400
# tail_chars = 4000

# Enable debug logging to ~/.acl2-mcp/debug.log (default: false).
# The log is cleared each time the server starts.
# debug_logging = false
```

If the file is malformed, `acl2-mcp` warns and falls back to built-in defaults.
If individual settings are unknown or invalid, `acl2-mcp` warns and ignores
just those settings. Explicit `start_session` arguments override config-file
defaults.

### Configure Claude Code: project vs. user scope

The command in [Installation](#2-register-with-claude-code) registers
`acl2-mcp` only for the project directory you run it from. To make it
available in every Claude Code session regardless of directory, use the
user scope instead:

```bash
claude mcp add --scope user acl2 /path/to/acl2-mcp/venv/bin/acl2-mcp
```

Project scope is good for teams with per-project tool configurations;
user scope is good if you want ACL2 tools everywhere.

### Configure Claude Desktop to use acl2-mcp

Add this to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "acl2": {
      "command": "/path/to/acl2-mcp/venv/bin/acl2-mcp"
    }
  }
}
```

Replace `/path/to/acl2-mcp` with the actual path to your installation directory.

We do not know if Claude Desktop works on Linux, so if you have that
configuration, you will need to find the appropriate json file and update it
similarly to the macOS example.

### Running the server standalone

Claude Desktop and Claude Code launch the server automatically once
configured. To start it by hand for development or testing:

```bash
acl2-mcp
```

## Usage

### Persistent Session Workflow (Recommended for Interactive Development)

For incremental development where you build up definitions and theorems step-by-step, use persistent sessions:

**1. Start a session:**
```
Tool: start_session
Arguments:
  name: "natural-numbers-proof"  (optional, for easy identification)

Returns: Session ID (e.g., "a1b2c3d4-...")
```

**2. Define functions incrementally:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defun plus (x y) (if (zp x) y (plus (1- x) (1+ y))))"

Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(plus 2 3)"  // Test the function
```

**3. Build on previous definitions:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defun times (x y) (if (zp y) 0 (plus x (times x (1- y)))))"
```

**4. Prove theorems interactively:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defthm plus-commutative (equal (plus x y) (plus y x)))"
```

**5. If proof fails, resubmit with hints:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(defthm plus-commutative
          (equal (plus x y) (plus y x))
          :hints ((\"Goal\" :induct (plus x y))))"
```

A failed `defthm` adds nothing to the session, so there is nothing to undo
first.

**6. Set a checkpoint before risky steps:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: "(deflabel before-induction)"
```

**7. Return to the checkpoint if needed:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: ":ubu before-induction"
```

`:ubu` undoes everything after the label and keeps the label, so you can
return to it again.  See the `acl2-session-history-management` skill.

**8. Inspect session history:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: ":pbt (:x -9)"  (show the last 10 commands)
```

**9. Undo mistakes:**
```lisp
Tool: evaluate
Arguments:
  session_id: "a1b2c3d4-..."
  code: ":u"  (undo the last command)
```

**10. End session when done:**
```
Tool: end_session
Arguments:
  session_id: "a1b2c3d4-..."
```

**Benefits of persistent sessions:**

- ✅ No need to wrap everything in `progn`
- ✅ Test functions immediately after defining them
- ✅ Build complex proofs incrementally
- ✅ Try different proof strategies without re-submitting entire files
- ✅ Set checkpoints (`deflabel`) and return to them (`:ubu`) while experimenting
- ✅ Sessions last until you end them (idle sessions are not cleaned up)

### Evaluating ACL2 Code

Send any of these through `evaluate` with a `session_id`.

**Prove a Theorem:**
```lisp
(defthm append-nil
  (implies (true-listp x)
           (equal (append x nil) x)))
```

**Evaluate Expressions:**
```lisp
(defun factorial (n)
  (if (zp n)
      1
    (* n (factorial (- n 1)))))

(factorial 5)
```

**Include a Book:**
```lisp
(include-book "arithmetic/top" :dir :system)
(include-book "mybook")  ; relative to the session's working directory
```

**Look Up an Event:**
```lisp
:pe append
```

### Certifying Books

**Certify a Book:**
```
Tool: certify_book
Arguments:
  file_path: "path/to/mybook"  (without .lisp extension)
  timeout: 120  (optional)
```

## Development

### Type Checking

This project uses strict static typing with mypy:

```bash
mypy acl2_mcp/
```

### Running Tests

```bash
./venv/bin/pytest tests/ -v
```

## How It Works

Every tool that runs ACL2 code runs it in a persistent session:
1. `start_session` creates a long-running ACL2 process using a PTY
2. Each tool call sends commands to the existing process and reads responses
3. The ACL2 world state accumulates across multiple commands
4. Sessions last until they are ended, or until the MCP server exits
5. Up to 50 concurrent sessions are supported

For a throwaway experiment in a clean ACL2 world, start a second session
and end it when you are done.

There is no default timeout: without one, a command waits until ACL2
returns to its prompt.  A `timeout` (1 to 300 seconds) stops the wait,
not ACL2; use `interrupt_session` to stop ACL2.

## Registering the MCP with Codex

Run
```bash
codex mcp add acl2 -- "<path-to-acl2-mcp>/venv/bin/acl2-mcp"
```

That will add the following to your `~/.codex/config.toml`:
```toml
[mcp_servers.acl2]
command = "<path-to-acl2-mcp>/venv/bin/acl2-mcp"
```

If your scripts to run ACL2 rely on the `ACL2` environment variable, add the following just after the `command` line above:
```toml
env_vars = ["ACL2"]
```

## License

BSD 3-Clause License - See [LICENSE](LICENSE) for details.
