# Installing acl2-mcp on a remote headless Linux server

This guide is for the following configuration:

- You use a ssh or mosh connection to the server.

- You work within `tmux` on the server.

- You use `emacs -nw` within `tmux`.

We describe an example installation procedure, along with
some background information to help you customize it.

The instructions are Claude-Code-centric, but `acl2-mcp` is
designed to work with any agent/framework supporting MCP.

## Prerequisites

| Need | Check |
|------|-------|
| Python 3.10+ | `python3 --version` |
| `venv` support | `python3 -c "import ensurepip" && echo "venv OK"` |
| Emacs | `emacs --version` and `command -v emacsclient` |
| tmux | `tmux -V` |
| ACL2 on PATH | `which acl2` |
| Your MCP client agent | `command -v claude` |

Debian/Ubuntu `venv` support is not usually installed by default.  To install:
```bash
sudo apt install python3-venv
```

One example setup for bounding LLM permissions is to have a container directory
under which acl2 and acl2-mcp are cloned, such as:
```
  mkdir ~/claude-code ; cd ~/claude-code
  git clone https://github.com/acl2/acl2
  git clone https://github.com/bendyarm/acl2-mcp
```

See also [README-CLAUDE-CODE-SECURITY-TIPS.md](README-CLAUDE-CODE-SECURITY-TIPS.md),
to proactively set up sandboxing and permissions for Claude Code.

## Installation

`acl2`, `emacsclient`, and `emacs` must be on your `PATH` *inside a tmux pane*, not
just your login shell. If `which acl2 emacsclient` is empty in a pane, see
Appendix C.

### 1. Install the package

```bash
cd ~/claude-code/acl2-mcp
python3 -m venv venv && source venv/bin/activate && pip install -e .
```

No `sudo` for `python3-venv`? Use `uv` instead (Appendix B). Either way the
launcher ends up at `~/claude-code/acl2-mcp/venv/bin/acl2-mcp`.

### 2. Register with Claude Code

Run this *from the directory you start `claude` in*, so that when Claude Code
runs, it automatically connects to the MCP server.  For example:

```bash
cd ~/claude-code/acl2
claude mcp add acl2 ~/claude-code/acl2-mcp/venv/bin/acl2-mcp
```

### 3. Enable the Emacs viewer

```bash
mkdir -p ~/.config/acl2-mcp
printf '[session_log]\nviewer = "emacs"\n' > ~/.config/acl2-mcp/config.toml
```

In other words, in the file `~/.config/acl2-mcp/config.toml`, enter:

```
[session_log]
viewer = "emacs"
```

To check it:

```bash
cd ~/claude-code/acl2-mcp
venv/bin/python -c "from acl2_mcp.config import load_config; print(load_config().session_log)"
```

### 4. Set up Emacs

In `~/.emacs`, add the following:

```elisp
;; -----------------------------------------------------------------------------
;; Forms added for running Claude Code and acl2-mcp remotely.

;; WARNING: The following assumes one Emacs per host (the default socket name).
;; If we need to support multiple emacses per host, we can do that
;; with distinct server names and acl2-mcp would have to pass --socket-name
;; to emacsclient.

;; 1. Emacs server, so acl2-mcp's emacsclient can reach this Emacs.
(require 'server)
(unless (server-running-p)
  (server-start))

(defun acl2-mcp-show-log (path)
  "Show PATH live via `tail -f' in a read-only, self-following right-side window."
  (let* ((file (expand-file-name path))
	 (name (format "*acl2-log: %s*" (file-name-nondirectory file)))
	 (buf  (get-buffer-create name)))
    (unless (get-buffer-process buf)                  ; don't spawn a second tail
      (with-current-buffer buf
	(let ((inhibit-read-only t)) (erase-buffer))
	(special-mode)                                ; read-only + q / scroll keys
	(let ((proc (start-process "acl2-tail" buf "tail" "-n" "200" "-f" file)))
	  (set-process-query-on-exit-flag proc nil)   ; killing the buffer reaps tail
	  (set-process-filter
	   proc
	   (lambda (p chunk)
	     (let ((b (process-buffer p)))
	       (when (buffer-live-p b)
		 (with-current-buffer b
		   (let ((inhibit-read-only t))
		     (goto-char (point-max))
		     (insert chunk))
		   (dolist (win (get-buffer-window-list b nil t))
		     (set-window-point win (point-max))))))))))) ; follow the end
    (let ((win (display-buffer buf '((display-buffer-in-side-window)
				     (side . right) (window-width . 0.5)))))
      (when win (set-window-point win (point-max))))
    buf))

(defun acl2-mcp-close-log (path)
  "Close the acl2-mcp log viewer for PATH.
Kill its `tail' process and buffer, and remove its window if shown."
  (let* ((file (expand-file-name path))
         (name (format "*acl2-log: %s*" (file-name-nondirectory file)))
         (buf  (get-buffer name)))
    (when buf
      (let ((win (get-buffer-window buf t))) ; t = search all frames
        (when (window-live-p win)
          (ignore-errors (delete-window win))))	; tolerate "sole window"
      (let ((proc (get-buffer-process buf)))
        (when proc (delete-process proc))) ; reap the tail process
      (kill-buffer buf))))
```

Restart Emacs (or eval the new forms), then sanity-check the Emacs side alone:

```bash
echo test > /tmp/x.log
emacsclient --eval '(acl2-mcp-show-log "/tmp/x.log")'
```

A read-only window tailing the file should appear on the right.

### 5. Set up tmux

Below is an example `.tmux.conf` file.  It changes some key bindings
to make it easier to use Emacs over tmux.  These have been tested
from a Mac.

- `C-\` is the "tmux prefix" key (default is `C-b`, which is not good
  for Emacs users). See the tmux docs for commands.

- `M-o` switches between the Emacs and Claude Code CLI panes.  

- `M-i`: If you want to scroll the Claude Code CLI pane, switch to it
   and do `M-i`; then you can scroll it with a mouse scroll wheel
   or the up and down arrow keys. (The scrolling mode is called
   `copy-mode`.) Exit `copy-mode` with `q`.

Example `.tmux.conf`:

```
# Rebind tmux control from Ctrl-b to Ctrl-\ (need to escape by doubling below)
set-option -g prefix C-\\
unbind-key C-b
bind-key C-\\ send-prefix

# Two ways to switch between tmux panes:
# (1) C-\ \  (2) M-o
bind \\ last-pane
bind -n M-o last-pane

# increase scrollback in subshell (default is 2000)
set -g history-limit 50000

# Switch current pane to tmux "copy mode".
# It should be called "scroll mode" since
# that is what it lets you do.
# Do M-i in the terminal pane, and that pane will enter copy mode.
# Exit copy mode with 'q'.
bind -n M-i copy-mode
```

The meta-key commands will only work if the terminal sends Option/Alt as Meta.
This works on a typical 2024 Mac, but may need some key sending attention
for another kind of terminal.

### 6. Set up a function on your local machine

When you start a terminal and run this example function,
it will connect to HOST and start tmux with emacs
in a left pane and a shell for claude code on the right.

If you use zsh on macOS, add the following to your `~/.zshrc`:

```bash
HOST() {
  local sess=${1:-main}
  ssh -t HOST "
    tmux has-session -t $sess 2>/dev/null || {
      tmux new-session -d -x $(tput cols) -y $(tput lines) -s $sess
      tmux split-window -h -l 33% -t $sess
      tmux send-keys -t ${sess}.0 'exec emacs -nw' Enter
    }
    tmux attach -d -t $sess
  "
}
```

Replace the instances of `HOST` by the remote server name.

## End-to-end walkthrough

With everything above in place, a working session looks like this:

1. On your local machine, run your launcher from Step 6. 
   It ssh's in and lands you in tmux: Emacs (`-nw`) on the left, a
   shell on the right.  Use `M-o` to switch between panes.
2. In the right pane, `cd` to your ACL2 directory (`~/claude-code/acl2`) and run
   `claude`.
3. Ask Claude to do some ACL2 work — e.g. *"Start an ACL2 session and prove that
   `append` on lists is associative."* Claude will find the tool called `start_session`.
4. As soon as the session starts, the log panel **opens by itself** in the Emacs
   pane, and tails a session log capturing ACL2's I/O, live while Claude works.
5. If you need to scroll up in the Claude pane, `M-i`, then the scroll wheel
   or arrow keys scroll back. `q` exits.
6. When the session ends, the log panel in Emacs closes.

## Appendix A. How it works

When a session starts, acl2-mcp opens the log with the configured `viewer`. With
`viewer = "emacs"` it runs `emacsclient -n --eval '(acl2-mcp-show-log "<log>")'`
against your running Emacs server, which tails the file in a side window. acl2-mcp,
Claude Code, Emacs, and the log file are all on the same server, so `emacsclient`
talks to a *local* Emacs — no `DISPLAY`, no X forwarding. The logs live at
`~/.acl2-mcp/sessions/<id>-<timestamp>.log`.

`view_log_in_terminal` (default `true`) is the on/off gate for opening any viewer;
`viewer` chooses the backend (`auto`/`emacs`/`terminal`/`none`).

## Appendix B. Installing without sudo (uv)

`uv` bundles its own venv support, so it needs no `python3-venv` and no `sudo`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
cd ~/claude-code/acl2-mcp && uv venv && uv pip install -e .
```

Same launcher at `venv/bin/acl2-mcp`. Identical steps on every host, no per-distro
`apt` differences.

## Appendix C. PATH on the server

acl2-mcp launches `acl2` and `emacsclient` by name, inheriting the environment of
the shell that started Claude Code; Emacs must also be launchable from the pane. On
bash, a *login* shell (interactive ssh) reads `~/.bash_profile`, but a *non-login*
shell (a tmux pane) reads only `~/.bashrc`. Put `PATH` in `~/.bashrc` and source it
from `~/.bash_profile`:

```bash
# ~/.bash_profile
[ -f ~/.bashrc ] && . ~/.bashrc
```

Verify inside a pane: `which acl2 emacsclient`.

## Appendix D. Troubleshooting

This stack fails silently (no `DISPLAY`; acl2-mcp swallows viewer errors), so
bisect:

- **Nothing appears.** Re-run the Step 3 parse check (`viewer='emacs'`), and
  **restart Claude Code** after any config or code change.
- **Is the Emacs side OK?** `emacsclient --eval '(acl2-mcp-show-log "/tmp/x.log")'`
  (no `-n`, so errors show). `void-function …` → re-eval/restart Emacs; can't
  connect → `(server-start)` isn't running.
- **`acl2`/`emacsclient` not found** → PATH issue (Appendix C).
- **Old build deployed** → `grep -n _emacsclient_eval acl2_mcp/server.py` should
  match.
