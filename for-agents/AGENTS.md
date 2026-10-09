# ACL2 work in this directory

This directory hosts ACL2 development assisted by the `acl2-mcp` Model
Context Protocol server. The MCP tools and the skills inlined below are
the recommended way to drive ACL2.

> **Note**: This file is the non-Claude counterpart to `CLAUDE.md` plus
> the `acl2-mcp` skill files. Claude Code reads those files separately;
> agents without a skills mechanism get the same guidance inlined here.

## Default workflow

For interactive ACL2 work, follow the steps in the **acl2-session-start**
skill below. Every tool that runs ACL2 code needs a session; sessions let
you build up definitions and theorems incrementally and keep ACL2's world
state intact across commands.

## Looking things up

To find ACL2 documentation for a symbol, function, macro, or concept,
follow the steps in the **acl2-doc-lookup** skill below.

## Undoing and checkpoints

To view or undo session history, or to set a checkpoint before
speculative work and return to it, follow the
**acl2-session-history-management** skill below.

## File path conventions

When calling the MCP tools, supply book paths (e.g., `certify_book`,
`include_book`) *without* the `.lisp` extension.

## ACL2 MCP startup

Before starting an ACL2 MCP session, do not pass `view_log_in_terminal`
unless the user explicitly asks. Let the MCP server use its configured default
from `~/.config/acl2-mcp/config.toml`

## Skills

### acl2-doc-lookup

Use this skill to look up ACL2 documentation for symbols, functions, macros, and concepts.

#### Prefer the local corpus (offline, milliseconds)

Before any online lookup, try the local xdoc agent corpus:

1. **Via the MCP server** (if available): `mcp__acl2__xdoc_search` with a
   query, then `mcp__acl2__xdoc_show` with the topic name.  These need no
   ACL2 session.
2. **Directly with grep** (works in any environment that has a corpus,
   e.g. the acl2-allcerts Docker image at
   `$ACL2_ROOT/books/doc/agent-corpus`, or a directory named by the
   `ACL2_XDOC_CORPUS` environment variable):
   - discover: `grep -i 'QUERY' $CORPUS/index.tsv`
   - read: open `$CORPUS/topics/<KEY>.txt` (KEY is column 2 of the index)
   - full-text: `grep -ril 'QUERY' $CORPUS/topics/`

The corpus covers every topic in the built manual but NOT topics defined
in the current session; use `:doc` via the `evaluate` tool for those.
Only fall back to the online lookup below when no corpus is available.

#### URL Pattern

The ACL2 documentation has an SEO-friendly interface that loads quickly, for example:

```
https://acl2.org/doc/index-seo.php?xkey=PACKAGE____SYMBOL
```

Note: The separator between package and symbol is **four underscores** (`____`).

#### Common Packages

- `ACL2` - Most built-in functions, macros, and the main part of the Axe toolkit
- `COMMON-LISP` - Common Lisp primitives available in ACL2
- `BUILD` - Build system utilities (cert.pl, depends-on, etc.)
- `FTY` - Data types
- `STD` - Std Utilities, including `Define` and `Defines`
- `STR` - String utilities from Std
- `X86ISA` - x86 model and related functions (x86isa project)
- `X` - x86 specific parts of the Axe toolkit

#### Hard-to-Guess Package Mappings

Some symbols are in unexpected packages.  For example:

```lisp
ACL2 !>(symbol-package-name 'symbol-package)
(symbol-package-name 'symbol-package)
"COMMON-LISP"
ACL2 !>(symbol-package-name 'symbol-package-name)
(symbol-package-name 'symbol-package-name)
"ACL2"
```

#### How to Look Up Documentation

1. **Determine the package**: Most symbols are in `ACL2`, so if you are not sure, try that.
   Source files have an `in-package` form at the top.  In the REPL, the ACL2 prompt shows
   the current package, so if a symbol is usable in that context, you can see
   its package by calling `symbol-package-name` on it.

2. **Construct the URL**:
   a. Start with the symbol's package name (e.g., `ACL2`)
   b. Append `____` (four underscores) as the package separator
   c. Append the `symbol-name`, applying these rules:
      - If the symbol prints without `|...|` bars, upcase it
      - If the symbol prints with `|...|` bars, preserve its case
      - Keep hyphens as-is
      - Replace each other non-alphanumeric character with `_XX`
        where XX is the two hex digits of its ASCII code, reversed
        (e.g., `*` = 0x2A → `_A2`, `+` = 0x2B → `_B2`, space = 0x20 → `_02`)
   d. Prepend `https://acl2.org/doc/index-seo.php?xkey=`

   Examples:
   - `x86isa` → `ACL2____X86ISA`
   - `*ACL2-exports*` → `ACL2_____A2ACL2-EXPORTS_A2` (note: five underscores — four for `::` and one that begins `_A2`)
   - `Modeling Algorithms in C++ and ACL2` → `RTL____Modeling_02Algorithms_02in_02C_B2_B2_02and_02ACL2` (a `|...|`-escaped symbol created for a documentation topic, so it has lowercase and spaces)

3. **Fetch the page**: Use WebFetch with a prompt to extract the relevant information.

4. **Follow subtopic links**: Documentation pages often link to subtopics with more detail. The link pattern includes `xkey=PACKAGE____SUBTOPIC`.

#### Example Usage

To look up documentation for `def-simplified`:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____DEF-SIMPLIFIED",
  prompt: "Show the complete documentation including function signature, parameters, and usage examples. List all subtopics."
)
```

To look up Axe rewriter tools:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____AXE-REWRITERS",
  prompt: "List all available rewriter tools and their descriptions."
)
```

#### Tips

- Documentation pages often have subtopics - follow these links for detailed information
- The SEO pages load much faster than the main `https://acl2.org/doc` interface
- When the web doc is sparse, check for comments and read the code in the relevant
  source file in the ACL2 community books source tree `/path/to/acl2/books/`.

#### Some Useful Top-Level Topics

- `ACL2____DEFTHM` - Theorem proving
- `ACL2____HINTS` - Proof hints
- `ACL2____BV` - Bitvector operations
- `ACL2____X86ISA` - x86 instruction set architecture model
- `ACL2____AXE` - Axe toolkit overview
- `ACL2____AXE-REWRITERS` - Rewriter tools (def-simplified, rewriter-basic, etc.)

### acl2-session-history-management

This skill covers efficient use of ACL2 session history management commands for viewing history, undoing events, and navigating the ACL2 world.

#### Key Commands

- `:pbt` - Print Back Through (view event history)
- `:ubt` - Undo Back Through (undo events up to and including a specific event)
- `:ubu` - Undo Back Up to (undo events after a specific event, keeping it)
- `:u` - Undo (undo the last event)
- `:oops` - Redo what was just undone
- `(deflabel name)` - Mark a checkpoint to return to with `:ubu name`

If the documentation below is insufficient for your use case of these commands,
or if you have a use case that these commands don't handle, you can see the
xdoc topic `ACL2____HISTORY` which has links to xdoc for these and other history
commands in detail.

#### Using :pbt (Print Back Through)

**Purpose**: View the history of events in your ACL2 session.

**Best practices**:

1. **Use `:pbt 1`** when you know there aren't many events (< 20)
   - Shows all events from the beginning
   - Most efficient for short sessions

2. **Use `:pbt (:x -N)`** to see the last N events
   - Start small: `:pbt (:x -5)` or `:pbt (:x -10)`
   - Only increase if you need more history
   - **Don't guess large numbers** like `-29` without reason

3. **Read the output** to find event numbers
   - Format: `3  (DEFTHM MY-THEOREM ...)`
   - The number (e.g., `3`) can be used directly with `:ubt`

**Example**:
```lisp
X !> :pbt 1
   1  (INCLUDE-BOOK ...)
   2  (DEFTHM RULE-1 ...)
   3  (DEFTHM RULE-2 ...)
   4  (DEF-UNROLLED MY-LIFT ...)
X !>
```

#### Using :ubt (Undo Back Through)

**Purpose**: Undo events back to and including a specific event.

**Two approaches**:

##### 1. Using event numbers (more efficient)
If you've already run `:pbt` and see the event numbers:
```lisp
:ubt 3  ; Undoes events 3, 4, 5, ... (everything from event 3 onward)
```

**Advantage**: Clean, concise, no need to type long event names

##### 2. Using event names (when you know the name)
If you know the event name and haven't run `:pbt`:
```lisp
:ubt my-theorem  ; Undoes my-theorem and everything after it
```

**Advantage**: Skip the `:pbt` step if you already know what to undo

**Example workflow**:
```lisp
; Scenario: You want to undo custom rules and retry a lift

X !> :pbt 1
   1  (INCLUDE-BOOK "unroller" ...)
   2  (INCLUDE-BOOK "support" ...)
   3  (DEFTHM CUSTOM-RULE-1 ...)
   4  (DEFTHM CUSTOM-RULE-2 ...)
   5  (DEF-UNROLLED MY-LIFT ...)
X !> :ubt 3
; This undoes events 3, 4, and 5
; Now you can try a different approach
```

#### Using :u (Undo One Event)

**Purpose**: Undo just the most recent event.

**When to use**:
- Undoing a single recent event
- Stepping back one event at a time
- When you need fine-grained control

**Example**:
```lisp
X !> :u          ; Undoes event 5
X !> :u          ; Undoes event 4
X !> :u          ; Undoes event 3
```

**Note**: If you need to undo multiple events, `:ubt` is more efficient than multiple `:u` commands.

#### Using :oops (Redo)

**Purpose**: Redo what was just undone.

**When to use**:
- You undid too much by accident
- You want to restore state after exploring an alternative

**Example**:
```lisp
X !> :ubt 3       ; Oops, I undid too much!
X !> :oops        ; Restores events 3, 4, 5
```

#### Checkpoints with deflabel

**Purpose**: Mark a known-good point before speculative work (helper
lemmas, an alternative definition, a lift with different rules), so you can
return to it in one step without counting commands.

```lisp
(deflabel before-helpers)   ; mark the point, as its own top-level command
(defthm helper-1 ...)       ; try things
(defthm main-thm ...)       ; doesn't work out
:ubu before-helpers         ; undo everything after the label; the label stays
(defthm helper-2 ...)       ; try something else
:ubu before-helpers         ; return again as often as you like
:pbt before-helpers         ; show everything done since the checkpoint
```

- `:ubu` ("undo back up to") keeps the label, so the checkpoint can be
  reused.  `:ubt before-helpers` undoes the label too.
- Submit the `deflabel` by itself.  A label inside another command
  (`progn`, `encapsulate`, an included book) names that whole command,
  so `:ubu` keeps all of it, and errors with "Can't undo back to where we
  already are!" if it is the latest command.
- Label names must be new.  `(deflabel cp)` fails if `cp` already exists
  (labels are never redundant), so pick a new name or `:ubt cp` first.
- A failed `defthm` or `defun` adds nothing to the history, so there is
  nothing to undo after a failed proof; just resubmit it with new hints.
  Use `:u` first only if the previous attempt *succeeded* and you want to
  replace it.

#### Best Practices Summary

1. **Check history efficiently**:
   - Use `:pbt 1` for short sessions
   - Use `:pbt (:x -5)` or `:pbt (:x -10)` as a starting point, increase if needed
   - Don't guess large numbers without reason

2. **Undo efficiently**:
   - If you've already done `:pbt`, use event numbers: `:ubt 3`
   - If you know the event name, use it directly: `:ubt my-rule`
   - For single events, `:u` is fine
   - For multiple events, `:ubt` is better than multiple `:u`

3. **Monitor what you're doing**:
   - After `:ubt`, you'll see which event you're now at
   - Use `:pbt 1` after undoing to verify the current state

4. **Checkpoint before speculative work**: `(deflabel name)`, then
   `:ubu name` to return to it

#### Common Workflow Example

```lisp
; You've been working and want to retry something

X !> :pbt 1
   dm      1  (WITH-OUTPUT :OFF WARNING! ...)
           2  (WITH-OUTPUT :OFF WARNING! ...)
           3  (DEFTHM CUSTOM-RULE ...)
           4  (DEFTHM CUSTOM-RULE-SMT ...)
           5:x(DEF-UNROLLED MY-LIFT ...)
X !>

; Want to undo the custom rules and lift, use event number:
X !> :ubt 3
           2:x(WITH-OUTPUT :OFF WARNING! ...)
X !>

; Now try alternative approach...
X !> (ld "alternative-approach.lisp")
```

#### Important Notes

- **Command numbers are session-local, but don't assume your first command
  is 1**: commands from an ACL2 customization file (e.g.
  `~/acl2-customization.lsp`) come first.  Read the numbers from `:pbt`.
- **Commands are case-insensitive**: `:PBT`, `:pbt`, and `:Pbt` all work
- **Send these commands through `mcp__acl2__evaluate`**, as the `code` string:
  ```
  mcp__acl2__evaluate(session_id, code=":pbt 1")
  ```

#### Avoid Redundant History Checks

- **Don't call `:pbt` multiple times** to see more history. If the first call didn't show enough, undo or proceed based on what you learned.
- **Prefer `:pbt (:x -5)` after LD or include-book**: If you want to know the last few successful events from an LD, this is sufficient.
- **The `mcp__acl2__get_world_state` tool uses `:pbt (:x -N)`** where N is the `limit` parameter. Large limits (e.g., 30+) will show prehistory (negative indices) which is rarely useful. Use small limits (3-5) or use `:pbt 1` directly via `mcp__acl2__evaluate`.

### acl2-session-start

This skill starts a persistent ACL2 session using the Model Context Protocol (MCP) ACL2 server.

#### Instructions

1. **Check MCP ACL2 server availability**:
   - Attempt to use `mcp__acl2__list_sessions` to verify the MCP ACL2 server is available
   - **If the tool is not available or returns an error**:
     - Report: "Sorry, the MCP ACL2 server is not available. The MCP server must be configured properly."
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

#### Example

```
ACL2 session started. Session ID: abc123
Log file: /Users/user/.acl2-mcp/sessions/abc123-20260405-110632.log
```

#### Notes

- Sessions maintain state across multiple tool calls
- You can have multiple sessions active simultaneously
- The session ID is required for all subsequent ACL2 operations in that session

#### Scratch Sessions

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

#### Session Lifecycle - Don't End Sessions Unnecessarily

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
- You're done with a scratch session (see Scratch Sessions above)

**On timeout**: Check the session log (`tail -20 <log-file>`) to see if ACL2 actually responded. A timeout often means the MCP server missed the prompt, not that ACL2 is stuck. You can usually just continue with the next command.

#### Monitoring Long-Running Operations

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
