# ACL2 work in this directory

This directory hosts ACL2 development assisted by the `acl2-mcp` Model
Context Protocol server. The MCP tools and the skills inlined below are
the recommended way to drive ACL2.

> **Note**: This file is the non-Claude counterpart to `CLAUDE.md` plus
> the `acl2-mcp` skill files. Claude Code reads those files separately;
> agents without a skills mechanism get the same guidance inlined here.

## Default workflow

For interactive ACL2 work, follow the steps in the **acl2-session-start**
skill below rather than relying on one-off tool calls. Sessions let you
build up definitions and theorems incrementally and keep ACL2's world
state intact across commands.

## Looking things up

To find ACL2 documentation for a symbol, function, macro, or concept,
follow the steps in the **acl2-doc-lookup** skill below.

## File path conventions

When calling the MCP tools:

- **Book paths** (e.g., `certify_book`, `include_book`): supply the path
  *without* the `.lisp` extension.
- **Regular file paths** (e.g., `check_theorem`, `query_event`): supply
  the full path *with* the `.lisp` extension.

## Skills

### acl2-doc-lookup

Use this skill to look up ACL2 documentation for symbols, functions, macros, and concepts.

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
