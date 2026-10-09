---
name: acl2-session-history-management
description: Manage ACL2 sessions using :pbt, :ubt, :ubu, :u, :oops commands efficiently, and checkpoint with deflabel before speculative work
allowed-tools: mcp__acl2__evaluate
---

<!-- Keep in sync with the acl2-session-history-management section of AGENTS.md -->

# ACL2 Session History Management

This skill covers efficient use of ACL2 session history management commands for viewing history, undoing events, and navigating the ACL2 world.

## Key Commands

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

## Using :pbt (Print Back Through)

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

## Using :ubt (Undo Back Through)

**Purpose**: Undo events back to and including a specific event.

**Two approaches**:

### 1. Using event numbers (more efficient)
If you've already run `:pbt` and see the event numbers:
```lisp
:ubt 3  ; Undoes events 3, 4, 5, ... (everything from event 3 onward)
```

**Advantage**: Clean, concise, no need to type long event names

### 2. Using event names (when you know the name)
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

## Using :u (Undo One Event)

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

## Using :oops (Redo)

**Purpose**: Redo what was just undone.

**When to use**:
- You undid too much by accident
- You want to restore state after exploring an alternative

**Example**:
```lisp
X !> :ubt 3       ; Oops, I undid too much!
X !> :oops        ; Restores events 3, 4, 5
```

## Checkpoints with deflabel

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

## Best Practices Summary

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

## Common Workflow Example

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

## Important Notes

- **Command numbers are session-local, but don't assume your first command
  is 1**: commands from an ACL2 customization file (e.g.
  `~/acl2-customization.lsp`) come first.  Read the numbers from `:pbt`.
- **Commands are case-insensitive**: `:PBT`, `:pbt`, and `:Pbt` all work
- **Send these commands through `mcp__acl2__evaluate`**, as the `code` string:
  ```
  mcp__acl2__evaluate(session_id, code=":pbt 1")
  ```

## Avoid Redundant History Checks

- **Don't call `:pbt` multiple times** to see more history. If the first call didn't show enough, undo or proceed based on what you learned.
- **Prefer `:pbt (:x -5)` after LD or include-book**: If you want to know the last few successful events from an LD, this is sufficient.
- **Keep N small in `:pbt (:x -N)`**: large values (e.g., 30+) reach into prehistory (negative indices), which is rarely useful. Use 3-5, or `:pbt 1` for the whole session.
