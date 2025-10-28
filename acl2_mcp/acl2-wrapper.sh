#!/bin/bash
#
# ACL2 Wrapper Script for MCP Server
#
# Purpose: Wraps ACL2 process to handle graceful termination when the MCP connection
#          is lost (e.g., when Claude Code exits). This prevents SBCL from entering
#          recursive error loops when stdin/stdout pipes are broken.
#
# Problem Solved:
#   When the Python MCP server process exits, it closes stdin/stdout pipes but doesn't
#   send signals to child processes. This causes SBCL (the Lisp implementation running
#   ACL2) to enter a recursive error loop trying to read from broken pipes, printing
#   endless backtraces.
#
# Solution:
#   Uses a named pipe (FIFO) and line-by-line forwarding to detect stdin closure
#   without polling. When stdin closes (EOF), immediately kills SBCL and ACL2.
#
# Architecture:
#   Python MCP Server -> Wrapper Script -> FIFO -> ACL2 -> SBCL
#
#   1. Wrapper reads from stdin line by line
#   2. Each line is forwarded to ACL2 via a FIFO
#   3. When stdin closes, the read loop exits
#   4. Cleanup kills SBCL first, then ACL2
#
# Author: ACL2-MCP Development Team
# Date: October 2025

# Configuration
DEBUG_LOG="/tmp/acl2-wrapper-debug.log"
DEBUG_ENABLED="${ACL2_WRAPPER_DEBUG:-1}"  # Set ACL2_WRAPPER_DEBUG=0 to disable logging

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------

log_debug() {
    if [ "$DEBUG_ENABLED" = "1" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): $*" >> "$DEBUG_LOG"
    fi
}

log_error() {
    # Always log errors, even if debug is disabled
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ERROR: $*" >> "$DEBUG_LOG" >&2
}

# -----------------------------------------------------------------------------
# Cleanup Function
# -----------------------------------------------------------------------------

do_cleanup() {
    local reason=$1
    log_debug "cleanup triggered by: $reason"

    # Kill SBCL child processes first (prevents recursive errors)
    if [ -n "$ACL2_PID" ]; then
        # Find SBCL processes that are children of ACL2
        # Note: Uses 'comm' field which shows full path on macOS
        local sbcl_pids=$(ps -o pid,ppid,comm 2>/dev/null | \
                          awk -v parent="$ACL2_PID" '$2 == parent && $3 ~ /sbcl/ {print $1}')

        if [ -n "$sbcl_pids" ]; then
            log_debug "Found SBCL PIDs: $sbcl_pids"
            for pid in $sbcl_pids; do
                if kill -0 "$pid" 2>/dev/null; then
                    log_debug "Killing SBCL process $pid with SIGKILL"
                    kill -9 "$pid" 2>/dev/null || true
                fi
            done
        else
            log_debug "No SBCL children found for ACL2 PID $ACL2_PID"
        fi

        # Kill ACL2 process
        if kill -0 "$ACL2_PID" 2>/dev/null; then
            log_debug "Killing ACL2 process $ACL2_PID with SIGKILL"
            kill -9 "$ACL2_PID" 2>/dev/null || true
        else
            log_debug "ACL2 process $ACL2_PID already terminated"
        fi
    fi

    # Close FIFO write descriptor
    if [ -n "$FIFO_FD" ]; then
        log_debug "Closing FIFO file descriptor $FIFO_FD"
        eval "exec $FIFO_FD>&-" 2>/dev/null || true
    fi

    # Remove FIFO file
    if [ -e "$FIFO" ]; then
        log_debug "Removing FIFO: $FIFO"
        rm -f "$FIFO"
    fi

    log_debug "Cleanup complete, exiting with status 0"
    exit 0
}

# -----------------------------------------------------------------------------
# Signal Handlers
# -----------------------------------------------------------------------------

handle_sigterm() {
    log_debug "Received SIGTERM"
    do_cleanup "SIGTERM"
}

handle_sigint() {
    log_debug "Received SIGINT"
    do_cleanup "SIGINT"
}

handle_sighup() {
    log_debug "Received SIGHUP"
    do_cleanup "SIGHUP"
}

# Install signal handlers
trap handle_sigterm SIGTERM
trap handle_sigint SIGINT
trap handle_sighup SIGHUP

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

log_debug "========================================="
log_debug "Starting ACL2 wrapper"
log_debug "Wrapper PID: $$"
log_debug "Parent PID: $PPID"
log_debug "Working directory: $(pwd)"
log_debug "========================================="

# Create unique named pipe (FIFO) for this session
FIFO=$(mktemp -u /tmp/acl2-fifo-XXXXXX)
if ! mkfifo "$FIFO"; then
    log_error "Failed to create FIFO at $FIFO"
    exit 1
fi
log_debug "Created FIFO: $FIFO"

# Start ACL2 reading from the FIFO
log_debug "Starting ACL2 process (reading from FIFO)"
acl2 < "$FIFO" &
ACL2_PID=$!

if ! kill -0 "$ACL2_PID" 2>/dev/null; then
    log_error "Failed to start ACL2 process"
    rm -f "$FIFO"
    exit 1
fi
log_debug "ACL2 started with PID: $ACL2_PID"

# Open FIFO for writing on file descriptor 3
# This keeps the FIFO open for the duration of the session
exec 3>"$FIFO"
FIFO_FD=3
log_debug "Opened FIFO for writing on file descriptor $FIFO_FD"

# Forward stdin to FIFO line by line
# This loop will block on each read until data arrives or EOF is reached
log_debug "Starting stdin-to-FIFO forwarding loop"
LINE_COUNT=0

while IFS= read -r line; do
    # Forward the line to ACL2 via the FIFO
    echo "$line" >&3

    LINE_COUNT=$((LINE_COUNT + 1))

    # Log progress periodically to avoid log spam
    if [ $((LINE_COUNT % 100)) -eq 0 ]; then
        log_debug "Forwarded $LINE_COUNT lines"
    fi
done

# If we reach here, stdin has been closed (EOF received)
log_debug "stdin closed (EOF) after forwarding $LINE_COUNT total lines"

# Perform cleanup
do_cleanup "stdin_eof"