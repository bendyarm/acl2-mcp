#!/usr/bin/env python3
"""Minimal MCP stdio client for driving acl2-mcp without an MCP host.

For agents (Claude Cowork cloud sessions, CI scripts, etc.) that cannot
register MCP servers in their tool harness: this speaks the MCP protocol
(newline-delimited JSON-RPC 2.0 over stdio) to an acl2-mcp server process
directly.  Requires only the Python standard library.

Typical use from an agent's own Python code:

    from mcp_stdio_client import MCP
    # Server on this machine:
    m = MCP(["acl2-mcp"])
    # Or server inside a Docker container (e.g. the acl2-kcerts image):
    m = MCP(["docker", "exec", "-i", "acl2dev", "/root/.venvs/mcp/bin/acl2-mcp"])

    m.initialize()
    print(m.tool_names())
    sid = m.start_session()
    print(m.call("evaluate", {"code": "(defthm my-thm (equal (append x nil) x) "
                                      ":hints ((\"Goal\" :induct t)))",
                              "session_id": sid}))
    m.call("end_session", {"session_id": sid})

NOTE: sessions live inside the server process.  Keep one MCP instance (and
thus one server process) alive for the whole interaction; a new instance
starts a fresh server with no sessions.

Run this file directly for a self-test (requires acl2 on PATH):
    python3 mcp_stdio_client.py [server-command args...]
"""
import json
import queue
import re
import subprocess
import sys
import threading
import time


class MCP:
    def __init__(self, cmd: list[str]):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1)
        self.q: queue.Queue = queue.Queue()
        self.id = 0
        self._tools: list[dict] | None = None
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        for line in self.p.stdout:
            line = line.strip()
            if line:
                try:
                    self.q.put(json.loads(line))
                except json.JSONDecodeError:
                    pass

    def _send(self, obj: dict) -> None:
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def request(self, method: str, params: dict | None = None,
                timeout: float = 600) -> dict:
        self.id += 1
        rid = self.id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if msg.get("id") == rid:
                return msg
        raise TimeoutError(f"no response to {method} within {timeout}s")

    def initialize(self) -> dict:
        r = self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp_stdio_client", "version": "1.0"},
        })
        # required notification completing the MCP handshake:
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized",
                    "params": {}})
        return r["result"]["serverInfo"]

    def tools(self) -> list[dict]:
        if self._tools is None:
            self._tools = self.request("tools/list")["result"]["tools"]
        return self._tools

    def tool_names(self) -> list[str]:
        return [t["name"] for t in self.tools()]

    def call(self, tool: str, args: dict, timeout: float = 600) -> str:
        """Call a tool; returns the concatenated text content."""
        r = self.request("tools/call", {"name": tool, "arguments": args},
                         timeout)
        if "error" in r:
            return f"RPC ERROR: {r['error']}"
        parts = r["result"].get("content", [])
        return "\n".join(p.get("text", "") for p in parts)

    def start_session(self) -> str:
        out = self.call("start_session", {})
        match = re.search(r"ID: (\S+)", out)
        if not match:
            raise RuntimeError(f"could not start session: {out}")
        return match.group(1)

    def close(self) -> None:
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(timeout=10)


def _self_test(cmd: list[str]) -> None:
    m = MCP(cmd)
    print("server:", m.initialize())
    print("tools:", ", ".join(m.tool_names()))
    sid = m.start_session()
    print("session:", sid)
    out = m.call("evaluate", {"code": "(+ 1 2)", "session_id": sid})
    print("evaluate (+ 1 2):", out.splitlines()[-2:] if out else out)
    assert "3" in out, "unexpected evaluate output"
    print(m.call("end_session", {"session_id": sid}))
    m.close()
    print("self-test OK")


if __name__ == "__main__":
    _self_test(sys.argv[1:] or ["acl2-mcp"])
