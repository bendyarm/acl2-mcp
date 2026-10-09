"""Shared fixtures for the ACL2 MCP server tests."""

from collections.abc import AsyncIterator

import pytest_asyncio

from acl2_mcp.server import call_tool


@pytest_asyncio.fixture
async def session_id() -> AsyncIterator[str]:
    """Start a fresh ACL2 session for one test and end it afterwards."""
    result = await call_tool("start_session", {})
    sid = result[0].text.split("ID: ")[1].split("\n")[0].strip()
    yield sid
    await call_tool("end_session", {"session_id": sid})
