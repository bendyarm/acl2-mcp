"""Write tool-doc.md from the tool definitions in acl2_mcp/server.py.

The tool sections are what an agent sees: each tool's description and
its parameters, from list_tools().  The General Notes section at the end
of tool-doc.md is written by hand, and kept as it is.

    python scripts/gen_tool_doc.py           # rewrite tool-doc.md
    python scripts/gen_tool_doc.py --check   # exit 1 if it is out of date

tests/test_tool_doc.py checks that tool-doc.md is up to date.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any

from acl2_mcp.server import list_tools

TOOL_DOC = Path(__file__).resolve().parents[1] / "tool-doc.md"

# The sections the tools are listed in, in order.  A new tool must be
# added here.
CATEGORIES = [
    ("Session Management Tools", ["start_session", "end_session", "list_sessions",
                                  "interrupt_session", "show_session_log"]),
    ("Code-based Tools", ["evaluate"]),
    ("File-based Tools", ["certify_book"]),
    ("Documentation Tools", ["xdoc_search", "xdoc_show"]),
]

NOTES_HEADING = "## General Notes"


def anchor(heading: str) -> str:
    """The anchor that GitHub makes for HEADING."""
    return heading.lower().replace(" ", "-")


def parameter_line(name: str, spec: dict[str, Any], required: bool) -> str:
    """The line describing parameter NAME, whose JSON schema is SPEC."""
    details = [spec["type"]] if "type" in spec else []
    details.append("required" if required else "optional")
    description = spec.get("description", "")
    if "default" in spec and "default" not in description.lower():
        default = spec["default"]
        details.append(f"default {str(default).lower() if isinstance(default, bool) else default}")
    return f"- `{name}` ({', '.join(details)}): {description}"


def render(tools: list[Any], notes: str) -> str:
    """tool-doc.md for TOOLS (as list_tools() returns them), ending with
    NOTES, the General Notes section."""
    by_name = {tool.name: tool for tool in tools}
    placed = [name for _, names in CATEGORIES for name in names]
    if missing := sorted(set(by_name) - set(placed)):
        raise ValueError(f"no category for {', '.join(missing)}: add it to CATEGORIES "
                         f"in {Path(__file__).name}")
    if gone := [name for name in placed if name not in by_name]:
        raise ValueError(f"no such tool: {', '.join(gone)}: remove it from CATEGORIES "
                         f"in {Path(__file__).name}")

    out = [
        "# ACL2 MCP Server - Tool Reference",
        "",
        "> **Note**: The tool sections of this file are generated from the tool "
        "definitions in `acl2_mcp/server.py` by `scripts/gen_tool_doc.py`: change "
        "a description there, then run `python scripts/gen_tool_doc.py`.  "
        "The General Notes section at the end is written by hand.",
        "",
        f"This document describes the {len(tools)} tools of the ACL2 MCP server, "
        "as an agent sees them: each tool's description and parameters.",
        "",
        "## Table of Contents",
        "",
    ]
    for heading, names in CATEGORIES:
        out.append(f"- [{heading}](#{anchor(heading)})")
        out.extend(f"  - [{name}](#{name})" for name in names)
    out += [f"- [General Notes](#{anchor('General Notes')})", "", "---", ""]

    for heading, names in CATEGORIES:
        out += [f"## {heading}", ""]
        for name in names:
            tool = by_name[name]
            schema = tool.inputSchema
            required = set(schema.get("required", []))
            parameters = [parameter_line(param, spec, param in required)
                          for param, spec in schema.get("properties", {}).items()]
            out += [f"### {name}", "", tool.description.strip(), "",
                    "**Parameters:**", "", *(parameters or ["None"]), "", "---", ""]
    return "\n".join(out) + "\n" + notes


def notes_section(text: str) -> str:
    """The General Notes section of TEXT, an existing tool-doc.md."""
    start = text.find(f"\n{NOTES_HEADING}\n")
    if start < 0:
        raise ValueError(f"{TOOL_DOC.name} has no '{NOTES_HEADING}' section")
    return text[start + 1:]


def generate() -> str:
    """tool-doc.md as it should be."""
    return render(asyncio.run(list_tools()), notes_section(TOOL_DOC.read_text()))


def main() -> None:
    text = generate()
    if "--check" in sys.argv[1:]:
        if TOOL_DOC.read_text() != text:
            sys.exit(f"{TOOL_DOC.name} is out of date: run python scripts/gen_tool_doc.py")
        return
    TOOL_DOC.write_text(text)


if __name__ == "__main__":
    main()
