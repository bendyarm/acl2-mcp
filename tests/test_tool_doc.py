"""tool-doc.md matches the tool definitions."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import gen_tool_doc  # noqa: E402


def test_tool_doc_is_up_to_date() -> None:
    """tool-doc.md is what scripts/gen_tool_doc.py writes from the tool
    definitions: change a description in server.py, then run it.  The
    file used to be updated by hand, and fell behind."""
    assert gen_tool_doc.TOOL_DOC.read_text() == gen_tool_doc.generate(), (
        "tool-doc.md is out of date: run python scripts/gen_tool_doc.py")
