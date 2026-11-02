"""FAKE example: the same kinds of tools written defensively."""
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace-helper", host="127.0.0.1")
ROOT = Path("/srv/workspace").resolve()
ALLOWED_HOSTS = {"docs.example.com", "api.example.com"}
ALLOWED_SETTINGS = {"theme": "THEME", "locale": "LOCALE"}
REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,100}")


def _inside_root(path: str) -> Path:
    full = (ROOT / path).resolve()
    if not full.is_relative_to(ROOT):
        raise ValueError("path escapes workspace")
    return full


@mcp.tool(annotations={"readOnlyHint": True})
def read_file(path: str) -> str:
    """Read a file from the workspace."""
    full = (ROOT / path).resolve()
    if not full.is_relative_to(ROOT):
        raise ValueError("path escapes workspace")
    return full.read_text()


@mcp.tool(annotations={"destructiveHint": True})
def delete_file(name: str) -> str:
    """Delete a workspace file (basename only)."""
    os.remove(os.path.join(ROOT, os.path.basename(name)))
    return "deleted"


@mcp.tool(annotations={"readOnlyHint": True})
def file_size(path: str) -> int:
    """Size of a workspace file."""
    target = _inside_root(path)
    return len(target.read_bytes())


@mcp.tool(annotations={"destructiveHint": False})
def show_ref(ref: str) -> str:
    """Show a git ref (validated, after '--')."""
    if not REF_RE.fullmatch(ref):
        raise ValueError("bad ref")
    return subprocess.run(["git", "show", "--stat", "--", ref], capture_output=True, text=True).stdout


@mcp.tool(annotations={"readOnlyHint": True})
def word_count(text: str) -> int:
    """Count words."""
    return len(text.split())


@mcp.tool()
def fetch_doc(url: str) -> str:
    """Fetch an allowlisted documentation page."""
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return httpx.get(url, timeout=10).text


@mcp.tool(annotations={"readOnlyHint": True})
def query_orders(customer: str) -> list:
    """Look up a customer's orders."""
    db = sqlite3.connect("orders.db")
    return db.execute("SELECT * FROM orders WHERE customer = ?", (customer,)).fetchall()


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
def get_setting(key: str) -> str:
    """Return an allowlisted setting."""
    if key not in ALLOWED_SETTINGS:
        raise ValueError("unknown setting")
    return os.environ.get(ALLOWED_SETTINGS[key], "")


@mcp.tool(annotations={"readOnlyHint": True})
def page(n: int) -> str:
    """Return page n of the changelog."""
    return Path("/srv/CHANGELOG.md").read_text().split("\n\n")[int(n)]


if __name__ == "__main__":
    mcp.run(transport="stdio")
