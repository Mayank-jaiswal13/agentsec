"""FAKE example: a deliberately vulnerable MCP server (do not deploy)."""
import os
import sqlite3
import subprocess
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("workspace-helper", host="0.0.0.0")
ROOT = Path("/srv/workspace")
API_TOKEN = os.environ.get("FAKE_EXAMPLE_TOKEN", "FAKE-EXAMPLE-not-a-real-token")


@mcp.tool(annotations={"readOnlyHint": True})
def read_file(path: str, ctx: Context) -> str:
    """Read a file from the workspace."""
    full = ROOT / path                      # '../../home/user/.ssh/id_rsa' escapes ROOT
    return full.read_text()


@mcp.tool()
def delete_file(name: str) -> str:
    """Delete a workspace file."""
    os.remove(os.path.join(ROOT, name))
    return "deleted"


@mcp.tool(annotations={"readOnlyHint": True})
def grep(pattern: str, folder: str = ".") -> str:
    """Search files."""
    cmd = f"grep -rn '{pattern}' {folder}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def git_log(ref: str) -> str:
    """Show git log for a ref."""
    return subprocess.check_output(["git", "log", ref], text=True)


@mcp.tool()
async def fetch_url(url: str) -> str:
    """Fetch a web page for the model."""
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers={"Authorization": "Bearer " + API_TOKEN})
        return r.text


@mcp.tool()
def query_orders(customer: str) -> list:
    """Look up a customer's orders."""
    db = sqlite3.connect("orders.db")
    return db.execute(f"SELECT * FROM orders WHERE customer = '{customer}'").fetchall()


@mcp.tool()
def run_sql(sql: str) -> list:
    """Run a read-only report query."""
    return sqlite3.connect("orders.db").execute(sql).fetchall()


@mcp.tool()
def calc(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))


@mcp.tool()
def get_config(key: str) -> str:
    """Return a configuration value."""
    return os.getenv(key, "")


@mcp.tool()
def debug_info() -> dict:
    """Diagnostics."""
    return {"cwd": os.getcwd(), "env": dict(os.environ)}


@mcp.resource("notes://{note_id}")
def note(note_id: str) -> str:
    return open(f"/srv/notes/{note_id}.md").read()


def _archive(target, label):
    subprocess.run("tar czf /tmp/%s.tgz %s" % (label, target), shell=True)


@mcp.tool()
def backup(directory: str) -> str:
    """Archive a directory."""
    _archive(directory, "backup")
    return "ok"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
