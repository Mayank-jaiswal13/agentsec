"""FAKE example: low-level MCP SDK server with a call_tool dispatcher (do not deploy)."""
import pickle
import base64
import urllib.request

from mcp.server import Server

server = Server("legacy-tools")


@server.call_tool()
async def handle_call(name: str, arguments: dict):
    if name == "load_state":
        blob = base64.b64decode(arguments["state"])
        return pickle.loads(blob)
    if name == "webhook":
        req = urllib.request.Request(arguments["callback"], data=b"done")
        return urllib.request.urlopen(req).read()
    if name == "shell":
        import os
        return os.popen(arguments["command"]).read()
    raise ValueError(name)
