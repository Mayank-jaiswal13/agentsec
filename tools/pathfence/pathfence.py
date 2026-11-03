#!/usr/bin/env python3
"""pathfence: offline sensitive-path / path-traversal auditor for AI agent tool calls.

Agents with read_file, write_file, edit, bash, or MCP filesystem tools can be steered
into secret stores, SSH keys, cloud credential files, browser password DBs, or paths
outside the intended workspace. pathfence extracts file-path arguments (and path-like
tokens inside shell commands) from saved transcripts (OpenAI, Anthropic, generic
JSON/JSONL) or from a plain path list, classifies each path, and reports findings
with tool + turn attribution.

Complements fetchfence (URL destinations), toolgate (policy you write), yolocheck
(static autonomy settings) and tracesweep (secret *values* in content). Stdlib only;
never runs an agent or contacts a network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "PF01": ("critical", "Secret / credential file path (.env, keys, tokens, secrets)"),
    "PF02": ("critical", "SSH / GPG private key path"),
    "PF03": ("critical", "Cloud provider credential path (AWS/GCP/Azure/kube)"),
    "PF04": ("high", "Browser cookie / password / autofill database path"),
    "PF05": ("critical", "OS identity / shadow / SAM / NTDS path"),
    "PF06": ("high", "Path traversal segment (../ or ..\\)"),
    "PF07": ("high", "Absolute path outside configured workspace roots"),
    "PF08": ("medium", "Broad home-directory or dotfile read (~/, $HOME, ~/.*)"),
    "PF09": ("high", "Write/delete targeting a sensitive path"),
    "PF10": ("high", "Container / hypervisor escape path (docker.sock, /proc, /sys)"),
    "PF11": ("high", "Windows sensitive system path (SAM, SECURITY, Unattend, NTDS)"),
    "PF12": ("info", "Inventory of file paths observed in tool calls"),
}

# Tool-name tokens that usually mean "agent is touching the filesystem"
FILE_TOKENS = {
    "read", "write", "edit", "create", "delete", "remove", "unlink", "rm",
    "open", "cat", "head", "tail", "stat", "list", "ls", "glob", "find",
    "file", "path", "fs", "filesystem", "directory", "dir", "folder",
    "save", "load", "append", "patch", "apply_patch", "applypatch",
    "move", "mv", "copy", "cp", "rename", "chmod", "chown", "touch",
    "mkdir", "rmdir", "upload", "download", "attach", "notebook",
    "bash", "shell", "exec", "execute", "run_command", "run_terminal",
    "terminal", "powershell", "pwsh", "cmd",
}

PATH_ARG_KEYS = {
    "path", "file", "filename", "filepath", "file_path", "target", "dest",
    "destination", "src", "source", "directory", "dir", "folder", "cwd",
    "workdir", "working_directory", "root", "roots", "output", "outfile",
    "infile", "input", "location", "name", "to", "from", "glob", "pattern",
}

WRITE_TOKENS = {
    "write", "edit", "create", "delete", "remove", "unlink", "rm", "save",
    "append", "patch", "apply", "move", "mv", "copy", "cp", "rename",
    "chmod", "chown", "mkdir", "rmdir", "touch", "truncate", "overwrite",
}

SHELL_TOKENS = {"bash", "shell", "exec", "execute", "terminal", "powershell", "pwsh", "cmd", "run"}

# Basename / suffix patterns for secret files (matched case-insensitive on final component)
SECRET_BASENAME_RE = re.compile(
    r"(?i)^("
    r"\.env(?:\..+)?|"
    r"\.env\.local|\.env\.production|\.env\.staging|\.env\.development|"
    r"secrets?(?:\.(?:json|ya?ml|toml|env|txt|cfg|ini))?|"
    r"credentials?(?:\.(?:json|ya?ml|toml|txt|csv|cfg|ini))?|"
    r".*\.pem$|.*\.p12$|.*\.pfx$|.*\.jks$|.*\.keystore$|"
    r"id_rsa|id_dsa|id_ecdsa|id_ed25519|.*_rsa$|.*_ed25519$|"
    r"auth(?:\.json)?|token(?:s)?(?:\.(?:json|txt|ya?ml))?|"
    r"service[-_]?account(?:[-_].*)?\.json|"
    r"application[-_]?default[-_]?credentials\.json|"
    r"netrc|\.netrc|"
    r"htpasswd|\.htpasswd|"
    r"master\.key|secret[-_]?key(?:\.(?:pem|txt|json))?|"
    r"private[-_]?key(?:\.(?:pem|txt|json|key))?|"
    r".*\.key$"
    r")$"
)

# Path substring patterns for secrets (posix-normalized, lowercased)
SECRET_PATH_RE = re.compile(
    r"(?i)("
    r"(?:^|/)(?:\.env)(?:$|/|\.)|"
    r"(?:^|/)(?:secrets?)(?:$|/|\.)|"
    r"(?:^|/)(?:credentials?)(?:$|/|\.)|"
    r"/etc/(?:shadow|passwd|gshadow|sudoers)|"
    r"(?:^|/)\.npmrc$|(?:^|/)\.pypirc$"
    r")"
)

SSH_GPG_RE = re.compile(
    r"(?i)("
    r"(?:^|/)\.ssh/(?:id_|authorized_keys|config|known_hosts)|"
    r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:$|\.)|"
    r"(?:^|/)\.gnupg/|"
    r"(?:^|/)secring\.gpg$"
    r")"
)

CLOUD_CRED_RE = re.compile(
    r"(?i)("
    r"(?:^|/)\.aws/(?:credentials|config|cli/cache)|"
    r"(?:^|/)\.config/gcloud/|"
    r"(?:^|/)\.config/gcloud/application_default_credentials\.json|"
    r"application_default_credentials\.json|"
    r"(?:^|/)\.azure/|"
    r"(?:^|/)\.kube/config|"
    r"(?:^|/)\.docker/config\.json|"
    r"(?:^|/)\.config/gh/hosts\.yml|"
    r"service[-_]?account(?:[-_].*)?\.json"
    r")"
)

BROWSER_DB_RE = re.compile(
    r"(?i)("
    r"(?:Cookies|Login Data|Web Data|History|Bookmarks)(?:-journal)?$|"
    r"/Chrome/.*/(Cookies|Login Data|Web Data)|"
    r"/Firefox/.*/(cookies\.sqlite|logins\.json|key[0-9]*\.db)|"
    r"/Brave-Browser/.*/(Cookies|Login Data)|"
    r"Keychain|login\.keychain|"
    r"Credentials(/|$)|Vault(/|$)"
    r")"
)

OS_IDENTITY_RE = re.compile(
    r"(?i)("
    r"/etc/(?:shadow|gshadow|master\.passwd|sudoers)|"
    r"/etc/passwd$|"
    r"(?:^|/)(?:SAM|SECURITY|SYSTEM)(?:$|\.)|"
    r"\\\\(?:SAM|SECURITY|SYSTEM)$|"
    r"ntds\.dit|"
    r"/etc/ssh/ssh_host_.*_key$"
    r")"
)

WINDOWS_SENSITIVE_RE = re.compile(
    r"(?i)("
    r"(?:^|[\\/])Windows[\\/]System32[\\/]config[\\/](?:SAM|SECURITY|SYSTEM|SOFTWARE)|"
    r"Unattend(?:ed)?\.xml|"
    r"ntds\.dit|"
    r"(?:^|[\\/])inetpub[\\/]|"
    r"web\.config$"
    r")"
)

CONTAINER_ESCAPE_RE = re.compile(
    r"(?i)("
    r"(?:^|/)var/run/docker\.sock$|"
    r"(?:^|/)run/docker\.sock$|"
    r"(?:^|/)proc/(?:self/|1/|sys/)|"
    r"(?:^|/)sys/(?:class|devices|fs|kernel)/|"
    r"(?:^|/)dev/(?:mem|kmem|sda|nvme)|"
    r"containerd\.sock|podman\.sock|crio\.sock"
    r")"
)

TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")

HOME_BROAD_RE = re.compile(
    r"(?i)^(?:"
    r"~/?$|"
    r"\$\{?HOME\}?/?$|"
    r"%USERPROFILE%\\?$|"
    r"~/\\.|"
    r"\$\{?HOME\}?/\.|"
    r"/home/[^/]+/?$|"
    r"/Users/[^/]+/?$"
    r")"
)

# Paths that look like placeholders / benign examples
PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|example(?:\.(?:com|txt|py|md))?|"
    r"\$\{?[A-Z0-9_]+\}?|<[^>]+>|your[-_].*|xxx+|placeholder.*|"
    r"\./README\.md|\./src/.*|file\.txt|path/to/.*)$"
)

# Extract path-looking tokens from shell command strings
SHELL_PATH_RE = re.compile(
    r"(?ix)"
    r"(?<![\w])"
    r"("
    r"(?:~|\$\{?HOME\}?|\$\{?PWD\}?|%USERPROFILE%)"
    r"(?:/[^\s;|&\"']+)+"
    r"|"
    r"(?:/(?:etc|var|home|Users|root|proc|sys|dev|tmp|opt|usr|run)(?:/[^\s;|&\"']*)?)"
    r"|"
    r"(?:\.\./[^\s;|&\"']+)+"
    r"|"
    r"(?:[A-Za-z]:\\[^\s;|&\"']+)"
    r"|"
    r"(?:/(?:[A-Za-z0-9._${}-]+/)+[A-Za-z0-9._${}-]+)"
    r")"
)

SHELL_CMD_KEYS = {
    "command", "cmd", "script", "code", "input", "argv", "shell", "bash", "line",
}


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "path", "tool", "turn", "op")

    def __init__(self, rule, source, message, path="", tool="", turn=None, op="read"):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.path = path
        self.tool = tool
        self.turn = turn
        self.op = op

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "path": self.path,
            "tool": self.tool,
            "op": self.op,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        return d


def _tool_words(name: str):
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if w]


def is_file_tool(name: str) -> bool:
    words = set(_tool_words(name))
    joined = "".join(words)
    if words & FILE_TOKENS:
        return True
    lower = (name or "").lower()
    for tok in ("read_file", "write_file", "list_dir", "apply_patch", "run_terminal",
                "run_command", "execute_command", "filesystem"):
        if tok.replace("_", "") in joined or tok in lower:
            return True
    return False


def is_write_tool(name: str) -> bool:
    words = set(_tool_words(name))
    if words & WRITE_TOKENS:
        return True
    lower = (name or "").lower()
    return any(t in lower for t in ("write", "delete", "remove", "unlink", "edit",
                                    "create_file", "apply_patch", "mkdir", "rmdir"))


def is_shell_tool(name: str) -> bool:
    words = set(_tool_words(name))
    if words & SHELL_TOKENS:
        return True
    lower = (name or "").lower()
    return any(t in lower for t in ("bash", "shell", "run_command", "execute_command",
                                    "run_terminal", "powershell"))


def _norm_path(p: str) -> str:
    """Normalize separators for matching; keep leading ~ and drive letters."""
    if not p:
        return p
    s = p.strip().strip("\"'")
    s = s.replace("\\", "/")
    # collapse duplicate slashes but keep leading // for UNC? treat as /
    while "//" in s and not s.startswith("\\\\"):
        s = s.replace("//", "/")
    return s


def _basename(p: str) -> str:
    s = _norm_path(p)
    if "/" in s:
        return s.rsplit("/", 1)[-1]
    return s


def _looks_like_path(s: str) -> bool:
    if not s or len(s) > 1024:
        return False
    s = s.strip()
    if PLACEHOLDER_RE.match(s):
        return False
    if "://" in s and not s.lower().startswith("file:"):
        return False  # URLs belong to fetchfence
    if s.startswith("file://"):
        return True
    if s.startswith(("~/", "~\\", "~", "/", "$HOME", "${HOME}", "%USERPROFILE%", ".")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", s):
        return True
    if "/" in s or "\\" in s:
        # require a path-ish character besides a lone module name
        if re.search(r"[/\\~.$]", s):
            return True
    return False


def _strip_file_url(s: str) -> str:
    if s.lower().startswith("file://"):
        # file:///etc/passwd → /etc/passwd ; file://localhost/etc → /etc
        rest = s[7:]
        if rest.startswith("localhost"):
            rest = rest[9:]
        return rest or "/"
    return s


def extract_paths_from_args(args: dict, tool_name: str = ""):
    """Yield (path, from_key) from tool arguments."""
    found = []
    shellish = is_shell_tool(tool_name)

    def add(val, key):
        if not isinstance(val, str):
            return
        s = val.strip()
        if not s or PLACEHOLDER_RE.match(s):
            return
        s = _strip_file_url(s)
        if _looks_like_path(s):
            found.append((s, key))

    for k, v in (args or {}).items():
        key_l = str(k).lower()
        if isinstance(v, str):
            if key_l in PATH_ARG_KEYS or key_l.endswith("_path") or key_l.endswith("path") \
                    or key_l.endswith("_file") or key_l.endswith("file") \
                    or key_l.endswith("_dir") or key_l.endswith("dir"):
                add(v, key_l)
            elif shellish and key_l in SHELL_CMD_KEYS:
                for m in SHELL_PATH_RE.finditer(v):
                    add(m.group(1), key_l)
            elif _looks_like_path(v) and ("/" in v or "\\" in v or v.startswith("~")):
                # opportunistic: path-shaped string values
                add(v, key_l)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    if key_l in PATH_ARG_KEYS or _looks_like_path(item):
                        add(item, key_l)
                elif isinstance(item, dict):
                    found.extend(extract_paths_from_args(item, tool_name))
        elif isinstance(v, dict):
            found.extend(extract_paths_from_args(v, tool_name))

    seen = set()
    out = []
    for p, k in found:
        if p not in seen:
            seen.add(p)
            out.append((p, k))
    return out


class PathEvent:
    __slots__ = ("source", "tool", "turn", "path", "key", "op")

    def __init__(self, source, tool, path, turn=None, key="", op="read"):
        self.source = source
        self.tool = tool
        self.path = path
        self.turn = turn
        self.key = key
        self.op = op


def _parse_args(raw):
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else {"_": val}
        except ValueError:
            return {"_": raw}
    return {"_": raw}


def _iter_messages(doc):
    if isinstance(doc, dict):
        if isinstance(doc.get("messages"), list):
            return doc["messages"]
        if isinstance(doc.get("items"), list):
            return doc["items"]
    if isinstance(doc, list):
        return doc
    return None


def extract_paths_from_obj(doc, source: str):
    events = []
    msgs = _iter_messages(doc)
    if msgs is not None:
        for i, msg in enumerate(msgs):
            if not isinstance(msg, dict):
                continue
            role = (msg.get("role") or "").lower()
            tcalls = msg.get("tool_calls") or msg.get("function_call")
            if tcalls:
                if isinstance(tcalls, dict):
                    tcalls = [tcalls]
                for tc in tcalls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or tc
                    name = fn.get("name") or tc.get("name") or ""
                    args = _parse_args(fn.get("arguments") or tc.get("arguments") or tc.get("input"))
                    paths = extract_paths_from_args(args, name)
                    if is_file_tool(name) or paths:
                        op = "write" if is_write_tool(name) else ("shell" if is_shell_tool(name) else "read")
                        for path, key in paths:
                            if is_file_tool(name) or key in PATH_ARG_KEYS or "path" in key or "file" in key \
                                    or key in SHELL_CMD_KEYS:
                                events.append(PathEvent(source, name, path, turn=i, key=key, op=op))
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") in ("tool_use", "tool_call", "function_call"):
                        name = block.get("name") or ""
                        args = _parse_args(block.get("input") or block.get("arguments") or {})
                        paths = extract_paths_from_args(args, name)
                        if is_file_tool(name) or paths:
                            op = "write" if is_write_tool(name) else ("shell" if is_shell_tool(name) else "read")
                            for path, key in paths:
                                if is_file_tool(name) or key in PATH_ARG_KEYS or "path" in key or "file" in key \
                                        or key in SHELL_CMD_KEYS:
                                    events.append(PathEvent(source, name, path, turn=i, key=key, op=op))
            if role in ("assistant", "tool", "") and msg.get("tool") and (
                msg.get("args") or msg.get("arguments") or msg.get("input")
            ):
                name = msg.get("tool") or msg.get("name") or ""
                args = _parse_args(msg.get("args") or msg.get("arguments") or msg.get("input"))
                paths = extract_paths_from_args(args, name)
                if is_file_tool(name) or paths:
                    op = "write" if is_write_tool(name) else ("shell" if is_shell_tool(name) else "read")
                    for path, key in paths:
                        events.append(PathEvent(source, name, path, turn=i, key=key, op=op))
        return events

    if isinstance(doc, dict):
        name = doc.get("tool") or doc.get("name") or doc.get("tool_name") or ""
        args = _parse_args(doc.get("args") or doc.get("arguments") or doc.get("input") or doc.get("parameters"))
        paths = extract_paths_from_args(args, name)
        if not paths and isinstance(doc.get("path"), str):
            paths = [(doc["path"], "path")]
        if name or paths:
            op = "write" if is_write_tool(name) else ("shell" if is_shell_tool(name) else "read")
            for path, key in paths:
                if not name or is_file_tool(name) or key in PATH_ARG_KEYS or "path" in key or "file" in key \
                        or key in SHELL_CMD_KEYS:
                    events.append(PathEvent(source, name or "path", path, turn=doc.get("turn"), key=key, op=op))
    return events


def load_events(path: str, as_paths: bool = False):
    """Load path events from a file path or '-' (stdin)."""
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path

    if as_paths or path.endswith(".txt") or (
        not raw.lstrip().startswith(("{", "["))
        and any(c in raw for c in ("/", "\\", "~"))
        and "tool_calls" not in raw and "tool_use" not in raw
    ):
        # Heuristic: plain path list if not JSON-shaped
        if as_paths or path.endswith(".txt") or not raw.lstrip().startswith(("{", "[")):
            events = []
            # But if it looks like JSON, fall through
            if not as_paths and not path.endswith(".txt") and raw.lstrip().startswith(("{", "[")):
                pass
            else:
                for line_no, line in enumerate(raw.splitlines(), 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    s = _strip_file_url(s)
                    events.append(PathEvent("%s:%d" % (source, line_no), "path-list", s,
                                            turn=line_no, key="line", op="read"))
                if as_paths or path.endswith(".txt") or events:
                    # only return early for explicit path lists
                    if as_paths or path.endswith(".txt"):
                        return events
                    # ambiguous text: if no JSON, use path list
                    if not raw.lstrip().startswith(("{", "[")):
                        return events

    events = []
    lines = raw.splitlines()
    jsonl_ok = False
    if len(lines) > 1:
        parsed_lines = []
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                parsed_lines.append(json.loads(s))
                jsonl_ok = True
            except ValueError:
                jsonl_ok = False
                break
        if jsonl_ok:
            for i, obj in enumerate(parsed_lines):
                ev = extract_paths_from_obj(obj, source)
                for e in ev:
                    if e.turn is None:
                        e.turn = i
                events.extend(ev)
            return events

    try:
        doc = json.loads(raw)
    except ValueError:
        events = []
        for line_no, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            s = _strip_file_url(s)
            events.append(PathEvent("%s:%d" % (source, line_no), "path-list", s,
                                    turn=line_no, key="line", op="read"))
        return events

    return extract_paths_from_obj(doc, source)


def _path_allowed(path: str, allow_globs: list[str]) -> bool:
    if not allow_globs:
        return False
    import fnmatch
    n = _norm_path(path)
    for g in allow_globs:
        if fnmatch.fnmatch(n, g) or fnmatch.fnmatch(n, g.replace("\\", "/")):
            return True
        # also try basename match for simple names
        if fnmatch.fnmatch(_basename(n), g):
            return True
    return False


def _outside_workspace(path: str, workspaces: list[str]) -> bool:
    """True if absolute/home path and not under any workspace root."""
    if not workspaces:
        return False
    n = _norm_path(path)
    # relative paths are considered inside
    if not (n.startswith(("/", "~", "$HOME", "${HOME}", "%USERPROFILE%"))
            or re.match(r"^[A-Za-z]:/", n)):
        return False
    # expand ~ for comparison only against workspace strings as-is
    candidates = [n]
    if n.startswith("~/"):
        candidates.append("/home/user/" + n[2:])
        candidates.append("/Users/user/" + n[2:])
    for ws in workspaces:
        ws_n = _norm_path(ws).rstrip("/")
        for c in candidates:
            if c == ws_n or c.startswith(ws_n + "/"):
                return False
            # also allow if workspace is given as ~
            if ws_n in ("~", "$HOME", "${HOME}") and (c.startswith("~/") or c.startswith("/home/") or c.startswith("/Users/")):
                return False
    return True


def classify_path(path: str, source: str, tool: str = "", turn=None, op: str = "read",
                  allow_paths=None, workspaces=None, disabled=None):
    """Return findings for one path."""
    allow_paths = allow_paths or []
    workspaces = workspaces or []
    disabled = set(disabled or [])
    findings = []

    def add(rule, message):
        if rule in disabled:
            return
        findings.append(Finding(rule, source, message, path=path, tool=tool, turn=turn, op=op))

    raw = (path or "").strip()
    if not raw or PLACEHOLDER_RE.match(raw):
        return findings

    n = _norm_path(_strip_file_url(raw))
    base = _basename(n)

    if _path_allowed(n, allow_paths):
        # Still flag traversal and OS identity even on allowlisted paths
        if TRAVERSAL_RE.search(n) and "PF06" not in disabled:
            add("PF06", "Path traversal segment in allowlisted path")
        if OS_IDENTITY_RE.search(n) and "PF05" not in disabled:
            add("PF05", "OS identity/shadow path on allowlist: %s" % n)
        return findings

    # PF06 traversal first (often combined with others)
    if TRAVERSAL_RE.search(n):
        add("PF06", "Path traversal segment in %r" % n)

    # PF02 SSH/GPG
    if SSH_GPG_RE.search(n) or re.match(r"(?i)^id_(rsa|dsa|ecdsa|ed25519)$", base):
        add("PF02", "SSH/GPG key path %r" % n)

    # PF03 cloud creds
    if CLOUD_CRED_RE.search(n):
        add("PF03", "Cloud credential path %r" % n)

    # PF05 OS identity
    if OS_IDENTITY_RE.search(n):
        add("PF05", "OS identity / shadow path %r" % n)

    # PF11 Windows
    if WINDOWS_SENSITIVE_RE.search(n) or WINDOWS_SENSITIVE_RE.search(raw.replace("/", "\\")):
        add("PF11", "Windows sensitive system path %r" % n)

    # PF10 container escape
    if CONTAINER_ESCAPE_RE.search(n):
        add("PF10", "Container/hypervisor sensitive path %r" % n)

    # PF04 browser DBs
    if BROWSER_DB_RE.search(n):
        add("PF04", "Browser cookie/password database path %r" % n)

    # PF01 secrets (basename + path patterns) — after more specific rules
    if SECRET_BASENAME_RE.match(base) or SECRET_PATH_RE.search(n):
        # avoid double-counting pure SSH key basenames already PF02
        if not (SSH_GPG_RE.search(n) or re.match(r"(?i)^id_(rsa|dsa|ecdsa|ed25519)$", base)):
            add("PF01", "Secret/credential file path %r" % n)
        elif SECRET_BASENAME_RE.match(base) and base.lower().startswith("id_"):
            pass  # covered by PF02
        else:
            # .pem etc. next to ssh already flagged; still note PF01 for .env etc.
            if re.search(r"(?i)\.env|secret|credential|token|\.pem|\.p12|netrc|htpasswd|master\.key", base):
                if not SSH_GPG_RE.search(n):
                    add("PF01", "Secret/credential file path %r" % n)

    # PF08 broad home
    if HOME_BROAD_RE.match(n) or HOME_BROAD_RE.match(raw.strip()):
        add("PF08", "Broad home-directory or dotfile path %r" % n)
    elif re.match(r"(?i)^~/(\.[^/]+)/?$", n) or re.match(r"(?i)^\$\{?HOME\}?/(\.[^/]+)/?$", n):
        add("PF08", "Home dotfile/directory path %r" % n)

    # PF07 outside workspace
    if workspaces and _outside_workspace(n, workspaces):
        add("PF07", "Path outside workspace roots %r" % n)

    # PF09 write to sensitive — escalate when op is write/shell and any high+ finding exists
    # Actually PF09 is its own rule when writing to sensitive paths
    sensitive_hit = any(f.rule in ("PF01", "PF02", "PF03", "PF04", "PF05", "PF10", "PF11") for f in findings)
    if op in ("write", "shell") and sensitive_hit:
        add("PF09", "Write/shell targeting sensitive path %r" % n)
    elif op == "write" and (SECRET_BASENAME_RE.match(base) or SSH_GPG_RE.search(n) or CLOUD_CRED_RE.search(n)):
        add("PF09", "Write targeting sensitive path %r" % n)

    return findings


def collect_paths(args_paths):
    paths = []
    for p in args_paths:
        if p == "-":
            paths.append(p)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
                for fn in sorted(files):
                    if fn.endswith((".json", ".jsonl", ".txt", ".md")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, events_count, paths_set, inventory=False):
    lines = []
    lines.append("pathfence %s — %d path event(s), %d unique path(s), %d finding(s)" % (
        VERSION, events_count, len(paths_set), len(findings)))
    if not findings:
        lines.append("No sensitive-path findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-18s %-6s %s" % ("RULE", "SEV", "TOOL", "OP", "MESSAGE"))
    lines.append("-" * 96)
    for f in findings:
        lines.append("%-6s %-8s %-18s %-6s %s" % (
            f.rule, f.severity, (f.tool or "-")[:18], (f.op or "-")[:6], f.message[:80]))
        lines.append("       path: %s" % f.path)
        if f.source:
            loc = f.source
            if f.turn is not None:
                loc += " turn=%s" % f.turn
            lines.append("       at:   %s" % loc)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pathfence",
        description="Offline sensitive-path / path-traversal auditor for AI agent tool calls.",
    )
    ap.add_argument("paths", nargs="*", help="transcripts, path lists, or directories (or - for stdin)")
    ap.add_argument("--as-paths", action="store_true", help="treat inputs as plain path lists")
    ap.add_argument("--allow-path", action="append", default=[], metavar="GLOB",
                    help="allowlist path glob (repeatable); still flags traversal + OS identity")
    ap.add_argument("--workspace", action="append", default=[], metavar="ROOT",
                    help="expected workspace root (repeatable); enables PF07 outside-root checks")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument("--fail-on", default="high",
                    choices=SEVERITIES + ["any", "none"],
                    help="exit 1 if any finding >= this severity (default high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="pathfence " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    file_paths = collect_paths(ns.paths)
    if not file_paths:
        sys.stderr.write("pathfence: no readable inputs\n")
        return 2

    all_events = []
    errors = 0
    for path in file_paths:
        try:
            all_events.extend(load_events(path, as_paths=ns.as_paths))
        except OSError as e:
            sys.stderr.write("pathfence: %s: %s\n" % (path, e))
            errors += 1

    if errors and not all_events:
        return 2

    findings = []
    path_set = set()
    disabled = set(ns.disable or [])
    for ev in all_events:
        path_set.add(_norm_path(ev.path))
        findings.extend(classify_path(
            ev.path, ev.source, tool=ev.tool, turn=ev.turn, op=ev.op,
            allow_paths=ns.allow_path, workspaces=ns.workspace, disabled=disabled,
        ))

    # PF12 inventory (one finding per unique path unless disabled)
    if "PF12" not in disabled:
        for p in sorted(path_set):
            # find a representative event
            ev = next((e for e in all_events if _norm_path(e.path) == p), None)
            findings.append(Finding(
                "PF12",
                ev.source if ev else "",
                "Observed path %r" % p,
                path=p,
                tool=ev.tool if ev else "",
                turn=ev.turn if ev else None,
                op=ev.op if ev else "read",
            ))

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.path or "", f.tool or ""))

    if ns.json:
        print(json.dumps({
            "tool": "pathfence",
            "version": VERSION,
            "events": len(all_events),
            "paths": sorted(path_set),
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, len(all_events), path_set))

    # For fail-on, ignore pure inventory (PF12 info) unless fail-on is info/any
    actionable = [f for f in shown if f.rule != "PF12"]
    if ns.fail_on == "none":
        return 0
    if ns.fail_on == "any":
        return 1 if actionable else 0
    threshold = SEV_RANK[ns.fail_on]
    pool = shown if ns.fail_on == "info" else actionable
    if any(SEV_RANK[f.severity] >= threshold for f in pool):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
