#!/usr/bin/env python3
"""mcpposture - offline least-privilege & supply-chain risk auditor for MCP client configs.

Static review of MCP (Model Context Protocol) client configuration files
(Claude Desktop, Cursor, VS Code, Windsurf/Cline/Gemini-style, generic
{"mcpServers": {...}}). It never launches servers, never touches the network,
and cannot see what a server does at runtime or verify token scopes.

Standard library only. MIT licensed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

__version__ = "0.1.0"
TOOL_NAME = "mcpposture"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"info": 0, "low": 3, "medium": 8, "high": 20, "critical": 40}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES: Dict[str, Dict[str, str]] = {
    "MP01": {"name": "inline-secret", "severity": "high",
             "rationale": "Secret value is stored in plaintext in the config file (env, header, or arg); config files get synced, shared, committed and read by other tools.",
             "fix": "Reference it instead: ${VAR}/${env:VAR}, VS Code ${input:id} with password:true, or an OS keychain/secret manager."},
    "MP02": {"name": "inline-bearer-token", "severity": "high",
             "rationale": "Authorization header carries a literal Bearer/Basic credential.",
             "fix": "Use ${input:...}/${env:...} substitution or the client's OAuth flow instead of a pasted token."},
    "MP03": {"name": "unpinned-package", "severity": "medium",
             "rationale": "Package/image is fetched at launch without an exact version (or @latest); a compromised or hijacked release runs with your privileges on next start.",
             "fix": "Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) and review upgrades deliberately."},
    "MP04": {"name": "auto-install-no-prompt", "severity": "low",
             "rationale": "`npx -y`/`--yes` installs whatever resolves without confirmation.",
             "fix": "Pin the version; preferably install once to a vetted location and run the local binary."},
    "MP05": {"name": "docker-privileged", "severity": "high",
             "rationale": "Container launched with privileges that weaken isolation (privileged, host network/pid/ipc, added caps, host root or docker.sock mounts, unconfined seccomp/apparmor).",
             "fix": "Drop the flag; mount only the specific directories needed, read-only where possible; never mount docker.sock."},
    "MP06": {"name": "broad-filesystem-root", "severity": "high",
             "rationale": "Filesystem-type server is granted an over-broad root (/, ~, $HOME, a whole user profile, drive root, /etc ...), exposing SSH keys, browser profiles, cloud creds.",
             "fix": "Grant only the project directories the agent needs."},
    "MP07": {"name": "shell-capable-server", "severity": "medium",
             "rationale": "Server is launched through a shell or looks like a shell/terminal/exec MCP server (heuristic, by name). Such servers give the model arbitrary command execution.",
             "fix": "Prefer narrowly-scoped servers; require per-call confirmation; run in a sandbox/container with no secrets."},
    "MP08": {"name": "plaintext-remote", "severity": "high",
             "rationale": "Remote MCP server reached over plain http:// / ws:// to a non-localhost host; traffic and tokens can be read or modified in transit.",
             "fix": "Use https:// (wss://)."},
    "MP09": {"name": "credential-in-url", "severity": "high",
             "rationale": "Remote URL embeds credentials in userinfo or a secret-looking query parameter; URLs leak into logs, history and proxies.",
             "fix": "Move the credential to a header populated from ${input:...}/${env:...} or use OAuth."},
    "MP10": {"name": "untrusted-exec-path", "severity": "high",
             "rationale": "Command or script runs from a world-writable/temp/download location that other users or processes can replace.",
             "fix": "Install the binary/script to a user-owned, non-writable-by-others location."},
    "MP11": {"name": "pipe-to-shell", "severity": "critical",
             "rationale": "Launch arguments download and execute remote code (curl|sh, wget|bash, iex(iwr ...)) on every start.",
             "fix": "Download, verify (checksum/signature), and pin a local copy."},
    "MP12": {"name": "broad-scope-credential", "severity": "medium",
             "rationale": "Credential type cannot be narrowly scoped or is long-lived (GitHub classic PAT ghp_, AWS long-term AKIA key, live payment key). Actual scopes cannot be verified offline.",
             "fix": "Use fine-grained/short-lived credentials (github_pat_ fine-grained, AWS SSO/STS role, restricted keys)."},
    "MP13": {"name": "secret-concentration", "severity": "low",
             "rationale": "Many secret-bearing variables are handed to a single server, enlarging blast radius if it is compromised.",
             "fix": "Split responsibilities; give each server only the credential it needs."},
    "MP14": {"name": "tls-verification-disabled", "severity": "high",
             "rationale": "Environment disables TLS certificate verification (NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0, ...).",
             "fix": "Remove the override; add a proper CA bundle if needed (NODE_EXTRA_CA_CERTS / SSL_CERT_FILE)."},
    "MP15": {"name": "code-injection-env", "severity": "medium",
             "rationale": "Environment sets loader/interpreter injection variables (LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS --require, PYTHONSTARTUP...).",
             "fix": "Remove unless strictly required and the referenced code is trusted."},
    "MP16": {"name": "unmasked-secret-input", "severity": "low",
             "rationale": "VS Code `inputs` entry looks like a secret but is not declared with \"password\": true, so it is echoed when typed.",
             "fix": "Add \"password\": true to the input definition."},
    "MP17": {"name": "duplicate-server-name", "severity": "info",
             "rationale": "Same server name defined in multiple files; which one wins depends on the client and precedence can surprise you.",
             "fix": "Rename or remove one definition."},
    "MP18": {"name": "duplicate-package", "severity": "info",
             "rationale": "Same package/image launched by more than one server entry (possibly with different versions/credentials).",
             "fix": "Consolidate into a single entry."},
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    server: str
    message: str
    line: int = 1
    evidence: str = ""

    @property
    def rule_name(self) -> str:
        return RULES[self.rule_id]["name"]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["rule_name"] = self.rule_name
        d["fix"] = RULES[self.rule_id]["fix"]
        return d


@dataclass
class Server:
    name: str
    file: str
    cfg: Dict[str, Any]
    line: int = 1
    transport: str = "stdio"
    launcher: str = "-"
    package: Optional[str] = None
    pinned: Optional[bool] = None
    inline_secrets: int = 0
    findings: List[Finding] = field(default_factory=list)

    def score(self) -> int:
        return sum(SEV_WEIGHT[f.severity] for f in self.findings)


def grade_for(score: int) -> str:
    if score == 0:
        return "A"
    if score < 10:
        return "B"
    if score < 25:
        return "C"
    if score < 50:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# JSONC parsing
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (outside strings) and trailing commas."""
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            seg = text[i:(n if j < 0 else j + 2)]
            out.append("\n" * seg.count("\n"))  # keep line numbers stable
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    # trailing commas (outside strings): re-scan to be string-safe
    res: List[str] = []
    in_str = False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            res.append(c)
            if c == "\\" and i + 1 < n:
                res.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j < n and s[j] in "}]":
                i += 1
                continue
        res.append(c)
        i += 1
    return "".join(res)


def load_config(path: str) -> Tuple[Any, str]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
    except OSError as e:
        raise ConfigError(f"{path}: cannot read: {e}")
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(strip_jsonc(raw)), raw
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON/JSONC at line {e.lineno} col {e.colno}: {e.msg}")


def extract_servers(doc: Any) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (servers, vscode_inputs) from known config shapes."""
    servers: Dict[str, Dict[str, Any]] = {}
    inputs: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return servers, inputs
    containers = [doc]
    if isinstance(doc.get("mcp"), dict):  # VS Code settings.json {"mcp": {"servers":..}}
        containers.append(doc["mcp"])
    for c in containers:
        for key in ("mcpServers", "servers", "context_servers"):
            block = c.get(key)
            if isinstance(block, dict):
                for name, cfg in block.items():
                    if isinstance(cfg, dict):
                        servers[str(name)] = cfg
        if isinstance(c.get("inputs"), list):
            inputs.extend(i for i in c["inputs"] if isinstance(i, dict))
    return servers, inputs


def find_line(raw: str, key: str, start: int = 1) -> int:
    lines = raw.splitlines()
    needle = json.dumps(key)
    for idx in range(max(start - 1, 0), len(lines)):
        if needle in lines[idx]:
            return idx + 1
    return start


# ---------------------------------------------------------------------------
# Helpers: secrets & placeholders
# ---------------------------------------------------------------------------

PLACEHOLDER_RE = re.compile(
    r"""^(
        \$\{[^}]+\}            # ${VAR} ${env:VAR} ${input:id}
      | \$[A-Za-z_][A-Za-z0-9_]*  # $VAR
      | %[A-Za-z_][A-Za-z0-9_]*%  # %VAR%
      | <[^>]*>                 # <your-token>
      | \{\{[^}]*\}\}           # {{TOKEN}}
      | [xX*._-]{3,}            # xxxx / ****
      | (your|my|insert|enter|replace|put)[-_ ]?.*
      | changeme|change[-_]?me|placeholder|todo|tbd|none|null|redacted|secret|token|password
    )$""", re.X | re.I)

SECRET_KEY_RE = re.compile(
    r"(TOKEN|SECRET|PASSW(OR)?D|PASSPHRASE|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"CLIENT[_-]?SECRET|CREDENTIAL|AUTH|_KEY$|^KEY$|COOKIE|SESSION|DSN|CONNECTION[_-]?STRING)", re.I)
NON_SECRET_KEY_RE = re.compile(r"(KEY_?ID$|_PATH$|_FILE$|_URL$|_HOST$|_REGION$|AUTHOR|_DIR$|_NAME$|_USER(NAME)?$|TOKEN_?TYPE$|AUTH_?TYPE$)", re.I)

TOKEN_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("GitHub classic PAT", re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("GitHub OAuth/app token", re.compile(r"\bgh[ousr]_[A-Za-z0-9]{20,}")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}")),
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("OpenAI-style key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}")),
    ("Stripe key", re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}")),
    ("Slack token", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

SECRET_QUERY_KEYS = re.compile(r"^(token|access_?token|api_?key|apikey|key|secret|client_?secret|password|pass|pwd|auth|sig|signature|code|session)$", re.I)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    if PLACEHOLDER_RE.match(v):
        return True
    # values that are entirely made of substitution references e.g. "Bearer ${input:tok}"
    stripped = re.sub(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%", "", v)
    if stripped != v and len(stripped.strip()) <= 12 and not token_type(stripped):
        return True
    return False


def token_type(value: str) -> Optional[str]:
    for label, rx in TOKEN_PATTERNS:
        if rx.search(value):
            return label
    return None


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "****"
    return f"{v[:4]}****({len(v)} chars)"


def looks_secret_kv(key: str, value: Any) -> Optional[str]:
    """Return a reason string if key/value pair is an inline secret."""
    if not isinstance(value, str):
        return None
    if is_placeholder(value):
        return None
    tt = token_type(value)
    if tt:
        return tt
    if SECRET_KEY_RE.search(key) and not NON_SECRET_KEY_RE.search(key):
        v = value.strip()
        if v.lower() in ("true", "false", "0", "1", "yes", "no", "on", "off"):
            return None
        if len(v) < 6:
            return None
        if re.match(r"^(https?://|/|~|\.\.?/|[A-Za-z]:\\)", v) and "@" not in v:
            return None  # a path or URL, not a secret
        return f"secret-named key '{key}'"
    return None


# ---------------------------------------------------------------------------
# Command analysis
# ---------------------------------------------------------------------------

def base(cmd: str) -> str:
    b = re.split(r"[\\/]", cmd.strip())[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if b.endswith(ext):
            b = b[: -len(ext)]
    return b


NPM_LAUNCHERS = {"npx", "bunx", "pnpx"}
SHELLS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "powershell", "pwsh", "cmd"}
SHELL_PKG_RE = re.compile(r"(shell|terminal|exec|run[-_]?command|command[-_]?runner|desktop[-_]?commander|ssh|code[-_]?runner|cli[-_]?mcp|mcp[-_]?cli|sandbox[-_]?exec|bash|powershell)", re.I)
FS_PKG_RE = re.compile(r"(filesystem|file[-_]?system|server[-_]?fs\b|mcp[-_]?fs\b|\bfs[-_]mcp|files?[-_]?server)", re.I)

NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--node-options", "--registry", "--cache", "--prefix", "-w", "--workspace"}
UVX_VALUE_FLAGS = {"--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--with-requirements", "--directory", "--env-file", "--constraint", "-c"}
DOCKER_VALUE_FLAGS = {"-v", "--volume", "-e", "--env", "--name", "--network", "--net", "-p", "--publish", "--mount",
                      "--pid", "--ipc", "--uts", "--userns", "--cap-add", "--cap-drop", "-w", "--workdir", "--user", "-u",
                      "--entrypoint", "--env-file", "--security-opt", "-l", "--label", "--platform", "-m", "--memory",
                      "--cpus", "--add-host", "--device", "--restart", "--hostname", "-h", "--pull", "--runtime",
                      "--tmpfs", "--log-driver", "--dns", "--group-add", "--cgroupns", "--ulimit", "--shm-size"}


def find_launch(cmd: str, args: List[str]) -> Tuple[str, Optional[str], List[str], List[str]]:
    """Return (launcher, package_spec, launcher_flags, rest_args)."""
    b = base(cmd)
    argv = list(args)
    ecosystem_launcher = None
    if b in NPM_LAUNCHERS:
        ecosystem_launcher = b
    elif b in ("pnpm", "yarn") and argv[:1] == ["dlx"]:
        ecosystem_launcher, argv = f"{b} dlx", argv[1:]
    elif b == "npm" and argv[:1] in (["exec"], ["x"]):
        ecosystem_launcher, argv = "npm exec", argv[1:]
    elif b == "bun" and argv[:1] == ["x"]:
        ecosystem_launcher, argv = "bun x", argv[1:]
    elif b == "uvx":
        ecosystem_launcher = "uvx"
    elif b == "uv" and argv[:2] == ["tool", "run"]:
        ecosystem_launcher, argv = "uv tool run", argv[2:]
    elif b == "pipx" and argv[:1] == ["run"]:
        ecosystem_launcher, argv = "pipx run", argv[1:]
    elif b in ("docker", "podman") and "run" in argv:
        ecosystem_launcher, argv = f"{b} run", argv[argv.index("run") + 1:]
    if not ecosystem_launcher:
        return (b or "-"), None, [], argv
    value_flags = NPX_VALUE_FLAGS
    if ecosystem_launcher in ("uvx", "uv tool run", "pipx run"):
        value_flags = UVX_VALUE_FLAGS | {"--spec"}
    if ecosystem_launcher.endswith(" run") and ecosystem_launcher.split()[0] in ("docker", "podman"):
        value_flags = DOCKER_VALUE_FLAGS
    flags: List[str] = []
    pkg = None
    i = 0
    from_spec = None
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            continue
        if a.startswith("-"):
            flags.append(a)
            if "=" not in a and a in value_flags and i + 1 < len(argv):
                flags.append(argv[i + 1])
                if a in ("--from", "--spec", "-p", "--package") and ecosystem_launcher != "docker run":
                    from_spec = argv[i + 1]
                i += 2
                continue
            if a.startswith(("--from=", "--spec=", "--package=")):
                from_spec = a.split("=", 1)[1]
            i += 1
            continue
        pkg = a
        i += 1
        break
    rest = argv[i:]
    if from_spec and not ecosystem_launcher.startswith(("docker", "podman")):
        pkg = from_spec
    return ecosystem_launcher, pkg, flags, rest


def npm_pinned(spec: str) -> Optional[bool]:
    s = spec.strip()
    if s.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:\\", s):
        return None  # local path
    if s.startswith(("git+", "git:", "github:", "http://", "https://")):
        return bool(re.search(r"#[0-9a-f]{7,40}$", s))
    name_ver = s[1:] if s.startswith("@") else s
    if "@" not in name_ver:
        return False
    ver = name_ver.split("@", 1)[1]
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?", ver))


def py_pinned(spec: str) -> Optional[bool]:
    s = spec.strip()
    if s.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:\\", s):
        return None
    if s.startswith(("git+", "http://", "https://")):
        return bool(re.search(r"@[0-9a-f]{7,40}$", s))
    if re.search(r"==\s*\d[\w.!+-]*$", s):
        return True
    m = re.search(r"@(.+)$", s)
    if m and re.fullmatch(r"v?\d+(\.\d+)+([\w.+-]*)", m.group(1)):
        return True
    return False


def image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    tag = last.split(":", 1)[1]
    return tag not in ("latest", "") and bool(re.search(r"\d", tag))


def pkg_name(spec: str) -> str:
    s = spec
    if s.startswith("@"):
        return "@" + s[1:].split("@", 1)[0]
    return re.split(r"==|>=|<=|~=|@|\[", s)[0]


HOME_RE = re.compile(r"^(~|\$HOME|\$\{HOME\}|\$\{env:HOME\}|\$\{userHome\}|%USERPROFILE%|\$env:USERPROFILE|/root|/Users/[^/]+|/home/[^/]+|[A-Za-z]:[\\/]+Users[\\/]+[^\\/]+)$", re.I)
SYSTEM_RE = re.compile(r"^(/|[A-Za-z]:[\\/]*|/etc|/var|/usr|/opt|/private|/System|/Library|/Users|/home|/mnt|/Volumes|[A-Za-z]:[\\/]+Windows|[A-Za-z]:[\\/]+Users)$", re.I)


def norm_path(p: str) -> str:
    p = p.strip()
    if p.startswith("--") and "=" in p:
        p = p.split("=", 1)[1]
    if len(p) > 1:
        p = p.rstrip("/\\") or "/"
        if re.fullmatch(r"[A-Za-z]:", p):
            p += "\\"
    return p


def broad_root(p: str) -> Optional[str]:
    n = norm_path(p)
    if n in ("/", "\\") or re.fullmatch(r"[A-Za-z]:[\\/]?", n):
        return "filesystem root"
    if HOME_RE.match(n):
        return "entire home directory"
    if SYSTEM_RE.match(n):
        return "system directory"
    return None


TMP_RE = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|[A-Za-z]:[\\/].*[\\/]Temp[\\/]|%TEMP%|%TMP%|\$TMPDIR|\$\{TMPDIR\}|~/Downloads/|/Users/[^/]+/Downloads/|/home/[^/]+/Downloads/|[A-Za-z]:[\\/]+Users[\\/]+[^\\/]+[\\/]+Downloads[\\/])", re.I)
PIPE_SHELL_RE = re.compile(
    r"((curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|(curl|wget)\b[^|;&]*\|\s*(python3?|node|perl|ruby)\b|"
    r"\b(iex|invoke-expression)\b.*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|new-object\s+net\.webclient)|"
    r"(ba)?sh\s+<\(\s*(curl|wget)|bash\s+-c\s+\"?\$\((curl|wget))", re.I)

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]", "host.docker.internal"}

TLS_ENV = {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "PYTHONHTTPSVERIFY": "0"}
INJECT_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "PYTHONSTARTUP",
              "PERL5OPT", "RUBYOPT", "BASH_ENV", "ENV", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"}


# ---------------------------------------------------------------------------
# Auditing
# ---------------------------------------------------------------------------

def as_str_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int, float))]
    return []


def audit_server(srv: Server) -> None:
    cfg = srv.cfg
    add = lambda rid, msg, ev="", sev=None: srv.findings.append(
        Finding(rid, sev or RULES[rid]["severity"], srv.file, srv.name, msg, srv.line, ev))

    url = None
    for k in ("url", "serverUrl", "httpUrl", "uri", "endpoint"):
        if isinstance(cfg.get(k), str):
            url = cfg[k]
            break
    typ = str(cfg.get("type") or cfg.get("transport") or "").lower()
    cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
    args = as_str_list(cfg.get("args"))
    # command given as a full string with spaces and no args (some clients allow it)
    if cmd and not args and " " in cmd.strip() and not os.path.exists(cmd):
        parts = cmd.split()
        cmd, args = parts[0], parts[1:]

    if url:
        srv.transport = typ if typ in ("sse", "http", "streamable-http", "streamablehttp", "ws", "websocket") else ("sse" if urlsplit(url).path.rstrip("/").endswith("/sse") else "http")
        srv.launcher = "remote"
    else:
        srv.transport = "stdio"

    # ---- environment ------------------------------------------------------
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    secret_named = 0
    for k, v in env.items():
        vs = v if isinstance(v, str) else str(v)
        if SECRET_KEY_RE.search(k) and not NON_SECRET_KEY_RE.search(k):
            secret_named += 1
        reason = looks_secret_kv(k, vs)
        if reason:
            srv.inline_secrets += 1
            add("MP01", f"inline secret in env {k} ({reason})", f"{k}={mask(vs)}")
            check_scope(srv, add, k, vs)
        if k.upper() in TLS_ENV and vs.strip() == TLS_ENV[k.upper()]:
            add("MP14", f"env {k}={vs} disables TLS certificate verification", f"{k}={vs}")
        if k.upper() in ("CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE") and vs.strip() == "":
            add("MP14", f"env {k} set empty (disables verification in some clients)", f"{k}=''")
        if k.upper() in INJECT_ENV and vs.strip():
            add("MP15", f"env {k} injects code/libraries into the server process", f"{k}={vs[:60]}")
        if k.upper() == "NODE_OPTIONS" and re.search(r"(--require|-r\s|--import|--loader|--experimental-loader|--inspect)", vs):
            add("MP15", "NODE_OPTIONS preloads code or opens an inspector port", f"NODE_OPTIONS={vs[:60]}")
    if secret_named >= 4:
        add("MP13", f"{secret_named} secret-bearing env vars passed to one server", f"{secret_named} vars")

    # ---- headers (remote) -------------------------------------------------
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    for hk, hv in headers.items():
        if not isinstance(hv, str):
            continue
        if hk.lower() in ("authorization", "proxy-authorization"):
            m = re.match(r"^\s*(Bearer|Basic|Token|Bot)\s+(.+)$", hv, re.I)
            cred = m.group(2) if m else hv
            if not is_placeholder(cred):
                srv.inline_secrets += 1
                add("MP02", f"literal {m.group(1) if m else ''} credential in {hk} header".replace("  ", " "),
                    f"{hk}: {(m.group(1) + ' ') if m else ''}{mask(cred)}")
                check_scope(srv, add, hk, cred)
            continue
        reason = looks_secret_kv(hk, hv)
        if reason:
            srv.inline_secrets += 1
            add("MP01", f"inline secret in header {hk} ({reason})", f"{hk}: {mask(hv)}")
            check_scope(srv, add, hk, hv)

    # ---- remote URL -------------------------------------------------------
    if url:
        try:
            u = urlsplit(url)
        except ValueError:
            u = None
        if u is not None:
            host = (u.hostname or "").lower()
            local = host in LOCAL_HOSTS or host.endswith(".localhost") or host.startswith("127.")
            if u.scheme in ("http", "ws") and not local:
                add("MP08", f"remote server uses plaintext {u.scheme}:// to {host}", f"{u.scheme}://{host}")
            if u.password or (u.username and not is_placeholder(u.username)):
                srv.inline_secrets += 1
                add("MP09", "credentials embedded in URL userinfo", f"{u.scheme}://{mask(u.username or '')}:****@{host}")
            for qk, qv in parse_qsl(u.query, keep_blank_values=True):
                if (SECRET_QUERY_KEYS.match(qk) or token_type(qv)) and qv and not is_placeholder(qv):
                    srv.inline_secrets += 1
                    add("MP09", f"secret-looking query parameter '{qk}' in URL", f"?{qk}={mask(qv)}")
                    check_scope(srv, add, qk, qv)

    # ---- stdio command ----------------------------------------------------
    if cmd:
        launcher, pkg, lflags, rest = find_launch(cmd, args)
        srv.launcher = launcher
        b = base(cmd)
        joined = " ".join([cmd] + args)

        # inline secrets in args: --token=xxx / --api-key xxx / token-shaped
        is_docker_cmd = launcher in ("docker run", "podman run")
        for i, a in enumerate(args):
            m = re.match(r"^--?([A-Za-z0-9_.-]+)=(.+)$", a)
            if m and looks_secret_kv(m.group(1).replace("-", "_"), m.group(2)):
                srv.inline_secrets += 1
                add("MP01", f"inline secret in argument --{m.group(1)}", f"--{m.group(1)}={mask(m.group(2))}")
                check_scope(srv, add, m.group(1), m.group(2))
                continue
            if a.startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
                key = a.lstrip("-").replace("-", "_")
                if SECRET_KEY_RE.search(key) and not NON_SECRET_KEY_RE.search(key) and looks_secret_kv(key, args[i + 1]):
                    srv.inline_secrets += 1
                    add("MP01", f"inline secret passed as value of {a}", f"{a} {mask(args[i + 1])}")
                    check_scope(srv, add, key, args[i + 1])
                    continue
            prev = args[i - 1] if i > 0 else ""
            if is_docker_cmd and prev in ("-e", "--env"):
                continue  # handled by docker checks
            if not a.startswith("-") and not (prev.startswith("-") and SECRET_KEY_RE.search(prev)):
                em = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$", a)
                if em and looks_secret_kv(em.group(1), em.group(2)):
                    srv.inline_secrets += 1
                    add("MP01", f"inline secret in argument {em.group(1)}=...", f"{em.group(1)}={mask(em.group(2))}")
                    check_scope(srv, add, em.group(1), em.group(2))
                    continue
                tt = token_type(a)
                if tt and not is_placeholder(a):
                    srv.inline_secrets += 1
                    add("MP01", f"token-shaped value in args ({tt})", mask(a))
                    check_scope(srv, add, "", a)

        # package pinning
        is_docker = launcher in ("docker run", "podman run")
        if pkg:
            srv.package = pkg_name(pkg) if not is_docker else pkg.split("@sha256")[0].rsplit(":", 1)[0] if ":" in pkg.rsplit("/", 1)[-1] or "@sha256" in pkg else pkg
            if is_docker:
                pinned = image_pinned(pkg)
            elif launcher in ("uvx", "uv tool run", "pipx run"):
                pinned = py_pinned(pkg)
            else:
                pinned = npm_pinned(pkg)
            srv.pinned = pinned
            if pinned is False:
                what = "image" if is_docker else "package"
                why = "@latest/floating tag" if re.search(r"[@:]latest$", pkg) else "no exact version"
                add("MP03", f"{what} '{pkg}' launched via {launcher} with {why}", pkg)
        if launcher in ("npx", "bunx", "pnpx", "npm exec") and any(f in ("-y", "--yes") for f in lflags):
            add("MP04", f"{launcher} -y auto-installs without confirmation", f"{launcher} -y")

        # docker
        if is_docker:
            check_docker(srv, add, lflags)

        # filesystem roots
        ident = " ".join([srv.name, pkg or "", cmd])
        if FS_PKG_RE.search(ident):
            seen = set()
            for p in rest + ([] if pkg else args):
                if p.startswith("-") and "=" not in p:
                    continue
                why = broad_root(p)
                if why and p not in seen:
                    seen.add(p)
                    add("MP06", f"filesystem server granted {why}: {p}", p)

        # shell-capable
        if b in SHELLS:
            add("MP07", f"server is launched through a shell ({b}); arbitrary command string executed (heuristic)", joined[:80])
        elif SHELL_PKG_RE.search(" ".join([srv.name, pkg or ""])):
            add("MP07", "server name/package suggests shell/terminal/exec capability (name-based heuristic)", pkg or srv.name)

        # tmp / world-writable path
        for p in [cmd] + args:
            if TMP_RE.match(p.strip()):
                add("MP10", f"executes from temp/download location: {p}", p)
                break

        # pipe-to-shell
        if PIPE_SHELL_RE.search(joined):
            add("MP11", "arguments download and execute remote code", joined[:100])


def check_docker(srv: Server, add, flags: List[str]) -> None:
    i = 0
    while i < len(flags):
        f = flags[i]
        name, val = (f.split("=", 1) + [None])[:2] if f.startswith("--") and "=" in f else (f, None)
        if val is None and name in DOCKER_VALUE_FLAGS and i + 1 < len(flags):
            val = flags[i + 1]
            i += 1
        i += 1
        if name == "--privileged":
            add("MP05", "container runs --privileged (full host device & capability access)", "--privileged", "critical")
        elif name in ("--network", "--net") and val == "host":
            add("MP05", "container shares host network namespace", f"{name} host")
        elif name in ("--pid", "--ipc", "--uts", "--userns", "--cgroupns") and val == "host":
            add("MP05", f"container shares host {name.lstrip('-')} namespace", f"{name} host")
        elif name == "--cap-add" and val:
            sev = "critical" if val.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH") else "high"
            add("MP05", f"container adds Linux capability {val}", f"--cap-add {val}", sev)
        elif name == "--security-opt" and val and re.search(r"(unconfined|no-new-privileges[:=]false)", val):
            add("MP05", f"container security profile disabled: {val}", f"--security-opt {val}")
        elif name == "--device" and val:
            add("MP05", f"host device passed into container: {val}", f"--device {val}", "medium")
        elif name in ("-v", "--volume", "--mount") and val:
            if name == "--mount":
                m = re.search(r"(?:source|src)=([^,]+)", val)
                src = m.group(1) if m else ""
            else:
                src = val.split(":")[0] if not re.match(r"^[A-Za-z]:\\", val) else val[:2] + val[2:].split(":")[0]
            if "docker.sock" in val:
                add("MP05", "Docker socket mounted into container (equivalent to root on host)", f"{name} {val}", "critical")
            elif src and broad_root(src) == "filesystem root":
                add("MP05", f"host root filesystem mounted into container: {val}", f"{name} {val}", "critical")
            elif src and broad_root(src):
                add("MP05", f"over-broad host path mounted into container ({broad_root(src)}): {val}", f"{name} {val}")
        elif name in ("-e", "--env") and val and "=" in val:
            k, v = val.split("=", 1)
            reason = looks_secret_kv(k, v)
            if reason:
                srv.inline_secrets += 1
                add("MP01", f"inline secret in docker -e {k} ({reason})", f"-e {k}={mask(v)}")
                check_scope(srv, add, k, v)


def check_scope(srv: Server, add, key: str, value: str) -> None:
    v = value.strip()
    if re.search(r"\bghp_[A-Za-z0-9]{20,}", v):
        add("MP12", "GitHub classic PAT (ghp_) cannot be fine-grained/repo-scoped; actual scopes cannot be verified offline", mask(v))
    elif re.search(r"\bAKIA[0-9A-Z]{16}\b", v):
        add("MP12", "AWS long-term access key (AKIA...); may belong to an IAM user or root - cannot be verified offline", mask(v))
    elif re.search(r"\b[sr]k_live_", v):
        add("MP12", "live payment-provider secret key; use a restricted key", mask(v))
    elif re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", v):
        add("MP12", "private key material inline", "-----BEGIN ... PRIVATE KEY-----")


def audit_inputs(inputs: List[Dict[str, Any]], path: str, raw: str) -> List[Finding]:
    out = []
    for inp in inputs:
        iid = str(inp.get("id", ""))
        desc = str(inp.get("description", ""))
        if (SECRET_KEY_RE.search(iid) or re.search(r"(token|secret|password|api key|apikey|key)", desc, re.I)) and inp.get("password") is not True:
            out.append(Finding("MP16", RULES["MP16"]["severity"], path, f"input:{iid}",
                               f"input '{iid}' looks secret but lacks \"password\": true", find_line(raw, iid), iid))
    return out


# ---------------------------------------------------------------------------
# Discovery & orchestration
# ---------------------------------------------------------------------------

KNOWN_FILENAMES = {"claude_desktop_config.json", "mcp.json", ".mcp.json", "mcp_config.json", "mcp_settings.json",
                   "cline_mcp_settings.json", "mcp_servers.json", "settings.json", "settings.jsonc", "mcp.jsonc"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}


def discover(paths: List[str]) -> Tuple[List[str], List[str]]:
    files, errors = [], []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, fnames in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for fn in sorted(fnames):
                    if fn.lower() in KNOWN_FILENAMES or fn.lower().endswith("claude_desktop_config.json") or (fn.lower().endswith((".json", ".jsonc")) and "mcp" in fn.lower()):
                        files.append(os.path.join(root, fn))
        else:
            errors.append(f"{p}: no such file or directory")
    return files, errors


@dataclass
class Report:
    servers: List[Server] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def audit_paths(paths: List[str], explicit_files_warn: bool = True) -> Report:
    rep = Report()
    files, errs = discover(paths)
    rep.errors.extend(errs)
    for f in files:
        try:
            doc, raw = load_config(f)
        except ConfigError as e:
            # in dir mode, settings.json that isn't JSON is not our business
            if os.path.basename(f).lower().startswith("settings") and f not in paths:
                continue
            rep.errors.append(str(e))
            continue
        servers, inputs = extract_servers(doc)
        if not servers and not inputs:
            continue
        rep.files.append(f)
        last = 1
        for name, cfg in servers.items():
            line = find_line(raw, name, 1)
            s = Server(name=name, file=f, cfg=cfg, line=line)
            audit_server(s)
            rep.servers.append(s)
            rep.findings.extend(s.findings)
            last = line
        rep.findings.extend(audit_inputs(inputs, f, raw))
    # cross-file checks
    by_name: Dict[str, List[Server]] = {}
    by_pkg: Dict[str, List[Server]] = {}
    for s in rep.servers:
        by_name.setdefault(s.name, []).append(s)
        if s.package:
            by_pkg.setdefault(s.package.lower(), []).append(s)
    for name, lst in by_name.items():
        files_ = sorted({s.file for s in lst})
        if len(files_) > 1:
            for s in lst:
                fnd = Finding("MP17", "info", s.file, s.name, f"server name '{name}' also defined in: " +
                              ", ".join(x for x in files_ if x != s.file), s.line, name)
                s.findings.append(fnd)
                rep.findings.append(fnd)
    for pkg, lst in by_pkg.items():
        if len(lst) > 1:
            for s in lst:
                others = ", ".join(f"{o.name}" for o in lst if o is not s)
                fnd = Finding("MP18", "info", s.file, s.name, f"package '{pkg}' also launched by: {others}", s.line, pkg)
                s.findings.append(fnd)
                rep.findings.append(fnd)
    return rep


def filter_findings(findings: List[Finding], min_sev: str, select: Optional[set], ignore: set) -> List[Finding]:
    out = []
    for f in findings:
        if SEV_RANK[f.severity] < SEV_RANK[min_sev]:
            continue
        if select and f.rule_id not in select:
            continue
        if f.rule_id in ignore:
            continue
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def server_rows(rep: Report, shown: List[Finding]) -> List[Dict[str, Any]]:
    rows = []
    for s in rep.servers:
        fs = [f for f in shown if f.file == s.file and f.server == s.name]
        score = sum(SEV_WEIGHT[f.severity] for f in fs)
        rows.append({"name": s.name, "file": s.file, "transport": s.transport, "launcher": s.launcher,
                     "package": s.package, "pinned": s.pinned, "inline_secrets": s.inline_secrets,
                     "findings": len(fs), "score": score, "grade": grade_for(score)})
    return rows


def overall(rows: List[Dict[str, Any]], shown: List[Finding]) -> Tuple[int, str]:
    if not rows:
        score = sum(SEV_WEIGHT[f.severity] for f in shown)
        return score, grade_for(score)
    worst = max(r["score"] for r in rows)
    extra = sum(SEV_WEIGHT[f.severity] for f in shown if f.server.startswith("input:"))
    # overall grade = worst server's grade, nudged by input findings
    score = worst + extra
    return score, grade_for(score)


def fmt_pinned(p: Optional[bool]) -> str:
    return {True: "yes", False: "NO", None: "-"}[p]


def render_text(rep: Report, shown: List[Finding], color: bool) -> str:
    C = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
    R = "\033[0m"
    lines = [f"{TOOL_NAME} {__version__} - static MCP config posture review (offline; heuristics, not runtime analysis)", ""]
    if not rep.files:
        lines.append("No MCP server definitions found.")
    for f in rep.files:
        fs = sorted([x for x in shown if x.file == f], key=lambda x: (-SEV_RANK[x.severity], x.line, x.rule_id))
        lines.append(f"== {f}")
        if not fs:
            lines.append("   no findings")
        for x in fs:
            sev = x.severity.upper()
            sev = f"{C[x.severity]}{sev:<8}{R}" if color else f"{sev:<8}"
            lines.append(f"   {sev} {x.rule_id} L{x.line:<4} [{x.server}] {x.message}")
            if x.evidence:
                lines.append(f"            evidence: {x.evidence}")
            lines.append(f"            fix: {RULES[x.rule_id]['fix']}")
        lines.append("")
    rows = server_rows(rep, shown)
    if rows:
        multi = len(rep.files) > 1
        hdr = (["FILE"] if multi else []) + ["SERVER", "TRANSPORT", "LAUNCHER", "PACKAGE", "PINNED", "SECRETS", "FINDINGS", "SCORE", "GRADE"]
        data = [([os.path.basename(r["file"])] if multi else []) + [r["name"], r["transport"], r["launcher"], (r["package"] or "-")[:40], fmt_pinned(r["pinned"]),
                 str(r["inline_secrets"]), str(r["findings"]), str(r["score"]), r["grade"]] for r in rows]
        w = [max(len(h), *(len(d[i]) for d in data)) for i, h in enumerate(hdr)]
        lines.append("Per-server summary:")
        lines.append("  " + "  ".join(h.ljust(w[i]) for i, h in enumerate(hdr)))
        lines.append("  " + "  ".join("-" * w[i] for i in range(len(hdr))))
        for d in data:
            lines.append("  " + "  ".join(d[i].ljust(w[i]) for i in range(len(hdr))))
        lines.append("")
    score, grade = overall(rows, shown)
    counts = {s: sum(1 for x in shown if x.severity == s) for s in reversed(SEVERITIES)}
    lines.append(f"Overall grade: {grade} (score {score} = worst server + input findings) | servers: {len(rows)} | files: {len(rep.files)} | " +
                 ", ".join(f"{k}: {v}" for k, v in counts.items()))
    for e in rep.errors:
        lines.append(f"ERROR: {e}")
    return "\n".join(lines)


def render_json(rep: Report, shown: List[Finding]) -> str:
    rows = server_rows(rep, shown)
    score, grade = overall(rows, shown)
    return json.dumps({"tool": TOOL_NAME, "version": __version__, "files": rep.files, "errors": rep.errors,
                       "overall": {"score": score, "grade": grade, "servers": len(rows), "findings": len(shown)},
                       "servers": rows, "findings": [f.to_dict() for f in shown]}, indent=2)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(rep: Report, shown: List[Finding]) -> str:
    rule_ids = sorted(RULES)
    rules = [{"id": rid, "name": RULES[rid]["name"],
              "shortDescription": {"text": RULES[rid]["name"].replace("-", " ")},
              "fullDescription": {"text": RULES[rid]["rationale"]},
              "help": {"text": RULES[rid]["fix"]},
              "defaultConfiguration": {"level": SARIF_LEVEL[RULES[rid]["severity"]]},
              "properties": {"severity": RULES[rid]["severity"]}} for rid in rule_ids]
    results = []
    for f in shown:
        results.append({"ruleId": f.rule_id, "ruleIndex": rule_ids.index(f.rule_id), "level": SARIF_LEVEL[f.severity],
                        "message": {"text": f"[{f.server}] {f.message}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                                                            "region": {"startLine": max(1, f.line)}}}],
                        "properties": {"severity": f.severity, "server": f.server, "evidence": f.evidence}})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": __version__,
                                                     "informationUri": "https://example.invalid/mcpposture",
                                                     "rules": rules}},
                                 "results": results}]}, indent=2)


def render_rules() -> str:
    out = ["ID    SEVERITY  NAME                         RATIONALE"]
    for rid in sorted(RULES):
        r = RULES[rid]
        out.append(f"{rid}  {r['severity']:<8}  {r['name']:<27}  {r['rationale']}")
    return "\n".join(out)


def parse_ids(s: Optional[str]) -> set:
    if not s:
        return set()
    ids = {x.strip().upper() for x in s.split(",") if x.strip()}
    bad = ids - set(RULES)
    if bad:
        raise ValueError(f"unknown rule id(s): {', '.join(sorted(bad))}")
    return ids


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL_NAME, description="Offline least-privilege & supply-chain risk auditor for MCP client config files.")
    ap.add_argument("paths", nargs="*", help="config files or directories to scan")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true", help="JSON output")
    g.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low",
                    help="report findings at/above this severity; also the exit-code threshold (default: low)")
    ap.add_argument("--select", help="comma-separated rule ids to include only")
    ap.add_argument("--ignore", help="comma-separated rule ids to skip")
    ap.add_argument("--exit-zero", action="store_true", help="always exit 0 unless usage/parse error")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    if a.list_rules:
        print(render_rules())
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print(f"{TOOL_NAME}: error: at least one path is required", file=sys.stderr)
        return 2
    try:
        select, ignore = parse_ids(a.select), parse_ids(a.ignore)
    except ValueError as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2
    rep = audit_paths(a.paths)
    shown = filter_findings(rep.findings, a.min_severity, select or None, ignore)
    if a.json:
        print(render_json(rep, shown))
    elif a.sarif:
        print(render_sarif(rep, shown))
    else:
        color = sys.stdout.isatty() and not a.no_color and not os.environ.get("NO_COLOR")
        print(render_text(rep, shown, color))
    if rep.errors:
        for e in rep.errors:
            print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2
    if shown and not a.exit_zero:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
