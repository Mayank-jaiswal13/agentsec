#!/usr/bin/env python3
"""yolocheck - offline auditor for coding-agent permission / autonomy settings.

Audits Claude Code settings.json, Codex config.toml, Gemini CLI settings.json,
VS Code (Copilot agent) settings.json and Cursor CLI permission JSON for risky
over-permissioning. Stdlib only. Never touches the network.

Schemas are best-effort as of 2026 and may drift; unknown approval-related keys
are reported as 'unrecognized' (info) instead of guessed at.
"""
import argparse
import json
import os
import re
import sys

try:  # Python 3.11+
    import tomllib  # type: ignore
except ImportError:  # pragma: no cover
    tomllib = None

__version__ = "0.1.0"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
PENALTY = {"high": 30, "medium": 10, "low": 3, "info": 0}

# id: (default severity, title, rationale, fix)
RULES = {
    "YC01": ("high", "Unrestricted shell auto-approved",
             "A bare/wildcard shell allow (Bash, Bash(*), Shell(*), '/.*/': true, run_shell_command) lets the agent run any command without asking, so one prompt injection = arbitrary code execution.",
             "Remove the wildcard; allow only specific, read-mostly commands (e.g. Bash(npm run test:*), Bash(git status)) and keep everything else on 'ask'."),
    "YC02": ("high", "Arbitrary-code interpreter auto-approved",
             "Allowing an interpreter or launcher with open arguments (python:*, node -e, bash -c, sh, npx, env, xargs, eval) is equivalent to an unrestricted shell.",
             "Allow specific scripts instead (e.g. Bash(python -m pytest:*)); never allow '-c'/'-e' style inline code."),
    "YC03": ("medium", "Network tool auto-approved",
             "curl/wget/nc/ssh/scp etc. without approval give an injected agent a ready exfiltration and download channel.",
             "Move network tools to 'ask' or deny; use a domain-restricted fetch tool (e.g. WebFetch(domain:docs.example.com)) instead."),
    "YC04": ("high", "Privilege escalation auto-approved",
             "sudo/su/doas/pkexec allowed without approval lets the agent act as root.",
             "Never allow privilege-escalation commands; add them to deny."),
    "YC05": ("medium", "Destructive or publishing command auto-approved",
             "rm, git push, git reset/clean, npm publish, docker push, terraform apply etc. can destroy work or publish code without a human in the loop.",
             "Put destructive/publishing commands on 'ask' or deny (e.g. deny Bash(git push:*), Bash(rm:*))."),
    "YC06": ("medium", "Unrestricted web fetch auto-approved",
             "WebFetch / URL auto-approve without a domain restriction allows silent exfiltration via URLs and ingestion of attacker-controlled content.",
             "Restrict to named domains, e.g. WebFetch(domain:docs.python.org)."),
    "YC07": ("medium", "Secrets not protected while reads are broad",
             "With broad read access (Read(**), unrestricted shell, bypass mode) and no deny rules for .env, ~/.ssh and private keys, credentials are one tool call away from the model context.",
             "Add deny rules such as Read(./.env), Read(./.env.*), Read(~/.ssh/**), Read(**/*.pem), Read(**/*.key)."),
    "YC08": ("high", "Permission prompts bypassed",
             "defaultMode bypassPermissions / --dangerously-skip-permissions / --dangerously-bypass-approvals-and-sandbox / --yolo turns off every approval prompt.",
             "Use defaultMode 'default' or 'plan'; reserve bypass modes for disposable, network-isolated sandboxes."),
    "YC09": ("high", "Codex sandbox disabled (danger-full-access)",
             "sandbox_mode = danger-full-access removes filesystem and network sandboxing for every command.",
             "Use sandbox_mode = \"workspace-write\" (or \"read-only\")."),
    "YC10": ("high", "Approvals disabled (approval_policy = never)",
             "approval_policy = never means the agent never asks; combined with write or network access it acts fully autonomously.",
             "Use approval_policy = \"on-request\" or \"untrusted\"; only use 'never' with read-only sandboxes in CI."),
    "YC11": ("medium", "Sandbox network access enabled",
             "network_access = true inside the workspace-write sandbox lets commands reach the internet without approval.",
             "Set network_access = false and allow network per-task with approval."),
    "YC12": ("high", "Global auto-approve / YOLO mode",
             "Gemini yolo / approval mode, VS Code chat.tools(.global).autoApprove, Cursor yolo/auto-run or trusted MCP servers skip confirmation for tool calls.",
             "Turn global auto-approve off; approve individual low-risk tools instead."),
    "YC13": ("high", "Hook/helper downloads-and-executes or exfiltrates",
             "A hook or helper command that pipes a network download to a shell, or sends environment variables / secrets over the network, runs automatically on agent events.",
             "Vendor hook scripts into the repo, pin and review them; never pipe curl/wget into a shell or send env to remote hosts."),
    "YC14": ("medium", "Hook/helper uses world-writable path",
             "Hooks executing from or writing to /tmp, /var/tmp, /dev/shm, %TEMP% (or chmod 777) can be hijacked by other local users or processes.",
             "Keep hook scripts in the project (e.g. $CLAUDE_PROJECT_DIR/.claude/hooks/) or a user-only directory."),
    "YC15": ("high", "Filesystem scope includes root or home",
             "additionalDirectories / writable_roots / trusted projects / write rules covering '/' or the home directory expose SSH keys, cloud credentials and every other project.",
             "Scope extra directories to specific project paths."),
    "YC16": ("medium", "All project MCP servers auto-enabled",
             "enableAllProjectMcpServers = true starts every MCP server declared in a cloned repo's .mcp.json without review.",
             "Set it to false and list reviewed servers in enabledMcpjsonServers."),
    "YC17": ("info", "Unrecognized key or shape",
             "yolocheck does not know this key/value/shape (schemas drift). It is reported rather than guessed at.",
             "Check the harness documentation; open an issue if yolocheck should understand it."),
}

SHELL_TOOLS = {"bash", "shell", "run_shell_command", "shelltool", "terminal"}
READ_TOOLS = {"Read", "Glob", "Grep", "LS", "NotebookRead"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
KNOWN_CLAUDE_TOOLS = READ_TOOLS | WRITE_TOOLS | {
    "Bash", "WebFetch", "WebSearch", "Task", "TodoWrite", "Skill", "SlashCommand",
    "KillShell", "BashOutput", "ExitPlanMode", "Agent", "TaskOutput"}
CURSOR_TOOLS = {"Shell", "Read", "Write", "WebFetch", "Mcp"}

INTERPRETERS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "python", "python2", "python3",
                "node", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell", "cmd",
                "eval", "exec", "env", "xargs", "osascript", "npx", "uvx", "bunx", "pnpx",
                "lua", "tclsh", "awk", "busybox", "nohup", "timeout", "watch"}
INLINE_FLAGS = {"-c", "-e", "--eval", "-p", "--print", "-command", "-encodedcommand", "/c",
                "-r", "-x", "-m"}
NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp",
             "rsync", "ftp", "tftp", "aria2c", "invoke-webrequest", "iwr", "invoke-restmethod",
             "irm", "http", "https", "xh", "lynx", "w3m"}
PRIV_TOOLS = {"sudo", "su", "doas", "pkexec", "runas", "gsudo"}
DESTRUCTIVE_FIRST = {"rm", "rmdir", "shred", "dd", "mkfs", "chmod", "chown", "truncate",
                     "del", "rd", "remove-item", "format"}
DESTRUCTIVE_SUB = {
    "git": {"push", "reset", "clean", "filter-branch", "filter-repo", "branch -d", "branch -D"},
    "npm": {"publish", "unpublish"}, "pnpm": {"publish"}, "yarn": {"publish", "npm"},
    "twine": {"upload"}, "cargo": {"publish"}, "gem": {"push"},
    "docker": {"push", "rm", "rmi", "system", "run"}, "kubectl": {"delete", "apply", "exec"},
    "terraform": {"apply", "destroy"}, "gh": {"repo", "release", "pr"},
    "aws": {"s3"}, "poetry": {"publish"}, "uv": {"publish"},
}

APPROVALISH = re.compile(r"(approv|yolo|autoaccept|auto_accept|autorun|auto_run|allowlist|"
                         r"allowedtools|bypass|dangerous|skip.?permission|trust)", re.I)
DANGER_FLAGS = re.compile(r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|"
                          r"(?<![\w-])--yolo(?![\w-])|--permission-mode[ =]bypassPermissions|"
                          r"--approval-mode[ =]yolo", re.I)

# ---------------------------------------------------------------- parsing

def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas outside of strings."""
    out = []
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
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            seg = text[i:n if j < 0 else j + 2]
            out.append("\n" * seg.count("\n"))  # keep line numbers stable
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    s = "".join(out)
    # trailing commas (outside strings: re-tokenise conservatively)
    res, in_str, i = [], False, 0
    while i < len(s):
        c = s[i]
        if in_str:
            res.append(c)
            if c == "\\" and i + 1 < len(s):
                res.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            res.append(c)
        elif c == ",":
            j = i + 1
            while j < len(s) and s[j] in " \t\r\n":
                j += 1
            if j < len(s) and s[j] in "}]":
                i += 1
                continue
            res.append(c)
        else:
            res.append(c)
        i += 1
    return "".join(res)


def parse_jsonc(text):
    if text.startswith("\ufeff"):
        text = text[1:]
    return json.loads(strip_jsonc(text))


def _mini_toml(text):  # pragma: no cover - only used without tomllib
    data, cur = {}, None
    cur = data
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip() if '"' not in raw else raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            cur = data
            for part in [p.strip().strip('"') for p in re.split(r'\.(?=(?:[^"]*"[^"]*")*[^"]*$)', m.group(1))]:
                cur = cur.setdefault(part, {})
            continue
        m = re.match(r'^([A-Za-z0-9_\-"]+)\s*=\s*(.+)$', line)
        if m:
            k, v = m.group(1).strip('"'), m.group(2).strip()
            if v in ("true", "false"):
                val = v == "true"
            elif v.startswith('"'):
                val = v.strip('"')
            elif v.startswith("["):
                val = re.findall(r'"([^"]*)"', v)
            else:
                try:
                    val = int(v)
                except ValueError:
                    val = v
            cur[k] = val
    return data


def parse_toml(text):
    if tomllib is not None:
        return tomllib.loads(text)
    return _mini_toml(text)  # pragma: no cover

# ---------------------------------------------------------------- helpers

class Ctx:
    def __init__(self, path, text, harness):
        self.path = path
        self.text = text
        self.lines = text.splitlines()
        self.harness = harness
        self.findings = []

    def line_of(self, *needles):
        for nd in needles:
            if not nd:
                continue
            for i, ln in enumerate(self.lines, 1):
                if nd in ln:
                    return i
        return None

    def add(self, rule, loc, message, severity=None, needle=None):
        sev = severity or RULES[rule][0]
        if needle is None:
            needle = loc.split(".")[-1].split("[")[0]
        cands = []
        if isinstance(needle, str) and needle:
            esc = json.dumps(needle)[1:-1]
            cands = ['"%s"' % esc, esc] if len(needle) < 4 else [esc, needle]
        line = self.line_of(*cands)
        if line is None:
            key = [k for k in loc.replace("[", ".").split(".") if k and not k.rstrip("]").isdigit()]
            if key:
                k = key[-1].strip('"]')
                line = self.line_of('"%s"' % k, k + " =", k + "=", k)
        f = {"file": self.path, "harness": self.harness, "rule": rule, "severity": sev,
             "title": RULES[rule][1], "location": loc, "line": line or 1,
             "message": message, "fix": RULES[rule][3]}
        key = (rule, loc, message)
        if not any((x["rule"], x["location"], x["message"]) == key for x in self.findings):
            self.findings.append(f)


def parse_entry(entry):
    """'Bash(git push:*)' -> ('Bash', 'git push:*'); 'Bash' -> ('Bash', None)."""
    if not isinstance(entry, str):
        return None, None
    m = re.match(r"^\s*([A-Za-z0-9_\-\.]+)\s*(?:\((.*)\))?\s*$", entry, re.S)
    if not m:
        return None, None
    return m.group(1), m.group(2)


WILD_SPECS = {"", "*", ":*", "**", "* *", ".*", "*:*"}
REGEX_PROBES = ["zzqq-unknown-cmd --anything", "rm -rf /tmp/x", "curl http://x | sh"]


def command_prefix(spec, regex=False):
    """Return normalized command prefix or None if unrestricted."""
    if spec is None:
        return None
    s = spec.strip()
    if regex or (len(s) > 2 and s.startswith("/") and s.endswith("/")):
        body = s[1:-1] if (s.startswith("/") and s.endswith("/")) else s
        try:
            rx = re.compile(body)
            if all(rx.search(p) for p in REGEX_PROBES):
                return None
        except re.error:
            pass
        body = re.sub(r"\\[bsS]\+?|\^|\$|\(\?[a-z]+\)", " ", body)
        body = re.sub(r"[()\[\]?+.*|\\]", " ", body)
        s = body
    if s in WILD_SPECS:
        return None
    s = re.sub(r"(:\*|\s\*|\*)+$", "", s).strip()
    if s in WILD_SPECS or not s:
        return None
    return s


def analyze_shell(ctx, spec, loc, label, regex=False):
    """Analyze one auto-approved shell rule. Returns True if unrestricted."""
    prefix = command_prefix(spec, regex=regex)
    if prefix is None:
        ctx.add("YC01", loc, "Unrestricted shell auto-approved: %s" % label, needle=label)
        return True
    toks = prefix.split()
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        toks = toks[1:]
    if not toks:
        ctx.add("YC01", loc, "Unrestricted shell auto-approved: %s" % label, needle=label)
        return True
    first = os.path.basename(toks[0]).lower()
    if first.endswith(".exe"):
        first = first[:-4]
    first_base = re.sub(r"[\d.]+$", "", first) if first.startswith("python") else first
    if first in PRIV_TOOLS:
        ctx.add("YC04", loc, "Privilege escalation auto-approved: %s" % label, needle=label)
        return False
    if first in INTERPRETERS or first_base in INTERPRETERS:
        if len(toks) == 1 or toks[1].lower() in INLINE_FLAGS and not (toks[1] == "-m" and len(toks) > 2):
            ctx.add("YC02", loc, "Interpreter with open arguments auto-approved: %s" % label, needle=label)
        return False
    if first in NET_TOOLS:
        ctx.add("YC03", loc, "Network tool auto-approved: %s" % label, needle=label)
        return False
    if first in DESTRUCTIVE_FIRST:
        ctx.add("YC05", loc, "Destructive command auto-approved: %s" % label, needle=label)
        return False
    if first in DESTRUCTIVE_SUB:
        rest = " ".join(toks[1:])
        if not rest:
            ctx.add("YC05", loc, "'%s' with any subcommand auto-approved (includes %s): %s"
                    % (first, "/".join(sorted(DESTRUCTIVE_SUB[first])[:3]), label), needle=label)
        elif any(rest == s or rest.startswith(s + " ") for s in DESTRUCTIVE_SUB[first]):
            ctx.add("YC05", loc, "Destructive/publishing command auto-approved: %s" % label, needle=label)
    return False


PIPE_TO_SHELL = re.compile(
    r"(curl|wget|iwr|invoke-webrequest|irm|fetch)\b[^|;&]*\|\s*(sudo\s+)?(-?\w+/)*"
    r"(ba|z|da|k|fi)?sh\b|(curl|wget|iwr|irm)\b[^|;&]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|iex|pwsh|powershell)\b"
    r"|(ba|z)?sh\s+<\(\s*(curl|wget)|(ba|z)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)"
    r"|(iex|invoke-expression)\b.*(downloadstring|iwr|irm|invoke-webrequest)", re.I)
ENV_TO_NET = re.compile(r"\b(env|printenv|set|export\s+-p)\b\s*\|.*\b(curl|wget|nc|ncat|netcat|socat)\b", re.I)
SECRET_REF = re.compile(r"\$\{?[A-Z0-9_]*(KEY|TOKEN|SECRET|PASS(WORD)?|CRED|AUTH)[A-Z0-9_]*\}?"
                        r"|~/\.ssh|\.aws/credentials|(?<![\w.])\.env\b|\$\((env|printenv)\)|id_rsa|\.netrc", re.I)
NET_CMD = re.compile(r"\b(curl|wget|nc|ncat|netcat|socat|scp|iwr|invoke-webrequest|invoke-restmethod)\b", re.I)
NET_DEV = re.compile(r"/dev/tcp/|/dev/udp/")
TMP_PATH = re.compile(r"(?<![\w.])(/tmp/|/tmp\b|/var/tmp|/dev/shm|%TEMP%|%TMP%|\$TMPDIR|\$\{TMPDIR|"
                      r"C:\\\\?Windows\\\\?Temp|AppData\\\\?Local\\\\?Temp)|chmod\s+(-R\s+)?[0-7]?77[0-7]|chmod\s+a\+w|chmod\s+o\+w", re.I)


def scan_command(ctx, cmd, loc):
    if not isinstance(cmd, str) or not cmd.strip():
        return
    short = cmd if len(cmd) <= 90 else cmd[:87] + "..."
    if PIPE_TO_SHELL.search(cmd):
        ctx.add("YC13", loc, "Hook/helper pipes a network download into an interpreter: %s" % short, needle=cmd[:40])
    elif ENV_TO_NET.search(cmd) or NET_DEV.search(cmd) or (NET_CMD.search(cmd) and SECRET_REF.search(cmd)):
        ctx.add("YC13", loc, "Hook/helper may send environment/secrets over the network: %s" % short, needle=cmd[:40])
    if TMP_PATH.search(cmd):
        ctx.add("YC14", loc, "Hook/helper references a world-writable path: %s" % short, needle=cmd[:40])


ROOT_PATHS = {"/", "//", "/*", "/**", "//**", "c:\\", "c:/", "c:", "c:\\*", "c:/**"}
HOME_RX = re.compile(r"^(~|\$home|\$\{home\}|%userprofile%|/home/[^/]+|/users/[^/]+|/root|c:[\\/]+users[\\/]+[^\\/]+)"
                     r"[\\/]*(\*\*?)?[\\/]*$", re.I)


def classify_dir(p):
    if not isinstance(p, str):
        return None
    s = p.strip()
    low = s.lower().rstrip()
    if low in ROOT_PATHS or re.fullmatch(r"/+\**", low):
        return "root"
    if HOME_RX.match(low) or low in ("~/", "~/**", "~/*"):
        return "home"
    return None


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, "%s.%s" % (path, k) if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, "%s[%d]" % (path, i))
    elif isinstance(obj, str):
        yield path, obj


def walk_keys(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k) if path else str(k)
            yield p, k, v
            yield from walk_keys(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_keys(v, "%s[%d]" % (path, i))


def generic_checks(ctx, data, handled_keys=()):
    for loc, s in walk_strings(data):
        if DANGER_FLAGS.search(s):
            ctx.add("YC08", loc, "Bypass flag found in configured value: %s" % s[:80], needle=s[:40])
    handled = set(handled_keys)
    for loc, k, v in walk_keys(data):
        if loc in handled or any(loc.startswith(h + ".") or loc.startswith(h + "[") for h in handled):
            continue
        if isinstance(k, str) and APPROVALISH.search(k):
            ctx.add("YC17", loc, "Unrecognized approval-related key '%s' (value %s); not evaluated"
                    % (loc, json.dumps(v)[:40] if not isinstance(v, (dict, list)) else type(v).__name__), needle=k)


SECRET_CHECKS = [
    (".env files", re.compile(r"\.env", re.I)),
    ("~/.ssh", re.compile(r"\.ssh|id_rsa|id_ed25519", re.I)),
    ("private keys (*.pem/*.key)", re.compile(r"\.pem|\.key\b|\*\.key|private", re.I)),
]
SECRET_PATH = re.compile(r"(^|/)\.env(\.|$|\*)|\.ssh|id_rsa|\.pem$|\.key$|\.aws|credentials|\.netrc", re.I)
BROAD_READ = {None, "", "*", "**", "/**", "//**", "~/**", "~", "/", "**/*", "./**", "//*"}

# ---------------------------------------------------------------- harness checks

CLAUDE_TOP = {"$schema", "permissions", "hooks", "env", "model", "apiKeyHelper", "cleanupPeriodDays",
              "includeCoAuthoredBy", "statusLine", "enableAllProjectMcpServers", "enabledMcpjsonServers",
              "disabledMcpjsonServers", "outputStyle", "forceLoginMethod", "forceLoginOrgUUID",
              "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "sandbox", "disableAllHooks",
              "spinnerTipsEnabled", "alwaysThinkingEnabled", "companyAnnouncements", "theme", "plugins",
              "enabledPlugins", "extraKnownMarketplaces", "autoUpdates", "verbose", "preferredNotifChannel",
              "subagentStatusLine", "allowedMcpServers", "deniedMcpServers", "language", "attribution",
              "fileSuggestion", "respectGitignore", "useEnterpriseMcpConfigOnly"}
CLAUDE_PERM = {"allow", "deny", "ask", "defaultMode", "additionalDirectories", "disableBypassPermissionsMode"}
CLAUDE_MODES = {"default", "plan", "acceptEdits", "bypassPermissions", "dontAsk"}


def check_permission_lists(ctx, perms, base, shell_names, known_tools, mcp_prefix="mcp__"):
    allow = perms.get("allow", []) if isinstance(perms, dict) else []
    deny = perms.get("deny", []) if isinstance(perms, dict) else []
    state = {"broad_read": False, "shell_open": False}
    if not isinstance(allow, list):
        ctx.add("YC17", base + ".allow", "permissions.allow is not a list; not evaluated")
        allow = []
    if not isinstance(deny, list):
        deny = []
    for i, entry in enumerate(allow):
        loc = "%s.allow[%d]" % (base, i)
        tool, spec = parse_entry(entry)
        if tool is None:
            ctx.add("YC17", loc, "Unrecognized permission entry %r" % (entry,), needle=str(entry))
            continue
        if tool.lower() in shell_names:
            if analyze_shell(ctx, spec, loc, entry):
                state["shell_open"] = True
        elif tool == "WebFetch":
            if spec is None or spec.strip() in ("", "*", "domain:*", "**", "domain:"):
                ctx.add("YC06", loc, "Unrestricted web fetch auto-approved: %s" % entry, needle=entry)
        elif tool in READ_TOOLS or tool == "Read":
            sp = None if spec is None else spec.strip()
            if sp in BROAD_READ or classify_dir(sp or "") is not None:
                state["broad_read"] = True
            if sp and SECRET_PATH.search(sp):
                ctx.add("YC07", loc, "Allow rule explicitly grants a secret path: %s" % entry, severity="high", needle=entry)
        elif tool in WRITE_TOOLS or tool == "Write":
            sp = None if spec is None else spec.strip()
            target = ("/" + sp.lstrip("/")) if sp and sp.startswith("//") else sp
            if spec is None or (target and classify_dir(target)):
                ctx.add("YC15", loc, "Write/edit auto-approved on root/home scope: %s" % entry, needle=entry)
        elif tool in known_tools or (mcp_prefix and tool.startswith(mcp_prefix)):
            pass
        else:
            ctx.add("YC17", loc, "Unrecognized tool name '%s' in allow rule" % tool, needle=entry)
    return state, [d for d in deny if isinstance(d, str)]


def check_secret_denies(ctx, state, deny, loc, reason):
    if not (state.get("broad_read") or state.get("shell_open") or state.get("bypass")):
        return
    joined = "\n".join(deny)
    missing = [label for label, rx in SECRET_CHECKS if not rx.search(joined)]
    if missing:
        ctx.add("YC07", loc, "Reads are broad (%s) but no deny rule covers: %s" % (reason, ", ".join(missing)),
                needle="permissions")


def check_hooks(ctx, hooks, base="hooks"):
    if isinstance(hooks, dict):
        for k, v in hooks.items():
            check_hooks(ctx, v, "%s.%s" % (base, k))
    elif isinstance(hooks, list):
        for i, v in enumerate(hooks):
            check_hooks(ctx, v, "%s[%d]" % (base, i))


def _hook_commands(obj, path):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k)
            if k in ("command", "cmd", "script") and isinstance(v, str):
                yield p, v
            elif k in ("command", "args") and isinstance(v, list):
                yield p, " ".join(str(x) for x in v)
            else:
                yield from _hook_commands(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _hook_commands(v, "%s[%d]" % (path, i))


def check_claude(ctx, data):
    handled = []
    for k in data:
        if k not in CLAUDE_TOP:
            if APPROVALISH.search(k):
                ctx.add("YC17", k, "Unrecognized top-level key '%s'; not evaluated" % k, needle=k)
            else:
                ctx.add("YC17", k, "Unrecognized top-level key '%s'" % k, needle=k)
            handled.append(k)
    perms = data.get("permissions", {})
    state, deny = {"broad_read": False, "shell_open": False}, []
    if isinstance(perms, dict):
        for k in perms:
            if k not in CLAUDE_PERM:
                ctx.add("YC17", "permissions." + k, "Unrecognized permissions key '%s'" % k, needle=k)
        state, deny = check_permission_lists(ctx, perms, "permissions", {"bash"}, KNOWN_CLAUDE_TOOLS)
        mode = perms.get("defaultMode")
        if mode is not None:
            if mode == "bypassPermissions":
                ctx.add("YC08", "permissions.defaultMode", "defaultMode is bypassPermissions (all prompts skipped)", needle="defaultMode")
                state["bypass"] = True
            elif mode == "acceptEdits":
                ctx.add("YC08", "permissions.defaultMode", "defaultMode is acceptEdits (file edits auto-approved)", severity="low", needle="defaultMode")
            elif mode not in CLAUDE_MODES:
                ctx.add("YC17", "permissions.defaultMode", "Unrecognized defaultMode %r; not evaluated" % (mode,), needle="defaultMode")
        dirs = perms.get("additionalDirectories", [])
        if isinstance(dirs, list):
            for i, d in enumerate(dirs):
                c = classify_dir(d)
                if c == "root":
                    ctx.add("YC15", "permissions.additionalDirectories[%d]" % i, "additionalDirectories includes filesystem root: %s" % d, needle=d)
                elif c == "home":
                    ctx.add("YC15", "permissions.additionalDirectories[%d]" % i, "additionalDirectories includes home directory: %s" % d, severity="medium", needle=d)
                if c:
                    state["broad_read"] = True
    elif perms is not None:
        ctx.add("YC17", "permissions", "permissions is not an object; not evaluated")
    reason = ", ".join(r for r, f in (("broad Read allow", state.get("broad_read")),
                                      ("unrestricted shell", state.get("shell_open")),
                                      ("bypass mode", state.get("bypass"))) if f)
    check_secret_denies(ctx, state, deny, "permissions.deny", reason)
    if data.get("enableAllProjectMcpServers") is True:
        ctx.add("YC16", "enableAllProjectMcpServers", "enableAllProjectMcpServers is true", needle="enableAllProjectMcpServers")
    for loc, cmd in _hook_commands(data.get("hooks", {}), "hooks"):
        scan_command(ctx, cmd, loc)
    sl = data.get("statusLine")
    if isinstance(sl, dict):
        scan_command(ctx, sl.get("command"), "statusLine.command")
    for k in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"):
        scan_command(ctx, data.get(k), k)
    generic_checks(ctx, data, handled_keys=list(CLAUDE_TOP | set(handled)))


def check_cursor(ctx, data):
    perms = data.get("permissions", {})
    state, deny = {"broad_read": False, "shell_open": False}, []
    if isinstance(perms, dict):
        state, deny = check_permission_lists(ctx, perms, "permissions", {"shell"}, CURSOR_TOOLS, mcp_prefix=None)
    for key in ("allowlist", "allowList", "commandAllowlist", "allowedCommands", "terminalAllowlist"):
        lst = data.get(key)
        if isinstance(lst, list):
            for i, c in enumerate(lst):
                if isinstance(c, str):
                    if analyze_shell(ctx, c if c.strip() not in ("*", "") else None, "%s[%d]" % (key, i), c):
                        state["shell_open"] = True
    for key in ("yoloMode", "yolo", "autoRun", "autoRunMode", "autoRunAll", "runEverything"):
        v = data.get(key)
        if v is True or (isinstance(v, str) and v.lower() in ("yolo", "all", "auto", "always", "on", "true")):
            ctx.add("YC12", key, "%s = %s enables auto-run of agent actions" % (key, json.dumps(v)), needle=key)
            state["bypass"] = True
    reason = ", ".join(r for r, f in (("broad Read allow", state.get("broad_read")),
                                      ("unrestricted shell", state.get("shell_open")),
                                      ("auto-run", state.get("bypass"))) if f)
    check_secret_denies(ctx, state, deny, "permissions.deny", reason)
    generic_checks(ctx, data, handled_keys=["permissions", "allowlist", "allowList", "commandAllowlist",
                                            "allowedCommands", "terminalAllowlist", "yoloMode", "yolo",
                                            "autoRun", "autoRunMode", "autoRunAll", "runEverything"])


def _get(d, dotted):
    """Lookup flat dotted key or nested path."""
    if not isinstance(d, dict):
        return None
    if dotted in d:
        return d[dotted]
    cur = d
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def check_gemini(ctx, data):
    handled = []
    for key in ("autoAccept", "tools.autoAccept"):
        if _get(data, key) is True:
            ctx.add("YC12", key, "%s is true (auto-accepts tool calls Gemini deems safe)" % key, severity="low", needle="autoAccept")
        handled.append(key)
    for key in ("yolo", "yoloMode", "general.yolo", "tools.yolo"):
        if _get(data, key) is True:
            ctx.add("YC12", key, "%s is true (all tool calls auto-approved)" % key, needle=key.split(".")[-1])
        handled.append(key)
    for key in ("approvalMode", "defaultApprovalMode", "general.approvalMode", "general.defaultApprovalMode",
                "tools.approvalMode", "security.approvalMode"):
        v = _get(data, key)
        handled.append(key)
        if v is None:
            continue
        if isinstance(v, str) and v.lower() == "yolo":
            ctx.add("YC12", key, "%s = yolo (all tool calls auto-approved)" % key, needle=key.split(".")[-1])
        elif isinstance(v, str) and v.lower() in ("auto_edit", "autoedit", "auto-edit"):
            ctx.add("YC12", key, "%s = %s (file edits auto-approved)" % (key, v), severity="low", needle=key.split(".")[-1])
        elif not (isinstance(v, str) and v.lower() in ("default", "plan", "ask")):
            ctx.add("YC17", key, "Unrecognized approval mode %r; not evaluated" % (v,), needle=key.split(".")[-1])
    if _get(data, "security.disableYoloMode") is not None:
        handled.append("security.disableYoloMode")
    for key in ("tools.allowed", "allowedTools", "autoApprovedTools"):
        lst = _get(data, key)
        handled.append(key)
        if isinstance(lst, list):
            for i, e in enumerate(lst):
                tool, spec = parse_entry(e)
                loc = "%s[%d]" % (key, i)
                if tool and tool.lower() in SHELL_TOOLS:
                    analyze_shell(ctx, spec, loc, e)
                elif tool and tool.lower() in ("web_fetch", "webfetchtool") and not spec:
                    ctx.add("YC06", loc, "Unrestricted web fetch auto-approved: %s" % e, needle=e)
    servers = data.get("mcpServers")
    handled.append("mcpServers")
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if isinstance(cfg, dict) and cfg.get("trust") is True:
                ctx.add("YC12", "mcpServers.%s.trust" % name, "MCP server '%s' is trusted (its tool calls skip confirmation)" % name,
                        severity="medium", needle="trust")
    for loc, cmd in _hook_commands(data.get("hooks", {}), "hooks"):
        scan_command(ctx, cmd, loc)
    handled.append("hooks")
    generic_checks(ctx, data, handled_keys=handled + ["coreTools", "excludeTools", "tools.core", "tools.exclude",
                                                       "security.folderTrust", "folderTrust"])


VSCODE_TERMINAL_KEYS = ("chat.tools.terminal.autoApprove", "chat.agent.terminal.autoApprove",
                        "github.copilot.chat.agent.terminal.allowList", "chat.agent.terminal.allowList")
VSCODE_KNOWN_SAFE = ("chat.tools.terminal.enableAutoApprove", "chat.tools.terminal.denyList",
                     "github.copilot.chat.agent.terminal.denyList", "chat.agent.terminal.denyList",
                     "chat.tools.terminal.ignoreDefaultAutoApproveRules", "chat.tools.eligibleForAutoApproval",
                     "chat.tools.terminal.autoReplyToPrompts", "chat.tools.terminal.blockDetectedFileWrites")


def _truthy_approval(v):
    if v is True:
        return True
    if isinstance(v, dict):
        return v.get("approve") is True
    return False


def check_vscode(ctx, data):
    handled = list(VSCODE_KNOWN_SAFE)
    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove", "github.copilot.chat.agent.autoApprove"):
        v = _get(data, key)
        handled.append(key)
        if v is True:
            ctx.add("YC12", key, "%s is true (every tool call auto-approved)" % key, needle=key)
        elif isinstance(v, dict):
            for tname, tv in v.items():
                if tv is True and tname in ("*", "**"):
                    ctx.add("YC12", "%s.%s" % (key, tname), "All tools auto-approved via '%s'" % tname, needle=tname)
        elif v not in (None, False):
            ctx.add("YC17", key, "Unrecognized value for %s: %r" % (key, v), needle=key)
    for key in VSCODE_TERMINAL_KEYS:
        v = _get(data, key)
        handled.append(key)
        if isinstance(v, dict):
            for cmd, val in v.items():
                if _truthy_approval(val):
                    label = "%s: %s" % (cmd, json.dumps(val))
                    analyze_shell(ctx, cmd, "%s[%s]" % (key, json.dumps(cmd)), label, regex=False)
        elif v is True:
            ctx.add("YC01", key, "%s is true (all terminal commands auto-approved)" % key, needle=key)
    v = _get(data, "chat.tools.urls.autoApprove")
    handled.append("chat.tools.urls.autoApprove")
    if v is True:
        ctx.add("YC06", "chat.tools.urls.autoApprove", "All URL fetches auto-approved", needle="chat.tools.urls.autoApprove")
    elif isinstance(v, dict):
        for pat, val in v.items():
            if _truthy_approval(val) and pat.strip() in ("*", "**", "https://*", "http://*", "https://**", "*://*", "/.*/"):
                ctx.add("YC06", "chat.tools.urls.autoApprove[%s]" % json.dumps(pat), "URL auto-approve pattern matches everything: %s" % pat, needle=pat)
    v = _get(data, "chat.tools.edits.autoApprove")
    handled.append("chat.tools.edits.autoApprove")
    if isinstance(v, dict):
        for pat, val in v.items():
            if val is True and pat.strip() in ("*", "**", "**/*", "/**"):
                ctx.add("YC12", "chat.tools.edits.autoApprove[%s]" % json.dumps(pat),
                        "All file edits auto-approved (%s), including agent edits to its own settings" % pat,
                        severity="medium", needle=pat)
    elif v is True:
        ctx.add("YC12", "chat.tools.edits.autoApprove", "All file edits auto-approved", severity="medium", needle="chat.tools.edits.autoApprove")
    # only flag unknown keys that look approval-related; VS Code settings are huge
    generic_checks(ctx, {k: val for k, val in data.items() if isinstance(k, str) and
                         (k.startswith("chat.") or "copilot" in k.lower() or APPROVALISH.search(k))
                         and not k.startswith("security.workspace")},
                   handled_keys=handled)


CODEX_SANDBOX = {"read-only", "workspace-write", "danger-full-access"}
CODEX_APPROVAL = {"untrusted", "on-failure", "on-request", "never"}


def _codex_scope(ctx, d, base):
    pre = base + "." if base else ""
    sb = d.get("sandbox_mode")
    ap = d.get("approval_policy")
    sww = d.get("sandbox_workspace_write") if isinstance(d.get("sandbox_workspace_write"), dict) else {}
    net = sww.get("network_access") is True
    if sb is not None:
        if sb == "danger-full-access":
            ctx.add("YC09", pre + "sandbox_mode", "sandbox_mode = danger-full-access", needle="sandbox_mode")
        elif sb not in CODEX_SANDBOX:
            ctx.add("YC17", pre + "sandbox_mode", "Unrecognized sandbox_mode %r; not evaluated" % (sb,), needle="sandbox_mode")
    if ap is not None:
        if ap == "never":
            if sb == "danger-full-access" or (sb == "workspace-write" and net):
                ctx.add("YC10", pre + "approval_policy", "approval_policy = never with %s" %
                        ("danger-full-access" if sb == "danger-full-access" else "workspace-write + network_access"), needle="approval_policy")
            elif sb == "workspace-write":
                ctx.add("YC10", pre + "approval_policy", "approval_policy = never with workspace-write (unattended writes)", severity="medium", needle="approval_policy")
            elif sb == "read-only":
                ctx.add("YC10", pre + "approval_policy", "approval_policy = never with read-only sandbox", severity="low", needle="approval_policy")
            else:
                ctx.add("YC10", pre + "approval_policy", "approval_policy = never (sandbox_mode not set in this scope)", severity="medium", needle="approval_policy")
        elif ap not in CODEX_APPROVAL:
            ctx.add("YC17", pre + "approval_policy", "Unrecognized approval_policy %r; not evaluated" % (ap,), needle="approval_policy")
    if sb == "danger-full-access" and ap == "never":
        ctx.add("YC08", pre + "approval_policy", "danger-full-access + never is the --dangerously-bypass-approvals-and-sandbox equivalent", needle="approval_policy")
    if net:
        ctx.add("YC11", pre + "sandbox_workspace_write.network_access", "network_access = true", needle="network_access")
    roots = sww.get("writable_roots", [])
    if isinstance(roots, list):
        for i, r in enumerate(roots):
            c = classify_dir(r)
            if c:
                ctx.add("YC15", "%ssandbox_workspace_write.writable_roots[%d]" % (pre, i), "writable_roots includes %s: %s" % (c, r),
                        severity="high" if c == "root" else "medium", needle=r)
    notify = d.get("notify")
    if isinstance(notify, list):
        scan_command(ctx, " ".join(str(x) for x in notify), pre + "notify")
    elif isinstance(notify, str):
        scan_command(ctx, notify, pre + "notify")


def check_codex(ctx, data):
    _codex_scope(ctx, data, "")
    profiles = data.get("profiles", {})
    if isinstance(profiles, dict):
        for name, p in profiles.items():
            if isinstance(p, dict):
                _codex_scope(ctx, p, "profiles." + name)
    projects = data.get("projects", {})
    if isinstance(projects, dict):
        for pth, p in projects.items():
            if isinstance(p, dict) and p.get("trust_level") == "trusted":
                c = classify_dir(pth)
                if c:
                    ctx.add("YC15", "projects.%s.trust_level" % json.dumps(pth), "%s directory marked trusted: %s" % (c, pth),
                            severity="high" if c == "root" else "medium", needle=pth)
    handled = ["sandbox_mode", "approval_policy", "sandbox_workspace_write", "profiles", "projects", "notify",
               "mcp_servers", "model_providers", "shell_environment_policy"]
    generic_checks(ctx, data, handled_keys=handled)

# ---------------------------------------------------------------- detection & driver

def detect_harness(path, data, is_toml):
    p = path.replace("\\", "/").lower()
    if is_toml:
        if isinstance(data, dict) and (set(data) & {"sandbox_mode", "approval_policy", "sandbox_workspace_write", "profiles", "model_provider", "model", "notify"} or "/.codex/" in p):
            return "codex"
        return None
    if not isinstance(data, dict):
        return None
    if "/.gemini/" in p or p.startswith(".gemini/"):
        return "gemini"
    if "/.vscode/" in p or p.startswith(".vscode/") or any(isinstance(k, str) and (k.startswith("chat.") or k.startswith("github.copilot")) for k in data):
        return "vscode"
    if "/.cursor/" in p or p.startswith(".cursor/") or p.endswith("cli-config.json"):
        return "cursor"
    if "/.claude/" in p or p.startswith(".claude/"):
        return "claude"
    perms = data.get("permissions")
    if isinstance(perms, dict):
        entries = [e for e in (perms.get("allow", []) or []) + (perms.get("deny", []) or []) if isinstance(e, str)]
        if any(e.startswith("Shell(") for e in entries) and not any(e.startswith("Bash") for e in entries):
            return "cursor"
        return "claude"
    if set(data) & {"hooks", "enableAllProjectMcpServers", "apiKeyHelper", "statusLine"}:
        return "claude"
    if set(data) & {"autoAccept", "yolo", "coreTools", "excludeTools", "tools", "general", "security", "mcpServers"}:
        return "gemini"
    if set(data) & {"yoloMode", "allowlist", "commandAllowlist", "autoRun"}:
        return "cursor"
    return None


DISCOVER = (".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml",
            ".gemini/settings.json", ".vscode/settings.json", ".cursor/cli.json", ".cursor/cli-config.json",
            ".cursor/permissions.json")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", ".mypy_cache"}


def discover(root):
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            rel = full.replace("\\", "/")
            if any(rel.endswith("/" + d) or rel == d for d in DISCOVER):
                out.append(full)
            elif fn in ("config.toml", "codex.toml") or fn.endswith(".codex.toml"):
                out.append(full)
            elif fn.endswith((".claude-settings.json", ".yolocheck.json")):
                out.append(full)
    return out


def scan_file(path, display=None):
    display = display or path
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    is_toml = path.lower().endswith(".toml")
    data = parse_toml(text) if is_toml else parse_jsonc(text)
    harness = detect_harness(path, data, is_toml)
    ctx = Ctx(display, text, harness or "unknown")
    checks = {"claude": check_claude, "codex": check_codex, "gemini": check_gemini,
              "vscode": check_vscode, "cursor": check_cursor}
    if harness is None:
        ctx.add("YC17", "(file)", "Unrecognized settings shape; no harness-specific rules applied", needle="")
        if isinstance(data, (dict, list)):
            generic_checks(ctx, data)
    else:
        checks[harness](ctx, data)
    return {"file": display, "harness": ctx.harness, "findings": ctx.findings}


def grade(findings):
    score = 100 - sum(PENALTY[f["severity"]] for f in findings)
    score = max(0, score)
    if score >= 90:
        g = "A"
    elif score >= 80:
        g = "B"
    elif score >= 70:
        g = "C"
    elif score >= 50:
        g = "D"
    else:
        g = "F"
    if g in ("A", "B") and any(f["severity"] == "high" for f in findings):
        g = "C"
    return g, score


def counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    return c


def should_fail(findings, fail_on):
    if fail_on == "none":
        return False
    thr = {"any": "info", "low": "low", "medium": "medium", "high": "high"}[fail_on]
    return any(SEV_RANK[f["severity"]] >= SEV_RANK[thr] for f in findings)


def render_text(results, errors, color=False):
    out = ["yolocheck %s - %d file(s) scanned" % (__version__, len(results)), ""]
    for r in results:
        c = counts(r["all"])
        out.append("%s  [%s]  grade %s (score %d; %d high, %d medium, %d low, %d info)" % (
            r["file"], r["harness"], r["grade"], r["score"], c["high"], c["medium"], c["low"], c["info"]))
        if not r["findings"]:
            out.append("  no findings at or above the selected severity")
        else:
            out.append("  %-7s %-5s %-5s %-40s %s" % ("SEV", "RULE", "LINE", "LOCATION", "MESSAGE"))
            for f in r["findings"]:
                loc = f["location"] if len(f["location"]) <= 40 else f["location"][:37] + "..."
                out.append("  %-7s %-5s %-5s %-40s %s" % (f["severity"], f["rule"], f["line"], loc, f["message"]))
                if f["severity"] != "info":
                    out.append("  %-19s fix: %s" % ("", f["fix"]))
        out.append("")
    for e in errors:
        out.append("ERROR: %s" % e)
    tot = counts([f for r in results for f in r["findings"]])
    out.append("Total: %d high, %d medium, %d low, %d info" % (tot["high"], tot["medium"], tot["low"], tot["info"]))
    return "\n".join(out)


def render_json(results, errors):
    return json.dumps({"tool": "yolocheck", "version": __version__,
                       "files": [{"file": r["file"], "harness": r["harness"], "grade": r["grade"],
                                  "score": r["score"], "counts": counts(r["findings"]), "findings": r["findings"]}
                                 for r in results],
                       "errors": errors}, indent=2)


SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(results, errors):
    rules = [{"id": rid, "name": t.replace(" ", "").replace("/", "").replace("(", "").replace(")", "").replace("=", "").replace("-", ""),
              "shortDescription": {"text": t}, "fullDescription": {"text": why},
              "help": {"text": fix}, "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
              "properties": {"severity": sev}}
             for rid, (sev, t, why, fix) in sorted(RULES.items())]
    res = []
    for r in results:
        for f in r["findings"]:
            res.append({"ruleId": f["rule"], "level": SARIF_LEVEL[f["severity"]],
                        "message": {"text": "%s (%s). Fix: %s" % (f["message"], f["location"], f["fix"])},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                            "region": {"startLine": max(1, int(f["line"]))}}}],
                        "properties": {"severity": f["severity"], "harness": f["harness"], "keyPath": f["location"]}})
    run = {"tool": {"driver": {"name": "yolocheck", "version": __version__, "informationUri": "https://example.invalid/yolocheck",
                               "rules": rules}}, "results": res}
    if errors:
        run["invocations"] = [{"executionSuccessful": False,
                               "toolExecutionNotifications": [{"level": "error", "message": {"text": e}} for e in errors]}]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}, indent=2)


def list_rules():
    lines = []
    for rid, (sev, t, why, fix) in sorted(RULES.items()):
        lines.append("%s  %-7s %s\n      why: %s\n      fix: %s" % (rid, sev, t, why, fix))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="yolocheck", description="Audit coding-agent permission/autonomy settings for risky over-permissioning (offline).")
    ap.add_argument("paths", nargs="*", help="settings files or directories (directories are searched for known settings files)")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity (default info)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "any", "none"], default="high",
                    help="exit 1 if a shown finding is at/above this severity (default high)")
    ap.add_argument("--disable", default="", help="comma-separated rule ids to skip, e.g. YC17,YC05")
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("-o", "--output", help="write report to file instead of stdout")
    ap.add_argument("--version", action="version", version="yolocheck " + __version__)
    a = ap.parse_args(argv)
    if a.list_rules:
        print(list_rules())
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print("yolocheck: error: no paths given", file=sys.stderr)
        return 2
    disabled = {x.strip().upper() for x in a.disable.split(",") if x.strip()}
    files, errors = [], []
    for p in a.paths:
        if os.path.isdir(p):
            found = discover(p)
            if not found:
                errors.append("%s: no known agent settings files found" % p)
            files.extend(found)
        elif os.path.isfile(p):
            files.append(p)
        else:
            errors.append("%s: no such file or directory" % p)
    results = []
    seen = set()
    for f in files:
        if os.path.abspath(f) in seen:
            continue
        seen.add(os.path.abspath(f))
        try:
            r = scan_file(f)
        except (ValueError, OSError, UnicodeError) as e:
            errors.append("%s: %s" % (f, e))
            continue
        allf = [x for x in r["findings"] if x["rule"] not in disabled]
        r["all"] = allf
        r["grade"], r["score"] = grade(allf)
        r["findings"] = sorted([x for x in allf if SEV_RANK[x["severity"]] >= SEV_RANK[a.min_severity]],
                               key=lambda x: (-SEV_RANK[x["severity"]], x["rule"], x["line"]))
        results.append(r)
    if a.json:
        report = render_json(results, errors)
    elif a.sarif:
        report = render_sarif(results, errors)
    else:
        report = render_text(results, errors)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)
    if errors:
        for e in errors:
            print("yolocheck: error: %s" % e, file=sys.stderr)
        return 2
    shown = [f for r in results for f in r["findings"]]
    return 1 if should_fail(shown, a.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
