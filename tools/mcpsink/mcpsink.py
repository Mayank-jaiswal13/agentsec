#!/usr/bin/env python3
"""mcpsink: offline taint scanner for Python MCP server code (tool/resource handlers).

Finds MCP tool, resource and call_tool handlers (FastMCP / official SDK decorators), treats their
parameters as attacker-controlled (the model, and whoever injected the model, chooses them), and follows
them through assignments and same-file helper functions into dangerous sinks: shell commands, file paths,
outbound URLs, SQL, eval/deserialization and environment variables. Also flags all-interface HTTP binds
and tool annotations that contradict what the code does. Standard library only (ast); no network.
Heuristic review aid, not a security boundary.
"""
import argparse
import ast
import fnmatch
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "MS01": ("critical", "Tool argument reaches a shell / process command (command or argument injection)"),
    "MS02": ("high", "Tool argument used as a filesystem path without a containment check (path traversal)"),
    "MS03": ("high", "Tool argument used as an outbound URL / host (SSRF, data exfiltration)"),
    "MS04": ("high", "Tool argument reaches a SQL execute call (SQL injection / arbitrary query)"),
    "MS05": ("critical", "Tool argument reaches eval/exec/import or unsafe deserialization (code execution)"),
    "MS06": ("high", "Tool exposes environment variables (caller-chosen name or whole os.environ)"),
    "MS07": ("medium", "MCP/HTTP server bound to all interfaces (0.0.0.0 / ::)"),
    "MS08": ("low", "Tool annotations contradict or omit destructive behaviour (readOnlyHint / destructiveHint)"),
    "MS09": ("info", "MCP handler inventory"),
}

HANDLER_DECORATORS = {"tool", "resource", "prompt", "call_tool", "read_resource", "get_prompt"}
SKIP_PARAMS = {"self", "cls", "ctx", "context"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "site-packages", "dist", "build"}

KINDS = ("cmd", "path", "url", "sql", "code", "env")
CLEAN_ALL = {"int", "float", "bool", "len", "abs", "round", "hash", "isinstance", "uuid.UUID"}
CLEAN_KIND = {
    "cmd": {"shlex.quote", "shlex.join", "pipes.quote"},
    "path": {"os.path.basename", "werkzeug.utils.secure_filename", "secure_filename"},
    "url": {"urllib.parse.quote", "quote", "urllib.parse.quote_plus", "quote_plus"},
    "sql": set(), "code": set(), "env": set(),
}

SHELL_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
               "commands.getoutput", "asyncio.create_subprocess_shell"}
PROC_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen", "asyncio.create_subprocess_exec", "os.execv", "os.execvp", "os.execl",
              "os.execlp", "os.spawnv", "os.spawnvp", "os.spawnl", "os.spawnlp", "pty.spawn"}
FS_READ = {"open", "io.open", "os.open", "os.listdir", "os.scandir", "os.walk", "os.stat", "glob.glob",
           "glob.iglob", "builtins.open", "aiofiles.open", "codecs.open", "shutil.make_archive", "tarfile.open",
           "zipfile.ZipFile", "send_file", "FileResponse"}
FS_WRITE = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename", "os.replace", "os.makedirs",
            "os.mkdir", "os.chmod", "os.chown", "os.symlink", "os.link", "os.truncate", "shutil.rmtree",
            "shutil.move", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.chown"}
PATH_READ_METHODS = {"read_text", "read_bytes", "iterdir", "glob", "rglob", "open"}
PATH_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "mkdir", "rename", "replace", "touch",
                      "chmod", "symlink_to", "hardlink_to"}
URL_FUNCS = {"urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve",
             "http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.create_connection",
             "aiohttp.request", "webbrowser.open"}
HTTP_LIBS = ("requests", "httpx", "aiohttp", "urllib3")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send",
                "urlopen", "ws_connect"}
HTTP_RECEIVER_HINT = re.compile(r"(client|session|http|requests|httpx|aiohttp|pool)", re.I)
SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql", "raw", "mogrify", "fetch",
               "fetchrow", "fetchval"}
SQL_FUNCS = {"sqlalchemy.text", "text", "pandas.read_sql", "pandas.read_sql_query", "pd.read_sql"}
CODE_FUNCS = {"eval", "exec", "compile", "__import__", "importlib.import_module", "pickle.loads", "pickle.load",
              "cPickle.loads", "dill.loads", "marshal.loads", "shelve.open", "yaml.unsafe_load", "yaml.full_load",
              "runpy.run_path", "runpy.run_module", "jsonpickle.decode", "torch.load", "joblib.load",
              "numpy.load", "code.interact", "jinja2.Template", "Template"}
ENV_FUNCS = {"os.getenv", "os.environ.get", "os.environ.pop", "os.environ.setdefault", "os.putenv"}
AMBIGUOUS_METHODS = {"open", "glob", "rename", "replace", "chmod"}
PATH_CTORS = {"Path", "PurePath", "PosixPath", "WindowsPath", "resolve", "joinpath", "expanduser", "absolute",
              "with_name", "with_suffix", "parent"}

PATH_GUARD = re.compile(r"\b(is_relative_to|commonpath|commonprefix)\b")
PATH_GUARD2 = re.compile(r"\.startswith\(")
PATH_RESOLVE = re.compile(r"\b(resolve|realpath|abspath|normpath)\(")
URL_GUARD = re.compile(r"\b(urlparse|urlsplit)\(")
URL_GUARD2 = re.compile(r"\b(hostname|netloc)\b")
IGNORE_RE = re.compile(r"#\s*mcpsink:\s*ignore(?:\[([A-Z0-9, ]+)\])?")


class Finding:
    __slots__ = ("rule", "severity", "path", "line", "handler", "message", "via")

    def __init__(self, rule, severity, path, line, handler, message, via=""):
        self.rule, self.severity, self.path, self.line = rule, severity, path, line
        self.handler, self.message, self.via = handler, message, via

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted(node.func)
        parts.append((inner or "?") + "()")
    else:
        return ""
    return ".".join(reversed(parts))


class Module:
    def __init__(self, path, src, extra_decorators=()):
        self.path, self.src = path, src
        self.tree = ast.parse(src, filename=path)
        self.lines = src.splitlines()
        self.aliases = {}
        self.funcs = {}
        self.extra = [d.lower() for d in extra_decorators]
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    self.aliases[a.asname or a.name] = n.module + "." + a.name
        for n in self.tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.funcs.setdefault(m.name, m)
        self.parents = {}
        for p in ast.walk(self.tree):
            for c in ast.iter_child_nodes(p):
                self.parents[c] = p

    def resolve(self, node):
        d = dotted(node)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        if head in self.aliases:
            head = self.aliases[head]
        return head + ("." + rest if rest else "")

    def handler_kind(self, fn):
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            d = dotted(target)
            last = d.split(".")[-1] if d else ""
            if last in HANDLER_DECORATORS:
                return last, dec
            for g in self.extra:
                if fnmatch.fnmatch(d.lower(), g) or fnmatch.fnmatch(last.lower(), g):
                    return "tool", dec
        return None, None

    def ignored(self, line, rule):
        if not line or line > len(self.lines):
            return False
        m = IGNORE_RE.search(self.lines[line - 1])
        if not m:
            return False
        return not m.group(1) or rule in [x.strip() for x in m.group(1).split(",")]


class Analyzer:
    def __init__(self, mod, disabled=()):
        self.mod, self.disabled = mod, set(disabled)
        self.findings, self.seen, self.inventory = [], set(), []

    def add(self, rule, sev, line, handler, msg, via=""):
        if rule in self.disabled or self.mod.ignored(line, rule):
            return
        key = (rule, line, msg)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append(Finding(rule, sev, self.mod.path, line, handler, msg, via))

    # ---- taint ----
    def tainted(self, node, kind, T, allow):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in T[kind] and node.id not in allow
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, (ast.Compare, ast.Lambda)):
            return False
        if isinstance(node, ast.Call):
            cn = self.mod.resolve(node.func)
            last = cn.split(".")[-1]
            if cn in CLEAN_ALL or last in CLEAN_ALL or cn in CLEAN_KIND[kind] or last in {
                    c.split(".")[-1] for c in CLEAN_KIND[kind]}:
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("isdigit", "isalnum", "isidentifier"):
                return False
            if kind in ("path", "url") and isinstance(node.func, ast.Name) and node.func.id in self.mod.funcs \
                    and self.guard_helper(node.func.id, kind):
                return False  # same-file validator such as safe_join()/check_url() that contains the guard
        if isinstance(node, ast.Attribute) and node.attr == "name" and kind == "path":
            return False  # Path(x).name strips directories
        return any(self.tainted(c, kind, T, allow) for c in ast.iter_child_nodes(node)
                   if isinstance(c, ast.expr) or isinstance(c, (ast.keyword, ast.comprehension, ast.Starred,
                                                                 ast.FormattedValue)))

    def guard_helper(self, name, kind):
        body = ast.unparse(self.mod.funcs[name])
        if kind == "path":
            return bool(PATH_GUARD.search(body) or (PATH_GUARD2.search(body) and PATH_RESOLVE.search(body)))
        return bool(URL_GUARD.search(body) and URL_GUARD2.search(body))

    def names_in(self, target):
        return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]

    def propagate(self, fn, T, allow):
        changed = True
        while changed:
            changed = False
            for n in ast.walk(fn):
                pairs = []
                if isinstance(n, ast.Assign):
                    pairs = [(t, n.value) for t in n.targets]
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    pairs = [(n.target, n.value)]
                elif isinstance(n, ast.NamedExpr):
                    pairs = [(n.target, n.value)]
                elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                    pairs = [(n.target, n.iter)]
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    pairs = [(i.optional_vars, i.context_expr) for i in n.items if i.optional_vars is not None]
                for tgt, val in pairs:
                    if isinstance(tgt, (ast.Subscript, ast.Attribute)):
                        continue
                    for k in KINDS:
                        if self.tainted(val, k, T, allow):
                            for nm in self.names_in(tgt):
                                if nm not in T[k]:
                                    T[k].add(nm)
                                    changed = True

    def allowlisted(self, fn):
        """Names checked with `x in COLLECTION` / `x not in COLLECTION` (exact allowlist) count as validated."""
        out, regex = set(), set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and len(n.ops) == 1 and isinstance(
                    n.ops[0], (ast.In, ast.NotIn)):
                c = n.comparators[0]
                if isinstance(c, (ast.Set, ast.List, ast.Tuple, ast.Dict)) or (
                        isinstance(c, ast.Name) and c.id.isupper()) or isinstance(c, ast.Attribute):
                    out.add(n.left.id)
            if isinstance(n, ast.Call):
                cn = self.mod.resolve(n.func)
                if cn.split(".")[-1] in ("fullmatch", "match") and cn.startswith(("re.", "regex.")) or (
                        isinstance(n.func, ast.Attribute) and n.func.attr == "fullmatch"):
                    for a in n.args:
                        if isinstance(a, ast.Name):
                            regex.add(a.id)
        return out, regex

    # ---- analysis ----
    def run(self):
        for fn in ast.walk(self.mod.tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            kind, dec = self.mod.handler_kind(fn)
            if not kind:
                continue
            params = [a for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
            if fn.args.vararg:
                params.append(fn.args.vararg)
            if fn.args.kwarg:
                params.append(fn.args.kwarg)
            names = []
            for a in params:
                ann = ast.unparse(a.annotation) if a.annotation is not None else ""
                if a.arg in SKIP_PARAMS or "Context" in ann:
                    continue
                names.append(a.arg)
            self.inventory.append({"handler": fn.name, "kind": kind, "line": fn.lineno, "params": names})
            self.add("MS09", "info", fn.lineno, fn.name, "%s handler '%s' params: %s" % (
                kind, fn.name, ", ".join(names) or "(none)"))
            T = {k: set(names) for k in KINDS}
            destructive = self.analyze(fn, T, fn.name, "", 0, set())
            if kind == "tool" and isinstance(dec, ast.Call):
                self.check_annotations(fn, dec, destructive)
            elif kind == "tool" and destructive:
                self.add("MS08", "low", fn.lineno, fn.name,
                         "tool performs %s but declares no annotations (destructiveHint)" % destructive[0])
        self.check_binds()
        return self.findings

    def analyze(self, fn, T, handler, via, depth, stack):
        allow, regex = self.allowlisted(fn)
        self.propagate(fn, T, allow)
        body = ast.unparse(fn)
        path_guard = bool(PATH_GUARD.search(body) or (PATH_GUARD2.search(body) and PATH_RESOLVE.search(body)))
        url_guard = bool(URL_GUARD.search(body) and URL_GUARD2.search(body))
        destructive = []
        pathobjs = self.path_objects(fn)
        tn = lambda node, k: self.tainted(node, k, T, allow)

        def sev_adj(sev, nodes):
            if any(isinstance(x, ast.Name) and x.id in regex for nd in nodes if nd is not None
                   for x in ast.walk(nd)):
                return "low", " (regex-validated; verify the pattern)"
            return sev, ""

        for n in ast.walk(fn):
            if isinstance(n, ast.Subscript) and self.mod.resolve(n.value) == "os.environ" and tn(n.slice, "env"):
                self.add("MS06", "high", n.lineno, handler, "os.environ[...] indexed by a tool argument: "
                         "the caller can read any secret in the server's environment", via)
            if isinstance(n, ast.Return) and n.value is not None:
                for x in ast.walk(n.value):
                    if self.mod.resolve(x) == "os.environ" and isinstance(x, ast.Attribute):
                        p = self.mod.parents.get(x)
                        if isinstance(p, ast.Subscript) and p.value is x:
                            continue
                        if isinstance(p, ast.Attribute) and p.attr in ("get", "pop"):
                            continue
                        self.add("MS06", "high", n.lineno, handler,
                                 "tool returns the whole os.environ (all API keys/tokens) to the model", via)
            if not isinstance(n, ast.Call):
                continue
            cn = self.mod.resolve(n.func)
            last = cn.split(".")[-1]
            args = list(n.args)
            kw = {k.arg: k.value for k in n.keywords if k.arg}
            a0 = args[0] if args else kw.get("args", kw.get("cmd", kw.get("url", kw.get("path"))))
            # MS01 shell / process
            if cn in SHELL_FUNCS or cn in PROC_FUNCS:
                destructive.append("process execution (%s)" % cn)
                shell = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
                if cn in SHELL_FUNCS or shell:
                    if a0 is not None and tn(a0, "cmd"):
                        s, note = sev_adj("critical", [a0])
                        self.add("MS01", s, n.lineno, handler, "tool argument in a shell command via %s%s: "
                                 "shell metacharacters run arbitrary commands; pass an argv list, no shell%s"
                                 % (cn, " (shell=True)" if shell else "", note), via)
                elif cn == "asyncio.create_subprocess_exec" or cn.startswith(("os.exec", "os.spawn")):
                    rest = args[1:] if not cn.startswith("os.spawn") else args[2:]
                    first = args[0] if not cn.startswith("os.spawn") else (args[1] if len(args) > 1 else None)
                    self._argv(n, handler, via, first, rest, tn, sev_adj, cn)
                elif a0 is not None:
                    if isinstance(a0, (ast.List, ast.Tuple)):
                        elts = a0.elts
                        self._argv(n, handler, via, elts[0] if elts else None, elts[1:], tn, sev_adj, cn)
                    elif tn(a0, "cmd"):
                        s, note = sev_adj("high", [a0])
                        self.add("MS01", s, n.lineno, handler, "tool argument controls the command run by %s "
                                 "(program and/or argv)%s" % (cn, note), via)
            # MS02 filesystem
            fs_write = cn in FS_WRITE
            fs_read = cn in FS_READ or last == "open" and cn in ("open", "io.open")
            if cn in ("open", "io.open", "builtins.open", "codecs.open"):
                mode = args[1] if len(args) > 1 else kw.get("mode")
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
                    fs_write = True
            if fs_write:
                destructive.append("filesystem writes/deletes (%s)" % cn)
            if fs_read or fs_write:
                cand = args[:2] if cn in ("os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copy2",
                                          "shutil.copyfile", "shutil.copytree", "os.symlink", "os.link") else args[:1]
                cand += [v for k, v in kw.items() if k in ("file", "path", "src", "dst", "name", "top", "pathname")]
                if any(tn(c, "path") for c in cand):
                    self._path(n, handler, via, cn, fs_write, path_guard, sev_adj, cand)
            elif isinstance(n.func, ast.Attribute) and (n.func.attr in PATH_READ_METHODS | PATH_WRITE_METHODS) \
                    and not cn.startswith(HTTP_LIBS) and not cn.startswith(("re.", "glob.", "fnmatch.")):
                w = n.func.attr in PATH_WRITE_METHODS
                if n.func.attr == "open":
                    mode = args[0] if args else kw.get("mode")
                    w = isinstance(mode, ast.Constant) and isinstance(mode.value, str) and bool(set(mode.value) & set("wax+"))
                recv = n.func.value
                ok = self._pathish(recv, n.func.attr, pathobjs)
                if w and ok:
                    destructive.append("filesystem writes/deletes (.%s)" % n.func.attr)
                if ok and tn(recv, "path"):
                    self._path(n, handler, via, "." + n.func.attr + "()", w, path_guard, sev_adj, [recv])
            # MS03 URL / SSRF
            is_url = cn in URL_FUNCS or (cn.split(".")[0] in HTTP_LIBS and last in HTTP_METHODS) or (
                isinstance(n.func, ast.Attribute) and last in HTTP_METHODS and
                HTTP_RECEIVER_HINT.search(dotted(n.func.value) or "") and not cn.startswith("os."))
            if is_url:
                cand = args[:2] if last == "request" else args[:1]
                cand += [v for k, v in kw.items() if k in ("url", "host", "address")]
                if any(tn(c, "url") for c in cand):
                    s = "info" if url_guard else "high"
                    s, note = sev_adj(s, cand)
                    self.add("MS03", s, n.lineno, handler, "tool argument used as the URL/host for %s: the model "
                             "can be steered to internal services (169.254.169.254, localhost) or to exfiltrate "
                             "data in the URL%s%s" % (cn or last, "; host check present, verify it" if url_guard
                                                      else "; enforce an allowlist of hosts", note), via)
            # MS04 SQL
            if (isinstance(n.func, ast.Attribute) and last in SQL_METHODS and not cn.startswith(HTTP_LIBS)) \
                    or cn in SQL_FUNCS:
                q = args[0] if args else kw.get("sql", kw.get("query", kw.get("statement")))
                if q is not None and tn(q, "sql"):
                    s, note = sev_adj("high", [q])
                    built = isinstance(q, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute) and q.func.attr == "format")
                    self.add("MS04", s, n.lineno, handler, ("SQL built from a tool argument by string formatting "
                             "in %s: use placeholders (?, %%s) and pass values separately%s" if built else
                             "tool argument passed as the SQL text to %s: the model can run any query (DROP, "
                             "ATTACH, exfiltrate other tables); expose fixed queries instead%s") % (cn or last, note), via)
            # MS05 code execution / deserialization
            if cn in CODE_FUNCS or last in ("loads",) and cn.split(".")[0] in ("pickle", "dill", "marshal", "cPickle") \
                    or (cn in ("yaml.load",) and not self._safe_yaml(n)):
                if any(tn(a, "code") for a in args + list(kw.values())):
                    s, note = sev_adj("critical", args)
                    self.add("MS05", s, n.lineno, handler, "tool argument reaches %s: arbitrary code execution on "
                             "the MCP host%s" % (cn, note), via)
            # MS06 env
            if cn in ENV_FUNCS and args and tn(args[0], "env"):
                self.add("MS06", "high", n.lineno, handler, "%s() with a tool-chosen variable name: the caller can "
                         "read any secret in the server's environment; map allowed names explicitly" % cn, via)
            # helper functions in the same file
            if isinstance(n.func, (ast.Name, ast.Attribute)) and depth < 3:
                hname = n.func.id if isinstance(n.func, ast.Name) else (
                    n.func.attr if isinstance(n.func.value, ast.Name) and n.func.value.id in ("self", "cls") else None)
                helper = self.mod.funcs.get(hname) if hname else None
                if helper is not None and helper is not fn and helper not in stack and \
                        not self.mod.handler_kind(helper)[0]:
                    hp = [a.arg for a in helper.args.posonlyargs + helper.args.args if a.arg not in ("self", "cls")]
                    HT = {k: set() for k in KINDS}
                    for i, a in enumerate(args):
                        if i < len(hp):
                            for k in KINDS:
                                if tn(a, k):
                                    HT[k].add(hp[i])
                    for k2, v in kw.items():
                        if k2 in hp:
                            for k in KINDS:
                                if tn(v, k):
                                    HT[k].add(k2)
                    if any(HT.values()):
                        d = self.analyze(helper, HT, handler, (via + " -> " if via else "via ") + helper.name,
                                         depth + 1, stack | {fn})
                        destructive.extend(d)
                    else:
                        destructive.extend(self.analyze(helper, HT, handler, "", depth + 1, stack | {fn}))
        return destructive

    def _pathish(self, recv, method, pathobjs):
        if method not in AMBIGUOUS_METHODS:
            return True
        if isinstance(recv, ast.BinOp) and isinstance(recv.op, ast.Div):
            return True
        if isinstance(recv, ast.Call):
            last = self.mod.resolve(recv.func).split(".")[-1]
            return last in PATH_CTORS
        return isinstance(recv, ast.Name) and recv.id in pathobjs

    def path_objects(self, fn):
        objs, changed = set(), True
        while changed:
            changed = False
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and self._pathish(n.value, "open", objs):
                    for t in n.targets:
                        if isinstance(t, ast.Name) and t.id not in objs:
                            objs.add(t.id)
                            changed = True
        return objs

    def _safe_yaml(self, n):
        for k in n.keywords:
            if k.arg == "Loader" and "Safe" in (dotted(k.value) or ""):
                return True
        return len(n.args) > 1 and "Safe" in (dotted(n.args[1]) or "")

    def _argv(self, n, handler, via, first, rest, tn, sev_adj, cn):
        if first is not None and tn(first, "cmd"):
            s, note = sev_adj("high", [first])
            self.add("MS01", s, n.lineno, handler, "tool argument chooses the program run by %s%s" % (cn, note), via)
            return
        bad, dashdash = [], False
        for e in rest:
            if isinstance(e, ast.Constant) and e.value == "--":
                dashdash = True
            elif tn(e, "cmd") and not dashdash:
                bad.append(e)
        if bad:
            prog = first.value if isinstance(first, ast.Constant) else (dotted(first) or "?")
            interp = str(prog).split("/")[-1] in ("sh", "bash", "zsh", "python", "python3", "node", "perl", "ruby",
                                                 "pwsh", "powershell", "cmd", "osascript")
            flag_c = any(isinstance(e, ast.Constant) and e.value in ("-c", "-e", "/c", "-Command") for e in rest)
            if interp and flag_c:
                s, note = sev_adj("critical", bad)
                self.add("MS01", s, n.lineno, handler, "tool argument passed as code to %s -c via %s: equivalent "
                         "to a shell%s" % (prog, cn, note), via)
            else:
                s, note = sev_adj("low", bad)
                self.add("MS01", s, n.lineno, handler, "tool argument in the argv of '%s' (%s): option/argument "
                         "injection (e.g. --upload-pack, -o); validate it and insert '--' before it%s"
                         % (prog, cn, note), via)

    def _path(self, n, handler, via, op, write, guard, sev_adj, cand):
        if guard:
            s, extra = "info", "; a containment check is present, verify it covers this path"
        else:
            s, extra = "high", ("; resolve() it and require is_relative_to(<allowed root>), "
                                "or reduce it to a basename")
        s, note = sev_adj(s, cand)
        self.add("MS02", s, n.lineno, handler, "tool argument used as a path for %s (%s): '../' or absolute paths "
                 "reach files outside the intended root (~/.ssh, .env)%s%s"
                 % (op, "write/delete" if write else "read", extra, note), via)

    def check_annotations(self, fn, dec, destructive):
        ro = dh = None
        def scan(kvs):
            nonlocal ro, dh
            for k, v in kvs:
                if k in ("readOnlyHint", "read_only_hint") and isinstance(v, ast.Constant):
                    ro = bool(v.value)
                if k in ("destructiveHint", "destructive_hint") and isinstance(v, ast.Constant):
                    dh = bool(v.value)
        scan([(k.arg, k.value) for k in dec.keywords])
        for k in dec.keywords:
            v = k.value
            if k.arg == "annotations":
                if isinstance(v, ast.Dict):
                    scan([(kk.value if isinstance(kk, ast.Constant) else None, vv) for kk, vv in zip(v.keys, v.values)])
                elif isinstance(v, ast.Call):
                    scan([(kk.arg, kk.value) for kk in v.keywords])
        if not destructive:
            return
        writes = [d for d in destructive if d.startswith("filesystem")]
        what = (writes or destructive)[0]
        if ro is True:
            self.add("MS08", "high" if writes else "medium", fn.lineno, fn.name, "tool declares readOnlyHint=True "
                     "but performs %s: clients may auto-approve it as read-only%s"
                     % (what, "" if writes else "; verify the command really is read-only"))
        elif dh is False and not writes:
            return
        elif dh is False:
            self.add("MS08", "medium", fn.lineno, fn.name, "tool declares destructiveHint=False but performs %s" % what)
        elif dh is None:
            self.add("MS08", "low", fn.lineno, fn.name, "tool performs %s but does not declare destructiveHint=True "
                     "(clients use annotations to decide when to ask the user)" % what)

    def check_binds(self):
        for n in ast.walk(self.mod.tree):
            if isinstance(n, ast.Call):
                for k in n.keywords:
                    if k.arg in ("host", "bind", "listen") and isinstance(k.value, ast.Constant) and \
                            k.value.value in ("0.0.0.0", "::", "[::]"):
                        self.add("MS07", "medium", n.lineno, "-", "%s(host=%r): the server listens on every interface;"
                                 " MCP HTTP/SSE transports usually have no auth, so anyone on the network can call "
                                 "its tools (also enables DNS-rebinding); bind 127.0.0.1 or add auth"
                                 % (self.mod.resolve(n.func) or "call", k.value.value))
            elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value in ("0.0.0.0", "::"):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and t.attr == "host":
                        self.add("MS07", "medium", n.lineno, "-", "%s = %r: server bound to all interfaces"
                                 % (dotted(t), n.value.value))


def looks_mcp(src):
    return bool(re.search(r"\b(mcp|fastmcp|FastMCP|call_tool|modelcontextprotocol)\b", src))


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p, True
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for f in sorted(files):
                    if f.endswith(".py"):
                        yield os.path.join(root, f), False
        else:
            raise FileNotFoundError(p)


def scan_source(path, src, extra_decorators=(), disabled=()):
    mod = Module(path, src, extra_decorators)
    an = Analyzer(mod, disabled)
    an.run()
    return an.findings, an.inventory


def scan_paths(paths, extra_decorators=(), disabled=()):
    results, errors = [], []
    for p, explicit in iter_files(paths):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError as e:
            errors.append("%s: %s" % (p, e))
            continue
        if not explicit and not looks_mcp(src) and not extra_decorators:
            continue
        try:
            f, inv = scan_source(p, src, extra_decorators, disabled)
        except SyntaxError as e:
            errors.append("%s: syntax error line %s: %s" % (p, e.lineno, e.msg))
            continue
        results.append({"path": p, "handlers": inv, "findings": f})
    return results, errors


def to_sarif(results):
    lvl = lambda s: {"critical": "error", "high": "error", "medium": "warning"}.get(s, "note")
    rules = [{"id": r, "shortDescription": {"text": t}, "defaultConfiguration": {"level": lvl(s)}}
             for r, (s, t) in sorted(RULES.items())]
    res = []
    for r in results:
        for f in r["findings"]:
            res.append({"ruleId": f.rule, "level": lvl(f.severity),
                        "message": {"text": "[%s] %s: %s%s" % (f.severity, f.handler, f.message,
                                                               " (%s)" % f.via if f.via else "")},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                                                            "region": {"startLine": f.line or 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "mcpsink", "version": VERSION, "rules": rules}}, "results": res}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcpsink", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", default=["."], help="Python files or directories (default .)")
    ap.add_argument("--decorator", action="append", default=[], metavar="GLOB",
                    help="extra decorator name/glob that marks a tool handler, e.g. 'register_tool' (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule id (repeatable)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--sarif", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="mcpsink " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (s, t) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, s, t))
        return 0
    try:
        results, errors = scan_paths(a.paths, a.decorator, set(a.disable))
    except FileNotFoundError as e:
        print("mcpsink: no such file or directory: %s" % e, file=sys.stderr)
        return 2
    for e in errors:
        print("mcpsink: " + e, file=sys.stderr)
    if errors and not results:
        return 2
    minr = SEV_RANK[a.min_severity]
    for r in results:
        r["findings"] = [f for f in r["findings"] if SEV_RANK[f.severity] >= minr]
        r["findings"].sort(key=lambda f: (-SEV_RANK[f.severity], f.line or 0, f.rule))
    allf = [f for r in results for f in r["findings"]]
    if a.json:
        print(json.dumps({"version": VERSION, "files": [{"path": r["path"], "handlers": r["handlers"],
                          "findings": [f.to_dict() for f in r["findings"]]} for r in results],
                          "errors": errors}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    else:
        for r in results:
            for f in r["findings"]:
                print("%-8s %s %s:%s handler=%s%s" % (f.severity.upper(), f.rule, f.path, f.line or "?", f.handler,
                                                     " " + f.via if f.via else ""))
                print("         " + f.message)
        nh = sum(len(r["handlers"]) for r in results)
        counts = {s: sum(1 for f in allf if f.severity == s) for s in SEVERITIES}
        summary = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if counts[s]) or "none"
        print("%d file(s), %d MCP handler(s); %d finding(s): %s" % (len(results), nh, len(allf), summary))
    if a.fail_on == "none":
        return 0
    thr = SEV_RANK["low"] if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= thr for f in allf) else 0


if __name__ == "__main__":
    sys.exit(main())
