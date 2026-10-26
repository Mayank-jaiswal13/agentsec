#!/usr/bin/env python3
"""slopcheck - offline hallucinated-package / slopsquatting risk checker.

Flags risky names in dependency manifests and source imports by comparing them
against a bundled, hand-picked snapshot of well-known package names. It does
NOT contact any registry and cannot tell whether a package exists or is
malicious. Treat every finding as "go verify this on the registry yourself".

Stdlib only. Python 3.8+ (tomllib used when available, 3.11+).
"""
import argparse
import ast
import json
import os
import re
import sys

__version__ = "0.1.0"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KNOWN = os.path.join(HERE, "slopcheck_known.json")
IGNORE_MARK = "slopcheck: ignore"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "SC01": ("info", "Name not in bundled snapshot or allowlist (unverified)"),
    "SC02": ("high", "Near-miss typo / confusable of a well-known package name"),
    "SC03": ("medium", "AI-hallucination naming pattern (popular base + generic affix)"),
    "SC04": ("medium", "Ecosystem confusion (name known only in the other ecosystem)"),
    "SC05": ("low", "Unpinned or loose version specifier"),
    "SC06": ("medium", "Direct URL / VCS / git dependency bypasses the registry"),
    "SC07": ("low", "Imported package has no declared dependency"),
    "SC08": ("low", "Declared dependency never imported"),
}

# import name -> distribution name (PyPI)
IMPORT_TO_DIST = {
    "yaml": "pyyaml", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "skimage": "scikit-image", "PIL": "pillow", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt",
    "docx": "python-docx", "Crypto": "pycryptodome", "nacl": "pynacl",
    "OpenSSL": "pyopenssl", "dns": "dnspython", "git": "gitpython",
    "github": "pygithub", "serial": "pyserial", "usb": "pyusb", "zmq": "pyzmq",
    "google": "google-api-core", "googleapiclient": "google-api-python-client",
    "attr": "attrs", "magic": "python-magic", "multipart": "python-multipart",
    "ruamel": "ruamel-yaml", "socks": "pysocks", "slack_sdk": "slack-sdk",
    "faiss": "faiss-cpu", "pinecone": "pinecone-client", "weaviate": "weaviate-client",
    "qdrant_client": "qdrant-client", "sentence_transformers": "sentence-transformers",
    "huggingface_hub": "huggingface-hub", "typing_extensions": "typing-extensions",
    "pkg_resources": "setuptools", "rest_framework": "djangorestframework",
    "websocket": "websocket-client", "pydantic_core": "pydantic-core",
    "prometheus_client": "prometheus-client", "email_validator": "email-validator",
    "opentelemetry": "opentelemetry-api", "sentry_sdk": "sentry-sdk",
    "psycopg2": "psycopg2", "MySQLdb": "mysqlclient", "fitz": "pymupdf",
    "agents": "openai-agents", "google.generativeai": "google-generativeai",
}
DIST_TO_IMPORTS = {}
for _imp, _dist in IMPORT_TO_DIST.items():
    DIST_TO_IMPORTS.setdefault(_dist, set()).add(_imp.split(".")[0].lower())

# Declared tools that are rarely imported; skipped by SC08.
NON_IMPORTED_PY = {
    "pytest", "pytest-cov", "pytest-mock", "pytest-asyncio", "coverage", "tox", "nox",
    "black", "isort", "flake8", "pylint", "mypy", "ruff", "pre-commit", "bandit",
    "safety", "setuptools", "wheel", "pip", "build", "twine", "gunicorn", "uvicorn",
    "hatchling", "flit-core", "poetry-core", "sphinx", "mkdocs", "mkdocs-material",
    "ipython", "jupyter", "notebook", "jupyterlab", "ipykernel", "psycopg2-binary",
    "opencv-python-headless", "tzdata", "python", "awscli",
}

AFFIXES_SUFFIX = [
    "utils", "util", "utilities", "helper", "helpers", "sdk", "api", "py",
    "python", "python3", "py3", "js", "node", "client", "tools", "tool", "toolkit",
    "pro", "plus", "extra", "extras", "lib", "wrapper", "ai", "core", "kit", "ext",
    "official", "lite", "fast", "async", "v2", "next", "cli", "dev",
]
AFFIXES_PREFIX = ["python", "py", "node", "js", "official", "easy", "simple", "fast", "pro", "the"]

NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events",
    "fs", "http", "http2", "https", "inspector", "module", "net", "os", "path",
    "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util",
    "v8", "vm", "wasi", "worker_threads", "zlib", "test",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
             "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".hg"}

JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

try:
    STDLIB = set(sys.stdlib_module_names)  # 3.10+
except AttributeError:  # pragma: no cover
    STDLIB = {"os", "sys", "re", "json", "ast", "time", "math", "typing", "collections",
              "itertools", "functools", "subprocess", "pathlib", "logging", "argparse",
              "unittest", "datetime", "random", "string", "io", "shutil", "tempfile",
              "asyncio", "dataclasses", "enum", "abc", "copy", "hashlib", "base64",
              "urllib", "http", "socket", "threading", "csv", "sqlite3", "pickle"}
STDLIB |= {"__future__"}


class SlopError(Exception):
    pass


# ---------------------------------------------------------------- helpers
def norm_pypi(name):
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def norm_npm(name):
    return name.strip().lower()


def normalize(name, eco):
    return norm_pypi(name) if eco == "pypi" else norm_npm(name)


def osa_distance(a, b, cap=None):
    """Damerau-Levenshtein (optimal string alignment) distance."""
    la, lb = len(a), len(b)
    if cap is not None and abs(la - lb) > cap:
        return cap + 1
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def load_known(path=None):
    path = path or DEFAULT_KNOWN
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise SlopError("cannot load snapshot %s: %s" % (path, e))
    if not isinstance(data, dict) or not isinstance(data.get("pypi"), list) or not isinstance(data.get("npm"), list):
        raise SlopError("snapshot %s must contain 'pypi' and 'npm' lists" % path)
    return {"pypi": {norm_pypi(n) for n in data["pypi"]},
            "npm": {norm_npm(n) for n in data["npm"]}}


def load_allow(path):
    names = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    names.add(line)
    except OSError as e:
        raise SlopError("cannot read allowlist %s: %s" % (path, e))
    return names


# ---------------------------------------------------------------- data model
class Dep(object):
    """A declared dependency or an imported package."""

    def __init__(self, name, eco, file, line, kind, spec="", dev=False, ignored=False,
                 module=None):
        self.name = name
        self.eco = eco          # 'pypi' | 'npm'
        self.file = file
        self.line = line
        self.kind = kind        # 'declared' | 'import'
        self.spec = spec
        self.dev = dev
        self.ignored = ignored
        self.module = module    # import name for imports

    def __repr__(self):
        return "Dep(%r,%r,%r,%r)" % (self.name, self.eco, self.kind, self.spec)


def finding(rule, dep, message, severity=None, related=None):
    f = {"rule": rule, "severity": severity or RULES[rule][0], "name": dep.name,
         "ecosystem": dep.eco, "file": dep.file, "line": dep.line, "kind": dep.kind,
         "message": message}
    if related:
        f["related"] = related
    return f


# ---------------------------------------------------------------- parsers
REQ_NAME_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
URL_RE = re.compile(r"^(git\+|hg\+|svn\+|bzr\+|https?://|file:|ftp://)", re.I)


def parse_requirement(text, file, line, dev=False, ignored=False):
    """Parse one PEP 508-ish requirement string. Returns Dep or None."""
    s = text.strip()
    if not s:
        return None
    if s.startswith(("-e ", "--editable ", "--editable=")):
        s = s.split(None, 1)[1] if " " in s else s.split("=", 1)[1]
        s = s.strip()
    if URL_RE.match(s):
        m = re.search(r"#egg=([A-Za-z0-9._-]+)", s)
        name = m.group(1) if m else re.split(r"[/@#]", s.rstrip("/").split("/")[-1])[0]
        name = re.sub(r"\.git$", "", name) or s
        return Dep(name, "pypi", file, line, "declared", spec=s, dev=dev, ignored=ignored)
    if s.startswith(("-", ".", "/")):
        return None
    m = REQ_NAME_RE.match(s)
    if not m:
        return None
    name, rest = m.group(1), m.group(3)
    rest = rest.split(";", 1)[0].strip()
    return Dep(name, "pypi", file, line, "declared", spec=rest, dev=dev, ignored=ignored)


def parse_requirements(path, text=None):
    if text is None:
        text = read_text(path)
    deps = []
    for i, raw in enumerate(text.splitlines(), 1):
        ignored = IGNORE_MARK in raw
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line or line.startswith(("-r", "-c", "--requirement", "--constraint",
                                        "--index-url", "--extra-index-url", "-i ",
                                        "--find-links", "-f ", "--hash", "--trusted-host")):
            continue
        line = re.sub(r"\s--hash[= ]\S+", "", line).rstrip(" \\")
        d = parse_requirement(line, path, i, ignored=ignored)
        if d:
            deps.append(d)
    return deps


def _find_line(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1, IGNORE_MARK in lines[i]
    return 0, False


def parse_pyproject(path, text=None):
    if text is None:
        text = read_text(path)
    lines = text.splitlines()
    data = None
    try:
        import tomllib  # type: ignore
        try:
            data = tomllib.loads(text)
        except Exception as e:
            raise SlopError("%s: invalid TOML: %s" % (path, e))
    except ImportError:  # pragma: no cover - fallback for <3.11
        data = _mini_toml(text)
    deps = []

    def add_req(req, dev=False):
        if not isinstance(req, str):
            return
        ln, ign = _find_line(lines, req.split(";")[0].strip()[:40])
        d = parse_requirement(req, path, ln, dev=dev, ignored=ign)
        if d:
            deps.append(d)

    proj = data.get("project", {}) if isinstance(data, dict) else {}
    for r in proj.get("dependencies", []) or []:
        add_req(r)
    for grp in (proj.get("optional-dependencies", {}) or {}).values():
        for r in grp or []:
            add_req(r, dev=True)
    for grp in (data.get("dependency-groups", {}) or {}).values():
        for r in grp or []:
            add_req(r, dev=True)
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    tables = [(poetry.get("dependencies", {}), False), (poetry.get("dev-dependencies", {}), True)]
    for g in (poetry.get("group", {}) or {}).values():
        tables.append(((g or {}).get("dependencies", {}), True))
    for table, dev in tables:
        for name, val in (table or {}).items():
            if name.lower() == "python":
                continue
            spec = ""
            if isinstance(val, str):
                spec = val
            elif isinstance(val, dict):
                if "git" in val:
                    spec = "git+" + str(val["git"])
                elif "url" in val:
                    spec = str(val["url"])
                elif "path" in val:
                    continue
                else:
                    spec = str(val.get("version", ""))
            ln, ign = 0, False
            for i, l in enumerate(lines):
                if re.match(r"^\s*\"?%s\"?\s*=" % re.escape(name), l):
                    ln, ign = i + 1, IGNORE_MARK in l
                    break
            if spec.strip() == "*":
                spec = "*"
            deps.append(Dep(name, "pypi", path, ln, "declared", spec=spec, dev=dev, ignored=ign))
    return deps


def _mini_toml(text):  # pragma: no cover - only used without tomllib (Python < 3.11)
    """Small section-aware fallback for the subset of pyproject.toml slopcheck reads:
    [project] dependencies, [project.optional-dependencies], [dependency-groups],
    and Poetry dependency tables (string values or inline tables)."""
    out = {"project": {"dependencies": [], "optional-dependencies": {}},
           "dependency-groups": {},
           "tool": {"poetry": {"dependencies": {}, "dev-dependencies": {}, "group": {}}}}

    def strings(val):
        return re.findall(r"\"([^\"]*)\"|'([^']*)'", val)

    def str_list(val):
        return [a or b for a, b in strings(val)]

    def inline_table(val):
        return {k: (a or b) for k, a, b in
                re.findall(r"([A-Za-z0-9_-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", val)}

    def target(sec):
        poetry = out["tool"]["poetry"]
        if sec == "tool.poetry.dependencies":
            return poetry["dependencies"]
        if sec == "tool.poetry.dev-dependencies":
            return poetry["dev-dependencies"]
        g = re.match(r"^tool\.poetry\.group\.([^.]+)\.dependencies$", sec or "")
        if g:
            return poetry["group"].setdefault(g.group(1), {"dependencies": {}})["dependencies"]
        return None

    sec, lines, i = None, text.splitlines(), 0
    while i < len(lines):
        line = lines[i].split(" #")[0].rstrip() if not lines[i].lstrip().startswith("#") else ""
        i += 1
        h = re.match(r"^\s*\[([^\[\]]+)\]\s*$", line)
        if h:
            sec = h.group(1).strip().replace('"', "")
            continue
        kv = re.match(r"^\s*\"?([A-Za-z0-9._-]+)\"?\s*=\s*(.*)$", line)
        if not kv:
            continue
        key, val = kv.group(1), kv.group(2).strip()
        if val.startswith("["):  # gather a possibly multi-line array
            while val.count("[") > val.count("]") and i < len(lines):
                val += " " + lines[i].split(" #")[0].strip()
                i += 1
        if sec == "project" and key == "dependencies":
            out["project"]["dependencies"] = str_list(val)
        elif sec == "project.optional-dependencies":
            out["project"]["optional-dependencies"][key] = str_list(val)
        elif sec == "dependency-groups":
            out["dependency-groups"][key] = str_list(val)
        else:
            t = target(sec)
            if t is not None:
                if val.startswith("{"):
                    t[key] = inline_table(val)
                else:
                    sv = str_list(val)
                    t[key] = sv[0] if sv else val
    return out


NPM_DEP_KEYS = [("dependencies", False), ("devDependencies", True),
                ("peerDependencies", False), ("optionalDependencies", False)]


def parse_package_json(path, text=None):
    if text is None:
        text = read_text(path)
    try:
        data = json.loads(text)
    except ValueError as e:
        raise SlopError("%s: invalid JSON: %s" % (path, e))
    if not isinstance(data, dict):
        raise SlopError("%s: top level must be an object" % path)
    lines = text.splitlines()
    ignore = set(data.get("slopcheck", {}).get("ignore", []) if isinstance(data.get("slopcheck"), dict) else [])
    deps = []
    for key, dev in NPM_DEP_KEYS:
        table = data.get(key) or {}
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            ln, _ = _find_line(lines, '"%s"' % name)
            deps.append(Dep(name, "npm", path, ln, "declared", spec=str(spec), dev=dev,
                            ignored=name in ignore))
    return deps


def parse_python_imports(path, text=None):
    if text is None:
        text = read_text(path)
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as e:
        raise SlopError("%s: syntax error: %s" % (path, e))
    lines = text.splitlines()
    out = []
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            mods = [node.module]
        else:
            continue
        ln = node.lineno
        ignored = 0 < ln <= len(lines) and IGNORE_MARK in lines[ln - 1]
        for mod in mods:
            top = mod.split(".")[0]
            if top in STDLIB:
                continue
            dist = IMPORT_TO_DIST.get(mod) or IMPORT_TO_DIST.get(top) or top
            out.append(Dep(dist, "pypi", path, ln, "import", ignored=ignored, module=top))
    return out


JS_IMPORT_RES = [
    re.compile(r"""\bimport\s+(?:[\w*{}\s,$]+\s+from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""\bexport\s+[\w*{}\s,$]+\s+from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
]


def js_package_name(spec):
    if spec.startswith((".", "/", "node:", "http:", "https:", "data:", "~", "#", "$")):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        if len(parts) < 2 or not parts[1]:
            return None
        name = "/".join(parts[:2])
    else:
        name = parts[0]
        if name in NODE_BUILTINS:
            return None
    return name


def parse_js_imports(path, text=None):
    if text is None:
        text = read_text(path)
    out = []
    lines = text.splitlines()
    starts = [0]
    for l in lines:
        starts.append(starts[-1] + len(l) + 1)
    import bisect
    seen = set()
    for rx in JS_IMPORT_RES:
        for m in rx.finditer(text):
            name = js_package_name(m.group(1))
            if not name:
                continue
            ln = bisect.bisect_right(starts, m.start(1))
            if (name, ln) in seen:
                continue
            seen.add((name, ln))
            ignored = IGNORE_MARK in lines[ln - 1] if 0 < ln <= len(lines) else False
            out.append(Dep(name, "npm", path, ln, "import", ignored=ignored, module=name))
    out.sort(key=lambda d: d.line)
    return out


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        raise SlopError("cannot read %s: %s" % (path, e))


def classify(path):
    base = os.path.basename(path).lower()
    if base == "package.json":
        return "package.json"
    if base == "pyproject.toml":
        return "pyproject"
    if base.endswith(".txt") and (base.startswith("requirements") or "requirements" in base):
        return "requirements"
    if base.endswith((".py", ".pyw")):
        return "py"
    if base.endswith(JS_EXTS) and not base.endswith(".d.ts"):
        return "js"
    return None


def collect_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
                for n in sorted(names):
                    fp = os.path.join(root, n)
                    if classify(fp):
                        files.append(fp)
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise SlopError("no such file or directory: %s" % p)
    return files


def local_modules(files):
    """First-party module names (stems of scanned .py files and their parent dirs)."""
    mods = set()
    for f in files:
        if classify(f) == "py":
            mods.add(os.path.splitext(os.path.basename(f))[0])
            parent = os.path.basename(os.path.dirname(os.path.abspath(f)))
            if parent:
                mods.add(parent)
    return mods


# ---------------------------------------------------------------- checks
def strip_affixes(n):
    """Return (core, removed_affixes) after peeling generic prefixes/suffixes."""
    parts = re.split(r"[-_.]", n)
    removed = []
    changed = True
    while changed and len(parts) > 1:
        changed = False
        if parts[-1] in AFFIXES_SUFFIX:
            removed.append(parts.pop())
            changed = True
        elif parts[0] in AFFIXES_PREFIX and len(parts) > 1:
            removed.append(parts.pop(0))
            changed = True
    return "-".join(parts), removed


def name_checks(dep, known, allow):
    eco = dep.eco
    other = "npm" if eco == "pypi" else "pypi"
    n = normalize(dep.name, eco)
    if n in allow[eco] or (eco == "npm" and n in allow.get("npm_raw", set())):
        return []
    own = known[eco]
    if n in own:
        if eco == "npm" and dep.name != dep.name.lower():
            return [finding("SC02", dep, "npm names are lowercase; '%s' is a case-confused form of '%s'"
                            % (dep.name, n), related=n)]
        return []
    out = []
    bare = n.split("/", 1)[1] if eco == "npm" and n.startswith("@") and "/" in n else n
    # SC04: ecosystem confusion
    other_n = normalize(dep.name, other)
    if other_n in known[other] and other_n not in own:
        out.append(finding("SC04", dep, "'%s' is a well-known %s package but not a known %s one; "
                           "likely wrong ecosystem" % (dep.name, other, eco), related=other_n))
    # SC02: typo / confusable
    best = None
    collapsed = re.sub(r"[-_.]", "", bare)
    for k in own:
        kb = k.split("/", 1)[1] if k.startswith("@") and "/" in k else k
        if k.startswith("@") != n.startswith("@") and k.startswith("@"):
            continue
        if len(kb) < 4:
            continue
        if re.sub(r"[-_.]", "", kb) == collapsed and kb != bare:
            best = (0, k, "separator confusion")
            break
        thr = 1 if len(kb) <= 6 else 2
        d = osa_distance(n if not k.startswith("@") else n, k, cap=thr)
        if d <= thr and (best is None or d < best[0]):
            best = (d, k, "edit distance %d" % d)
    if best:
        out.append(finding("SC02", dep, "'%s' is a near-miss of well-known '%s' (%s); possible typo or "
                           "slopsquat" % (dep.name, best[1], best[2]), related=best[1]))
    # SC03: hallucination naming pattern
    core, removed = strip_affixes(bare)
    if removed and core and (core in own or normalize(core, eco) in own) and core != bare:
        out.append(finding("SC03", dep, "'%s' = popular '%s' + generic affix(es) %s; a common shape of "
                           "AI-hallucinated names" % (dep.name, core, "/".join(removed)), related=core))
    if not out:
        out.append(finding("SC01", dep, "'%s' is not in the bundled snapshot or allowlist: unverified, "
                           "check the registry yourself" % dep.name))
    return out


def version_checks(dep):
    if dep.kind != "declared":
        return []
    spec = (dep.spec or "").strip()
    out = []
    if dep.eco == "pypi":
        if URL_RE.match(spec) or spec.startswith("@") or "://" in spec:
            out.append(finding("SC06", dep, "direct URL/VCS dependency (%s) bypasses the registry; pin a "
                               "commit hash and review the source" % spec[:80]))
            return out
        if not spec or spec == "*":
            out.append(finding("SC05", dep, "no version pin; an attacker-registered or changed release "
                               "would be picked up automatically"))
        elif "==" not in spec and "~=" not in spec and not spec.startswith(("^", "~")) \
                and not re.match(r"^\d", spec) and "<" not in spec:
            out.append(finding("SC05", dep, "loose version '%s' (no upper bound or exact pin)" % spec))
    else:
        low = spec.lower()
        if re.match(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?://|file:)", low) or \
                re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec):
            out.append(finding("SC06", dep, "direct URL/git dependency (%s) bypasses the registry" % spec[:80]))
        elif low in ("", "*", "latest", "x", "next") or re.match(r"^>=?\s*[\d.]+$", low):
            out.append(finding("SC05", dep, "unpinned/loose version '%s'" % (spec or "(empty)")))
    return out


def analyze(files, known, allow, check_usage=True):
    deps = []
    errors = []
    for f in files:
        kind = classify(f) or ("requirements" if f.endswith(".txt") else None)
        try:
            if kind == "requirements":
                deps += parse_requirements(f)
            elif kind == "pyproject":
                deps += parse_pyproject(f)
            elif kind == "package.json":
                deps += parse_package_json(f)
            elif kind == "py":
                deps += parse_python_imports(f)
            elif kind == "js":
                deps += parse_js_imports(f)
            else:
                errors.append("unsupported file type: %s" % f)
        except SlopError as e:
            errors.append(str(e))
    locals_ = local_modules(files)
    deps = [d for d in deps if not (d.kind == "import" and d.eco == "pypi" and d.module in locals_)]
    findings = []
    checked = set()
    for d in deps:
        if d.ignored:
            continue
        key = (d.eco, normalize(d.name, d.eco), d.file, d.line)
        if key in checked:
            continue
        checked.add(key)
        findings += name_checks(d, known, allow)
        findings += version_checks(d)
    if check_usage:
        findings += usage_checks(deps, allow)
    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["file"], f["line"], f["rule"]))
    return {"findings": findings, "errors": errors, "files": files,
            "counts": {"declared": sum(1 for d in deps if d.kind == "declared"),
                       "imports": sum(1 for d in deps if d.kind == "import")}}


def usage_checks(deps, allow):
    out = []
    for eco in ("pypi", "npm"):
        declared = [d for d in deps if d.eco == eco and d.kind == "declared"]
        imports = [d for d in deps if d.eco == eco and d.kind == "import"]
        if not declared or not imports:
            continue
        dnames = {normalize(d.name, eco) for d in declared}
        inames = {normalize(d.name, eco) for d in imports}
        imods = {(d.module or "").lower() for d in imports}
        reported = set()
        for d in imports:
            n = normalize(d.name, eco)
            if d.ignored or n in dnames or n in reported:
                continue
            if eco == "npm" and ("@types/" + n) in dnames:
                continue
            reported.add(n)
            out.append(finding("SC07", d, "imported '%s' but no matching dependency is declared in the "
                               "scanned manifests" % (d.module or d.name)))
        for d in declared:
            n = normalize(d.name, eco)
            if d.ignored or n in inames or d.dev:
                continue
            if eco == "pypi":
                if n in NON_IMPORTED_PY or n.startswith("types-"):
                    continue
                cands = {n.replace("-", "_")} | DIST_TO_IMPORTS.get(n, set())
                if cands & imods:
                    continue
            else:
                if n.startswith("@types/"):
                    continue
            out.append(finding("SC08", d, "declared '%s' but it is never imported in the scanned sources "
                               "(remove it, or it may be a phantom dependency)" % d.name))
    return out


# ---------------------------------------------------------------- output
def render_text(result, out):
    fs = result["findings"]
    if not fs:
        out.write("slopcheck: no findings in %d file(s) (%d declared, %d imports).\n"
                  % (len(result["files"]), result["counts"]["declared"], result["counts"]["imports"]))
    else:
        rows = [("SEV", "RULE", "ECO", "NAME", "LOCATION", "MESSAGE")]
        for f in fs:
            loc = "%s:%s" % (os.path.relpath(f["file"]) if f["file"] else "-", f["line"])
            rows.append((f["severity"].upper(), f["rule"], f["ecosystem"], f["name"], loc, f["message"]))
        widths = [max(len(r[i]) for r in rows) for i in range(5)]
        for r in rows:
            out.write("  ".join(r[i].ljust(widths[i]) for i in range(5)) + "  " + r[5] + "\n")
        summ = {s: sum(1 for f in fs if f["severity"] == s) for s in SEVERITIES}
        out.write("\n%d finding(s): %d high, %d medium, %d low, %d info  (%d file(s) scanned)\n"
                  % (len(fs), summ["high"], summ["medium"], summ["low"], summ["info"], len(result["files"])))
    for e in result["errors"]:
        out.write("error: %s\n" % e)
    out.write("note: snapshot-based offline heuristics; cannot confirm a package exists or is safe. "
              "Verify flagged names on pypi.org / npmjs.com yourself.\n")


def to_json(result):
    return {"tool": "slopcheck", "version": __version__, "files": result["files"],
            "counts": result["counts"], "findings": result["findings"], "errors": result["errors"],
            "disclaimer": "Offline, snapshot-based heuristics. Does not query any registry."}


def to_sarif(result):
    level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": desc},
              "defaultConfiguration": {"level": level[sev]}}
             for rid, (sev, desc) in sorted(RULES.items())]
    results = []
    for f in result["findings"]:
        loc = {"physicalLocation": {"artifactLocation": {"uri": f["file"].replace(os.sep, "/")}}}
        if f["line"]:
            loc["physicalLocation"]["region"] = {"startLine": f["line"]}
        results.append({"ruleId": f["rule"], "level": level[f["severity"]],
                        "message": {"text": f["message"]}, "locations": [loc],
                        "properties": {"severity": f["severity"], "package": f["name"],
                                       "ecosystem": f["ecosystem"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "slopcheck", "version": __version__,
                                          "informationUri": "https://example.invalid/slopcheck",
                                          "rules": rules}},
                      "results": results}]}


def should_fail(findings, fail_on):
    if fail_on == "none":
        return False
    if fail_on == "any":
        return bool(findings)
    thr = SEV_RANK[fail_on]
    return any(SEV_RANK[f["severity"]] >= thr for f in findings)


def build_parser():
    p = argparse.ArgumentParser(prog="slopcheck", description="Offline hallucinated-package / "
                                "slopsquatting risk checker for dependency lists and imports.")
    p.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    p.add_argument("--allow", action="append", default=[], metavar="FILE",
                   help="allowlist file, one package name per line (repeatable)")
    p.add_argument("--known", metavar="FILE", help="alternate snapshot JSON (default: bundled)")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "any", "none"], default="high",
                   help="exit 1 if findings at/above this severity (default: high)")
    p.add_argument("--no-usage", action="store_true", help="skip SC07/SC08 import-vs-manifest checks")
    p.add_argument("--list-rules", action="store_true", help="print rules and exit")
    p.add_argument("--version", action="version", version="slopcheck " + __version__)
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for rid, (sev, desc) in sorted(RULES.items()):
            out.write("%s  %-6s  %s\n" % (rid, sev, desc))
        return 0
    try:
        known = load_known(args.known)
        allow = {"pypi": set(), "npm": set()}
        for a in args.allow:
            for n in load_allow(a):
                allow["pypi"].add(norm_pypi(n))
                allow["npm"].add(norm_npm(n))
        files = collect_files(args.paths)
    except SlopError as e:
        sys.stderr.write("slopcheck: error: %s\n" % e)
        return 2
    result = analyze(files, known, allow, check_usage=not args.no_usage)
    thr = SEV_RANK[args.min_severity]
    result["findings"] = [f for f in result["findings"] if SEV_RANK[f["severity"]] >= thr]
    if args.json:
        out.write(json.dumps(to_json(result), indent=2) + "\n")
    elif args.sarif:
        out.write(json.dumps(to_sarif(result), indent=2) + "\n")
    else:
        render_text(result, out)
    if result["errors"]:
        for e in result["errors"]:
            sys.stderr.write("slopcheck: error: %s\n" % e)
        return 2
    return 1 if should_fail(result["findings"], args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
