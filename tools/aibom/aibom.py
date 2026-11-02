#!/usr/bin/env python3
"""aibom: offline AI bill-of-materials (AI-BOM) inventory for a code repository.

Finds the AI components a repo actually uses and writes them down: LLM/agent SDKs
(declared dependencies and imports), model identifiers, model weight files, AI provider
endpoints, AI API-key environment variable *names* (never values), MCP server configs,
agent instruction/settings files. Adds governance notes (pickle-format weights, unpinned
AI dependencies, floating model aliases, plaintext endpoints) and can diff against a
saved baseline to catch new, undeclared ("shadow") AI components in CI.

Output: text, --json, or --cyclonedx (CycloneDX 1.6 JSON).
Stdlib only, no network. Exit codes: 0 ok, 1 notes/new components at --fail-on, 2 usage error.
"""
import argparse
import ast
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

__version__ = "0.1.0"

# ------------------------------------------------------------------ knowledge
PY_SDKS = {
    "openai": "OpenAI", "anthropic": "Anthropic", "google.generativeai": "Google Gemini (legacy SDK)",
    "google.genai": "Google Gen AI", "vertexai": "Google Vertex AI", "mistralai": "Mistral",
    "cohere": "Cohere", "groq": "Groq", "ollama": "Ollama", "litellm": "LiteLLM", "xai_sdk": "xAI",
    "together": "Together AI", "replicate": "Replicate", "boto3": None,
    "langchain": "LangChain", "langchain_core": "LangChain", "langchain_openai": "LangChain",
    "langchain_anthropic": "LangChain", "langchain_community": "LangChain", "langgraph": "LangGraph",
    "llama_index": "LlamaIndex", "crewai": "CrewAI", "autogen": "AutoGen", "autogen_agentchat": "AutoGen",
    "semantic_kernel": "Semantic Kernel", "dspy": "DSPy", "haystack": "Haystack", "smolagents": "smolagents",
    "pydantic_ai": "Pydantic AI", "agents": None, "openai_agents": "OpenAI Agents SDK", "mcp": "Model Context Protocol",
    "fastmcp": "FastMCP", "transformers": "Hugging Face Transformers", "huggingface_hub": "Hugging Face Hub",
    "sentence_transformers": "Sentence Transformers", "vllm": "vLLM", "llama_cpp": "llama.cpp",
    "torch": "PyTorch", "tensorflow": "TensorFlow", "onnxruntime": "ONNX Runtime", "diffusers": "Diffusers",
    "chromadb": "Chroma (vector DB)", "pinecone": "Pinecone (vector DB)", "qdrant_client": "Qdrant (vector DB)",
    "weaviate": "Weaviate (vector DB)", "pymilvus": "Milvus (vector DB)", "faiss": "FAISS",
    "tiktoken": "tiktoken", "guardrails": "Guardrails AI", "nemoguardrails": "NeMo Guardrails",
}
# PyPI distribution names -> import names, where different
PY_DIST_ALIASES = {"google-generativeai": "google.generativeai", "google-genai": "google.genai",
                   "google-cloud-aiplatform": "vertexai", "llama-index": "llama_index", "llama-cpp-python": "llama_cpp",
                   "sentence-transformers": "sentence_transformers", "huggingface-hub": "huggingface_hub",
                   "qdrant-client": "qdrant_client", "weaviate-client": "weaviate", "pinecone-client": "pinecone",
                   "openai-agents": "openai_agents", "pyautogen": "autogen", "autogen-agentchat": "autogen_agentchat",
                   "semantic-kernel": "semantic_kernel", "pydantic-ai": "pydantic_ai", "faiss-cpu": "faiss",
                   "faiss-gpu": "faiss", "nemoguardrails": "nemoguardrails", "guardrails-ai": "guardrails",
                   "haystack-ai": "haystack", "xai-sdk": "xai_sdk", "onnxruntime-gpu": "onnxruntime",
                   "langchain-openai": "langchain_openai", "langchain-anthropic": "langchain_anthropic",
                   "langchain-core": "langchain_core", "langchain-community": "langchain_community"}
JS_SDKS = {
    "openai": "OpenAI", "@anthropic-ai/sdk": "Anthropic", "@anthropic-ai/claude-agent-sdk": "Claude Agent SDK",
    "@google/generative-ai": "Google Gemini (legacy SDK)", "@google/genai": "Google Gen AI",
    "@mistralai/mistralai": "Mistral", "cohere-ai": "Cohere", "groq-sdk": "Groq", "ollama": "Ollama",
    "ai": "Vercel AI SDK", "langchain": "LangChain", "llamaindex": "LlamaIndex",
    "@modelcontextprotocol/sdk": "Model Context Protocol", "@xenova/transformers": "Transformers.js",
    "@huggingface/transformers": "Transformers.js", "@huggingface/inference": "Hugging Face Inference",
    "@pinecone-database/pinecone": "Pinecone (vector DB)", "chromadb": "Chroma (vector DB)",
    "@qdrant/js-client-rest": "Qdrant (vector DB)", "@openai/agents": "OpenAI Agents SDK",
    "replicate": "Replicate", "together-ai": "Together AI", "@mastra/core": "Mastra",
}
JS_SDK_PREFIXES = {"@ai-sdk/": "Vercel AI SDK provider", "@langchain/": "LangChain", "@llamaindex/": "LlamaIndex"}

MODEL_RE = re.compile(r"""(?<![\w./-])(
    (?:gpt-(?:3\.5|4|4o|4\.1|5)(?:[\w.-]*)?)|(?:o[1345](?:-(?:mini|pro|preview)[\w.-]*)?)|(?:chatgpt-4o[\w.-]*)|
    (?:text-embedding-[\w.-]+)|(?:claude-[a-z0-9][\w.-]*)|(?:gemini-[0-9][\w.-]*)|(?:gemma[-\d][\w.:-]*)|
    (?:llama-?[234](?:\.\d)?[\w.:-]*)|(?:(?:open-)?mi[sx]tral[\w.:-]*)|(?:codestral[\w.-]*)|(?:grok-[\w.-]+)|
    (?:command-r[\w.-]*)|(?:deepseek-[\w.-]+)|(?:qwen[\d.]*[\w.:-]*)|(?:phi-?[34][\w.:-]*)|
    (?:dall-e-[23])|(?:whisper-1)|(?:tts-1(?:-hd)?)|(?:(?:anthropic|meta|amazon|mistral|cohere)\.[\w.-]+-v\d[\w:.-]*)
)(?![\w-])""", re.X | re.I)
HF_RE = re.compile(r"""(?:from_pretrained|pipeline|hf_hub_download|snapshot_download|SentenceTransformer|AutoModel\w*|model\s*=)\s*\(?\s*(?:[^"')]*?model\s*=\s*)?["']([A-Za-z0-9][\w.-]*/[\w.-]+)["']""")
FLOATING_RE = re.compile(r"(latest|preview|exp|experimental)$|^(gpt-4o|gpt-4|gpt-5|o3|o4-mini|o1|gpt-4o-mini|gpt-4\.1|claude-[\w.-]*-latest|grok-[\w.-]+)$", re.I)

ENDPOINTS = {
    "api.openai.com": "OpenAI", "api.anthropic.com": "Anthropic", "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex AI", "api.mistral.ai": "Mistral", "api.cohere.ai": "Cohere",
    "api.cohere.com": "Cohere", "api.groq.com": "Groq", "api.x.ai": "xAI", "api.together.xyz": "Together AI",
    "api.deepseek.com": "DeepSeek", "openrouter.ai": "OpenRouter", "api.perplexity.ai": "Perplexity",
    "api-inference.huggingface.co": "Hugging Face Inference", "router.huggingface.co": "Hugging Face Inference",
    "api.replicate.com": "Replicate", "api.fireworks.ai": "Fireworks",
}
ENDPOINT_SUFFIX = {".openai.azure.com": "Azure OpenAI", ".cognitiveservices.azure.com": "Azure AI",
                   ".services.ai.azure.com": "Azure AI Foundry"}
URL_RE = re.compile(r"\b(https?)://([A-Za-z0-9.-]+)(?::(\d+))?(/[^\s\"'`)]*)?")
LOCAL_LLM_PORTS = {"11434": "Ollama (local)", "1234": "LM Studio (local)", "8000": None}
BEDROCK_RE = re.compile(r"bedrock-runtime(?:\.[a-z0-9-]+)?(?:\.amazonaws\.com)?|['\"]bedrock-runtime['\"]")
ENV_RE = re.compile(r"\b((?:OPENAI|AZURE_OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_GENAI|GOOGLE|MISTRAL|COHERE|CO|GROQ|XAI|GROK|TOGETHER|DEEPSEEK|OPENROUTER|PERPLEXITY|PPLX|HF|HUGGINGFACE(?:HUB)?|HUGGING_FACE_HUB|REPLICATE|FIREWORKS|PINECONE|LANGCHAIN|LANGSMITH|QDRANT|WEAVIATE|COHERE)_(?:API_)?(?:KEY|TOKEN|API_TOKEN))\b")

WEIGHT_EXT = {".safetensors": "safetensors", ".gguf": "gguf", ".ggml": "ggml", ".onnx": "onnx", ".tflite": "tflite",
              ".pt": "pytorch-pickle", ".pth": "pytorch-pickle", ".ckpt": "checkpoint-pickle", ".pkl": "pickle",
              ".pickle": "pickle", ".joblib": "joblib-pickle", ".h5": "keras-hdf5", ".keras": "keras", ".mlmodel": "coreml",
              ".npz": "numpy"}
PICKLE_FORMATS = {"pytorch-pickle", "checkpoint-pickle", "pickle", "joblib-pickle"}

MCP_FILES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp_settings.json"}
AGENT_FILES = {"agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
               "copilot-instructions.md", "skill.md"}
AGENT_SETTINGS = [(".claude", "settings.json"), (".claude", "settings.local.json"), (".codex", "config.toml"),
                  (".gemini", "settings.json"), (".cursor", "cli.json"), (".vscode", "settings.json")]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "dist", "build", ".mypy_cache",
             ".pytest_cache", "site-packages", ".next"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".ipynb", ".java", ".go", ".rb", ".cs", ".rs",
            ".yaml", ".yml", ".toml", ".json", ".env", ".cfg", ".ini", ".sh", ".md"}
MAX_BYTES = 2_000_000


# ------------------------------------------------------------------ inventory
class Inventory:
    def __init__(self):
        self.items = {}   # key -> component
        self.notes = []

    def add(self, kind, name, path, line=None, **extra):
        key = "%s:%s" % (kind, name.lower() if kind != "weights" else name)
        c = self.items.get(key)
        if not c:
            c = self.items[key] = {"kind": kind, "name": name, "locations": []}
        for k, v in extra.items():
            if v is not None and c.get(k) in (None, ""):
                c[k] = v
        loc = path + (":%d" % line if line else "")
        if loc not in c["locations"]:
            c["locations"].append(loc)
        return c

    def note(self, code, severity, msg, path, line=None):
        n = {"code": code, "severity": severity, "message": msg, "location": path + (":%d" % line if line else "")}
        if n not in self.notes:
            self.notes.append(n)

    def sorted_notes(self):
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        return sorted(self.notes, key=lambda n: (rank.get(n["severity"], 9), n["code"], n["location"]))

    def components(self):
        order = ["sdk", "model", "weights", "endpoint", "mcp-server", "agent-file", "credential-env"]
        return sorted(self.items.values(), key=lambda c: (order.index(c["kind"]), c["name"].lower()))


def _sdk_for_py(mod):
    parts = mod.split(".")
    for i in range(len(parts), 0, -1):
        cand = ".".join(parts[:i])
        if cand in PY_SDKS and PY_SDKS[cand]:
            return cand, PY_SDKS[cand]
    return None, None


def _sdk_for_js(mod):
    if mod in JS_SDKS:
        return mod, JS_SDKS[mod]
    for pre, label in JS_SDK_PREFIXES.items():
        if mod.startswith(pre):
            return mod, label
    if mod.startswith("@"):
        base = "/".join(mod.split("/")[:2])
    else:
        base = mod.split("/")[0]
    return (base, JS_SDKS[base]) if base in JS_SDKS else (None, None)


REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _check_pin(inv, eco, name, spec, rel, line):
    spec = (spec or "").strip().split(";")[0].strip().strip(",")
    pinned = bool(re.match(r"^(==|===)\s*\d", spec)) if eco == "pypi" else bool(re.match(r"^\d+\.\d+\.\d+", spec))
    if not pinned:
        inv.note("AB02", "low", "AI dependency '%s' is not pinned to an exact version (%s)" % (name, spec or "any version"), rel, line)
    return spec or None


def scan_requirements(text, rel, inv):
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.split("#")[0].strip()
        if not s or s.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE_RE.match(s)
        if not m:
            continue
        dist = m.group(1).lower().replace("_", "-")
        mod = PY_DIST_ALIASES.get(dist, dist.replace("-", "_"))
        key, label = _sdk_for_py(mod)
        if label:
            spec = _check_pin(inv, "pypi", dist, m.group(3), rel, n)
            inv.add("sdk", dist, rel, n, ecosystem="pypi", label=label, version=spec, declared=True)


def scan_pyproject(text, rel, inv):
    for n, raw in enumerate(text.splitlines(), 1):
        for m in re.finditer(r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([<>=!~^][^\"']*)?[\"']", raw):
            dist = m.group(1).lower().replace("_", "-")
            mod = PY_DIST_ALIASES.get(dist, dist.replace("-", "_"))
            if _sdk_for_py(mod)[1]:
                spec = _check_pin(inv, "pypi", dist, m.group(3), rel, n)
                inv.add("sdk", dist, rel, n, ecosystem="pypi", label=_sdk_for_py(mod)[1], version=spec, declared=True)
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*[\"'{]", raw)  # poetry style
        if m:
            dist = m.group(1).lower().replace("_", "-")
            mod = PY_DIST_ALIASES.get(dist, dist.replace("-", "_"))
            if _sdk_for_py(mod)[1] and dist not in ("name", "version", "python"):
                vm = re.search(r"=\s*[\"']([^\"']*)[\"']|version\s*=\s*[\"']([^\"']*)[\"']", raw)
                spec = (vm.group(1) or vm.group(2)) if vm else ""
                spec = ("==" + spec) if re.match(r"^\d", spec or "") else spec
                spec = _check_pin(inv, "pypi", dist, spec, rel, n)
                inv.add("sdk", dist, rel, n, ecosystem="pypi", label=_sdk_for_py(mod)[1], version=spec, declared=True)


def scan_package_json(text, rel, inv):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        inv.note("AB00", "info", "package.json could not be parsed", rel)
        return
    for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(sect) or {}).items():
            key, label = _sdk_for_js(name)
            if label:
                line = next((i for i, l in enumerate(text.splitlines(), 1) if '"%s"' % name in l), None)
                spec = _check_pin(inv, "npm", name, str(spec), rel, line)
                inv.add("sdk", name, rel, line, ecosystem="npm", label=label, version=spec, declared=True)


def scan_python_imports(text, rel, inv):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        for n, l in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", l)
            if m:
                _py_import(m.group(1) or m.group(2), rel, n, inv)
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                _py_import(a.name, rel, node.lineno, inv)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            _py_import(node.module, rel, node.lineno, inv)


def _py_import(mod, rel, line, inv):
    key, label = _sdk_for_py(mod)
    if label:
        dist = next((d for d, m in PY_DIST_ALIASES.items() if m == key), key.replace("_", "-"))
        inv.add("sdk", dist, rel, line, ecosystem="pypi", label=label, imported=True)


JS_IMPORT_RE = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"'./][^"']*)["']""")


def scan_js_imports(text, rel, inv):
    for n, l in enumerate(text.splitlines(), 1):
        for m in JS_IMPORT_RE.finditer(l):
            key, label = _sdk_for_js(m.group(1))
            if label:
                inv.add("sdk", key, rel, n, ecosystem="npm", label=label, imported=True)


def scan_strings(text, rel, inv):
    for n, l in enumerate(text.splitlines(), 1):
        for m in MODEL_RE.finditer(l):
            name = m.group(1)
            before = l[:m.start()]
            # must look like a string literal / config value, not prose or a filename
            if not re.search(r"[\"'`=:]\s*$|model\W{0,3}$", before) and not rel.endswith((".yaml", ".yml", ".toml", ".env", ".json")):
                continue
            if name.lower() in ("o1", "o3", "o4", "o5") and not re.search(r"model", l, re.I):
                continue
            c = inv.add("model", name, rel, n, source="identifier")
            if FLOATING_RE.search(name):
                inv.note("AB03", "low", "model '%s' is a floating alias; pin a dated snapshot for reproducible behaviour" % name, rel, n)
        for m in HF_RE.finditer(l):
            inv.add("model", m.group(1), rel, n, source="huggingface-hub")
        for m in URL_RE.finditer(l):
            scheme, host, port = m.group(1), m.group(2).lower(), m.group(3)
            prov = ENDPOINTS.get(host) or next((v for s, v in ENDPOINT_SUFFIX.items() if host.endswith(s)), None)
            if not prov and host in ("localhost", "127.0.0.1", "0.0.0.0") and port in LOCAL_LLM_PORTS and LOCAL_LLM_PORTS[port]:
                prov = LOCAL_LLM_PORTS[port]
            if prov:
                url = "%s://%s%s" % (scheme, host, ":" + port if port else "")
                inv.add("endpoint", url, rel, n, provider=prov)
                if scheme == "http" and host not in ("localhost", "127.0.0.1", "0.0.0.0"):
                    inv.note("AB04", "medium", "plaintext http:// endpoint for %s (%s)" % (prov, host), rel, n)
        if BEDROCK_RE.search(l):
            inv.add("endpoint", "aws-bedrock-runtime", rel, n, provider="AWS Bedrock")
        for m in ENV_RE.finditer(l):
            inv.add("credential-env", m.group(1), rel, n)


def scan_mcp(text, rel, inv):
    try:
        data = json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.M))
    except json.JSONDecodeError:
        inv.note("AB00", "info", "MCP config could not be parsed", rel)
        return
    servers = {}
    for key in ("mcpServers", "servers", "context_servers"):
        if isinstance(data.get(key), dict):
            servers.update(data[key])
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
        servers.update(data["mcp"]["servers"])
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        target = cfg.get("url") or " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", [])]).strip()
        line = next((i for i, l in enumerate(text.splitlines(), 1) if '"%s"' % name in l), None)
        inv.add("mcp-server", name, rel, line, transport="remote" if cfg.get("url") else "stdio", target=target)


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_repo(root, do_hash=False):
    inv = Inventory()
    root = os.path.abspath(root)
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fn in sorted(files):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            low = fn.lower()
            ext = os.path.splitext(low)[1]
            parent = os.path.basename(dirpath).lower()
            if ext in WEIGHT_EXT and not (ext == ".json"):
                fmt = WEIGHT_EXT[ext]
                if ext in (".npz", ".h5") and not re.search(r"model|weight|ckpt|checkpoint", rel, re.I):
                    continue
                size = os.path.getsize(full)
                c = inv.add("weights", rel, rel, format=fmt, size=size,
                            sha256=hash_file(full) if do_hash else None)
                if fmt in PICKLE_FORMATS:
                    inv.note("AB01", "high", "model file uses a pickle-based format (%s); loading it can execute code. Prefer safetensors" % fmt, rel)
                continue
            is_mcp = low in MCP_FILES or (parent in (".cursor", ".vscode", ".gemini") and low == "mcp.json")
            is_agent = low in AGENT_FILES or (parent == "rules" and ext == ".mdc") or \
                any(parent == d and low == f for d, f in AGENT_SETTINGS)
            if ext not in CODE_EXT and low not in AGENT_FILES and not low.startswith(("requirements", ".env")) \
                    and low not in (".cursorrules", ".windsurfrules", ".clinerules") and ext != ".mdc":
                continue
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if is_agent:
                inv.add("agent-file", rel, rel, role="settings" if ext in (".json", ".toml") else "instructions")
            if is_mcp:
                scan_mcp(text, rel, inv)
            if low.startswith("requirements") and ext in (".txt", ".in", ""):
                scan_requirements(text, rel, inv)
            elif low == "pyproject.toml":
                scan_pyproject(text, rel, inv)
            elif low == "package.json":
                scan_package_json(text, rel, inv)
            if ext == ".py":
                scan_python_imports(text, rel, inv)
            elif ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
                scan_js_imports(text, rel, inv)
            elif ext == ".ipynb":
                try:
                    nb = json.loads(text)
                    src = "\n".join("".join(c.get("source", [])) for c in nb.get("cells", []) if c.get("cell_type") == "code")
                    scan_python_imports(src, rel, inv)
                    text = src
                except (json.JSONDecodeError, AttributeError):
                    pass
            if low not in ("package.json", "package-lock.json") and not low.endswith(".lock"):
                scan_strings(text, rel, inv)
    # undeclared SDKs: imported but not in any manifest
    declared = {c["name"] for c in inv.items.values() if c["kind"] == "sdk" and c.get("declared")}
    has_manifest = any(c.get("declared") for c in inv.items.values())
    for c in inv.items.values():
        if c["kind"] == "sdk" and c.get("imported") and not c.get("declared") and has_manifest and c["name"] not in declared:
            inv.note("AB05", "medium", "AI SDK '%s' is imported but not declared in any dependency manifest" % c["name"], c["locations"][0])
    return inv


# ------------------------------------------------------------------ output
def comp_id(c):
    return "%s:%s" % (c["kind"], c["name"])


def to_json(inv, root):
    return {"tool": "aibom", "version": __version__, "root": os.path.basename(os.path.abspath(root)),
            "components": inv.components(), "notes": inv.sorted_notes(),
            "summary": {k: sum(1 for c in inv.items.values() if c["kind"] == k)
                        for k in ["sdk", "model", "weights", "endpoint", "mcp-server", "agent-file", "credential-env"]}}


def to_cyclonedx(inv, root):
    comps, services = [], []
    for c in inv.components():
        ref = comp_id(c)
        props = [{"name": "aibom:kind", "value": c["kind"]}] + \
                [{"name": "aibom:location", "value": l} for l in c["locations"][:20]]
        if c["kind"] == "sdk":
            purl = "pkg:%s/%s" % (c["ecosystem"], c["name"].replace("@", "%40"))
            ver = (c.get("version") or "").lstrip("=")
            if re.match(r"^\d[\w.]*$", ver):
                purl += "@" + ver
            comps.append({"type": "library", "bom-ref": ref, "name": c["name"], "version": c.get("version") or "",
                          "purl": purl, "description": c.get("label", ""), "properties": props})
        elif c["kind"] in ("model", "weights"):
            d = {"type": "machine-learning-model", "bom-ref": ref, "name": c["name"], "properties": props}
            if c.get("sha256"):
                d["hashes"] = [{"alg": "SHA-256", "content": c["sha256"]}]
            if c.get("format"):
                props.append({"name": "aibom:format", "value": c["format"]})
            comps.append(d)
        elif c["kind"] == "endpoint":
            services.append({"bom-ref": ref, "name": c.get("provider", c["name"]),
                             "endpoints": [c["name"]], "properties": props})
        elif c["kind"] == "mcp-server":
            props.append({"name": "aibom:transport", "value": c.get("transport", "")})
            props.append({"name": "aibom:target", "value": c.get("target", "")})
            services.append({"bom-ref": ref, "name": "mcp:" + c["name"], "properties": props})
        else:
            comps.append({"type": "data", "bom-ref": ref, "name": c["name"], "properties": props})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
           "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "tools": {"components": [{"type": "application", "name": "aibom", "version": __version__}]},
                        "component": {"type": "application", "name": os.path.basename(os.path.abspath(root)), "bom-ref": "root"}},
           "components": comps, "services": services}
    return bom


def load_baseline(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    ids = set()
    for c in data.get("components", []):
        if "kind" in c:
            ids.add(comp_id(c))
        elif "bom-ref" in c:
            ids.add(c["bom-ref"])
    for s in data.get("services", []):
        ids.add(s.get("bom-ref"))
    return ids


def print_text(inv, root, new=None):
    labels = {"sdk": "AI SDKs / frameworks", "model": "Models referenced", "weights": "Model weight files",
              "endpoint": "AI endpoints", "mcp-server": "MCP servers", "agent-file": "Agent instruction / settings files",
              "credential-env": "AI credential env var names (values never read)"}
    comps = inv.components()
    print("AI-BOM for %s" % os.path.abspath(root))
    if not comps:
        print("  no AI components found")
    for kind, label in labels.items():
        group = [c for c in comps if c["kind"] == kind]
        if not group:
            continue
        print("\n%s (%d)" % (label, len(group)))
        for c in group:
            extra = []
            for k in ("label", "version", "provider", "format", "transport", "target", "source"):
                if c.get(k):
                    extra.append(str(c[k]))
            if c["kind"] == "sdk":
                extra.append("declared" if c.get("declared") else "import only")
            flag = "  [NEW]" if new and comp_id(c) in new else ""
            print("  - %s%s%s" % (c["name"], " (" + ", ".join(extra) + ")" if extra else "", flag))
            print("      %s%s" % (", ".join(c["locations"][:3]), " +%d more" % (len(c["locations"]) - 3) if len(c["locations"]) > 3 else ""))
    if inv.notes:
        print("\nGovernance notes (%d)" % len(inv.notes))
        for n in inv.sorted_notes():
            print("  %-6s %s %s  %s" % (n["severity"].upper(), n["code"], n["location"], n["message"]))


SEV = ["info", "low", "medium", "high"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aibom", description=__doc__.split("\n\n")[0])
    ap.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="aibom JSON (also usable as --baseline)")
    fmt.add_argument("--cyclonedx", action="store_true", help="CycloneDX 1.6 JSON")
    ap.add_argument("-o", "--output", help="write output to a file instead of stdout")
    ap.add_argument("--hash", action="store_true", help="SHA-256 model weight files (slow for big files)")
    ap.add_argument("--baseline", help="previous aibom --json or --cyclonedx file; report components not in it")
    ap.add_argument("--fail-on", default="none", choices=["none", "new", "low", "medium", "high"],
                    help="exit 1 on new components (with --baseline) or notes at/above a severity (default none)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.path):
        print("aibom: error: not a directory: %s" % a.path, file=sys.stderr)
        return 2
    if a.fail_on == "new" and not a.baseline:
        print("aibom: error: --fail-on new needs --baseline", file=sys.stderr)
        return 2
    inv = scan_repo(a.path, a.hash)
    new = None
    if a.baseline:
        try:
            base = load_baseline(a.baseline)
        except (OSError, ValueError) as e:
            print("aibom: error: cannot read baseline: %s" % e, file=sys.stderr)
            return 2
        new = {comp_id(c) for c in inv.components()} - base

    out = sys.stdout
    if a.output:
        out = open(a.output, "w", encoding="utf-8")
    try:
        if a.json or a.cyclonedx:
            doc = to_json(inv, a.path) if a.json else to_cyclonedx(inv, a.path)
            if new is not None:
                doc["new_since_baseline" if a.json else "x-aibom-new-since-baseline"] = sorted(new)
            out.write(json.dumps(doc, indent=2) + "\n")
        else:
            stdout, sys.stdout = sys.stdout, out
            try:
                print_text(inv, a.path, new)
                if new is not None:
                    print("\n%d component(s) new since baseline%s" % (len(new), ": " + ", ".join(sorted(new)) if new else ""))
            finally:
                sys.stdout = stdout
    finally:
        if a.output:
            out.close()

    if a.fail_on == "new":
        return 1 if new else 0
    if a.fail_on != "none":
        th = SEV.index(a.fail_on)
        return 1 if any(SEV.index(n["severity"]) >= th for n in inv.notes if n["severity"] in SEV) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
