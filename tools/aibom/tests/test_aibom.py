import json, os, shutil, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import aibom
SAMPLE = os.path.join(ROOT, "examples", "sample_app")
BASELINE = os.path.join(ROOT, "examples", "baseline.json")
CLI = [sys.executable, os.path.join(ROOT, "aibom.py")]


def repo(files):
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(content, bytes) else "w") as fh:
            fh.write(content)
    return d


def names(inv, kind):
    return {c["name"] for c in inv.components() if c["kind"] == kind}


def codes(inv):
    return [n["code"] for n in inv.notes]


class TestSample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = aibom.scan_repo(SAMPLE)

    def test_sdks(self):
        self.assertEqual(names(self.inv, "sdk"), {
            "@ai-sdk/openai", "@modelcontextprotocol/sdk", "ai", "anthropic", "chromadb", "langchain-openai",
            "litellm", "openai", "sentence-transformers", "torch", "transformers"})

    def test_non_ai_deps_ignored(self):
        self.assertNotIn("requests", names(self.inv, "sdk"))
        self.assertNotIn("react", names(self.inv, "sdk"))

    def test_models(self):
        m = names(self.inv, "model")
        for x in ("gpt-4o", "claude-sonnet-4-20250514", "gemini-2.5-flash", "gpt-4.1-mini-2025-04-14",
                  "text-embedding-3-small", "sentence-transformers/all-MiniLM-L6-v2"):
            self.assertIn(x, m)

    def test_weights_and_pickle_note(self):
        w = {c["name"]: c for c in self.inv.components() if c["kind"] == "weights"}
        self.assertEqual(w["models/intent_classifier.pkl"]["format"], "pickle")
        self.assertEqual(w["models/reranker.safetensors"]["format"], "safetensors")
        ab01 = [n for n in self.inv.notes if n["code"] == "AB01"]
        self.assertEqual(len(ab01), 1)
        self.assertEqual(ab01[0]["severity"], "high")

    def test_endpoints(self):
        self.assertEqual(names(self.inv, "endpoint"), {"http://api.openai.com", "http://localhost:11434",
                                                       "https://generativelanguage.googleapis.com"})
        ab04 = [n for n in self.inv.notes if n["code"] == "AB04"]
        self.assertEqual(len(ab04), 1)  # localhost http is not flagged

    def test_mcp_servers(self):
        mcp = {c["name"]: c for c in self.inv.components() if c["kind"] == "mcp-server"}
        self.assertEqual(mcp["github"]["transport"], "stdio")
        self.assertEqual(mcp["docs-search"]["transport"], "remote")

    def test_agent_file_and_env_names(self):
        self.assertIn("AGENTS.md", names(self.inv, "agent-file"))
        self.assertEqual(names(self.inv, "credential-env"), {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "HF_TOKEN"})

    def test_env_values_never_recorded(self):
        blob = json.dumps(aibom.to_json(self.inv, SAMPLE))
        self.assertNotIn("FAKE-EXAMPLE-0000", blob)

    def test_unpinned_and_undeclared_notes(self):
        unpinned = {n["message"].split("'")[1] for n in self.inv.notes if n["code"] == "AB02"}
        self.assertEqual(unpinned, {"anthropic", "langchain-openai", "ai", "@modelcontextprotocol/sdk"})
        undeclared = {n["message"].split("'")[1] for n in self.inv.notes if n["code"] == "AB05"}
        self.assertEqual(undeclared, {"litellm", "sentence-transformers", "transformers", "torch"})

    def test_floating_alias(self):
        floating = {n["message"].split("'")[1] for n in self.inv.notes if n["code"] == "AB03"}
        self.assertEqual(floating, {"gpt-4o"})

    def test_notes_sorted_by_severity(self):
        sev = [n["severity"] for n in self.inv.sorted_notes()]
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.assertEqual(sev, sorted(sev, key=order.get))


class TestDetectors(unittest.TestCase):
    def test_pyproject_pep621_and_poetry(self):
        d = repo({"pyproject.toml": '[project]\ndependencies = ["openai==1.2.3", "httpx"]\n'
                                    '[tool.poetry.dependencies]\nanthropic = "0.30.0"\nllama-index = "^0.10"\n'})
        inv = aibom.scan_repo(d)
        self.assertEqual(names(inv, "sdk"), {"openai", "anthropic", "llama-index"})
        unpinned = {n["message"].split("'")[1] for n in inv.notes if n["code"] == "AB02"}
        self.assertEqual(unpinned, {"llama-index"})

    def test_js_require_and_dynamic_import(self):
        d = repo({"a.js": 'const A = require("@anthropic-ai/sdk");\nconst g = await import("@google/genai");\nimport x from "./local";\n'})
        self.assertEqual(names(aibom.scan_repo(d), "sdk"), {"@anthropic-ai/sdk", "@google/genai"})

    def test_python_submodule_import(self):
        d = repo({"x.py": "from google.genai import types\nfrom llama_index.core import VectorStoreIndex\n"})
        self.assertEqual(names(aibom.scan_repo(d), "sdk"), {"google-genai", "llama-index"})

    def test_unparsable_python_falls_back(self):
        d = repo({"x.py": "import openai\ndef broken(:\n"})
        self.assertIn("openai", names(aibom.scan_repo(d), "sdk"))

    def test_model_in_prose_ignored(self):
        d = repo({"x.py": "# we compared gpt-4o and others\nprint('hi')\n"})
        self.assertEqual(names(aibom.scan_repo(d), "model"), set())

    def test_bedrock_and_azure(self):
        d = repo({"x.py": 'c = boto3.client("bedrock-runtime")\nm = "anthropic.claude-3-haiku-20240307-v1:0"\n'
                          'u = "https://myco.openai.azure.com/openai"\n'})
        inv = aibom.scan_repo(d)
        self.assertIn("aws-bedrock-runtime", names(inv, "endpoint"))
        self.assertIn("https://myco.openai.azure.com", names(inv, "endpoint"))
        self.assertIn("anthropic.claude-3-haiku-20240307-v1:0", names(inv, "model"))

    def test_skip_dirs(self):
        d = repo({"node_modules/openai/index.js": 'import x from "openai"', ".venv/lib/a.py": "import anthropic"})
        self.assertEqual(aibom.scan_repo(d).components(), [])

    def test_vscode_mcp_servers_key(self):
        d = repo({".vscode/mcp.json": '{\n  // comment\n  "servers": {"fs": {"command": "node", "args": ["s.js"]}}\n}'})
        self.assertEqual(names(aibom.scan_repo(d), "mcp-server"), {"fs"})

    def test_mdc_rules_and_agent_settings(self):
        d = repo({".cursor/rules/style.mdc": "---\nalwaysApply: true\n---\n", ".claude/settings.json": "{}"})
        self.assertEqual(names(aibom.scan_repo(d), "agent-file"), {".cursor/rules/style.mdc", ".claude/settings.json"})

    def test_hash_weights(self):
        d = repo({"m/model.gguf": b"FAKE"})
        c = [c for c in aibom.scan_repo(d, do_hash=True).components() if c["kind"] == "weights"][0]
        self.assertEqual(c["sha256"], __import__("hashlib").sha256(b"FAKE").hexdigest())
        self.assertEqual(c["format"], "gguf")

    def test_no_undeclared_note_without_manifest(self):
        d = repo({"x.py": "import openai\n"})
        self.assertNotIn("AB05", codes(aibom.scan_repo(d)))

    def test_empty_repo(self):
        self.assertEqual(aibom.scan_repo(repo({"README.md": "hello"})).components(), [])


class TestOutputs(unittest.TestCase):
    def test_cyclonedx_shape(self):
        bom = aibom.to_cyclonedx(aibom.scan_repo(SAMPLE), SAMPLE)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        types = {c["type"] for c in bom["components"]}
        self.assertTrue({"library", "machine-learning-model", "data"} <= types)
        refs = [c["bom-ref"] for c in bom["components"]] + [s["bom-ref"] for s in bom["services"]]
        self.assertEqual(len(refs), len(set(refs)))
        openai = [c for c in bom["components"] if c["name"] == "openai"][0]
        self.assertEqual(openai["purl"], "pkg:pypi/openai@1.51.0")
        self.assertIn("mcp:github", [s["name"] for s in bom["services"]])

    def test_baseline_from_cyclonedx(self):
        inv = aibom.scan_repo(SAMPLE)
        p = os.path.join(tempfile.mkdtemp(), "bom.json")
        with open(p, "w") as fh:
            json.dump(aibom.to_cyclonedx(inv, SAMPLE), fh)
        ids = aibom.load_baseline(p)
        self.assertEqual({aibom.comp_id(c) for c in inv.components()} - ids, set())


class TestCLI(unittest.TestCase):
    def run_cli(self, *a):
        return subprocess.run(CLI + list(a), capture_output=True, text=True)

    def test_text(self):
        p = self.run_cli(SAMPLE)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("MCP servers (2)", p.stdout)
        self.assertIn("Governance notes", p.stdout)

    def test_json(self):
        d = json.loads(self.run_cli(SAMPLE, "--json").stdout)
        self.assertEqual(d["summary"]["sdk"], 11)
        self.assertEqual(d["summary"]["mcp-server"], 2)

    def test_baseline_new(self):
        p = self.run_cli(SAMPLE, "--baseline", BASELINE, "--fail-on", "new")
        self.assertEqual(p.returncode, 1)
        self.assertIn("2 component(s) new since baseline: mcp-server:docs-search, sdk:litellm", p.stdout)
        self.assertIn("[NEW]", p.stdout)

    def test_baseline_self_is_clean(self):
        tmp = os.path.join(tempfile.mkdtemp(), "b.json")
        self.assertEqual(self.run_cli(SAMPLE, "--json", "-o", tmp).returncode, 0)
        self.assertEqual(self.run_cli(SAMPLE, "--baseline", tmp, "--fail-on", "new").returncode, 0)

    def test_fail_on_severity(self):
        self.assertEqual(self.run_cli(SAMPLE, "--fail-on", "high").returncode, 1)
        d = repo({"requirements.txt": "openai==1.0.0\n"})
        self.assertEqual(self.run_cli(d, "--fail-on", "low").returncode, 0)

    def test_errors(self):
        self.assertEqual(self.run_cli("/nonexistent/dir").returncode, 2)
        self.assertEqual(self.run_cli(SAMPLE, "--fail-on", "new").returncode, 2)
        self.assertEqual(self.run_cli(SAMPLE, "--baseline", "/nonexistent.json").returncode, 2)

    def test_json_and_cyclonedx_exclusive(self):
        self.assertEqual(self.run_cli(SAMPLE, "--json", "--cyclonedx").returncode, 2)


if __name__ == "__main__":
    unittest.main()
