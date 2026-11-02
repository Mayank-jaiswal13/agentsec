# aibom

Offline **AI bill of materials** for a code repository. It answers "what AI is in this
repo?" for reviews, audits, vendor questionnaires and AI-governance inventories (for
example, the AI asset inventory that ISO/IEC 42001 and the NIST AI RMF expect), and it can
fail CI when a new, undeclared AI component appears ("shadow AI").

Single Python file, standard library only, no network calls. It reads files; it never
imports, executes or loads anything it finds.

## What it inventories

| Kind | How it is found |
|---|---|
| `sdk` | LLM, agent, MCP, embedding and vector-DB libraries in `requirements*.txt`, `pyproject.toml` (PEP 621 and Poetry), `package.json`, Python imports (AST, including notebooks) and JS/TS `import`/`require` |
| `model` | Model identifiers in string literals and config values (OpenAI, Anthropic, Gemini, Gemma, Llama, Mistral, Grok, Cohere, DeepSeek, Qwen, Phi, Bedrock IDs) and Hugging Face `org/name` repo IDs passed to `from_pretrained`, `pipeline`, `SentenceTransformer`, … |
| `weights` | Model files: `.safetensors`, `.gguf`, `.onnx`, `.tflite`, `.pt`/`.pth`/`.ckpt`, `.pkl`/`.joblib`, `.keras`, `.mlmodel` (optional SHA-256 with `--hash`) |
| `endpoint` | AI provider API hosts (OpenAI, Anthropic, Gemini, Vertex, Azure OpenAI/AI Foundry, Bedrock, Mistral, Groq, xAI, OpenRouter, …) and local Ollama/LM Studio ports |
| `mcp-server` | Servers in `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` (stdio command or remote URL) |
| `agent-file` | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `copilot-instructions.md`, `SKILL.md`, `.claude/settings.json`, `.codex/config.toml`, … |
| `credential-env` | AI API-key environment variable **names** (`OPENAI_API_KEY`, `HF_TOKEN`, …). Values are never read into the output |

`node_modules`, virtualenvs, `.git`, `dist`, `build` and files over 2 MB are skipped.

## Governance notes

| Code | Severity | Meaning |
|---|---|---|
| AB01 | high | Model file in a pickle-based format (`.pkl`, `.pt`, `.ckpt`, `.joblib`): loading it can run arbitrary code |
| AB02 | low | AI dependency not pinned to an exact version |
| AB03 | low | Floating model alias (`gpt-4o`, `*-latest`, `*-preview`, `*-exp`): behaviour can change under you |
| AB04 | medium | Plaintext `http://` to a remote AI provider |
| AB05 | medium | AI SDK imported in code but not declared in any dependency manifest |

## Usage

```sh
python3 aibom.py path/to/repo                       # human-readable inventory + notes
python3 aibom.py . --json -o aibom.json             # machine-readable; also a baseline
python3 aibom.py . --cyclonedx --hash -o bom.cdx.json   # CycloneDX 1.6 (ML-BOM components, services)
python3 aibom.py . --baseline aibom.json --fail-on new  # CI: fail when new AI components appear
python3 aibom.py . --fail-on high                   # CI: fail on pickle model files
```

`--baseline` accepts either an earlier `--json` or `--cyclonedx` output. Components are
matched by kind and name (for example `sdk:openai`, `mcp-server:github`).

Exit codes: `0` ok, `1` new components (`--fail-on new`) or notes at or above the chosen
severity, `2` usage or input error. The default `--fail-on none` always exits 0.

## Example

```text
$ python3 aibom.py examples/sample_app --baseline examples/baseline.json
AI-BOM for .../examples/sample_app

AI SDKs / frameworks (11)
  - @ai-sdk/openai (Vercel AI SDK provider, 1.0.5, declared)
      web/chat.ts:2, web/package.json:6
  ...
  - litellm (LiteLLM, import only)  [NEW]
      app.py:6
...
MCP servers (2)
  - docs-search (remote, https://mcp.docs.example/sse)  [NEW]
  - github (stdio, npx -y @modelcontextprotocol/server-github)

Governance notes (11)
  HIGH   AB01 models/intent_classifier.pkl  model file uses a pickle-based format (pickle); ...
  MEDIUM AB04 app.py:14  plaintext http:// endpoint for OpenAI (api.openai.com)
  MEDIUM AB05 app.py:6  AI SDK 'litellm' is imported but not declared in any dependency manifest
  ...
2 component(s) new since baseline: mcp-server:docs-search, sdk:litellm
```

`examples/sample_app` is a fake multi-language app (Python, TypeScript, a notebook, YAML,
an MCP config, placeholder model files) with fake values only.

## Limits

- Static and pattern based. Model names built at runtime, loaded from a remote config, or
  passed through unusual wrappers are missed; Hugging Face IDs without an `org/` prefix are
  not reported. Model-name regexes cover common families as of 2026 and will need updates.
- The SDK list is curated, not exhaustive. A library it does not know is not reported.
- Lockfiles are not parsed, so transitive AI dependencies are not listed.
- The file format of weights is taken from the extension; contents are not inspected
  (pair it with a pickle scanner if you load third-party models).
- An inventory is not a risk assessment. It tells you what to review, not whether it is safe.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
