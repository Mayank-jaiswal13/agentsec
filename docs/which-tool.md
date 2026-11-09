# Which tool should I run?

These tools are experimental heuristic aids for human review, not a security boundary. A clean result does not prove something is safe. All tools run offline with Python's standard library.

- **I have an MCP client config** (Claude Desktop, Cursor, or VS Code): start with [mcpposture](../tools/mcpposture/). To inspect tool definitions for hidden instructions or shadowing, use [toolpoison](../tools/toolpoison/) or pin definitions with [toolpin](../tools/toolpin/).
- **I have an agent transcript or log:** use [tracesweep](../tools/tracesweep/) for leaked secrets, [piiguard](../tools/piiguard/) for PII, [promptleak](../tools/promptleak/) for system-prompt leakage, or [secretflow](../tools/secretflow/) to track secret-shaped values across tool calls.
- **I am preparing documents for a RAG system:** use [ragsieve](../tools/ragsieve/) to scan them for indirect prompt injection before ingestion.
- **I want to review coding-agent settings:** use [yolocheck](../tools/yolocheck/) for permission and autonomy settings, or [rulesguard](../tools/rulesguard/) for instruction-file backdoors.
- **I want a CI gate for AI-written code:** start with [vibeaudit](../tools/vibeaudit/) for heuristic code smells or [slopcheck](../tools/slopcheck/) for suspicious dependency and import names.
- **I want to review an agent's tool permissions:** use [trifecta](../tools/trifecta/) to look for the combination of private data, untrusted content, and exfiltration; [toolgate](../tools/toolgate/) for policy checks on tool calls; or [schemafence](../tools/schemafence/) for tool input schemas.
- **I want to review shell, file-system, or fetch activity:** use [shellfence](../tools/shellfence/) for shell commands, [pathfence](../tools/pathfence/) for touched paths, or [fetchfence](../tools/fetchfence/) for fetched URLs.

Each tool has its own README with supported inputs and examples. See the [tool list](../README.md#the-tools) for more options.
