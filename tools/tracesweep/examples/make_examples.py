#!/usr/bin/env python3
"""Regenerate the synthetic example transcripts. All secrets here are FAKE:
they only match the token *shapes* and were never issued by any provider."""
import base64, json, os

HERE = os.path.dirname(os.path.abspath(__file__))

def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

FAKE = {
    "aws_akid": "AKIA" + "IOSFODNN7EXAMPL3",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYFAKEKEY123",
    "github": "ghp" + "_FAKE0tracesweep0test0token0000000001",
    "openai": "sk" + "-proj-FAKEtracesweepTEST1234567890abcdEFGH",
    "anthropic": "sk" + "-ant-api03-FAKEtracesweepTEST0987654321zyxw",
    "slack": "xox" + "b-1234567890-FAKEtracesweep01",
    "stripe": "sk" + "_live_FAKEtracesweep0123TEST",
    "google": "AI" + "zaFAKEtracesweep_TEST-0123456789abcde",
    "jwt": b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"sub": "fake-user", "name": "Test"}) + ".FAKEsignatureTRACESWEEP0123456789",
    "db_pass": "Fak3Passw0rd!",
    "generic": "hunter2-FAKE-pass",
}
PEM = ("-----BEGIN " + "RSA PRIVATE KEY-----\n"
       + "\n".join(base64.b64encode(b"tracesweep FAKE key material, not a real key. " * 2).decode()[i:i+64]
                   for i in range(0, 120, 64))
       + "\n-----END " + "RSA PRIVATE KEY-----")

def main():
    # 1. Claude-Code-style JSONL: tool output leaks a key, assistant echoes it.
    claude = [
        {"type": "user", "message": {"role": "user", "content": "Why does deploy fail? Check the env file."}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "text", "text": "Let me read the env file."},
            {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"command": "cat .env"}}]}},
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01", "content":
             "AWS_ACCESS_KEY_ID=%s\naws_secret_access_key=%s\nOPENAI_API_KEY=%s\nDATABASE_URL=postgres://admin:%s@db.internal.test:5432/app\n"
             % (FAKE["aws_akid"], FAKE["aws_secret"], FAKE["openai"], FAKE["db_pass"])}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "text", "text": "Your key %s looks fine; the DB password is the problem." % FAKE["openai"]}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_02", "name": "WebFetch",
             "input": {"url": "https://api.example.test/check", "headers": {"Authorization": "Bearer " + FAKE["github"]}}}]}},
        {"type": "user", "message": {"role": "user", "content": "Docs say use AKIAIOSFODNN7EXAMPLE and your_api_key here - fine."}},
    ]
    with open(os.path.join(HERE, "claude_session.jsonl"), "w") as fh:
        for r in claude:
            fh.write(json.dumps(r) + "\n")

    # 2. OpenAI chat-format JSON array with tool_calls and role=tool.
    chat = [
        {"role": "system", "content": "You are a helpful ops agent."},
        {"role": "user", "content": "Post the release note to Slack."},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_1", "type": "function", "function": {
                "name": "slack_post", "arguments": json.dumps({"token": FAKE["slack"], "channel": "#releases"})}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": json.dumps({"ok": True, "debug_session": FAKE["jwt"]})},
        {"role": "assistant", "content": "Posted. Also, the deploy key was:\n" + PEM},
        {"role": "user", "content": "Billing uses stripe key %s and maps key %s" % (FAKE["stripe"], FAKE["google"])},
        {"role": "assistant", "content": "Noted. Anthropic key on file: " + FAKE["anthropic"]},
    ]
    with open(os.path.join(HERE, "openai_chat.json"), "w") as fh:
        json.dump(chat, fh, indent=2)

    # 3. Plain text log with role prefixes.
    text = "\n".join([
        "User: run the migration",
        "Assistant: running it now",
        "Tool(bash): export DB_PASSWORD=%s" % FAKE["generic"],
        "Tool(bash): connecting to mysql://root:%s@10.0.0.5/prod" % FAKE["db_pass"],
        "Assistant: done. I used password %s" % FAKE["generic"],
        "Assistant: (placeholder example) api_key = <your_api_key>",
        "",
    ])
    with open(os.path.join(HERE, "agent_run.log"), "w") as fh:
        fh.write(text)

    # 4. Clean transcript (should produce no findings).
    clean = [{"role": "user", "content": "hello"},
             {"role": "assistant", "content": "Set OPENAI_API_KEY=your_api_key_here, max_tokens: 4096"}]
    with open(os.path.join(HERE, "clean.json"), "w") as fh:
        json.dump(clean, fh, indent=2)

if __name__ == "__main__":
    main()
