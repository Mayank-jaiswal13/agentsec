"""FAKE EXAMPLE app used by aibom tests. Not real code."""
import os
from openai import OpenAI
import anthropic
from langchain_openai import ChatOpenAI
import litellm  # imported but not declared in requirements.txt

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
claude = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL = "gpt-4o"
FALLBACK = "claude-sonnet-4-20250514"
EMBED_MODEL = "text-embedding-3-small"
LOCAL = "http://localhost:11434/api/generate"
PROXY = "http://api.openai.com/v1"  # plaintext, flagged


def ask(q):
    return client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": q}])
