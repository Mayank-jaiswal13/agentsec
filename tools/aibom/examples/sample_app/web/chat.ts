import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

export async function chat(prompt: string) {
  return streamText({ model: openai("gpt-4.1-mini-2025-04-14"), prompt });
}
