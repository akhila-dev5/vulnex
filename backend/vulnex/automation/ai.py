"""A small client for any OpenAI-compatible chat API.

The default is GitHub Models, which is free to use and needs no extra account: inside
GitHub Actions the built-in token works. Point it somewhere else (Groq, OpenRouter's free
models, Gemini's compatible endpoint, a local server) with environment variables.
"""

from __future__ import annotations

import os
import time
from typing import Callable

import requests

Chat = Callable[[list[dict]], str]

DEFAULT_BASE_URL = "https://models.github.ai/inference"
DEFAULT_MODEL = "openai/gpt-4.1"


def build_chat(env: dict | None = None) -> Chat | None:
    """A chat function, or ``None`` when no key is configured."""
    env = os.environ if env is None else env
    key = env.get("VULNEX_AI_API_KEY") or env.get("GITHUB_TOKEN") or ""
    if not key:
        return None
    base = (env.get("VULNEX_AI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    model = env.get("VULNEX_AI_MODEL") or DEFAULT_MODEL

    def chat(messages: list[dict]) -> str:
        for attempt in range(4):
            response = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "temperature": 0.1},
                timeout=180,
            )
            if response.status_code in (429, 500, 502, 503) and attempt < 3:
                time.sleep(min(60, 5 * 2 ** attempt))  # free tiers are rate limited
                continue
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"] or ""
        return ""

    return chat
