"""
Groq AI Client — ultra-fast LLM inference for the Guardian AI Intelligence Layer.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


class GroqClient:
    """Wrapper for Groq API using standard Python libraries."""

    DEFAULT_MODEL = "openai/gpt-oss-120b"
    FALLBACK_MODELS = ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        if not self.api_key:
            env_file = Path(".env")
            if env_file.exists():
                for line in env_file.read_text(encoding="utf-8").splitlines():
                    if line.startswith("GROQ_API_KEY="):
                        self.api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break

        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ) -> str:
        """Call Groq API with automatic model fallback."""
        if not self.is_available:
            raise RuntimeError("GROQ_API_KEY is not set. Please provide a key.")

        models_to_try = [model] if model else [self.DEFAULT_MODEL] + self.FALLBACK_MODELS

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "GuardianAI/1.0",
        }

        last_err = None
        for m in models_to_try:
            if not m:
                continue
            payload = {
                "model": m,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            try:
                req = urllib.request.Request(
                    self.api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as err:
                last_err = err
                continue
            except Exception as err:
                last_err = err
                continue

        raise RuntimeError(f"All Groq models failed. Last error: {last_err}")
