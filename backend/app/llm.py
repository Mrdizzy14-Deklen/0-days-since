"""Minimal async client for OpenAI-compatible chat-completion endpoints.

Works with NVIDIA NIM (`https://integrate.api.nvidia.com/v1`, Nemotron), Gemini's
OpenAI-compatible API, Anthropic's OpenAI-compatible API, vLLM, Ollama, etc. Endpoints are
tried in order; each gets a retry on 429/5xx. Replies are parsed as JSON objects, with one
"repair" round-trip if the model wraps or mangles its JSON.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


class LLMError(RuntimeError):
    """Raised when no endpoint produced a usable reply."""


@dataclass(frozen=True, slots=True)
class LLMEndpoint:
    base_url: str
    api_key: str
    model: str

    @property
    def label(self) -> str:
        return self.model


@dataclass(slots=True)
class LLMReply:
    data: dict[str, Any]
    model: str
    raw: str


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model reply (handles fences and chatter)."""
    candidates = [m.group(1) for m in _FENCE_RE.finditer(text)] + [text]
    decoder = json.JSONDecoder()
    for candidate in candidates:
        for i, ch in enumerate(candidate):
            if ch != "{":
                continue
            try:
                obj, _ = decoder.raw_decode(candidate[i:])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
    return None


class LLMClient:
    def __init__(self, endpoints: list[LLMEndpoint], *, timeout: float = 90.0,
                 max_tokens: int = 4096, transport: httpx.AsyncBaseTransport | None = None
                 ) -> None:
        self.endpoints = [e for e in endpoints if e.base_url and e.api_key and e.model]
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._transport = transport

    @classmethod
    def from_settings(cls, settings: Settings | None = None,
                      transport: httpx.AsyncBaseTransport | None = None) -> LLMClient:
        s = settings or get_settings()
        return cls(
            [LLMEndpoint(s.llm_base_url, s.llm_api_key, s.llm_model),
             LLMEndpoint(s.llm_fallback_base_url, s.llm_fallback_api_key, s.llm_fallback_model)],
            timeout=s.llm_timeout_seconds, max_tokens=s.llm_max_tokens, transport=transport,
        )

    @property
    def available(self) -> bool:
        return bool(self.endpoints)

    async def _chat(self, client: httpx.AsyncClient, endpoint: LLMEndpoint,
                    messages: list[dict[str, str]], temperature: float) -> str:
        url = endpoint.base_url.rstrip("/") + "/chat/completions"
        body = {"model": endpoint.model, "messages": messages, "temperature": temperature,
                "top_p": 0.9, "max_tokens": self.max_tokens}
        headers = {"Authorization": f"Bearer {endpoint.api_key}", "Accept": "application/json"}
        for attempt in range(2):
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                retry_after = resp.headers.get("retry-after", "")
                await asyncio.sleep(min(10.0, float(retry_after) if retry_after.isdigit()
                                        else 2.0))
                continue
            resp.raise_for_status()
            payload = resp.json()
            content = payload["choices"][0]["message"].get("content") or ""
            if isinstance(content, list):  # some providers return content parts
                content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
            return content
        raise LLMError("unreachable")

    async def complete_json(self, system: str, user: str, *, temperature: float = 0.1
                            ) -> LLMReply:
        if not self.endpoints:
            raise LLMError("no LLM endpoint configured")
        errors: list[str] = []
        async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
            for endpoint in self.endpoints:
                messages = [{"role": "system", "content": system},
                            {"role": "user", "content": user}]
                try:
                    raw = await self._chat(client, endpoint, messages, temperature)
                    data = extract_json_object(raw)
                    if data is None:
                        messages += [
                            {"role": "assistant", "content": raw[:8000]},
                            {"role": "user", "content": "That reply was not a valid JSON object. "
                             "Reply again with ONLY the JSON object, no prose, no code fences."},
                        ]
                        raw = await self._chat(client, endpoint, messages, 0.0)
                        data = extract_json_object(raw)
                    if data is not None:
                        return LLMReply(data=data, model=endpoint.label, raw=raw)
                    errors.append(f"{endpoint.label}: unparseable JSON")
                except (httpx.HTTPError, KeyError, IndexError, ValueError, LLMError) as exc:
                    errors.append(f"{endpoint.label}: {type(exc).__name__}: {exc}")
                    logger.warning("LLM endpoint %s failed: %s", endpoint.label, exc)
        raise LLMError("; ".join(errors))
