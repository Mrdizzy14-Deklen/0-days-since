"""Scripted OpenAI-compatible endpoint that replays the demo scenario's AI responses.

It receives the real Pass 1 / Pass 2 prompts produced by :mod:`app.ai_scanner` and answers
from the current :class:`~app.demo.scenario.Step` script. Replies go through the normal
parsing, validation and guardrails. The model label is ``demo-replay`` so seeded data never
pretends to come from a real model.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.ai_scanner import PASS2_SYSTEM
from app.demo.scenario import Step
from app.llm import LLMClient, LLMEndpoint

REPLAY_MODEL = "demo-replay"
DEFAULT_CONFIRM = ("No sanitizer, validation or authorization check was found between the "
                   "entry point and the sink in the provided slice.")


def _line_of(source: str, needle: str) -> int:
    for i, line in enumerate(source.split("\n"), start=1):
        if needle in line:
            return i
    raise ValueError(f"needle not found: {needle!r}")


def _candidates(user_prompt: str) -> list[dict[str, Any]]:
    start = user_prompt.index("## Candidates to verify\n") + len("## Candidates to verify\n")
    end = user_prompt.index("\n\n## Cross-file call-graph slice")
    return json.loads(user_prompt[start:end])


class ReplayLLM:
    def __init__(self) -> None:
        self.step: Step | None = None
        self.files: dict[str, str] = {}
        self.calls = 0

    def pass1(self) -> dict[str, Any]:
        assert self.step is not None
        ai = self.step.ai
        vulns = []
        for v in ai.vulns:
            line = _line_of(self.files[v["file_path"]], v["needle"])
            vulns.append({k: val for k, val in v.items() if k != "needle"} |
                         {"start_line": line, "end_line": line})
        return {
            "summary": ai.summary,
            "vulnerabilities": vulns,
            "readability": {"docs_adjustment": ai.docs, "readability_adjustment": ai.readability,
                            "type_hints_adjustment": ai.type_hints, "notes": ai.notes,
                            "issues": []},
        }

    def pass2(self, user_prompt: str) -> dict[str, Any]:
        assert self.step is not None
        ai = self.step.ai
        verdicts = []
        for c in _candidates(user_prompt):
            reason = ai.reject.get(c["rule"]) or (ai.reject.get(c["cwe"]) if c["cwe"] else None)
            if reason:
                verdicts.append({"id": c["id"], "verdict": "rejected", "confidence": 0.85,
                                 "reasoning": reason})
            else:
                verdicts.append({"id": c["id"], "verdict": "confirmed", "severity": c["severity"],
                                 "confidence": 0.9,
                                 "reasoning": ai.confirm_reason or DEFAULT_CONFIRM})
        return {"verdicts": verdicts}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        body = json.loads(request.content)
        system, user = body["messages"][0]["content"], body["messages"][1]["content"]
        reply = self.pass2(user) if system == PASS2_SYSTEM else self.pass1()
        return httpx.Response(200, json={"model": REPLAY_MODEL, "choices": [
            {"message": {"role": "assistant", "content": json.dumps(reply)}}]})

    def client(self) -> LLMClient:
        return LLMClient([LLMEndpoint("https://replay.invalid/v1", "replay", REPLAY_MODEL)],
                         transport=httpx.MockTransport(self.handler))
