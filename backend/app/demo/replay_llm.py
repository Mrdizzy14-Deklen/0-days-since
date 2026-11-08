"""Scripted OpenAI-compatible endpoint that replays the demo scenario's AI responses.

It receives the real Pass 1 / Pass 2 prompts produced by :mod:`app.ai_scanner` and answers
from the current :class:`~app.demo.scenario.Step` script. Replies go through the normal
parsing, validation and guardrails. The model label is ``demo-replay`` so seeded data never
pretends to come from a real model.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.ai_scanner import PASS2_SYSTEM
from app.demo.scenario import Step
from app.fixer import FIX_SYSTEM, VERIFY_SYSTEM
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

    def agent_turn(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """A short scripted investigation; every tool call runs against the real graph."""
        turn = sum(1 for m in messages if m["role"] == "assistant") + 1
        brief = messages[1]["content"]
        section = brief.split("## Changed symbols (start here)\n", 1)[-1].split("\n\n", 1)[0]
        first = section.split(" (", 1)[0].strip() if "(" in section else ""
        if not first or turn >= 4:
            return {"thought": "I have traced the change end to end; reporting.",
                    "action": "finish", "args": {"report": self.pass1()}}
        if turn == 1:
            return {"plan": ["Inspect the changed function and where its inputs come from",
                             "Trace entry points through the change to dangerous calls",
                             "Read the code on the path for validation or auth checks",
                             "Report only what the evidence supports"],
                    "thought": "Start with the changed symbol.", "action": "symbol",
                    "args": {"name": first}}
        if turn == 2:
            return {"thought": "Check whether untrusted input reaches a dangerous call.",
                    "action": "trace", "args": {"name": first}}
        assert self.step is not None
        target = self.step.ai.vulns[0] if self.step.ai.vulns else None
        if target:
            path, line = target["file_path"], _line_of(self.files[target["file_path"]],
                                                        target["needle"])
        else:  # "node_id (path/to/file.py:12-30) [...]"; prefer the one holding the sink
            lines = section.split("\n")
            pick = next((ln for ln in lines if "sinks=" in ln), lines[0])
            m = re.search(r"\(([^():]+):(\d+)-", pick)
            if m is None:
                return {"thought": "Nothing more to read; reporting.", "action": "finish",
                        "args": {"report": self.pass1()}}
            path, line = m.group(1), int(m.group(2))
        return {"thought": "Read the code on the path to look for validation.",
                "action": "read_code",
                "args": {"file_path": path, "start_line": max(1, line - 6),
                         "end_line": line + 12}}

    def fix(self) -> dict[str, Any]:
        assert self.step is not None
        script = self.step.ai.fix
        if not script:
            return {"edits": []}
        edits = []
        for e in script["edits"]:
            src = self.files[e["file_path"]]
            edits.append({"file_path": e["file_path"], "start_line": _line_of(src, e["needle"]),
                          "end_line": _line_of(src, e["end_needle"]),
                          "replacement": e["replacement"]})
        return {"explanation": script["explanation"],
                "commit_message": script["commit_message"], "edits": edits}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        body = json.loads(request.content)
        messages = body["messages"]
        system, user = messages[0]["content"], messages[1]["content"]
        if system == PASS2_SYSTEM:
            reply = self.pass2(user)
        elif system == FIX_SYSTEM:
            reply = self.fix()
        elif system == VERIFY_SYSTEM:
            reply = {"verdict": "fixed", "reasoning": "The input is now bound, not formatted."}
        elif "autonomous application-security agent" in system:
            reply = self.agent_turn(messages)
        else:
            reply = self.pass1()
        return httpx.Response(200, json={"model": REPLAY_MODEL, "choices": [
            {"message": {"role": "assistant", "content": json.dumps(reply)}}]})

    def client(self) -> LLMClient:
        return LLMClient([LLMEndpoint("https://replay.invalid/v1", "replay", REPLAY_MODEL)],
                         transport=httpx.MockTransport(self.handler))
