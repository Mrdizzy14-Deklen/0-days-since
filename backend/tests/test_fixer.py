"""Agent auto-fix: patch application, re-scan verification and fix pull requests."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.ai_scanner import ScanFinding
from app.ast_engine import ProjectGraph
from app.enums import FindingCategory, FindingSource, FindingStatus, Severity
from app.fixer import FixAgent, apply_edits
from app.llm import LLMClient, LLMEndpoint
from tests.test_ast_engine import REPO, _line


def _client(reply: dict[str, Any]) -> LLMClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(reply)}}]})
    return LLMClient([LLMEndpoint("https://llm.test/v1", "k", "nemotron")],
                     transport=httpx.MockTransport(handler))


def _sqli(graph: ProjectGraph) -> ScanFinding:
    f = next(x for x in graph.files["app/db.py"].findings if x.rule_id == "PY-SEC-003")
    return ScanFinding(category=FindingCategory.SECURITY, source=FindingSource.STATIC,
                       status=FindingStatus.VERIFIED, severity=Severity.HIGH,
                       rule_id=f.rule_id, title=f.title, description=f.message,
                       file_path=f.file_path, start_line=f.line, end_line=f.end_line,
                       cwe=f.cwe, symbol_node_id=f.symbol)


def test_apply_edits_validates_ranges() -> None:
    src = {"a.py": "one\ntwo\nthree"}
    assert apply_edits(src, [{"file_path": "a.py", "start_line": 2, "end_line": 2,
                              "replacement": "TWO\nTWO-B"}]) == {"a.py": "one\nTWO\nTWO-B\nthree"}
    with pytest.raises(ValueError):
        apply_edits(src, [{"file_path": "b.py", "start_line": 1, "end_line": 1,
                           "replacement": "x"}])
    with pytest.raises(ValueError):
        apply_edits(src, [{"file_path": "a.py", "start_line": 1, "end_line": 9,
                           "replacement": "x"}])
    with pytest.raises(ValueError):
        apply_edits(src, [{"file_path": "a.py", "start_line": 1, "end_line": 2, "replacement": "x"},
                          {"file_path": "a.py", "start_line": 2, "end_line": 3,
                           "replacement": "y"}])


async def test_real_fix_is_verified_by_rescan() -> None:
    graph = ProjectGraph.from_sources(REPO)
    q = _line("app/db.py", "query = f\"SELECT")
    good = {"explanation": "bind the id", "commit_message": "Bind user id",
            "edits": [{"file_path": "app/db.py", "start_line": q, "end_line": q + 2,
                       "replacement": "        cur = self.conn.cursor()\n"
                                      "        cur.execute(\"SELECT * FROM users WHERE id = ?\", "
                                      "(user_id,))"}]}
    proposal = await FixAgent(_client(good)).propose(graph, _sqli(graph))
    assert proposal is not None and proposal.verified, proposal.verification
    assert "no longer fires" in proposal.verification
    assert "+" in proposal.diff and "-        query = f" in proposal.diff
    assert proposal.file_paths == ["app/db.py"]


async def test_cosmetic_fix_is_caught() -> None:
    graph = ProjectGraph.from_sources(REPO)
    q = _line("app/db.py", "query = f\"SELECT")
    fake = {"explanation": "renamed", "commit_message": "Rename",
            "edits": [{"file_path": "app/db.py", "start_line": q, "end_line": q,
                       "replacement": "        query = f\"SELECT * FROM users WHERE id = "
                                      "'{user_id}'\"  # sanitized"}]}
    proposal = await FixAgent(_client(fake)).propose(graph, _sqli(graph))
    assert proposal is not None and not proposal.verified
    assert "still reports PY-SEC-003" in proposal.verification


async def test_broken_or_empty_patches() -> None:
    graph = ProjectGraph.from_sources(REPO)
    q = _line("app/db.py", "query = f\"SELECT")
    broken = {"edits": [{"file_path": "app/db.py", "start_line": q, "end_line": q,
                         "replacement": "        query = (("}]}
    proposal = await FixAgent(_client(broken)).propose(graph, _sqli(graph))
    assert proposal is not None and proposal.error and "patch rejected" in proposal.error
    assert await FixAgent(_client({"edits": []})).propose(graph, _sqli(graph)) is None
