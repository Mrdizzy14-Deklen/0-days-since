"""Nemotron agent: graph tools, the plan -> tool -> observe loop, and its fallbacks."""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.agent import GraphTools
from app.ai_scanner import AIScanner
from app.ast_engine import ProjectGraph
from app.enums import FindingStatus
from app.llm import LLMClient, LLMEndpoint
from tests.test_ai_scanner import _db_change, _input
from tests.test_ast_engine import REPO


def _client(handler: Any) -> LLMClient:
    return LLMClient([LLMEndpoint("https://llm.test/v1", "key", "nemotron-agent")],
                     transport=httpx.MockTransport(handler))


def _reply(obj: dict[str, Any] | str) -> httpx.Response:
    content = obj if isinstance(obj, str) else json.dumps(obj)
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def test_graph_tools_answer_from_the_real_graph() -> None:
    graph = ProjectGraph.from_sources(REPO)
    tools = GraphTools(graph)

    sym = tools.symbol("get_user")
    assert "app/routes/users.py" in sym and '"entry_point": true' in sym
    assert "UserService.find_user" in sym  # callee listed

    assert "UserService.find_user" in tools.callees("get_user")
    assert "get_user" in tools.callers("UserService.find_user")

    code = tools.read_code("app/db.py", 1, 400)
    assert code.startswith("app/db.py lines 1-") and "|" in code
    assert len(code.split("\n")) <= 81  # header + max 80 lines

    trace = tools.trace("UserService.find_user")
    assert "app.routes.users:get_user" in trace and "sql" in trace

    assert "app/db.py" in tools.search("execute(")
    assert tools.run("rm_rf", {}).startswith("Unknown tool")
    assert "No symbol" in tools.symbol("does_not_exist_anywhere")
    # dotted paths (how models usually write them) resolve to node ids
    assert tools.resolve("app.services.user_service.UserService.find_user")[0].node_id == \
        "app.services.user_service:UserService.find_user"


async def test_agent_plans_investigates_and_reports() -> None:
    graph = ProjectGraph.from_sources(REPO)
    seen: list[list[dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        messages = json.loads(request.content)["messages"]
        system = messages[0]["content"]
        if "adversarial skeptic" in system:
            ids = [c["id"] for c in json.loads(
                messages[1]["content"].split("## Candidates to verify\n", 1)[1]
                .split("\n\n## Cross-file", 1)[0])]
            return _reply({"verdicts": [{"id": i, "verdict": "confirmed", "confidence": 0.9,
                                         "reasoning": "no sanitizer on the path"} for i in ids]})
        seen.append(messages)
        turn = sum(1 for m in messages if m["role"] == "assistant") + 1
        if turn == 1:
            return _reply({"plan": ["inspect changed query", "trace callers", "confirm sink"],
                           "thought": "start at the changed DB code", "action": "symbol",
                           "args": {"name": "Database.find_by_id"}})
        if turn == 2:
            return _reply({"thought": "who reaches it", "action": "trace",
                           "args": {"name": "UserService.find_user"}})
        if turn == 3:
            return _reply({"thought": "read the sink", "action": "read_code",
                           "args": {"file_path": "app/db.py", "start_line": 1, "end_line": 30}})
        return _reply({"thought": "enough evidence", "action": "finish", "args": {"report": {
            "summary": "Route input reaches a formatted SQL query in app/db.py.",
            "vulnerabilities": [], "readability": {"notes": "Add docstrings."}}}})

    scanner = AIScanner(_client(handler), agent_max_steps=6)
    result = await scanner.scan(_input(graph, _db_change(graph)))

    run = result.agent
    assert run is not None and run.finished and run.model == "nemotron-agent"
    assert run.plan == ["inspect changed query", "trace callers", "confirm sink"]
    assert [s.action for s in run.steps] == ["symbol", "trace", "read_code", "finish"]
    assert "app/db.py" in run.steps[2].observation  # real tool output, not model text
    assert result.summary.startswith("Route input reaches")
    # tool output is fed back as untrusted data, after the model's own action
    last = seen[-1]
    assert last[-2]["role"] == "assistant" and '<untrusted kind="tool_output">' in last[-1][
        "content"]
    # the static SQL finding still goes through the skeptic and counts
    sqli = next(f for f in result.findings if f.rule_id == "PY-SEC-003")
    assert sqli.status is FindingStatus.VERIFIED
    assert run.to_dict()["steps"][0]["action"] == "symbol"


async def test_agent_falls_back_to_one_shot_review() -> None:
    graph = ProjectGraph.from_sources(REPO)
    one_shot = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        messages = json.loads(request.content)["messages"]
        system = messages[0]["content"]
        if "adversarial skeptic" in system:
            return _reply({"verdicts": []})
        if "autonomous application-security agent" in system:
            return _reply({"thought": "hmm", "action": "dance", "args": {}})  # never finishes
        one_shot["n"] += 1
        return _reply({"summary": "one-shot summary", "vulnerabilities": []})

    scanner = AIScanner(_client(handler), agent_max_steps=3)
    result = await scanner.scan(_input(graph, _db_change(graph)))
    assert one_shot["n"] == 1 and result.summary == "one-shot summary"
    assert result.agent is not None and not result.agent.finished
    assert any(e.startswith("agent:") for e in result.errors)


async def test_agent_accepts_a_bare_report() -> None:
    """Models sometimes skip the tool protocol and answer directly; that still counts."""
    graph = ProjectGraph.from_sources(REPO)

    def handler(request: httpx.Request) -> httpx.Response:
        system = json.loads(request.content)["messages"][0]["content"]
        if "adversarial skeptic" in system:
            return _reply({"verdicts": []})
        return _reply({"summary": "direct", "vulnerabilities": []})

    result = await AIScanner(_client(handler)).scan(_input(graph, _db_change(graph)))
    assert result.agent is not None and result.agent.finished and result.summary == "direct"
