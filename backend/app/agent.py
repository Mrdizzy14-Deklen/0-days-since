"""Nemotron security agent: plans an investigation, calls code-graph tools, then reports.

The one-shot "Pass 1" prompt is replaced by a loop. The model first writes a plan, then each
turn picks ONE tool (look up a symbol, read code, walk callers/callees, trace entry-point ->
sink paths, search the repo) and sees the real result before deciding the next step. It ends
by calling ``finish`` with a report in the Pass 1 schema, so the existing validation,
adversarial verifier (Pass 2) and scoring guardrails apply unchanged.

The protocol is plain JSON ("thought" / "action" / "args") rather than provider-specific
function calling, so it works with any Nemotron NIM model and with the fallback endpoints.
Tool results are wrapped as untrusted data: they contain the developer's code.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from app.ast_engine import BlastRadius, ProjectGraph, SymbolInfo
from app.enums import SymbolKind
from app.llm import LLMClient, LLMError

logger = logging.getLogger(__name__)

MAX_READ_LINES = 80
MAX_OBSERVATION_CHARS = 3_500
MAX_SEARCH_HITS = 25

TOOL_DOCS = """\
- symbol {"name": "..."}: look up a function/method/class by name or id. Returns file, lines, \
whether it is an entry point (route), its untrusted inputs, dangerous calls (sinks), callers \
and callees.
- read_code {"file_path": "...", "start_line": 1, "end_line": 40}: line-numbered source \
(max 80 lines per call).
- callers {"name": "..."}: functions that call it, with the call line.
- callees {"name": "..."}: functions it calls, with the call line.
- trace {"name": "..."}: entry-point -> ... -> dangerous-call paths through this symbol, and \
whether caller-controlled data reaches the sink at every hop.
- search {"pattern": "..."}: case-insensitive literal text search across the repository \
(max 25 hits).
- finish {"report": {...}}: end the investigation and submit the report."""


def agent_system_prompt(report_schema: str, untrusted_notice: str, max_steps: int) -> str:
    return f"""You are an autonomous application-security agent reviewing ONE git push to a \
Python repository. You do not see the whole codebase up front: you investigate it with tools \
over a cross-file call graph, one tool call per turn, and see each real result before \
choosing the next step.

How to work:
1. In your FIRST reply include "plan": 3-6 short steps you intend to take.
2. Each reply is ONE JSON object: {{"thought": "why this step", "action": "<tool>", \
"args": {{...}}}}.
3. Follow untrusted input from entry points through the changed code into dangerous calls in \
other files. Check for validation, authorization and parameterization on the way before you \
conclude anything.
4. You have at most {max_steps} turns. Call "finish" as soon as you have enough evidence.

Tools:
{TOOL_DOCS}

The "report" passed to finish must follow this schema (same rules as a manual review: \
only issues you can tie to specific lines; precision matters more than recall; do not repeat \
the deterministic findings S*/C* as new vulnerabilities, set "duplicates" to their id):
{report_schema}

{untrusted_notice}"""


@dataclass(slots=True)
class AgentStep:
    step: int
    thought: str
    action: str
    args: dict[str, Any]
    observation: str
    ms: int = 0  # how long the model took to choose this step

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "thought": self.thought[:600], "action": self.action,
                "args": self.args, "observation": self.observation[:700], "ms": self.ms}


@dataclass(slots=True)
class AgentRun:
    report: dict[str, Any] | None
    plan: list[str] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    model: str | None = None
    finished: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"plan": self.plan, "steps": [s.to_dict() for s in self.steps],
                "model": self.model, "finished": self.finished, "error": self.error}


# --------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------


class GraphTools:
    """Read-only views of the project graph exposed to the agent."""

    def __init__(self, graph: ProjectGraph, radius: BlastRadius | None = None) -> None:
        self.graph = graph
        self.radius = radius

    # ---- resolution -----------------------------------------------------------------
    def resolve(self, name: str) -> list[SymbolInfo]:
        name = str(name or "").strip().strip("`").removesuffix("()")
        if not name:
            return []
        exact = self.graph.symbol(name)
        if exact is not None:
            return [exact]
        if ":" not in name and "." in name:
            # Models often write a dotted path: "app.services.billing.BillingService.get".
            parts = name.split(".")
            for i in range(len(parts) - 1, 0, -1):
                hit = self.graph.symbol(".".join(parts[:i]) + ":" + ".".join(parts[i:]))
                if hit is not None:
                    return [hit]
        syms = [s for s in self.graph._symbols.values() if s.kind is not SymbolKind.MODULE]
        tail = name.split(":")[-1]
        for test in (lambda s: s.qualname == tail,
                     lambda s: s.qualname.endswith("." + tail) or s.name == tail,
                     lambda s: tail.lower() in s.qualname.lower()):
            hits = [s for s in syms if test(s)]
            if hits:
                return sorted(hits, key=lambda s: (s.file_path, s.lineno))[:5]
        return []

    def _one(self, name: str) -> tuple[SymbolInfo | None, str | None]:
        hits = self.resolve(name)
        if not hits:
            return None, f"No symbol matches {name!r}. Try `search` or a shorter name."
        if len(hits) > 1 and hits[0].qualname.split(".")[-1] != str(name).split(":")[-1]:
            return None, "Ambiguous; use one of: " + ", ".join(s.node_id for s in hits)
        return hits[0], None

    @staticmethod
    def _sym_line(s: SymbolInfo) -> str:
        tags = []
        if s.is_entry_point:
            tags.append(f"ENTRY {s.framework or ''} {','.join(s.http_methods)} "
                        f"{s.route_path or ''}".strip())
        if s.sinks:
            tags.append("sinks=" + ",".join(
                f"{k.kind.value}@L{k.lineno}{'(tainted)' if k.tainted else ''}" for k in s.sinks))
        return f"{s.node_id} ({s.file_path}:{s.lineno}-{s.end_lineno})" + \
            (f" [{'; '.join(tags)}]" if tags else "")

    def _edges(self, node: str, *, incoming: bool) -> list[str]:
        view = self.graph._call_view()
        if node not in view:
            return []
        edges = view.in_edges(node, data=True) if incoming else view.out_edges(node, data=True)
        out = []
        for u, v, data in edges:
            other = self.graph.symbol(u if incoming else v)
            if other is None:
                continue
            out.append(f"{self._sym_line(other)} via line {data.get('lineno')}"
                       + (" [tainted args]" if data.get("tainted_args") else "")
                       + (f" [confidence {data.get('confidence')}]"
                          if (data.get("confidence") or 1) < 0.6 else ""))
        return sorted(set(out))[:30]

    # ---- tools ---------------------------------------------------------------------
    def symbol(self, name: str = "", **_: Any) -> str:
        s, err = self._one(name)
        if s is None:
            return err or ""
        info = {
            "id": s.node_id, "kind": s.kind.value, "file": s.file_path,
            "lines": [s.lineno, s.end_lineno], "params": s.params,
            "entry_point": s.is_entry_point,
            "route": " ".join(filter(None, [",".join(s.http_methods), s.route_path])) or None,
            "depends_on": s.dependencies, "untrusted_inputs": s.sources,
            "dangerous_calls": [{"kind": k.kind.value, "call": k.call, "line": k.lineno,
                                 "reached_by_untrusted_data": k.tainted} for k in s.sinks],
            "has_docstring": bool(s.docstring),
        }
        return (json.dumps(info, indent=1) + "\ncallers:\n  " +
                ("\n  ".join(self._edges(s.node_id, incoming=True)) or "(none)") +
                "\ncallees:\n  " + ("\n  ".join(self._edges(s.node_id, incoming=False))
                                    or "(none)"))

    def read_code(self, file_path: str = "", start_line: Any = 1, end_line: Any = None,
                  **_: Any) -> str:
        pf = self.graph.files.get(str(file_path).lstrip("./"))
        if pf is None:
            close = [p for p in self.graph.files if p.endswith(str(file_path).split("/")[-1])]
            return f"No such file {file_path!r}." + (f" Did you mean: {', '.join(close[:5])}"
                                                      if close else "")
        lines = pf.source.split("\n")
        try:
            start = max(1, int(start_line))
            end = int(end_line) if end_line is not None else start + 40
        except (TypeError, ValueError):
            return "start_line and end_line must be integers."
        end = min(len(lines), max(start, end), start + MAX_READ_LINES - 1)
        body = "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(start, end + 1))
        return f"{pf.path} lines {start}-{end} of {len(lines)}\n{body}"

    def callers(self, name: str = "", **_: Any) -> str:
        s, err = self._one(name)
        if s is None:
            return err or ""
        return "\n".join(self._edges(s.node_id, incoming=True)) or f"No callers of {s.node_id}."

    def callees(self, name: str = "", **_: Any) -> str:
        s, err = self._one(name)
        if s is None:
            return err or ""
        return "\n".join(self._edges(s.node_id, incoming=False)) or \
            f"{s.node_id} calls nothing resolvable."

    def trace(self, name: str = "", **_: Any) -> str:
        s, err = self._one(name)
        if s is None:
            return err or ""
        paths = [p for p in (self.radius.taint_paths if self.radius else [])
                 if s.node_id in p["nodes"]]
        if not paths:
            radius = self.graph.blast_radius({s.file_path: set(range(s.lineno,
                                                                      s.end_lineno + 1))})
            paths = [p for p in radius.taint_paths if s.node_id in p["nodes"]]
        if not paths:
            return f"No entry-point -> dangerous-call path runs through {s.node_id}."
        out = []
        for p in paths[:8]:
            out.append(" -> ".join(p["nodes"]) +
                       f"\n   entry={p['entry_route'] or '-'} inputs={p['entry_sources']} "
                       f"sinks={p['sink_kinds']} sink_reached_by_untrusted={p['sink_tainted']} "
                       f"caller_controlled_args_every_hop={p['args_flow']} "
                       f"cross_file={p['cross_file']}")
        return "\n".join(out)

    def search(self, pattern: str = "", **_: Any) -> str:
        needle = str(pattern or "").strip().lower()
        if len(needle) < 2:
            return "pattern must be at least 2 characters."
        hits = []
        for path in sorted(self.graph.files):
            for i, line in enumerate(self.graph.files[path].source.split("\n"), start=1):
                if needle in line.lower():
                    hits.append(f"{path}:{i}: {line.strip()[:160]}")
                    if len(hits) >= MAX_SEARCH_HITS:
                        return "\n".join(hits) + "\n(more hits omitted)"
        return "\n".join(hits) or f"No matches for {pattern!r}."

    def run(self, action: str, args: dict[str, Any]) -> str:
        tool = {"symbol": self.symbol, "read_code": self.read_code, "callers": self.callers,
                "callees": self.callees, "trace": self.trace, "search": self.search}.get(action)
        if tool is None:
            return (f"Unknown tool {action!r}. Valid tools: symbol, read_code, callers, "
                    "callees, trace, search, finish.")
        try:
            result = tool(**{k: v for k, v in args.items() if isinstance(k, str)})
        except TypeError as exc:
            result = f"Bad arguments for {action}: {exc}"
        return result if len(result) <= MAX_OBSERVATION_CHARS else \
            result[:MAX_OBSERVATION_CHARS] + "\n... (truncated)"


# --------------------------------------------------------------------------------------
# Loop
# --------------------------------------------------------------------------------------

_ACTION_RE = re.compile(r"^[a-z_]{2,20}$")


def _report_from(data: dict[str, Any]) -> dict[str, Any] | None:
    """Accept `finish` in the documented shape and the common variations models produce."""
    args = data.get("args") if isinstance(data.get("args"), dict) else {}
    for candidate in (args.get("report"), data.get("report"), args, data):
        if isinstance(candidate, dict) and ("vulnerabilities" in candidate
                                            or "summary" in candidate):
            return candidate
    return None


class SecurityAgent:
    def __init__(self, llm: LLMClient, *, max_steps: int = 10) -> None:
        self.llm = llm
        self.max_steps = max_steps

    async def investigate(self, *, system: str, brief: str, tools: GraphTools) -> AgentRun:
        run = AgentRun(report=None)
        messages: list[dict[str, str]] = [{"role": "system", "content": system},
                                          {"role": "user", "content": brief}]
        for turn in range(1, self.max_steps + 1):
            remaining = self.max_steps - turn
            t0 = time.perf_counter()
            try:
                reply = await self.llm.complete_json_messages(messages)
            except LLMError as exc:
                run.error = str(exc)
                return run
            ms = int((time.perf_counter() - t0) * 1000)
            run.model = run.model or reply.model
            data = reply.data
            if turn == 1 and isinstance(data.get("plan"), list):
                run.plan = [str(p)[:200] for p in data["plan"][:8]]
            action = str(data.get("action") or "").strip().lower()
            thought = str(data.get("thought") or "")
            args = data.get("args") if isinstance(data.get("args"), dict) else {}

            if action == "finish" or (not action and _report_from(data)):
                run.report = _report_from(data)
                run.finished = run.report is not None
                run.steps.append(AgentStep(turn, thought, "finish", {}, "Report submitted.", ms))
                if run.finished:
                    return run
                observation = "finish needs args.report following the schema. Try again."
            elif not _ACTION_RE.match(action):
                observation = "Reply with one JSON object containing thought, action and args."
            else:
                observation = tools.run(action, args)
                run.steps.append(AgentStep(turn, thought, action, args, observation, ms))

            nudge = ("You must call finish NOW with your report." if remaining <= 1
                     else f"{remaining} turns left.")
            messages += [
                {"role": "assistant", "content": json.dumps(data)[:6000]},
                {"role": "user", "content": f"<observation tool=\"{action or 'none'}\">\n"
                 f"<untrusted kind=\"tool_output\">\n{observation}\n</untrusted>\n"
                 f"</observation>\n{nudge}"},
            ]

        # Budget exhausted: one last chance to report.
        messages.append({"role": "user", "content": "Turn budget exhausted. Reply with "
                         "{\"action\": \"finish\", \"args\": {\"report\": {...}}} now."})
        try:
            reply = await self.llm.complete_json_messages(messages, temperature=0.0)
            run.report = _report_from(reply.data)
            run.finished = run.report is not None
        except LLMError as exc:
            run.error = str(exc)
        if not run.finished and run.error is None:
            run.error = "agent did not submit a report"
        return run


def build_brief(*, repo: str, changed_files: list[str], commit_message: str, diff: str,
                candidates: list[dict[str, Any]], metrics: dict[str, Any],
                graph: ProjectGraph, radius: BlastRadius) -> str:
    """Opening message: what changed and where to start, without dumping the codebase."""
    changed_syms = []
    for n in radius.seeds:
        s = graph.symbol(n)
        if s is not None and s.kind is not SymbolKind.MODULE:
            changed_syms.append(GraphTools._sym_line(s))
    paths = [" -> ".join(p["nodes"]) + f"  [sinks={','.join(p['sink_kinds'])}; "
             f"caller-controlled args every hop={p['args_flow']}]"
             for p in radius.taint_paths[:6]]
    return (
        f"Repository: {repo}\nChanged Python files: {', '.join(changed_files)}\n\n"
        f"<untrusted kind=\"commit_message\">\n{commit_message[:2000]}\n</untrusted>\n\n"
        f"## Changed symbols (start here)\n" + ("\n".join(changed_syms) or "(module-level only)")
        + "\n\n## Candidate entry -> change -> sink paths found by the graph\n"
        + ("\n".join(paths) or "(none)")
        + f"\n\n## Diff\n<untrusted kind=\"diff\">\n{diff}\n</untrusted>\n\n"
        "## Deterministic findings & cross-file candidates\n"
        + json.dumps(candidates, indent=1)
        + f"\n\n## Readability metrics for the changed code\n{json.dumps(metrics)}\n\n"
        "Your first reply MUST include \"plan\" (3-6 short steps) together with your first "
        "tool call. Then investigate."
    )
