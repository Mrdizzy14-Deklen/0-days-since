"""Tests for the whole-project AST engine using a realistic multi-file FastAPI app."""

from __future__ import annotations

import textwrap

import pytest

from app.ast_engine import (
    ProjectGraph,
    changed_lines_from_patch,
    is_analyzable_path,
    parse_python_file,
)
from app.enums import EdgeKind, FindingCategory, Severity, SinkKind


def _src(code: str) -> str:
    return textwrap.dedent(code).lstrip("\n")


REPO: dict[str, str] = {
    "app/__init__.py": "",
    "app/main.py": _src('''
        """Application factory."""
        from fastapi import FastAPI

        from app.routes import users

        app = FastAPI()
        app.include_router(users.router)
    '''),
    "app/auth.py": _src('''
        """Authentication helpers."""


        def get_current_user(token: str = "") -> dict:
            """Resolve the current user from a bearer token."""
            return {"token": token}
    '''),
    "app/routes/__init__.py": "",
    "app/routes/users.py": _src('''
        """User routes."""
        from fastapi import APIRouter, Depends

        from app.auth import get_current_user
        from app.services.user_service import UserService
        from ..services.files import read_document

        router = APIRouter()


        @router.get("/users/{user_id}")
        async def get_user(user_id: str, current: dict = Depends(get_current_user)) -> dict:
            """Fetch a single user."""
            service = UserService()
            return service.find_user(user_id)


        @router.post("/export")
        def export_report(name: str) -> None:
            """Export a report archive."""
            from app.services import reports
            reports.build_report(name)


        @router.get("/docs/{doc}")
        def get_doc(doc: str) -> str:
            """Return a stored document."""
            return read_document(doc)
    '''),
    "app/services/__init__.py": "",
    "app/services/user_service.py": _src('''
        """User domain service."""
        from app.db import Database


        class UserService:
            """Business logic for users."""

            def __init__(self) -> None:
                self.db = Database()

            def find_user(self, user_id: str) -> dict:
                """Look a user up by id."""
                return self.db.fetch_user(user_id)
    '''),
    "app/services/reports.py": _src('''
        import subprocess


        def build_report(name):
            subprocess.run(f"tar czf /tmp/{name}.tgz /data", shell=True)
    '''),
    "app/services/files.py": _src('''
        """Document storage."""


        def read_document(name: str) -> str:
            """Read a document from disk."""
            with open(name) as fh:
                return fh.read()
    '''),
    "app/db.py": _src('''
        import sqlite3

        DB_PASSWORD = "Sup3rS3cretP4ssw0rd!x"


        class Database:
            def __init__(self):
                self.conn = sqlite3.connect("app.db")

            def fetch_user(self, user_id):
                query = f"SELECT * FROM users WHERE id = '{user_id}'"
                cur = self.conn.cursor()
                cur.execute(query)
                return cur.fetchone()

            def fetch_safe(self, user_id: str) -> tuple:
                """Parameterized lookup."""
                cur = self.conn.cursor()
                cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                return cur.fetchone()
    '''),
    ".venv/lib/site-packages/evil.py": "eval(input())",
}


@pytest.fixture()
def graph() -> ProjectGraph:
    return ProjectGraph.from_sources(REPO)


def _has_edge(g: ProjectGraph, src: str, dst: str, kind: EdgeKind = EdgeKind.CALL) -> bool:
    return g.graph.has_edge(src, dst, key=kind)


def _line(path: str, needle: str) -> int:
    for i, line in enumerate(REPO[path].split("\n"), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} not in {path}")


# ---------------------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------------------


def test_excludes_virtualenv_files(graph: ProjectGraph) -> None:
    assert ".venv/lib/site-packages/evil.py" not in graph.files
    assert not is_analyzable_path("node_modules/x.py")
    assert is_analyzable_path("src/app/x.py")


def test_symbols_and_metadata(graph: ProjectGraph) -> None:
    get_user = graph.symbol("app.routes.users:get_user")
    assert get_user is not None
    assert get_user.is_entry_point and get_user.framework == "fastapi"
    assert get_user.route_path == "/users/{user_id}" and get_user.http_methods == ["GET"]
    assert get_user.dependencies == ["get_current_user"]
    assert "route_param:user_id" in get_user.sources
    assert get_user.has_type_hints and get_user.docstring == "Fetch a single user."

    fetch = graph.symbol("app.db:Database.fetch_user")
    assert fetch is not None and fetch.docstring is None
    assert fetch.type_hint_coverage == 0.0
    assert any(s.kind is SinkKind.SQL and s.unsafe_construction for s in fetch.sinks)


def test_cross_file_call_resolution(graph: ProjectGraph) -> None:
    users, svc, db = "app.routes.users", "app.services.user_service", "app.db"
    # constructor call -> class + __init__
    assert _has_edge(graph, f"{users}:get_user", f"{svc}:UserService")
    assert _has_edge(graph, f"{users}:get_user", f"{svc}:UserService.__init__")
    # local variable type inference: service = UserService(); service.find_user()
    assert _has_edge(graph, f"{users}:get_user", f"{svc}:UserService.find_user")
    # self attribute type inference: self.db = Database(); self.db.fetch_user()
    assert _has_edge(graph, f"{svc}:UserService.find_user", f"{db}:Database.fetch_user")
    # FastAPI Depends() implicit edge
    assert _has_edge(graph, f"{users}:get_user", "app.auth:get_current_user")
    # function-local `from app.services import reports` + module attribute call
    assert _has_edge(graph, f"{users}:export_report", "app.services.reports:build_report")
    # relative import `from ..services.files import read_document`
    assert _has_edge(graph, f"{users}:get_doc", "app.services.files:read_document")
    # module import edges
    assert _has_edge(graph, f"{users}:<module>", f"{svc}:<module>", EdgeKind.IMPORT)


def test_call_edges_record_argument_taint(graph: ProjectGraph) -> None:
    data = graph.graph.get_edge_data("app.services.user_service:UserService.find_user",
                                     "app.db:Database.fetch_user", key=EdgeKind.CALL)
    assert data["tainted_args"] is True
    dep = graph.graph.get_edge_data("app.routes.users:get_user", "app.auth:get_current_user",
                                    key=EdgeKind.CALL)
    assert dep["tainted_args"] is False


# ---------------------------------------------------------------------------------------
# Deterministic security pass
# ---------------------------------------------------------------------------------------


def _findings(graph: ProjectGraph, path: str, category: FindingCategory) -> list:
    return [f for f in graph.files[path].findings if f.category is category]


def test_sql_injection_detected_but_parameterized_query_is_clean(graph: ProjectGraph) -> None:
    sec = _findings(graph, "app/db.py", FindingCategory.SECURITY)
    sqli = [f for f in sec if f.rule_id == "PY-SEC-003"]
    assert len(sqli) == 1
    assert sqli[0].line == _line("app/db.py", "cur.execute(query)")
    assert sqli[0].severity is Severity.HIGH and sqli[0].cwe == "CWE-89"
    assert sqli[0].symbol == "app.db:Database.fetch_user"


def test_hardcoded_secret_and_command_injection(graph: ProjectGraph) -> None:
    secrets = [f for f in _findings(graph, "app/db.py", FindingCategory.SECURITY)
               if f.rule_id == "PY-SEC-004"]
    assert len(secrets) == 1 and "Sup3rS3cretP4ssw0rd!x" not in secrets[0].message

    cmd = [f for f in _findings(graph, "app/services/reports.py", FindingCategory.SECURITY)
           if f.rule_id == "PY-SEC-002"]
    assert len(cmd) == 1 and cmd[0].severity is Severity.HIGH and cmd[0].cwe == "CWE-78"


def test_direct_route_input_escalates_to_critical() -> None:
    pf = parse_python_file("app/api.py", _src('''
        import os
        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/ping")
        def ping():
            host = request.args.get("host")
            os.system("ping -c 1 " + host)
            return eval(request.form["expr"])
    '''))
    sym = pf.symbols["ping"]
    assert sym.is_entry_point and sym.framework == "flask" and "request.args" in sym.sources
    sev = {f.rule_id: f.severity for f in pf.findings if f.category is FindingCategory.SECURITY}
    assert sev["PY-SEC-002"] is Severity.CRITICAL
    assert sev["PY-SEC-001"] is Severity.CRITICAL


def test_fastapi_typed_scalar_params_are_not_sources() -> None:
    pf = parse_python_file("app/files.py", _src('''
        from fastapi import APIRouter
        from fastapi.responses import FileResponse

        router = APIRouter()


        @router.get("/invoices/{invoice_id}.pdf")
        def invoice_pdf(invoice_id: int) -> FileResponse:
            return FileResponse(f"/srv/invoices/{invoice_id}.pdf")


        @router.get("/raw/{name}")
        def raw(name: str) -> FileResponse:
            return FileResponse(f"/srv/raw/{name}")
    '''))
    flagged = {f.symbol for f in pf.findings if f.rule_id == "PY-SEC-009"}
    assert flagged == {"raw"}
    assert pf.symbols["invoice_pdf"].sources == []


def test_misc_security_rules() -> None:
    pf = parse_python_file("app/misc.py", _src('''
        import hashlib
        import jwt
        import pickle
        import requests
        import yaml


        def go(url, blob, token, text):
            requests.get(f"https://{url}/api", verify=False)
            pickle.loads(blob)
            jwt.decode(token, options={"verify_signature": False})
            yaml.load(text)
            yaml.load(text, Loader=yaml.SafeLoader)
            hashlib.md5(b"x")
            hashlib.md5(b"x", usedforsecurity=False)
            api_key = "AKIAIOSFODNN7EXAMPLQ"
            password = "changeme-placeholder"
    '''))
    rules = sorted(f.rule_id for f in pf.findings if f.category is FindingCategory.SECURITY)
    assert rules.count("PY-SEC-005") == 2  # pickle + unsafe yaml (not the SafeLoader call)
    assert rules.count("PY-SEC-008") == 1  # md5 only when used for security
    assert {"PY-SEC-006", "PY-SEC-010", "PY-SEC-011", "PY-SEC-004"} <= set(rules)
    assert rules.count("PY-SEC-004") == 1  # placeholder password ignored


# ---------------------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------------------


def test_blast_radius_two_hops_from_changed_sink(graph: ProjectGraph) -> None:
    line = _line("app/db.py", "cur.execute(query)")
    radius = graph.blast_radius({"app/db.py": {line}}, hops=2)
    assert radius.seeds == ["app.db:Database.fetch_user"]
    assert radius.upstream["app.services.user_service:UserService.find_user"] == 1
    assert radius.upstream["app.routes.users:get_user"] == 2
    assert radius.entry_points == ["app.routes.users:get_user"]
    assert any(s["kind"] == "sql" for s in radius.sinks)
    path = radius.taint_paths[0]
    assert path["nodes"] == ["app.routes.users:get_user",
                             "app.services.user_service:UserService.find_user",
                             "app.db:Database.fetch_user"]
    assert path["args_flow"] and path["cross_file"] and path["sink_tainted"]
    assert "app/routes/users.py" in radius.impacted_files
    assert "app.services.user_service" in radius.dependent_modules
    payload = radius.to_dict()
    assert {n["role"] for n in payload["nodes"]} == {"seed", "upstream"}

    context = graph.slice_prompt_context(radius)
    assert "[CHANGED]" in context and "ENTRY POINT fastapi GET /users/{user_id}" in context
    assert "cur.execute(query)" in context


def test_blast_radius_downstream_from_changed_route(graph: ProjectGraph) -> None:
    line = _line("app/routes/users.py", "return service.find_user(user_id)")
    radius = graph.blast_radius({"app/routes/users.py": {line}}, hops=2)
    assert radius.seeds == ["app.routes.users:get_user"]
    assert radius.downstream["app.services.user_service:UserService.find_user"] == 1
    assert radius.downstream["app.db:Database.fetch_user"] == 2
    assert radius.entry_points == ["app.routes.users:get_user"]


def test_cross_file_candidate_for_unflagged_sink(graph: ProjectGraph) -> None:
    line = _line("app/routes/users.py", "return read_document(doc)")
    radius = graph.blast_radius({"app/routes/users.py": {line}})
    candidates = graph.cross_file_candidates(radius)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.rule_id == "PY-SEC-100" and cand.cwe == "CWE-22"
    assert cand.file_path == "app/services/files.py"
    assert [s["role"] for s in cand.taint_flow] == ["source", "sink"]
    assert cand.taint_flow[-1]["snippet"] == "with open(name) as fh:"


# ---------------------------------------------------------------------------------------
# Quality / craft scoring
# ---------------------------------------------------------------------------------------


def test_quality_report_rewards_documented_typed_code(graph: ProjectGraph) -> None:
    good = graph.quality_report({"app/services/user_service.py": None})
    bad = graph.quality_report({"app/services/reports.py": None})
    assert good.docstring_coverage == 1.0 and good.type_hint_coverage == 1.0
    assert bad.docstring_coverage == 0.0 and bad.type_hint_coverage == 0.0
    assert good.craft_score > bad.craft_score
    assert 0 <= bad.craft_score <= 300 and 0 <= good.craft_score <= 300


def test_quality_penalties_for_complex_code() -> None:
    nested = _src('''
        def tangled(a: int, items: list = []) -> int:
            """Deliberately awful."""
            total = 0
            for x in items:
                if x:
                    for y in range(x):
                        if y % 2:
                            while y:
                                if y > a:
                                    total += y
                                y -= 1
            try:
                total += 1
            except:
                pass
            return total
    ''')
    g = ProjectGraph.from_sources({"pkg/mod.py": nested})
    # pkg/ has no __init__.py, so it is a source root and the module is just "mod"
    sym = g.symbol("mod:tangled")
    assert sym is not None and sym.max_nesting == 6
    report = g.quality_report({"pkg/mod.py": None})
    assert report.deep_nesting == 1
    assert report.best_practice_violations == {"PY-QUAL-006": 1, "PY-QUAL-007": 1,
                                               "PY-QUAL-008": 1}
    assert report.readability_score < 100 and report.type_hints_score < 100
    rules = {f.rule_id for f in g.files["pkg/mod.py"].findings}
    assert {"PY-QUAL-004", "PY-QUAL-006", "PY-QUAL-007", "PY-QUAL-008"} <= rules


def test_findings_for_change_only_blames_touched_lines(graph: ProjectGraph) -> None:
    safe_line = _line("app/db.py", '"SELECT * FROM users WHERE id = ?"')
    introduced, context = graph.findings_for_change({"app/db.py": {safe_line}})
    assert not [f for f in introduced if f.rule_id == "PY-SEC-003"]
    assert [f for f in context if f.rule_id == "PY-SEC-003"]


# ---------------------------------------------------------------------------------------
# Incremental updates, other frameworks, robustness
# ---------------------------------------------------------------------------------------


def test_incremental_update_reparses_only_changed_files(graph: ProjectGraph) -> None:
    fixed = REPO["app/db.py"].replace(
        'query = f"SELECT * FROM users WHERE id = \'{user_id}\'"',
        'query = "SELECT * FROM users WHERE id = ?"',
    ).replace("cur.execute(query)", "cur.execute(query, (user_id,))")
    reparsed = graph.update_files({**REPO, "app/db.py": fixed})
    assert reparsed == ["app/db.py"]
    assert not [f for f in graph.files["app/db.py"].findings if f.rule_id == "PY-SEC-003"]
    # edges into the re-parsed file are re-resolved
    assert _has_edge(graph, "app.services.user_service:UserService.find_user",
                     "app.db:Database.fetch_user")

    graph.update_files({}, removed=["app/services/reports.py"])
    assert "app.services.reports:build_report" not in graph.graph
    assert not _has_edge(graph, "app.routes.users:export_report",
                         "app.services.reports:build_report")


def test_django_urlconf_marks_views_as_entry_points() -> None:
    g = ProjectGraph.from_sources({
        "shop/__init__.py": "",
        "shop/views.py": _src('''
            from django.db import connection
            from django.views import View


            def order_detail(request, order_id):
                with connection.cursor() as cur:
                    cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)


            class InvoiceView(View):
                def get(self, request, pk):
                    return pk
        '''),
        "shop/urls.py": _src('''
            from django.urls import path

            from . import views

            urlpatterns = [
                path("orders/<int:order_id>/", views.order_detail),
                path("invoices/<int:pk>/", views.InvoiceView.as_view()),
            ]
        '''),
    })
    detail = g.symbol("shop.views:order_detail")
    assert detail and detail.is_entry_point and detail.route_path == "/orders/<int:order_id>/"
    assert "route_param:order_id" in detail.sources
    assert g.symbol("shop.views:InvoiceView.get").is_entry_point
    assert g.graph.has_edge("shop.urls:<module>", "shop.views:order_detail", key=EdgeKind.ROUTE)
    sqli = [f for f in g.files["shop/views.py"].findings if f.rule_id == "PY-SEC-003"]
    assert sqli and sqli[0].severity is Severity.CRITICAL


def test_src_layout_and_stdlib_shadowing() -> None:
    g = ProjectGraph.from_sources({
        "src/proj/__init__.py": "",
        "src/proj/core.py": "def helper_function():\n    return 1\n",
        "src/proj/cli.py": "import json\nfrom proj.core import helper_function\n\n"
                           "def main():\n    json.dumps({})\n    return helper_function()\n",
        "scripts/json.py": "def dumps(x):\n    return x\n",
    })
    assert g.module_for_path("src/proj/core.py") == "proj.core"
    assert g.graph.has_edge("proj.cli:main", "proj.core:helper_function", key=EdgeKind.CALL)
    assert not g.graph.has_edge("proj.cli:main", "json:dumps", key=EdgeKind.CALL)


def test_syntax_error_does_not_break_the_graph() -> None:
    g = ProjectGraph.from_sources({"a.py": "def broken(:\n", "b.py": "def ok():\n    pass\n"})
    assert g.files["a.py"].syntax_error
    assert g.files["a.py"].findings[0].rule_id == "PY-QUAL-000"
    assert "b:ok" in g.graph
    assert g.stats()["parse_errors"] == 1


def test_changed_lines_from_patch() -> None:
    patch = _src('''
        @@ -1,4 +1,5 @@
         import os
        -x = 1
        +x = 2
        +y = 3
         z = 4
        @@ -10,2 +11,2 @@ def f():
        -    old()
        +    new()
    ''')
    assert changed_lines_from_patch(patch) == {2, 3, 11}
    assert changed_lines_from_patch(None) == set()


def test_records_match_model_columns(graph: ProjectGraph) -> None:
    from app.models import CodeEdge, CodeSymbol

    sym_cols = set(CodeSymbol.model_fields) - {"id", "repository_id", "commit_sha", "updated_at"}
    edge_cols = set(CodeEdge.model_fields) - {"id", "repository_id"}
    for rec in graph.symbol_records():
        assert set(rec) == sym_cols
        CodeSymbol(repository_id=1, **rec)
    for rec in graph.edge_records():
        assert set(rec) == edge_cols
        CodeEdge(repository_id=1, **rec)
