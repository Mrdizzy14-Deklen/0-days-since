"""Whole-project Python AST engine: symbol/call graph, blast radius, quality & security passes.

Pipeline
--------
1. ``parse_python_file`` parses ONE file into a module-agnostic :class:`ParsedFile`:
   symbols (module / classes / functions / methods) with docstrings, type-hint stats,
   cyclomatic complexity, nesting depth, raw call sites, intra-procedural taint,
   framework entry points (FastAPI / Flask / Django / DRF / Celery / CLI), sinks, and
   deterministic security + readability findings.
2. :class:`ProjectGraph` owns every ParsedFile of a repository. ``rebuild()`` assigns
   module names, resolves imports (absolute, relative, re-exports, star imports) and
   call chains (locals, ``self``/``super()``, typed locals, constructor and return-type
   inference, FastAPI ``Depends``) into a ``networkx.MultiDiGraph``. Parsing is the
   expensive part and is cached per file, so incremental pushes only re-parse the
   changed files while resolution re-runs project-wide (cheap, and always consistent).
3. ``ProjectGraph.blast_radius`` returns the N-hop upstream/downstream slice around the
   changed lines, entry points, reachable sinks and entry -> change -> sink taint paths.
4. ``ProjectGraph.quality_report`` grades only the code the developer touched and
   produces the three 0-100 craft sub-scores (docs/comments, readability, type hints &
   best practices).

The module depends only on the standard library + networkx so it can run anywhere.
"""

from __future__ import annotations

import ast
import hashlib
import io
import logging
import math
import re
import sys
import tokenize
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import networkx as nx

from app.enums import EdgeKind, FindingCategory, Severity, SinkKind, SymbolKind

logger = logging.getLogger(__name__)

__all__ = [
    "BlastRadius",
    "CallSite",
    "ParsedFile",
    "ProjectGraph",
    "QualityReport",
    "SinkSite",
    "StaticFinding",
    "SymbolInfo",
    "changed_lines_from_patch",
    "decode_source",
    "is_analyzable_path",
    "parse_python_file",
]

# --------------------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------------------

MODULE_QUALNAME = "<module>"
COMPLEXITY_LIMIT = 10  # McCabe; > limit is penalised
NESTING_LIMIT = 4  # nested branch/loop depth; > limit is penalised (5+ levels deep)
FUNCTION_LENGTH_LIMIT = 60  # lines; > limit is penalised
PARAM_LIMIT = 6
LINE_LENGTH_LIMIT = 99
COMMENT_DENSITY_TARGET = 0.12  # ~1 comment line per 8 code lines earns full marks
MAX_SOURCE_CHARS = 20_000  # per-symbol source stored in the DB
HEURISTIC_CONFIDENCE = 0.4
INFERRED_CONFIDENCE = 0.8

EXCLUDED_DIR_PARTS = frozenset(
    {
        ".git", ".hg", ".svn", ".tox", ".nox", ".venv", "venv", "env", ".env", "virtualenv",
        "site-packages", "dist-packages", "node_modules", "__pycache__", "build", "dist",
        ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache", "third_party", "vendor",
    }
)

_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))

# Very common method names: never use them for "unique method name" heuristic edges.
COMMON_METHOD_NAMES = frozenset(
    {
        "get", "set", "put", "post", "delete", "patch", "update", "add", "remove", "pop", "append",
        "extend", "insert", "clear", "copy", "keys", "values", "items", "read", "write", "close",
        "open", "run", "start", "stop", "send", "recv", "join", "split", "strip", "format", "save",
        "load", "dump", "dumps", "loads", "execute", "commit", "rollback", "query", "filter", "all",
        "first", "one", "count", "exists", "create", "list", "find", "parse", "process", "handle",
        "call", "apply", "validate", "render", "encode", "decode", "lower", "upper", "replace",
        "sort", "index", "flush", "refresh", "connect", "fetch", "fetchone", "fetchall", "next",
        "info", "debug", "warning", "error", "exception", "log", "emit", "wait", "result", "cancel",
        "submit", "map", "reduce", "init", "setup", "teardown", "build", "compile", "check", "test",
    }
)

# Untrusted-input attributes on request-like objects (Flask, Django, FastAPI/Starlette).
SOURCE_ATTRS = frozenset(
    {
        "args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST",
        "FILES", "COOKIES", "META", "body", "query_params", "path_params", "get_json", "get_data",
        "stream", "query_string", "full_path", "path", "view_args", "raw_post_data",
    }
)
REQUEST_NAMES = frozenset({"request", "req", "flask.request"})

# Canonical dotted name -> sink kind.
EXACT_SINKS: dict[str, SinkKind] = {
    # command execution
    "os.system": SinkKind.COMMAND, "os.popen": SinkKind.COMMAND,
    "commands.getoutput": SinkKind.COMMAND, "asyncio.create_subprocess_shell": SinkKind.COMMAND,
    "asyncio.create_subprocess_exec": SinkKind.COMMAND,
    # code execution
    "eval": SinkKind.CODE_EXEC, "exec": SinkKind.CODE_EXEC, "compile": SinkKind.CODE_EXEC,
    "builtins.eval": SinkKind.CODE_EXEC, "builtins.exec": SinkKind.CODE_EXEC,
    "__import__": SinkKind.CODE_EXEC, "importlib.import_module": SinkKind.CODE_EXEC,
    # deserialization
    "pickle.loads": SinkKind.DESERIALIZATION, "pickle.load": SinkKind.DESERIALIZATION,
    "cPickle.loads": SinkKind.DESERIALIZATION, "cPickle.load": SinkKind.DESERIALIZATION,
    "dill.loads": SinkKind.DESERIALIZATION, "dill.load": SinkKind.DESERIALIZATION,
    "marshal.loads": SinkKind.DESERIALIZATION, "marshal.load": SinkKind.DESERIALIZATION,
    "shelve.open": SinkKind.DESERIALIZATION, "jsonpickle.decode": SinkKind.DESERIALIZATION,
    "yaml.load": SinkKind.DESERIALIZATION, "yaml.unsafe_load": SinkKind.DESERIALIZATION,
    "yaml.full_load": SinkKind.DESERIALIZATION, "pandas.read_pickle": SinkKind.DESERIALIZATION,
    "torch.load": SinkKind.DESERIALIZATION,
    # file system
    "open": SinkKind.FILE, "io.open": SinkKind.FILE, "os.remove": SinkKind.FILE,
    "os.unlink": SinkKind.FILE, "os.rmdir": SinkKind.FILE, "os.rename": SinkKind.FILE,
    "os.makedirs": SinkKind.FILE, "shutil.rmtree": SinkKind.FILE, "shutil.copy": SinkKind.FILE,
    "shutil.copyfile": SinkKind.FILE, "shutil.copytree": SinkKind.FILE,
    "shutil.move": SinkKind.FILE, "tarfile.open": SinkKind.FILE, "zipfile.ZipFile": SinkKind.FILE,
    "flask.send_file": SinkKind.FILE, "flask.send_from_directory": SinkKind.FILE,
    "fastapi.responses.FileResponse": SinkKind.FILE,
    "starlette.responses.FileResponse": SinkKind.FILE, "django.http.FileResponse": SinkKind.FILE,
    "pathlib.Path": SinkKind.FILE,
    # network (SSRF)
    "urllib.request.urlopen": SinkKind.NETWORK, "urllib.request.Request": SinkKind.NETWORK,
    "urllib.urlopen": SinkKind.NETWORK, "urllib2.urlopen": SinkKind.NETWORK,
    "aiohttp.request": SinkKind.NETWORK, "http.client.HTTPConnection": SinkKind.NETWORK,
    "http.client.HTTPSConnection": SinkKind.NETWORK, "socket.create_connection": SinkKind.NETWORK,
    # templates / XSS / SSTI
    "flask.render_template_string": SinkKind.TEMPLATE, "jinja2.Template": SinkKind.TEMPLATE,
    "markupsafe.Markup": SinkKind.TEMPLATE, "flask.Markup": SinkKind.TEMPLATE,
    "django.utils.safestring.mark_safe": SinkKind.TEMPLATE,
    "django.utils.html.format_html": SinkKind.TEMPLATE,
    "fastapi.responses.HTMLResponse": SinkKind.TEMPLATE,
    # open redirect
    "flask.redirect": SinkKind.REDIRECT, "django.shortcuts.redirect": SinkKind.REDIRECT,
    "django.http.HttpResponseRedirect": SinkKind.REDIRECT,
    "fastapi.responses.RedirectResponse": SinkKind.REDIRECT,
    "starlette.responses.RedirectResponse": SinkKind.REDIRECT,
    # SQL
    "sqlalchemy.text": SinkKind.SQL, "sqlalchemy.sql.text": SinkKind.SQL,
}
PREFIX_SINKS: tuple[tuple[str, SinkKind], ...] = (
    ("subprocess.", SinkKind.COMMAND),
    ("os.exec", SinkKind.COMMAND),
    ("os.spawn", SinkKind.COMMAND),
    ("pty.spawn", SinkKind.COMMAND),
)
HTTP_CLIENT_MODULES = ("requests", "httpx", "aiohttp", "urllib3")
HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request",
                        "stream", "urlopen", "ws_connect"})
SQL_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "mogrify",
                         "exec_driver_sql", "fetch", "fetchrow", "fetchval"})
ORM_METHODS = frozenset({"query", "filter_by", "get_or_404", "first_or_404", "extra"})
SHELL_ALWAYS = frozenset({"os.system", "os.popen", "subprocess.getoutput",
                          "subprocess.getstatusoutput", "commands.getoutput",
                          "asyncio.create_subprocess_shell"})

# Route decorators: @app.get("/x"), @router.post(...), @app.route("/x", methods=[...]) ...
ROUTE_DECORATOR_ATTRS = frozenset({"get", "post", "put", "patch", "delete", "head", "options",
                                   "trace", "route", "api_route", "websocket"})
DJANGO_VIEW_BASE_SUFFIXES = ("View", "APIView", "ViewSet", "ViewSetMixin", "GenericAPIView")
DJANGO_VIEW_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options",
                                 "list", "create", "retrieve", "update", "partial_update",
                                 "destroy", "dispatch"})
TASK_DECORATORS = frozenset({"task", "shared_task", "periodic_task", "actor"})
CLI_DECORATORS = frozenset({"command", "group"})
DEPENDS_NAMES = frozenset({"Depends", "Security"})

SECRET_NAME_RE = re.compile(
    r"(passw(or)?d|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"
    r"access[_-]?token|refresh[_-]?token|bearer|private[_-]?key|client[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|webhook[_-]?secret|db[_-]?pass|credentials?|token)$",
    re.IGNORECASE,
)
SECRET_NAME_EXCLUDE_RE = re.compile(
    r"(_url|_uri|_path|_file|_name|_field|_header|_env|_var|_key_name|_prefix|_type|_length|"
    r"_len|_id_field|_param|_regex|_pattern|_template|_format)$",
    re.IGNORECASE,
)
SECRET_PLACEHOLDER_RE = re.compile(
    r"(change[_-]?me|example|placeholder|dummy|your[_-]|<[^>]+>|\$\{|\{\{|xxxx|\*\*\*\*|todo|"
    r"redacted|insert|replace|fake|test|sample|none|null)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
     Severity.CRITICAL),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"), Severity.CRITICAL),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"), Severity.HIGH),
    ("NVIDIA API key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{40,}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
     Severity.CRITICAL),
)

_FUNC_NAME_RE = re.compile(r"^_{0,2}[a-z][a-z0-9_]*_{0,2}$|^__[a-z][a-z0-9_]*__$")
_CLASS_NAME_RE = re.compile(r"^_?[A-Z][A-Za-z0-9]*$")
_NAMING_EXEMPT_FUNCS = frozenset({"setUp", "tearDown", "setUpClass", "tearDownClass",
                                  "asyncSetUp", "asyncTearDown", "setUpModule", "tearDownModule"})
_NAMING_EXEMPT_PREFIXES = ("visit_", "depart_", "leave_", "do_", "test")
_DIRECTIVE_COMMENT_RE = re.compile(
    r"^#\s*(noqa|type:|pragma|pylint:|fmt:|isort:|mypy:|ruff:|-\*-|!|nosec)", re.IGNORECASE
)

_NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith,
                  ast.Match) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())
_DEF_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


# --------------------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class CallSite:
    """A call expression inside a symbol, kept unresolved until the graph is built.

    ``parts`` is the dotted chain of the callee, e.g. ``("self", "repo", "get")``.
    Special heads: ``<super>`` for ``super().m()``, ``<call>`` when the receiver is the
    result of another call (that inner chain is in ``receiver_call``), ``<expr>`` when
    the receiver is any other expression (subscript, literal ...).
    """

    parts: tuple[str, ...]
    lineno: int
    receiver_call: tuple[str, ...] | None = None
    implicit: bool = False  # e.g. FastAPI Depends(fn): the framework calls fn
    tainted_args: bool = False  # an argument derives from a parameter / untrusted source


@dataclass(slots=True)
class SinkSite:
    kind: SinkKind
    call: str  # canonical dotted name, e.g. "subprocess.run" or "cursor.execute"
    lineno: int
    tainted: bool  # an argument derives from a parameter or an untrusted source
    direct_source: bool  # an argument derives from request data / route params in this function
    tainted_by: list[str] = field(default_factory=list)
    unsafe_construction: bool = False  # f-string / % / + / .format() string building

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "call": self.call,
            "lineno": self.lineno,
            "tainted": self.tainted,
            "direct_source": self.direct_source,
            "tainted_by": self.tainted_by,
            "unsafe_construction": self.unsafe_construction,
        }


@dataclass(slots=True)
class StaticFinding:
    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    message: str
    file_path: str
    line: int
    end_line: int
    cwe: str | None = None
    symbol: str | None = None  # qualname inside the file (node id once the graph is built)
    remediation: str | None = None
    taint_flow: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "cwe": self.cwe,
            "symbol": self.symbol,
            "remediation": self.remediation,
            "taint_flow": self.taint_flow,
        }

    def to_annotation(self) -> dict[str, Any]:
        """GitHub Checks API annotation payload."""
        if self.category is FindingCategory.SECURITY and self.severity.blocks_merge:
            level = "failure"
        elif self.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM) or (
            self.category is FindingCategory.SECURITY
        ):
            level = "warning"
        else:
            level = "notice"
        prefix = f"[{self.severity.value}{' ' + self.cwe if self.cwe else ''}] "
        message = self.message
        if self.remediation:
            message = f"{message}\n\nFix: {self.remediation}"
        return {
            "path": self.file_path,
            "start_line": max(1, self.line),
            "end_line": max(1, self.end_line, self.line),
            "annotation_level": level,
            "title": (prefix + self.title)[:255],
            "message": message[:64_000],
        }


@dataclass(slots=True)
class SymbolInfo:
    qualname: str
    name: str
    kind: SymbolKind
    file_path: str
    lineno: int  # line of `def` / `class`
    end_lineno: int
    decorator_lineno: int  # first decorator line (== lineno without decorators)
    docstring: str | None = None
    source_code: str = ""
    parent_class: str | None = None  # qualname of the enclosing class (methods only)
    enclosing_function: str | None = None  # qualname of the enclosing function (nested defs)
    decorators: list[str] = field(default_factory=list)
    bases: list[tuple[str, ...]] = field(default_factory=list)  # classes only (raw dotted)
    params: list[str] = field(default_factory=list)
    params_total: int = 0
    params_annotated: int = 0
    returns_counted: bool = False
    returns_annotated: bool = False
    return_annotation: tuple[str, ...] | None = None
    cyclomatic_complexity: int = 1
    max_nesting: int = 0
    is_entry_point: bool = False
    framework: str | None = None  # fastapi|flask|django|drf|celery|cli|lambda|script
    route_path: str | None = None
    http_methods: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)  # FastAPI Depends(...) targets
    sources: list[str] = field(default_factory=list)
    sinks: list[SinkSite] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    local_types: dict[str, tuple[str, ...]] = field(default_factory=dict)
    self_attr_types: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mutable_defaults: int = 0
    is_static_or_class_method: bool = False
    node_id: str = ""  # assigned by ProjectGraph.rebuild()

    @property
    def length(self) -> int:
        return self.end_lineno - self.lineno + 1

    @property
    def is_function(self) -> bool:
        return self.kind in (SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION, SymbolKind.METHOD,
                             SymbolKind.ASYNC_METHOD)

    @property
    def is_public(self) -> bool:
        return not self.name.startswith("_")

    @property
    def is_dunder(self) -> bool:
        return self.name.startswith("__") and self.name.endswith("__")

    @property
    def requires_docstring(self) -> bool:
        """PEP 257: public modules-level functions, classes and methods should be documented."""
        if self.kind is SymbolKind.MODULE or self.enclosing_function is not None:
            return False
        return self.is_public and not self.is_dunder

    @property
    def type_hint_coverage(self) -> float:
        total = self.params_total + (1 if self.returns_counted else 0)
        if not self.is_function or total == 0:
            return 1.0
        return (self.params_annotated + (1 if self.returns_annotated else 0)) / total

    @property
    def has_type_hints(self) -> bool:
        return self.type_hint_coverage >= 0.999

    def contains_line(self, line: int) -> bool:
        return self.decorator_lineno <= line <= self.end_lineno

    def intersects(self, lines: set[int]) -> bool:
        return any(self.decorator_lineno <= ln <= self.end_lineno for ln in lines)

    def to_record(self, module: str) -> dict[str, Any]:
        """Dict matching :class:`app.models.CodeSymbol` columns (minus repository_id)."""
        return {
            "node_id": self.node_id,
            "module": module,
            "qualname": self.qualname,
            "symbol_name": self.name,
            "kind": self.kind,
            "file_path": self.file_path,
            "lineno": self.lineno,
            "end_lineno": self.end_lineno,
            "docstring": self.docstring,
            "has_type_hints": self.has_type_hints,
            "type_hint_coverage": round(self.type_hint_coverage, 4),
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "max_nesting": self.max_nesting,
            "source_code": self.source_code[:MAX_SOURCE_CHARS],
            "is_entry_point": self.is_entry_point,
            "route_path": self.route_path,
            "http_methods": list(self.http_methods),
            "sinks": [s.to_dict() for s in self.sinks],
            "sources": list(self.sources),
        }


@dataclass(slots=True)
class ImportBinding:
    """``alias`` in a module is bound to ``module`` (and optionally ``name`` within it)."""

    alias: str
    module: str  # absolute dotted module, or "" for a pure relative "from . import x"
    name: str | None
    level: int
    lineno: int


@dataclass(slots=True)
class UrlPattern:
    route: str
    view: tuple[str, ...]
    lineno: int


@dataclass(slots=True)
class ParsedFile:
    path: str
    source: str
    sha256: str
    is_package: bool
    symbols: dict[str, SymbolInfo] = field(default_factory=dict)
    imports: list[ImportBinding] = field(default_factory=list)
    star_imports: list[ImportBinding] = field(default_factory=list)
    url_patterns: list[UrlPattern] = field(default_factory=list)
    findings: list[StaticFinding] = field(default_factory=list)
    syntax_error: str | None = None
    comment_lines: frozenset[int] = frozenset()
    code_lines: frozenset[int] = frozenset()
    long_lines: frozenset[int] = frozenset()
    line_count: int = 0
    module: str = ""  # assigned by ProjectGraph.rebuild()

    def innermost_symbol(self, line: int) -> SymbolInfo | None:
        best: SymbolInfo | None = None
        for sym in self.symbols.values():
            if sym.kind is SymbolKind.MODULE or not sym.contains_line(line):
                continue
            if best is None or sym.length < best.length:
                best = sym
        return best or self.symbols.get(MODULE_QUALNAME)


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def decode_source(data: bytes) -> str:
    """Decode Python source honoring PEP 263 coding cookies; never raises."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except SyntaxError:
        encoding = "utf-8"
    try:
        return data.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="replace")


def is_analyzable_path(path: str) -> bool:
    """True for project ``.py`` files (skips virtualenvs, vendored code, build outputs)."""
    p = PurePosixPath(path)
    if p.suffix != ".py":
        return False
    return not any(part in EXCLUDED_DIR_PARTS or part.endswith(".egg-info") for part in p.parts)


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines_from_patch(patch: str | None) -> set[int]:
    """Return the new-file line numbers added/modified by a unified diff hunk set.

    Works on the ``patch`` field returned by GitHub's compare / pull files APIs. Pure
    deletions mark the line where the deletion happened so the surrounding symbol is
    still considered touched.
    """
    lines: set[int] = set()
    if not patch:
        return lines
    new_line = 0
    for raw in patch.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if new_line == 0 or raw.startswith("\\"):
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            lines.add(max(1, new_line))
        else:
            new_line += 1
    return lines


def _dotted(node: ast.AST) -> tuple[str, ...] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "super":
            parts.append("<super>")
        else:
            parts.append("<call>")
    elif parts:
        parts.append("<expr>")
    else:
        return None
    return tuple(reversed(parts))


def _innermost_call(node: ast.AST) -> ast.Call | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def _annotation_parts(node: ast.AST | None) -> tuple[str, ...] | None:
    """Best-effort class reference from an annotation (handles Optional/Annotated/|/strings)."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return _annotation_parts(ast.parse(node.value, mode="eval").body)
        except SyntaxError:
            return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        for side in (node.left, node.right):
            if not (isinstance(side, ast.Constant) and side.value is None):
                return _annotation_parts(side)
        return None
    if isinstance(node, ast.Subscript):
        head = _dotted(node.value)
        if head and head[-1] in {"Optional", "Annotated", "Union", "Type", "type"}:
            inner = node.slice
            if isinstance(inner, ast.Tuple) and inner.elts:
                inner = inner.elts[0]
            return _annotation_parts(inner)
        return None
    if isinstance(node, ast.Name | ast.Attribute):
        parts = _dotted(node)
        if parts and parts[0] not in ("<call>", "<expr>", "<super>"):
            return parts
    return None


def _target_names(target: ast.AST) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Tuple | ast.List):
        for elt in target.elts:
            yield from _target_names(elt)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_literal(node: ast.AST) -> bool:
    """A value fully known at parse time (no variables)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def _is_dynamic_string(node: ast.AST, dynamic_names: set[str]) -> bool:
    """True if ``node`` builds a string from runtime values (f-string, %, +, .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod) and _const_str(node.left) is not None:
            return not _is_literal(node.right)
        if isinstance(node.op, ast.Add):
            left_s = _const_str(node.left) is not None or isinstance(node.left, ast.JoinedStr)
            right_s = _const_str(node.right) is not None or isinstance(node.right, ast.JoinedStr)
            if left_s or right_s or _is_dynamic_string(node.left, dynamic_names) or \
                    _is_dynamic_string(node.right, dynamic_names):
                return not (_is_literal(node.left) and _is_literal(node.right))
        return False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and _const_str(node.func.value) is not None:
            return bool(node.args or node.keywords)
        if node.func.attr == "join" and _const_str(node.func.value) is not None:
            return bool(node.args) and not _is_literal(node.args[0])
    if isinstance(node, ast.Name):
        return node.id in dynamic_names
    return False


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _mask(secret: str) -> str:
    return secret[:4] + "…" + ("*" * 4) if len(secret) > 8 else "****"


def _iter_own_nodes(root: ast.AST) -> Iterator[ast.AST]:
    """Walk ``root``'s body without descending into nested function/class definitions."""
    stack: list[ast.AST] = []
    if isinstance(root, ast.Module):
        stack.extend(reversed(root.body))
    elif isinstance(root, _DEF_NODES):
        stack.extend(reversed(root.body))
    else:
        stack.append(root)
    while stack:
        node = stack.pop()
        if isinstance(node, _DEF_NODES):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _cyclomatic_complexity(root: ast.AST) -> int:
    cc = 1
    for node in _iter_own_nodes(root):
        if isinstance(node, ast.For | ast.AsyncFor | ast.While):
            cc += 2 if node.orelse else 1
        elif isinstance(node, ast.If | ast.IfExp | ast.ExceptHandler | ast.Assert |
                        ast.match_case):
            cc += 1
        elif isinstance(node, ast.BoolOp):
            cc += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            cc += 1 + len(node.ifs)
    return cc


def _max_nesting(stmts: list[ast.stmt], depth: int = 0) -> int:
    best = depth
    for stmt in stmts:
        if isinstance(stmt, _DEF_NODES) or not isinstance(stmt, _NESTING_NODES):
            continue
        if isinstance(stmt, ast.If):
            best = max(best, _max_nesting(stmt.body, depth + 1))
            if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
                best = max(best, _max_nesting(stmt.orelse, depth))  # elif: same level
            else:
                best = max(best, _max_nesting(stmt.orelse, depth + 1))
        elif isinstance(stmt, ast.Match):
            for case in stmt.cases:
                best = max(best, _max_nesting(case.body, depth + 1))
        elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            for body in (stmt.body, stmt.orelse, stmt.finalbody):
                best = max(best, _max_nesting(body, depth + 1))
            for handler in stmt.handlers:
                best = max(best, _max_nesting(handler.body, depth + 1))
        else:  # loops / with
            best = max(best, _max_nesting(stmt.body, depth + 1))
            best = max(best, _max_nesting(getattr(stmt, "orelse", []), depth + 1))
    return best


def _scan_tokens(source: str) -> tuple[frozenset[int], frozenset[int]]:
    """Return (documentation comment lines, code lines) using the tokenizer."""
    comments: set[int] = set()
    code: set[int] = set()
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
            tokenize.ENCODING, tokenize.ENDMARKER}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                if not _DIRECTIVE_COMMENT_RE.match(tok.string) and len(tok.string.strip("# ")) > 1:
                    comments.add(tok.start[0])
            elif tok.type not in skip:
                code.update(range(tok.start[0], tok.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return frozenset(comments), frozenset(code)


# --------------------------------------------------------------------------------------
# Per-symbol body scanner (calls, sinks, taint, findings)
# --------------------------------------------------------------------------------------


class _FileContext:
    """Per-file state shared by every body scanner."""

    def __init__(self, path: str, source: str, lines: list[str]) -> None:
        self.path = path
        self.source = source
        self.lines = lines
        self.aliases: dict[str, str] = {}  # local alias -> absolute dotted name (level-0 only)
        self.findings: list[StaticFinding] = []
        self._seen: set[tuple[str, int]] = set()

    def canonical(self, parts: tuple[str, ...]) -> str:
        head = parts[0]
        resolved = self.aliases.get(head, head)
        return ".".join((resolved, *parts[1:]))

    def add(self, finding: StaticFinding) -> None:
        key = (finding.rule_id, finding.line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)


class _BodyScanner(ast.NodeVisitor):
    """Scans one symbol's own body in source order with lightweight forward taint."""

    def __init__(self, ctx: _FileContext, symbol: SymbolInfo, tainted: dict[str, set[str]]) -> None:
        self.ctx = ctx
        self.sym = symbol
        self.tainted = tainted  # name -> origins ("param:x", "source:request.args", ...)
        self.dynamic_strings: set[str] = set()
        self.sources: set[str] = set()

    # ---- scope boundaries -------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # nested defs scanned separately
        return

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def scan(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit(stmt)
        self.sym.sources = sorted(self.sources)

    # ---- taint helpers ----------------------------------------------------------------
    def _source_label(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Attribute):
            parts = _dotted(node)
            if not parts:
                return None
            for i in range(len(parts) - 1):
                head = parts[: i + 1]
                if head == ("self", "request") or (
                    len(head) == 1 and (head[0] in REQUEST_NAMES or
                                        self.ctx.aliases.get(head[0]) == "flask.request")
                ):
                    if parts[i + 1] in SOURCE_ATTRS:
                        return "source:" + ".".join(parts[: i + 2])
            if self.ctx.canonical(parts) == "sys.argv":
                return "source:sys.argv"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "input":
            return "source:input()"
        return None

    def _expr_taint(self, expr: ast.AST | None) -> set[str]:
        origins: set[str] = set()
        if expr is None:
            return origins
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                origins |= self.tainted.get(node.id, set())
            else:
                label = self._source_label(node)
                if label:
                    origins.add(label)
                    self.sources.add(label.removeprefix("source:"))
        return origins

    def _bind(self, target: ast.AST, origins: set[str], value: ast.AST | None) -> None:
        dynamic = value is not None and _is_dynamic_string(value, self.dynamic_strings)
        for name in _target_names(target):
            if origins:
                self.tainted[name] = set(origins)
            else:
                self.tainted.pop(name, None)
            if dynamic:
                self.dynamic_strings.add(name)
            else:
                self.dynamic_strings.discard(name)
        # self.x = ... inside methods -> attribute type inference
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                and target.value.id == "self" and isinstance(value, ast.Call):
            parts = _dotted(value.func)
            if parts and parts[0] not in ("<call>", "<expr>", "<super>"):
                self.sym.self_attr_types[target.attr] = parts
        if isinstance(target, ast.Name) and isinstance(value, ast.Call):
            parts = _dotted(value.func)
            if parts and parts[0] not in ("<call>", "<expr>", "<super>"):
                self.sym.local_types[target.id] = parts

    # ---- statements ---------------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        origins = self._expr_taint(node.value)
        for target in node.targets:
            self._bind(target, origins, node.value)
            if not isinstance(target, ast.Name):
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        origins = self._expr_taint(node.value)
        self._bind(node.target, origins, node.value)
        ann = _annotation_parts(node.annotation)
        if ann:
            if isinstance(node.target, ast.Name):
                self.sym.local_types[node.target.id] = ann
            elif (isinstance(node.target, ast.Attribute)
                  and isinstance(node.target.value, ast.Name)
                  and node.target.value.id == "self"):
                self.sym.self_attr_types[node.target.attr] = ann

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        origins = self._expr_taint(node.value)
        for name in _target_names(node.target):
            if origins:
                self.tainted.setdefault(name, set()).update(origins)
            if isinstance(node.op, ast.Add) and not _is_literal(node.value):
                self.dynamic_strings.add(name)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind(node.target, self._expr_taint(node.value), node.value)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._bind(node.target, self._expr_taint(node.iter), None)
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, self._expr_taint(item.context_expr),
                           item.context_expr)
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        body = node.body
        if node.type is None:
            self.ctx.add(StaticFinding(
                rule_id="PY-QUAL-006", category=FindingCategory.QUALITY, severity=Severity.MEDIUM,
                title="Bare `except:` clause",
                message="A bare `except:` also catches SystemExit/KeyboardInterrupt and hides "
                        "real errors.",
                remediation="Catch the specific exception types you expect (e.g. "
                            "`except ValueError:`), or at least `except Exception:`.",
                file_path=self.ctx.path, line=node.lineno, end_line=node.lineno,
                cwe="CWE-396", symbol=self.sym.qualname,
            ))
        if all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and
                                           isinstance(s.value, ast.Constant)) or
               isinstance(s, ast.Continue) for s in body):
            self.ctx.add(StaticFinding(
                rule_id="PY-QUAL-007", category=FindingCategory.QUALITY, severity=Severity.LOW,
                title="Exception silently swallowed",
                message="The exception handler does nothing, so failures disappear without a "
                        "trace.",
                remediation="Log the exception, re-raise it, or handle it explicitly.",
                file_path=self.ctx.path, line=node.lineno, end_line=body[-1].end_lineno or
                node.lineno, cwe="CWE-390", symbol=self.sym.qualname,
            ))
        self.generic_visit(node)

    # ---- calls --------------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        parts = _dotted(node.func)
        if parts:
            receiver = None
            if parts[0] == "<call>":
                inner = _innermost_call(node.func.value) if isinstance(node.func,
                                                                       ast.Attribute) else None
                if inner is not None:
                    receiver = _dotted(inner.func)
            tainted_args = any(self._expr_taint(a) for a in
                               [*node.args, *(kw.value for kw in node.keywords)])
            self.sym.calls.append(CallSite(parts=parts, lineno=node.lineno,
                                           receiver_call=receiver, tainted_args=tainted_args))
            self._check_call(node, parts)
        self.generic_visit(node)

    def _receiver_type(self, parts: tuple[str, ...]) -> str | None:
        """Canonical type name of the receiver for chains like ``session.get(...)``."""
        if len(parts) < 2:
            return None
        if parts[0] in self.sym.local_types:
            return self.ctx.canonical(self.sym.local_types[parts[0]])
        if parts[0] == "self" and len(parts) >= 3 and parts[1] in self.sym.self_attr_types:
            return self.ctx.canonical(self.sym.self_attr_types[parts[1]])
        return None

    def _classify_sink(self, parts: tuple[str, ...], canonical: str) -> SinkKind | None:
        if canonical in EXACT_SINKS:
            return EXACT_SINKS[canonical]
        for prefix, kind in PREFIX_SINKS:
            if canonical.startswith(prefix):
                return kind
        method = parts[-1]
        root = canonical.split(".", 1)[0]
        if root in HTTP_CLIENT_MODULES and method in HTTP_VERBS:
            return SinkKind.NETWORK
        recv_type = self._receiver_type(parts)
        if recv_type and recv_type.split(".", 1)[0] in HTTP_CLIENT_MODULES and method in HTTP_VERBS:
            return SinkKind.NETWORK
        if len(parts) >= 2 and method in SQL_METHODS:
            return SinkKind.SQL
        if len(parts) >= 2 and (method in ORM_METHODS or
                                (len(parts) >= 3 and parts[-2] == "objects" and
                                 method in {"get", "filter", "raw", "extra"})):
            return SinkKind.DB_ORM
        return None

    def _finding(self, rule_id: str, severity: Severity, cwe: str, title: str, message: str,
                 remediation: str, node: ast.AST) -> None:
        self.ctx.add(StaticFinding(
            rule_id=rule_id, category=FindingCategory.SECURITY, severity=severity, title=title,
            message=message, remediation=remediation, file_path=self.ctx.path,
            line=node.lineno, end_line=getattr(node, "end_lineno", None) or node.lineno,
            cwe=cwe, symbol=self.sym.qualname,
        ))

    def _check_call(self, node: ast.Call, parts: tuple[str, ...]) -> None:
        canonical = self.ctx.canonical(parts)
        first = node.args[0] if node.args else None
        if first is None:
            for name in ("args", "cmd", "url", "sql", "statement", "query", "file", "path",
                         "source", "location", "data"):
                first = _kw(node, name)
                if first is not None:
                    break
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        origins: set[str] = set()
        for arg in all_args:
            origins |= self._expr_taint(arg)
        first_origins = self._expr_taint(first) if first is not None else set()
        direct = any(o.startswith("source:") for o in first_origins or origins)
        dynamic_first = first is not None and not _is_literal(first)
        unsafe_build = first is not None and _is_dynamic_string(first, self.dynamic_strings)
        # os.path.join(base, user_value) / Path(base) / user_value are classic traversal shapes
        joined_path = isinstance(first, ast.Call) and (_dotted(first.func) or ("",))[-1] in {
            "join", "joinpath"} or (isinstance(first, ast.BinOp) and
                                    isinstance(first.op, ast.Div))

        kind = self._classify_sink(parts, canonical)
        if kind is not None:
            self.sym.sinks.append(SinkSite(
                kind=kind, call=canonical, lineno=node.lineno, tainted=bool(first_origins or
                                                                            origins),
                direct_source=direct, tainted_by=sorted(first_origins or origins),
                unsafe_construction=unsafe_build,
            ))
        method = parts[-1]
        where = f"`{canonical}()`"

        # -- code execution ----------------------------------------------------------------
        if kind is SinkKind.CODE_EXEC and canonical in {"eval", "exec", "builtins.eval",
                                                         "builtins.exec"}:
            sev = Severity.CRITICAL if direct else (Severity.HIGH if dynamic_first else
                                                    Severity.LOW)
            self._finding("PY-SEC-001", sev, "CWE-95", f"Dynamic code execution via {where}",
                          f"{where} executes arbitrary Python"
                          + (" built from untrusted request data." if direct else "."),
                          "Use `ast.literal_eval` for literals or an explicit dispatch table.",
                          node)

        # -- OS command injection ------------------------------------------------------------
        elif kind is SinkKind.COMMAND:
            shell = canonical in SHELL_ALWAYS or _is_true(_kw(node, "shell"))
            if shell and dynamic_first:
                sev = Severity.CRITICAL if direct else Severity.HIGH
                self._finding("PY-SEC-002", sev, "CWE-78",
                              f"Shell command built from variables in {where}",
                              f"{where} runs through a shell with a non-constant command"
                              + (" derived from request input" if direct else "")
                              + "; metacharacters like `;`, `|` or `$()` allow command injection.",
                              "Pass an argument list with `shell=False` and validate inputs "
                              "(`shlex.quote` only as a last resort).", node)
            elif shell:
                self._finding("PY-SEC-002", Severity.LOW, "CWE-78", f"Shell invocation in {where}",
                              f"{where} spawns a shell. Constant today, injection-prone tomorrow.",
                              "Prefer `subprocess.run([...], shell=False)`.", node)
            elif first_origins and dynamic_first:
                self._finding("PY-SEC-002", Severity.MEDIUM if direct else Severity.LOW, "CWE-88",
                              f"Process arguments from caller input in {where}",
                              f"{where} receives arguments derived from "
                              f"{', '.join(sorted(first_origins))}; option injection is possible.",
                              "Allow-list the executable and arguments; separate options with "
                              "`--`.", node)

        # -- SQL injection -----------------------------------------------------------------
        elif kind is SinkKind.SQL and unsafe_build:
            sev = Severity.CRITICAL if direct else Severity.HIGH
            self._finding("PY-SEC-003", sev, "CWE-89",
                          f"SQL built with string formatting in {where}",
                          "The SQL statement is assembled with an f-string / % / + / .format() "
                          "instead of bound parameters"
                          + (" and contains request data." if direct else "."),
                          "Use parameterized queries: `cursor.execute(\"... WHERE id = %s\", "
                          "(user_id,))` or SQLAlchemy `text(...).bindparams(...)`.", node)

        # -- deserialization -----------------------------------------------------------------
        elif kind is SinkKind.DESERIALIZATION:
            if canonical == "yaml.load":
                loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
                loader_parts = _dotted(loader) if loader is not None else None
                if not loader_parts or loader_parts[-1] not in {"SafeLoader", "CSafeLoader",
                                                                "BaseLoader"}:
                    self._finding("PY-SEC-005", Severity.HIGH if direct else Severity.MEDIUM,
                                  "CWE-502", "`yaml.load` without SafeLoader",
                                  "`yaml.load` with the default/full loader can instantiate "
                                  "arbitrary Python objects.",
                                  "Use `yaml.safe_load(...)`.", node)
            elif canonical in {"shelve.open", "torch.load"} and not first_origins:
                pass
            else:
                sev = Severity.CRITICAL if direct else (Severity.HIGH if first_origins else
                                                        Severity.MEDIUM)
                self._finding("PY-SEC-005", sev, "CWE-502", f"Unsafe deserialization via {where}",
                              f"{where} can execute code when fed attacker-controlled bytes.",
                              "Use a data-only format (JSON) or sign & verify payloads first.",
                              node)

        # -- path traversal ----------------------------------------------------------------
        elif kind is SinkKind.FILE and first_origins and dynamic_first and (
            direct or unsafe_build or joined_path
        ):
            sev = Severity.HIGH if direct else Severity.MEDIUM
            self._finding("PY-SEC-009", sev, "CWE-22", f"File path from caller input in {where}",
                          f"The path passed to {where} derives from "
                          f"{', '.join(sorted(first_origins))}; `../` sequences can escape the "
                          "intended directory.",
                          "Resolve the path and verify it stays under an allowed base directory "
                          "(`Path(base, name).resolve().is_relative_to(base)`), or use "
                          "`werkzeug.utils.secure_filename`.", node)

        # -- SSRF -----------------------------------------------------------------------------
        elif kind is SinkKind.NETWORK and first_origins and dynamic_first and (
            direct or unsafe_build
        ):
            sev = Severity.HIGH if direct else Severity.MEDIUM
            self._finding("PY-SEC-010", sev, "CWE-918",
                          "Outbound request to caller-controlled URL "
                          f"in {where}",
                          f"The URL passed to {where} derives from "
                          f"{', '.join(sorted(first_origins))}; attackers can reach internal "
                          "services (e.g. cloud metadata at 169.254.169.254).",
                          "Allow-list hosts/schemes and block private address ranges before "
                          "requesting.", node)

        # -- SSTI / XSS -------------------------------------------------------------------------
        elif kind is SinkKind.TEMPLATE and dynamic_first:
            sev = Severity.CRITICAL if direct else (Severity.HIGH if first_origins else
                                                    Severity.MEDIUM)
            cwe = "CWE-1336" if "Template" in canonical or "template_string" in canonical \
                else "CWE-79"
            self._finding("PY-SEC-012", sev, cwe, f"Untrusted content rendered by {where}",
                          f"{where} renders a non-constant template/markup; this enables "
                          "template injection or XSS.",
                          "Render a static template and pass user data as context variables "
                          "(auto-escaped).", node)

        # -- open redirect -----------------------------------------------------------------
        elif kind is SinkKind.REDIRECT and direct:
            self._finding("PY-SEC-013", Severity.MEDIUM, "CWE-601", f"Open redirect via {where}",
                          "The redirect target comes straight from the request.",
                          "Only redirect to relative paths or an allow-list of hosts.", node)

        # -- TLS verification disabled ----------------------------------------------------
        if _is_false(_kw(node, "verify")) and (kind is SinkKind.NETWORK or
                                               canonical.split(".", 1)[0] in HTTP_CLIENT_MODULES):
            self._finding("PY-SEC-006", Severity.MEDIUM, "CWE-295", "TLS certificate verification "
                          "disabled", f"{where} is called with `verify=False`, enabling MITM.",
                          "Remove `verify=False`; pin a CA bundle if you use a private CA.", node)

        # -- debug mode in production servers ------------------------------------------------
        if method == "run" and _is_true(_kw(node, "debug")):
            self._finding("PY-SEC-007", Severity.MEDIUM, "CWE-489", "Debug mode enabled",
                          "`debug=True` exposes an interactive debugger / stack traces that can "
                          "lead to remote code execution.",
                          "Drive debug mode from configuration and keep it off in production.",
                          node)

        # -- weak hashes -------------------------------------------------------------------
        weak = canonical in {"hashlib.md5", "hashlib.sha1"} or (
            canonical == "hashlib.new" and (_const_str(first) or "").lower() in {"md5", "sha1"}
        )
        if weak and not _is_false(_kw(node, "usedforsecurity")):
            self._finding("PY-SEC-008", Severity.LOW, "CWE-328", f"Weak hash function {where}",
                          "MD5/SHA-1 are broken for security purposes (passwords, signatures, "
                          "tokens).",
                          "Use `hashlib.sha256`, or `bcrypt`/`argon2` for passwords. Pass "
                          "`usedforsecurity=False` for non-security checksums.", node)

        # -- JWT verification disabled -------------------------------------------------------
        if canonical.endswith("jwt.decode"):
            options = _kw(node, "options")
            no_verify = _is_false(_kw(node, "verify"))
            if isinstance(options, ast.Dict):
                for k, v in zip(options.keys, options.values, strict=False):
                    if _const_str(k) == "verify_signature" and _is_false(v):
                        no_verify = True
            algs = _kw(node, "algorithms")
            if isinstance(algs, ast.List | ast.Tuple) and any(
                (_const_str(e) or "").lower() == "none" for e in algs.elts
            ):
                no_verify = True
            if no_verify:
                self._finding("PY-SEC-011", Severity.HIGH, "CWE-347", "JWT signature not verified",
                              "Tokens are decoded without verifying the signature, so anyone can "
                              "forge identities.",
                              "Always verify: `jwt.decode(token, key, algorithms=[\"HS256\"])`.",
                              node)

        # -- insecure temp files ------------------------------------------------------------
        if canonical == "tempfile.mktemp":
            self._finding("PY-SEC-014", Severity.LOW, "CWE-377", "Insecure temporary file",
                          "`tempfile.mktemp` is race-prone (TOCTOU).",
                          "Use `tempfile.NamedTemporaryFile` or `mkstemp`.", node)


# --------------------------------------------------------------------------------------
# File parser
# --------------------------------------------------------------------------------------


class _FileParser:
    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source.replace("\r\n", "\n").replace("\r", "\n")
        self.lines = self.source.split("\n")
        self.ctx = _FileContext(path, self.source, self.lines)
        self.is_package = PurePosixPath(path).name == "__init__.py"
        self.pf = ParsedFile(
            path=path, source=self.source,
            sha256=hashlib.sha256(self.source.encode("utf-8", "replace")).hexdigest(),
            is_package=self.is_package, line_count=len(self.lines),
        )

    # ------------------------------------------------------------------------------------
    def parse(self) -> ParsedFile:
        pf = self.pf
        comments, code = _scan_tokens(self.source)
        pf.comment_lines, pf.code_lines = comments, code
        pf.long_lines = frozenset(i + 1 for i, line in enumerate(self.lines)
                                  if len(line) > LINE_LENGTH_LIMIT)
        try:
            tree = ast.parse(self.source, filename=self.path)
        except (SyntaxError, ValueError) as exc:
            line = getattr(exc, "lineno", None) or 1
            pf.syntax_error = f"{type(exc).__name__}: {exc}"
            pf.findings.append(StaticFinding(
                rule_id="PY-QUAL-000", category=FindingCategory.QUALITY, severity=Severity.MEDIUM,
                title="File does not parse", message=pf.syntax_error, file_path=self.path,
                line=line, end_line=line,
                remediation="Fix the syntax error; the file cannot be analyzed or imported.",
            ))
            return pf
        except (RecursionError, MemoryError) as exc:
            pf.syntax_error = f"{type(exc).__name__}: file too deeply nested to analyze"
            return pf

        try:
            self._collect_imports(tree)
            self._module_symbol(tree)
            self._walk_defs(tree.body, prefix="", parent_class=None, enclosing_function=None)
            self._module_level_checks(tree)
            self._scan_secrets(tree)
        except RecursionError:
            pf.syntax_error = "RecursionError: file too deeply nested to analyze"
        pf.findings.extend(self.ctx.findings)
        self._quality_findings()
        return pf

    # ------------------------------------------------------------------------------------
    def _collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        binding = ImportBinding(alias.asname, alias.name, None, 0, node.lineno)
                        self.ctx.aliases[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".", 1)[0]
                        binding = ImportBinding(top, top, None, 0, node.lineno)
                        self.ctx.aliases.setdefault(top, top)
                        if "." in alias.name:  # `import a.b` also makes a.b importable as edge
                            self.pf.imports.append(
                                ImportBinding(f"<import:{alias.name}>", alias.name, None, 0,
                                              node.lineno))
                    self.pf.imports.append(binding)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        self.pf.star_imports.append(
                            ImportBinding("*", module, None, node.level, node.lineno))
                        continue
                    local = alias.asname or alias.name
                    self.pf.imports.append(
                        ImportBinding(local, module, alias.name, node.level, node.lineno))
                    if node.level == 0:
                        self.ctx.aliases[local] = f"{module}.{alias.name}" if module else alias.name

    def _source_segment(self, start: int, end: int) -> str:
        return "\n".join(self.lines[start - 1:end])

    def _module_symbol(self, tree: ast.Module) -> None:
        sym = SymbolInfo(
            qualname=MODULE_QUALNAME, name=PurePosixPath(self.path).stem, kind=SymbolKind.MODULE,
            file_path=self.path, lineno=1, end_lineno=max(1, len(self.lines)), decorator_lineno=1,
            docstring=ast.get_docstring(tree),
        )
        sym.cyclomatic_complexity = _cyclomatic_complexity(tree)
        sym.max_nesting = _max_nesting(tree.body)
        scanner = _BodyScanner(self.ctx, sym, tainted={})
        scanner.scan([s for s in tree.body if not isinstance(s, _DEF_NODES)])
        # `if __name__ == "__main__":` makes the module itself an entry point
        for stmt in tree.body:
            if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Compare):
                left = stmt.test.left
                if isinstance(left, ast.Name) and left.id == "__name__":
                    sym.is_entry_point, sym.framework = True, "script"
        # Django urls.py: path("route/", views.fn) / re_path / url
        if PurePosixPath(self.path).name == "urls.py":
            self._collect_url_patterns(tree)
        self.pf.symbols[MODULE_QUALNAME] = sym

    def _collect_url_patterns(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and len(node.args) >= 2):
                continue
            func = _dotted(node.func)
            if not func or func[-1] not in {"path", "re_path", "url"}:
                continue
            route = _const_str(node.args[0])
            view = node.args[1]
            if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) \
                    and view.func.attr == "as_view":
                view = view.func.value
            parts = _dotted(view) if isinstance(view, ast.Name | ast.Attribute) else None
            if route is not None and parts:
                self.pf.url_patterns.append(UrlPattern(route=route, view=parts, lineno=node.lineno))

    # ------------------------------------------------------------------------------------
    def _unique_qualname(self, qualname: str, lineno: int) -> str:
        return qualname if qualname not in self.pf.symbols else f"{qualname}@{lineno}"

    def _walk_defs(self, body: list[ast.stmt], prefix: str, parent_class: str | None,
                   enclosing_function: str | None) -> None:
        for stmt in body:
            if isinstance(stmt, ast.ClassDef):
                self._class(stmt, prefix, enclosing_function)
            elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                self._function(stmt, prefix, parent_class, enclosing_function)
            elif isinstance(stmt, ast.If | ast.Try | ast.With | ast.AsyncWith | ast.For |
                            ast.While) or type(stmt).__name__ == "TryStar":
                # defs guarded by `if TYPE_CHECKING:` / try-import fallbacks still count
                for sub in ("body", "orelse", "finalbody"):
                    self._walk_defs(getattr(stmt, sub, []) or [], prefix, parent_class,
                                    enclosing_function)
                for handler in getattr(stmt, "handlers", []) or []:
                    self._walk_defs(handler.body, prefix, parent_class, enclosing_function)

    def _class(self, node: ast.ClassDef, prefix: str, enclosing_function: str | None) -> None:
        qual = self._unique_qualname(f"{prefix}{node.name}", node.lineno)
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or node.lineno
        sym = SymbolInfo(
            qualname=qual, name=node.name, kind=SymbolKind.CLASS, file_path=self.path,
            lineno=node.lineno, end_lineno=end, decorator_lineno=start,
            docstring=ast.get_docstring(node), source_code=self._source_segment(start, end),
            enclosing_function=enclosing_function,
            decorators=[ast.unparse(d) for d in node.decorator_list],
            bases=[p for b in node.bases if (p := _dotted(b)) and p[0] not in ("<call>", "<expr>")],
        )
        sym.cyclomatic_complexity = _cyclomatic_complexity(node)
        for stmt in node.body:  # class-level annotations: `repo: UserRepo`
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                ann = _annotation_parts(stmt.annotation)
                if ann:
                    sym.self_attr_types[stmt.target.id] = ann
        _BodyScanner(self.ctx, sym, tainted={}).scan(
            [s for s in node.body if not isinstance(s, _DEF_NODES)])
        is_django_view = any(b[-1].endswith(DJANGO_VIEW_BASE_SUFFIXES) for b in sym.bases)
        if is_django_view:
            sym.framework = "django"
        self.pf.symbols[qual] = sym
        self._walk_defs(node.body, prefix=f"{qual}.", parent_class=qual,
                        enclosing_function=enclosing_function)
        if is_django_view:
            for child in self.pf.symbols.values():
                if child.parent_class == qual and child.name in DJANGO_VIEW_METHODS:
                    child.is_entry_point = True
                    child.framework = "django"
                    child.http_methods = [child.name.upper()] if child.name in HTTP_VERBS else []

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str,
                  parent_class: str | None, enclosing_function: str | None) -> None:
        is_async = isinstance(node, ast.AsyncFunctionDef)
        if parent_class is not None:
            kind = SymbolKind.ASYNC_METHOD if is_async else SymbolKind.METHOD
        else:
            kind = SymbolKind.ASYNC_FUNCTION if is_async else SymbolKind.FUNCTION
        qual = self._unique_qualname(f"{prefix}{node.name}", node.lineno)
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or node.lineno
        decorators = [ast.unparse(d) for d in node.decorator_list]
        sym = SymbolInfo(
            qualname=qual, name=node.name, kind=kind, file_path=self.path, lineno=node.lineno,
            end_lineno=end, decorator_lineno=start, docstring=ast.get_docstring(node),
            source_code=self._source_segment(start, end), parent_class=parent_class,
            enclosing_function=enclosing_function, decorators=decorators,
        )
        sym.is_static_or_class_method = any(d in ("staticmethod", "classmethod")
                                            for d in decorators)
        is_static = "staticmethod" in decorators

        # ---- parameters & type hints ------------------------------------------------------
        args = node.args
        positional = args.posonlyargs + args.args
        all_args = positional + args.kwonlyargs + [a for a in (args.vararg, args.kwarg) if a]
        skip_first = parent_class is not None and not is_static and positional
        counted = [a for i, a in enumerate(all_args) if not (skip_first and a is positional[0])]
        sym.params = [a.arg for a in all_args]
        sym.params_total = len(counted)
        sym.params_annotated = sum(1 for a in counted if a.annotation is not None)
        sym.returns_counted = node.name != "__init__"
        sym.returns_annotated = node.returns is not None
        sym.return_annotation = _annotation_parts(node.returns)
        for a in counted:
            ann = _annotation_parts(a.annotation)
            if ann:
                sym.local_types[a.arg] = ann
        defaults = list(args.defaults) + [d for d in args.kw_defaults if d is not None]
        sym.mutable_defaults = sum(
            1 for d in defaults
            if isinstance(d, ast.List | ast.Dict | ast.Set | ast.ListComp | ast.DictComp)
            or (isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                and d.func.id in {"list", "dict", "set", "defaultdict"})
        )

        # ---- entry points -----------------------------------------------------------------
        self._detect_entry_point(sym, node)

        # FastAPI dependencies: `user = Depends(get_current_user)` -> implicit call edge
        default_by_arg: dict[str, ast.AST] = {}
        for a, d in zip(positional[len(positional) - len(args.defaults):], args.defaults,
                        strict=False):
            default_by_arg[a.arg] = d
        for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=False):
            if d is not None:
                default_by_arg[a.arg] = d
        depends_args: set[str] = set()
        for a in all_args:
            candidates = [default_by_arg.get(a.arg)]
            if isinstance(a.annotation, ast.Subscript):  # Annotated[User, Depends(fn)]
                sl = a.annotation.slice
                candidates.extend(sl.elts if isinstance(sl, ast.Tuple) else [sl])
            for cand in candidates:
                if isinstance(cand, ast.Call) and (p := _dotted(cand.func)) and \
                        p[-1] in DEPENDS_NAMES:
                    depends_args.add(a.arg)
                    if cand.args and (dep := _dotted(cand.args[0])):
                        sym.dependencies.append(".".join(dep))
                        sym.calls.append(CallSite(parts=dep, lineno=cand.lineno, implicit=True))

        # ---- initial taint: every param is caller-controlled; route params are sources ------
        tainted: dict[str, set[str]] = {}
        for i, a in enumerate(all_args):
            if (skip_first and a is positional[0]) or a.arg in depends_args:
                continue
            origin = f"param:{a.arg}"
            if sym.is_entry_point and sym.framework in {"fastapi", "flask", "django", "drf",
                                                        "lambda"}:
                if sym.framework == "django" and i == (1 if skip_first else 0) \
                        and a.arg == "request":
                    continue  # the request object itself; its attributes are sources
                ann = _annotation_parts(a.annotation)
                if ann and ann[-1] in {"Request", "WebSocket", "HttpRequest", "Session",
                                       "AsyncSession", "BackgroundTasks", "Response"}:
                    continue
                origin = f"source:route_param:{a.arg}"
            tainted[a.arg] = {origin}

        scanner = _BodyScanner(self.ctx, sym, tainted=tainted)
        scanner.scan(node.body)
        for origins in tainted.values():
            for o in origins:
                if o.startswith("source:route_param:"):
                    sym.sources.append(o.removeprefix("source:"))
        sym.sources = sorted(set(sym.sources))
        sym.cyclomatic_complexity = _cyclomatic_complexity(node)
        sym.max_nesting = _max_nesting(node.body)

        self.pf.symbols[qual] = sym
        self._walk_defs(node.body, prefix=f"{qual}.", parent_class=None,
                        enclosing_function=qual)

    def _detect_entry_point(self, sym: SymbolInfo, node: ast.FunctionDef | ast.AsyncFunctionDef
                            ) -> None:
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            parts = _dotted(call.func if call else dec)
            if not parts:
                continue
            attr = parts[-1]
            if call is not None and attr in ROUTE_DECORATOR_ATTRS and len(parts) >= 2:
                route = _const_str(call.args[0]) if call.args else None
                route = route or _const_str(_kw(call, "path")) or _const_str(_kw(call, "rule"))
                if route is None and attr != "route":
                    continue
                sym.is_entry_point = True
                sym.route_path = route
                if attr in {"route", "api_route"}:
                    methods = _kw(call, "methods")
                    if isinstance(methods, ast.List | ast.Tuple | ast.Set):
                        sym.http_methods = [m.upper() for e in methods.elts
                                            if (m := _const_str(e))]
                    else:
                        sym.http_methods = ["GET"]
                    sym.framework = "flask" if attr == "route" else "fastapi"
                elif attr == "websocket":
                    sym.http_methods = ["WS"]
                    sym.framework = "fastapi"
                else:
                    sym.http_methods = [attr.upper()]
                    root = self.ctx.canonical(parts[:1])
                    sym.framework = "flask" if "flask" in root.lower() or parts[0] in {"bp",
                                                                                      "blueprint"} \
                        else "fastapi"
                return
            if attr == "api_view":  # DRF function views
                sym.is_entry_point, sym.framework = True, "drf"
                if call and call.args and isinstance(call.args[0], ast.List | ast.Tuple):
                    sym.http_methods = [m.upper() for e in call.args[0].elts
                                        if (m := _const_str(e))]
                return
            if attr in TASK_DECORATORS:
                sym.is_entry_point, sym.framework = True, "celery"
                return
            if attr in CLI_DECORATORS and parts[0] in {"click", "cli", "app", "typer"}:
                sym.is_entry_point, sym.framework = True, "cli"
                return
        args = [a.arg for a in node.args.args]
        if sym.parent_class is None and PurePosixPath(self.path).name == "views.py" \
                and args[:1] == ["request"]:
            sym.is_entry_point, sym.framework = True, "django"
        elif args == ["event", "context"] and sym.parent_class is None:
            sym.is_entry_point, sym.framework = True, "lambda"

    # ------------------------------------------------------------------------------------
    def _module_level_checks(self, tree: ast.Module) -> None:
        for star in self.pf.star_imports:
            self.ctx.add(StaticFinding(
                rule_id="PY-QUAL-012", category=FindingCategory.QUALITY, severity=Severity.LOW,
                title="Wildcard import", file_path=self.path, line=star.lineno,
                end_line=star.lineno,
                message=f"`from {'.' * star.level}{star.module} import *` pollutes the namespace "
                        "and hides where names come from.",
                remediation="Import the names you use explicitly.",
            ))
        if PurePosixPath(self.path).name in {"settings.py", "config.py"}:
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and _is_true(stmt.value) and any(
                    isinstance(t, ast.Name) and t.id == "DEBUG" for t in stmt.targets
                ):
                    self.ctx.add(StaticFinding(
                        rule_id="PY-SEC-007", category=FindingCategory.SECURITY,
                        severity=Severity.MEDIUM, cwe="CWE-489", title="DEBUG = True in settings",
                        message="Debug mode leaks stack traces, settings and SQL to visitors.",
                        remediation="Read DEBUG from the environment and default it to False.",
                        file_path=self.path, line=stmt.lineno, end_line=stmt.lineno,
                    ))

    def _scan_secrets(self, tree: ast.Module) -> None:
        def report(name: str, value: str, node: ast.AST, sev: Severity, label: str) -> None:
            sym = self.pf.innermost_symbol(node.lineno)
            self.ctx.add(StaticFinding(
                rule_id="PY-SEC-004", category=FindingCategory.SECURITY, severity=sev,
                cwe="CWE-798", title=f"Hardcoded {label}",
                message=f"`{name}` contains a hardcoded {label} ({_mask(value)}). Anyone with "
                        "repo access (or a leaked clone) can use it.",
                remediation="Load it from the environment / a secrets manager and rotate the "
                            "exposed value now.",
                file_path=self.path, line=node.lineno,
                end_line=getattr(node, "end_lineno", None) or node.lineno,
                symbol=sym.qualname if sym else None,
            ))

        def check_named(name: str, value_node: ast.AST, node: ast.AST) -> None:
            value = _const_str(value_node)
            if value is None or not SECRET_NAME_RE.search(name) or \
                    SECRET_NAME_EXCLUDE_RE.search(name):
                return
            if len(value) < 8 or any(ch.isspace() for ch in value) or \
                    SECRET_PLACEHOLDER_RE.search(value) or _shannon_entropy(value) < 2.5:
                return
            if value.isupper() and value.replace("_", "").isalpha():  # an env var NAME
                return
            report(name, value, node, Severity.HIGH, "secret")

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = target.id if isinstance(target, ast.Name) else (
                        target.attr if isinstance(target, ast.Attribute) else None)
                    if name:
                        check_named(name, node.value, node)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                target = node.target
                name = target.id if isinstance(target, ast.Name) else (
                    target.attr if isinstance(target, ast.Attribute) else None)
                if name:
                    check_named(name, node.value, node)
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg:
                        check_named(kw.arg, kw.value, kw.value)
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values, strict=False):
                    if (key := _const_str(k)) is not None:
                        check_named(key, v, v)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and len(node.value) >= 20:
                for label, pattern, sev in SECRET_VALUE_PATTERNS:
                    if m := pattern.search(node.value):
                        report("string literal", m.group(0), node, sev, label)
                        break

    # ------------------------------------------------------------------------------------
    def _quality_findings(self) -> None:
        add = self.pf.findings.append
        for sym in self.pf.symbols.values():
            if sym.kind is SymbolKind.MODULE:
                continue
            def mk(rule: str, sev: Severity, title: str, msg: str, fix: str, *, s: SymbolInfo = sym
                   ) -> StaticFinding:
                return StaticFinding(rule_id=rule, category=FindingCategory.QUALITY, severity=sev,
                                     title=title, message=msg, remediation=fix,
                                     file_path=self.path, line=s.lineno, end_line=s.lineno,
                                     symbol=s.qualname)

            label = f"`{sym.qualname}`"
            if sym.requires_docstring and not sym.docstring:
                add(mk("PY-QUAL-001", Severity.LOW, f"Missing docstring on {label}",
                       f"Public {sym.kind.value.replace('_', ' ')} {label} has no docstring.",
                       "Add a docstring describing purpose, parameters, return value and raised "
                       "errors."))
            if sym.is_function:
                missing = (sym.params_total - sym.params_annotated) + (
                    1 if sym.returns_counted and not sym.returns_annotated else 0)
                if missing:
                    add(mk("PY-QUAL-002", Severity.INFO, f"Missing type hints on {label}",
                           f"{missing} parameter/return annotation(s) missing "
                           f"({sym.type_hint_coverage:.0%} coverage).",
                           "Annotate every parameter and the return type."))
                if sym.cyclomatic_complexity > COMPLEXITY_LIMIT:
                    sev = Severity.MEDIUM if sym.cyclomatic_complexity > 2 * COMPLEXITY_LIMIT \
                        else Severity.LOW
                    add(mk("PY-QUAL-003", sev, f"High cyclomatic complexity in {label}",
                           f"Complexity {sym.cyclomatic_complexity} exceeds {COMPLEXITY_LIMIT}.",
                           "Split into smaller functions; replace branch ladders with lookup "
                           "tables or early returns."))
                if sym.max_nesting > NESTING_LIMIT:
                    add(mk("PY-QUAL-004", Severity.LOW, f"Deeply nested logic in {label}",
                           f"Branches/loops nest {sym.max_nesting} levels deep "
                           f"(limit {NESTING_LIMIT}).",
                           "Use guard clauses / early returns and extract inner blocks."))
                if sym.length > FUNCTION_LENGTH_LIMIT:
                    add(mk("PY-QUAL-005", Severity.LOW, f"Long function {label}",
                           f"{sym.length} lines (limit {FUNCTION_LENGTH_LIMIT}).",
                           "Extract cohesive steps into well-named helpers."))
                if sym.mutable_defaults:
                    add(mk("PY-QUAL-008", Severity.MEDIUM, f"Mutable default argument in {label}",
                           "Mutable defaults are shared between calls and leak state.",
                           "Default to `None` and create the object inside the function."))
                if sym.params_total > PARAM_LIMIT:
                    add(mk("PY-QUAL-011", Severity.INFO, f"Too many parameters in {label}",
                           f"{sym.params_total} parameters (limit {PARAM_LIMIT}).",
                           "Group related parameters into a dataclass / config object."))
            if _naming_violation(sym):
                add(mk("PY-QUAL-009", Severity.INFO, f"PEP 8 naming: {label}",
                       "Functions/methods should be snake_case and classes CapWords (PEP 8).",
                       "Rename to follow PEP 8 naming conventions."))
        if self.pf.long_lines:
            first = min(self.pf.long_lines)
            add(StaticFinding(
                rule_id="PY-QUAL-010", category=FindingCategory.QUALITY, severity=Severity.INFO,
                title="Lines exceed PEP 8 length", file_path=self.path, line=first,
                end_line=first,
                message=f"{len(self.pf.long_lines)} line(s) longer than {LINE_LENGTH_LIMIT} chars "
                        f"(first at line {first}).",
                remediation="Wrap long expressions or run a formatter such as `ruff format`.",
            ))


def _naming_violation(sym: SymbolInfo) -> bool:
    name = sym.name
    if sym.kind is SymbolKind.CLASS:
        return not _CLASS_NAME_RE.match(name)
    if not sym.is_function or name in _NAMING_EXEMPT_FUNCS or \
            name.startswith(_NAMING_EXEMPT_PREFIXES):
        return False
    return not _FUNC_NAME_RE.match(name)


def parse_python_file(path: str, source: str) -> ParsedFile:
    """Parse a single Python file into a :class:`ParsedFile` (never raises on bad input)."""
    return _FileParser(path, source).parse()


# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class BlastRadius:
    seeds: list[str]
    upstream: dict[str, int]  # node_id -> hop distance
    downstream: dict[str, int]
    edges: list[dict[str, Any]]
    entry_points: list[str]
    sinks: list[dict[str, Any]]
    taint_paths: list[dict[str, Any]]  # see ProjectGraph._describe_path
    impacted_files: list[str]
    dependent_modules: list[str]
    nodes: list[dict[str, Any]]

    @property
    def all_nodes(self) -> list[str]:
        return list(dict.fromkeys([*self.seeds, *self.upstream, *self.downstream]))

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form persisted on ``PushEvent.blast_radius`` for the viewer."""
        return {
            "seeds": self.seeds,
            "upstream": self.upstream,
            "downstream": self.downstream,
            "nodes": self.nodes,
            "edges": self.edges,
            "entry_points": self.entry_points,
            "sinks": self.sinks,
            "taint_paths": self.taint_paths,
            "impacted_files": self.impacted_files,
            "dependent_modules": self.dependent_modules,
        }


@dataclass(slots=True)
class QualityReport:
    graded_symbols: int
    documentable: int
    documented: int
    docstring_coverage: float
    params_total: int
    params_annotated: int
    returns_total: int
    returns_annotated: int
    type_hint_coverage: float
    comment_lines: int
    code_lines: int
    comment_density: float
    avg_complexity: float
    max_complexity: int
    long_functions: int
    deep_nesting: int
    long_lines: int
    naming_violations: int
    best_practice_violations: dict[str, int]
    docs_score: float  # 0-100
    readability_score: float  # 0-100
    type_hints_score: float  # 0-100
    per_symbol: list[dict[str, Any]]

    @property
    def craft_score(self) -> float:
        """0-300: docs/comments + readability/complexity + type hints/best practices."""
        return round(self.docs_score + self.readability_score + self.type_hints_score, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graded_symbols": self.graded_symbols,
            "documentable": self.documentable,
            "documented": self.documented,
            "docstring_coverage": round(self.docstring_coverage, 4),
            "params_total": self.params_total,
            "params_annotated": self.params_annotated,
            "returns_total": self.returns_total,
            "returns_annotated": self.returns_annotated,
            "type_hint_coverage": round(self.type_hint_coverage, 4),
            "comment_lines": self.comment_lines,
            "code_lines": self.code_lines,
            "comment_density": round(self.comment_density, 4),
            "avg_complexity": round(self.avg_complexity, 2),
            "max_complexity": self.max_complexity,
            "long_functions": self.long_functions,
            "deep_nesting": self.deep_nesting,
            "long_lines": self.long_lines,
            "naming_violations": self.naming_violations,
            "best_practice_violations": self.best_practice_violations,
            "docs_score": self.docs_score,
            "readability_score": self.readability_score,
            "type_hints_score": self.type_hints_score,
            "craft_score": self.craft_score,
            "per_symbol": self.per_symbol,
        }


# --------------------------------------------------------------------------------------
# Project graph
# --------------------------------------------------------------------------------------

# Resolved entity during chain walking: ("module", name) | ("node", node_id) | ("external", dotted)
_Entity = tuple[str, str]
ChangedLines = Mapping[str, set[int] | None]  # path -> changed new-file lines (None = whole file)

_CALL_EDGE_KINDS = frozenset({EdgeKind.CALL, EdgeKind.ROUTE})


class ProjectGraph:
    """Whole-repository symbol & dependency graph backed by ``networkx.MultiDiGraph``.

    Node ids are ``"<module>:<qualname>"`` (module nodes use ``<module>`` as qualname).
    Edge direction: caller -> callee, importer -> imported, subclass -> base. Edge keys
    are :class:`EdgeKind` values; attributes: ``file_path``, ``lineno``, ``confidence``.
    """

    def __init__(self, *, max_files: int = 5000, max_file_bytes: int = 1_000_000) -> None:
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.files: dict[str, ParsedFile] = {}
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self.skipped: dict[str, str] = {}  # path -> reason
        self._module_to_path: dict[str, str] = {}
        self._name_index: dict[str, list[str]] = {}  # full/short module name -> canonical names
        self._symbols: dict[str, SymbolInfo] = {}  # node_id -> info
        self._class_methods: dict[str, dict[str, str]] = {}  # class node -> name -> method node
        self._class_bases: dict[str, list[str]] = {}
        self._class_attr_types: dict[str, dict[str, tuple[str, ...]]] = {}
        self._methods_by_name: dict[str, list[str]] = {}
        self._binding_cache: dict[tuple[str, str], _Entity | None] = {}
        self._full_names: dict[str, str] = {}

    # ---- construction -----------------------------------------------------------------
    @classmethod
    def from_sources(cls, sources: Mapping[str, str], **kwargs: Any) -> ProjectGraph:
        graph = cls(**kwargs)
        graph.update_files(sources)
        return graph

    def update_files(self, changed: Mapping[str, str], removed: Iterable[str] = ()) -> list[str]:
        """Re-parse changed files, drop removed ones, then rebuild resolution.

        Returns the list of paths that were (re)parsed. Unchanged content is not re-parsed.
        """
        for path in removed:
            self.files.pop(path, None)
            self.skipped.pop(path, None)
        reparsed: list[str] = []
        for path in sorted(changed):
            source = changed[path]
            if not is_analyzable_path(path):
                continue
            if len(source.encode("utf-8", "replace")) > self.max_file_bytes:
                self.skipped[path] = "file too large"
                self.files.pop(path, None)
                continue
            if path not in self.files and len(self.files) >= self.max_files:
                self.skipped[path] = "max file count reached"
                continue
            digest = hashlib.sha256(
                source.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8", "replace")
            ).hexdigest()
            existing = self.files.get(path)
            if existing is not None and existing.sha256 == digest:
                continue
            self.files[path] = parse_python_file(path, source)
            self.skipped.pop(path, None)
            reparsed.append(path)
        self.rebuild()
        return reparsed

    # ---- module naming ------------------------------------------------------------------
    def _assign_module_names(self) -> None:
        paths = sorted(self.files)
        pkg_dirs = {str(PurePosixPath(p).parent) for p in paths
                    if PurePosixPath(p).name == "__init__.py"}
        full: dict[str, str] = {}
        short: dict[str, str] = {}
        for p in paths:
            pp = PurePosixPath(p)
            mod_parts = list(pp.with_suffix("").parts)
            if mod_parts and mod_parts[-1] == "__init__":
                mod_parts = mod_parts[:-1]
            dir_parts = pp.parent.parts if str(pp.parent) != "." else ()
            k = len(dir_parts)
            while k > 0 and "/".join(dir_parts[:k]) in pkg_dirs:
                k -= 1
            full[p] = ".".join(mod_parts) or "__root__"
            short[p] = ".".join(mod_parts[k:]) or full[p]
        short_counts = Counter(short.values())
        self._module_to_path.clear()
        self._name_index.clear()
        self._full_names = full
        for p in paths:
            canonical = short[p] if short_counts[short[p]] == 1 else full[p]
            self.files[p].module = canonical
            self._module_to_path[canonical] = p
            for name in {canonical, full[p], short[p]}:
                self._name_index.setdefault(name, [])
                if canonical not in self._name_index[name]:
                    self._name_index[name].append(canonical)

    def _lookup_module(self, name: str, from_module: str | None = None) -> str | None:
        cands = self._name_index.get(name)
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        if from_module is None:
            return sorted(cands, key=len)[0]
        from_full = self._full_names.get(self._module_to_path.get(from_module, ""), from_module)

        def shared_prefix(c: str) -> int:
            a = self._full_names.get(self._module_to_path[c], c).split(".")
            b = from_full.split(".")
            n = 0
            for x, y in zip(a, b, strict=False):
                if x != y:
                    break
                n += 1
            return n

        return max(cands, key=lambda c: (shared_prefix(c), -len(c)))

    def _package_of(self, pf: ParsedFile) -> str:
        return pf.module if pf.is_package else pf.module.rpartition(".")[0]

    def _absolute_module(self, pf: ParsedFile, binding: ImportBinding) -> str:
        if binding.level == 0:
            return binding.module
        base = self._package_of(pf).split(".") if self._package_of(pf) else []
        if binding.level > 1:
            base = base[: max(0, len(base) - (binding.level - 1))]
        if binding.module:
            base.append(binding.module)
        return ".".join(p for p in base if p)

    # ---- rebuild ------------------------------------------------------------------------
    def rebuild(self) -> None:
        """Assign module names / node ids and resolve all imports and calls into edges."""
        self._assign_module_names()
        g = nx.MultiDiGraph()
        self._symbols.clear()
        self._class_methods.clear()
        self._class_bases.clear()
        self._class_attr_types.clear()
        self._methods_by_name.clear()
        self._binding_cache.clear()

        for pf in self.files.values():
            for sym in pf.symbols.values():
                sym.node_id = f"{pf.module}:{sym.qualname}"
                self._symbols[sym.node_id] = sym
                g.add_node(sym.node_id, **self._node_attrs(pf, sym))
            for sym in pf.symbols.values():
                if sym.parent_class is not None:
                    cls_id = f"{pf.module}:{sym.parent_class}"
                    self._class_methods.setdefault(cls_id, {}).setdefault(sym.name, sym.node_id)
                    if not sym.is_dunder:
                        self._methods_by_name.setdefault(sym.name, []).append(sym.node_id)
                if sym.kind is SymbolKind.CLASS:
                    self._class_methods.setdefault(sym.node_id, {})
                    attrs = dict(sym.self_attr_types)
                    self._class_attr_types[sym.node_id] = attrs
            for sym in pf.symbols.values():  # self.x = Foo() assignments inside methods
                if sym.parent_class is not None and sym.self_attr_types:
                    cls_attrs = self._class_attr_types.setdefault(
                        f"{pf.module}:{sym.parent_class}", {})
                    for attr, parts in sym.self_attr_types.items():
                        cls_attrs.setdefault(attr, parts)
        self.graph = g

        # class bases (needed before resolving method calls through MRO)
        for pf in self.files.values():
            for sym in pf.symbols.values():
                if sym.kind is not SymbolKind.CLASS:
                    continue
                bases: list[str] = []
                for parts in sym.bases:
                    for target, _conf in self._resolve_chain(pf, sym, parts, constructor=False):
                        if self._symbols.get(target) and \
                                self._symbols[target].kind is SymbolKind.CLASS:
                            bases.append(target)
                            self._add_edge(sym.node_id, target, EdgeKind.INHERITS, pf.path,
                                           sym.lineno, 1.0)
                self._class_bases[sym.node_id] = bases

        for pf in self.files.values():
            module_node = f"{pf.module}:{MODULE_QUALNAME}"
            # import edges
            for binding in [*pf.imports, *pf.star_imports]:
                entity = self._resolve_import(pf, binding)
                if entity is None:
                    continue
                kind, value = entity
                if kind == "module":
                    target = f"{value}:{MODULE_QUALNAME}"
                elif kind == "node":
                    target = value
                    target_mod = value.split(":", 1)[0]
                    self._add_edge(module_node, f"{target_mod}:{MODULE_QUALNAME}",
                                   EdgeKind.IMPORT, pf.path, binding.lineno, 1.0)
                else:
                    continue
                if target != module_node:
                    self._add_edge(module_node, target, EdgeKind.IMPORT, pf.path,
                                   binding.lineno, 1.0)
            # call edges
            for sym in pf.symbols.values():
                for call in sym.calls:
                    for target, conf in self._resolve_call(pf, sym, call):
                        if target != sym.node_id or call.parts[-1] == sym.name:
                            self._add_edge(sym.node_id, target, EdgeKind.CALL, pf.path,
                                           call.lineno, conf, tainted=call.tainted_args)
            # Django URLConf -> views
            for pattern in pf.url_patterns:
                mod_sym = pf.symbols[MODULE_QUALNAME]
                for target, conf in self._resolve_chain(pf, mod_sym, pattern.view,
                                                        constructor=False):
                    view = self._symbols.get(target)
                    if view is None:
                        continue
                    targets = [target]
                    if view.kind is SymbolKind.CLASS:
                        targets += [m for name, m in self._class_methods.get(target, {}).items()
                                    if name in DJANGO_VIEW_METHODS]
                    for t in targets:
                        tv = self._symbols[t]
                        tv.is_entry_point = True
                        tv.framework = tv.framework or "django"
                        tv.route_path = tv.route_path or "/" + pattern.route.lstrip("^/")
                        g.nodes[t].update(self._node_attrs(self.files[tv.file_path], tv))
                        self._add_edge(module_node, t, EdgeKind.ROUTE, pf.path, pattern.lineno,
                                       conf, tainted=True)

        # attach symbol node ids to findings
        for pf in self.files.values():
            for finding in pf.findings:
                if finding.symbol and ":" not in finding.symbol:
                    finding.symbol = f"{pf.module}:{finding.symbol}"

    def _node_attrs(self, pf: ParsedFile, sym: SymbolInfo) -> dict[str, Any]:
        return {
            "module": pf.module,
            "qualname": sym.qualname,
            "name": sym.name,
            "kind": sym.kind.value,
            "file_path": pf.path,
            "lineno": sym.lineno,
            "end_lineno": sym.end_lineno,
            "is_entry_point": sym.is_entry_point,
            "framework": sym.framework,
            "route_path": sym.route_path,
            "http_methods": list(sym.http_methods),
            "sink_kinds": sorted({s.kind.value for s in sym.sinks}),
            "has_tainted_sink": any(s.tainted for s in sym.sinks),
            "sources": list(sym.sources),
        }

    def _add_edge(self, src: str, dst: str, kind: EdgeKind, path: str, lineno: int,
                  confidence: float, *, tainted: bool = False) -> None:
        if src not in self.graph or dst not in self.graph:
            return
        existing = self.graph.get_edge_data(src, dst, key=kind)
        if existing is not None:
            existing["confidence"] = max(existing["confidence"], confidence)
            existing["tainted_args"] = existing["tainted_args"] or tainted
            return
        self.graph.add_edge(src, dst, key=kind, kind=kind.value, file_path=path, lineno=lineno,
                            confidence=confidence, tainted_args=tainted)

    # ---- resolution ---------------------------------------------------------------------
    def _top_level(self, module: str, name: str) -> str | None:
        node = f"{module}:{name}"
        return node if node in self._symbols else None

    def _lookup_import(self, name: str, pf: ParsedFile, level: int) -> str | None:
        """Module lookup for an import; absolute stdlib names only match repo-root files."""
        if not name:
            return None
        mod = self._lookup_module(name, pf.module)
        if mod and level == 0 and name.split(".", 1)[0] in _STDLIB and \
                self._full_names.get(self._module_to_path[mod]) != name:
            return None  # `import json` is the stdlib, not some nested scripts/json.py
        return mod

    def _resolve_import(self, pf: ParsedFile, binding: ImportBinding) -> _Entity | None:
        absolute = self._absolute_module(pf, binding)
        if binding.name is None:
            mod = self._lookup_import(absolute, pf, binding.level)
            return ("module", mod) if mod else ("external", absolute)
        if binding.alias == "*":
            mod = self._lookup_import(absolute, pf, binding.level)
            return ("module", mod) if mod else None
        sub = self._lookup_import(f"{absolute}.{binding.name}" if absolute else binding.name,
                                  pf, binding.level)
        if sub:
            return ("module", sub)
        mod = self._lookup_import(absolute, pf, binding.level)
        if mod:
            return self._member(("module", mod), binding.name, depth=0) or \
                ("external", f"{absolute}.{binding.name}")
        return ("external", f"{absolute}.{binding.name}" if absolute else binding.name)

    def _binding(self, module: str, alias: str, depth: int = 0) -> _Entity | None:
        key = (module, alias)
        if key in self._binding_cache:
            return self._binding_cache[key]
        if depth > 6:
            return None
        self._binding_cache[key] = None  # cycle guard
        pf = self.files.get(self._module_to_path.get(module, ""))
        result: _Entity | None = None
        if pf is not None:
            for binding in reversed(pf.imports):  # last import wins
                if binding.alias == alias:
                    result = self._resolve_import(pf, binding)
                    break
            if result is None:
                for star in pf.star_imports:
                    star_mod = self._lookup_module(self._absolute_module(pf, star), module)
                    if star_mod and not alias.startswith("_"):
                        result = self._member(("module", star_mod), alias, depth + 1)
                        if result:
                            break
        self._binding_cache[key] = result
        return result

    def _member(self, entity: _Entity, name: str, depth: int) -> _Entity | None:
        kind, value = entity
        if kind == "external":
            return ("external", f"{value}.{name}")
        if kind == "module":
            sub = self._lookup_module(f"{value}.{name}", value)
            if sub:
                return ("module", sub)
            top = self._top_level(value, name)
            if top:
                return ("node", top)
            global_cls = self._module_global_type(value, name)
            if global_cls:  # `db = Database()` at module level, imported elsewhere
                return ("instance", global_cls)
            return self._binding(value, name, depth + 1)
        if kind == "instance":
            method = self._method_lookup(value, name)
            if method:
                return ("node", method)
            attr_type = self._class_attr_type(value, name)
            return ("instance", attr_type) if attr_type else None
        sym = self._symbols.get(value)
        if sym is None:
            return None
        if sym.kind is SymbolKind.CLASS:
            method = self._method_lookup(value, name)
            if method:
                return ("node", method)
            attr_type = self._class_attr_type(value, name)
            if attr_type:
                return ("instance", attr_type)
        return None

    def _module_global_type(self, module: str, name: str) -> str | None:
        pf = self.files.get(self._module_to_path.get(module, ""))
        if pf is None or MODULE_QUALNAME not in pf.symbols:
            return None
        module_sym = pf.symbols[MODULE_QUALNAME]
        parts = module_sym.local_types.get(name)
        if not parts or parts == (name,):
            return None
        return self._class_from_parts(pf, module_sym, parts)

    def _mro(self, class_id: str) -> list[str]:
        order: list[str] = []
        queue = deque([class_id])
        while queue and len(order) < 50:
            cid = queue.popleft()
            if cid in order:
                continue
            order.append(cid)
            queue.extend(self._class_bases.get(cid, []))
        return order

    def _method_lookup(self, class_id: str, name: str, *, skip_self: bool = False) -> str | None:
        for cid in self._mro(class_id)[1 if skip_self else 0:]:
            method = self._class_methods.get(cid, {}).get(name)
            if method:
                return method
        return None

    def _class_attr_type(self, class_id: str, attr: str) -> str | None:
        for cid in self._mro(class_id):
            parts = self._class_attr_types.get(cid, {}).get(attr)
            if parts:
                cls_sym = self._symbols[cid]
                pf = self.files[cls_sym.file_path]
                return self._class_from_parts(pf, cls_sym, parts)
        return None

    def _class_from_parts(self, pf: ParsedFile, sym: SymbolInfo, parts: tuple[str, ...]
                          ) -> str | None:
        """Resolve a type reference (annotation / constructor / factory call) to a class node."""
        for target, _ in self._resolve_chain(pf, sym, parts, constructor=False, _depth=1):
            return self._class_of(target)
        return None

    def _class_of(self, node_id: str) -> str | None:
        tsym = self._symbols.get(node_id)
        if tsym is None:
            return None
        if tsym.kind is SymbolKind.CLASS:
            return node_id
        if tsym.is_function and tsym.return_annotation:
            tpf = self.files[tsym.file_path]
            module_sym = tpf.symbols[MODULE_QUALNAME]
            for target, _ in self._resolve_chain(tpf, module_sym, tsym.return_annotation,
                                                 constructor=False, _depth=1):
                t = self._symbols.get(target)
                if t and t.kind is SymbolKind.CLASS:
                    return target
        return None

    def _enclosing_class(self, pf: ParsedFile, sym: SymbolInfo) -> str | None:
        if sym.parent_class:
            return f"{pf.module}:{sym.parent_class}"
        # nested function inside a method: walk up
        cur = sym
        while cur.enclosing_function:
            parent = pf.symbols.get(cur.enclosing_function)
            if parent is None:
                break
            if parent.parent_class:
                return f"{pf.module}:{parent.parent_class}"
            cur = parent
        return None

    def _local_def(self, pf: ParsedFile, sym: SymbolInfo, name: str) -> str | None:
        scope: str | None = sym.qualname if sym.is_function else None
        while scope:
            candidate = pf.symbols.get(f"{scope}.{name}")
            if candidate is not None and candidate.enclosing_function == scope:
                return candidate.node_id
            scope = pf.symbols[scope].enclosing_function if scope in pf.symbols else None
        return None

    def _local_type(self, pf: ParsedFile, sym: SymbolInfo, name: str) -> tuple[str, ...] | None:
        cur: SymbolInfo | None = sym
        while cur is not None:
            if name in cur.local_types:
                return cur.local_types[name]
            cur = pf.symbols.get(cur.enclosing_function) if cur.enclosing_function else None
        return None

    def _resolve_head(self, pf: ParsedFile, sym: SymbolInfo, head: str, depth: int
                      ) -> _Entity | None:
        local = self._local_def(pf, sym, head)
        if local:
            return ("node", local)
        if depth == 0:
            ltype = self._local_type(pf, sym, head)
            if ltype and ltype != (head,):
                cls = self._class_from_parts(pf, sym, ltype)
                if cls:
                    return ("instance", cls)
            global_cls = self._module_global_type(pf.module, head)
            if global_cls and self._top_level(pf.module, head) is None:
                return ("instance", global_cls)
        top = self._top_level(pf.module, head)
        if top:
            return ("node", top)
        bound = self._binding(pf.module, head)
        if bound:
            return bound
        return None

    def _resolve_chain(self, pf: ParsedFile, sym: SymbolInfo, parts: tuple[str, ...], *,
                       constructor: bool = True, _depth: int = 0) -> list[tuple[str, float]]:
        """Resolve a dotted callee chain to graph node ids with a confidence score."""
        if not parts or _depth > 3:
            return []
        head, rest = parts[0], list(parts[1:])
        confidence = 1.0
        entity: _Entity | None
        if head in ("self", "cls") and (cls := self._enclosing_class(pf, sym)):
            entity = ("instance", cls)
        elif head == "<super>" and (cls := self._enclosing_class(pf, sym)):
            if not rest:
                return []
            method = self._method_lookup(cls, rest[0], skip_self=True)
            if not method:
                return []
            entity, rest = ("node", method), rest[1:]
        elif head in ("<call>", "<expr>"):
            return []
        else:
            entity = self._resolve_head(pf, sym, head, _depth)
            if entity and entity[0] == "instance":
                confidence = INFERRED_CONFIDENCE
        if entity is None:
            return []

        for name in rest:
            nxt = self._member(entity, name, depth=0)
            if nxt is None:
                return []
            if nxt[0] == "instance":
                confidence = min(confidence, INFERRED_CONFIDENCE)
            entity = nxt
        kind, value = entity
        if kind != "node":
            return []
        target = self._symbols.get(value)
        if target is None:
            return []
        if target.kind is SymbolKind.CLASS and constructor:
            results = [(value, confidence)]
            init = self._method_lookup(value, "__init__")
            if init:
                results.append((init, confidence))
            return results
        return [(value, confidence)]

    def _resolve_call(self, pf: ParsedFile, sym: SymbolInfo, call: CallSite
                      ) -> list[tuple[str, float]]:
        parts = call.parts
        if parts[0] == "<call>" and call.receiver_call and len(parts) == 2:
            # Foo().bar() / get_repo().bar()  -> type of the inner call result
            for inner, _conf in self._resolve_chain(pf, sym, call.receiver_call,
                                                    constructor=False):
                cls = self._class_of(inner)
                if cls:
                    method = self._method_lookup(cls, parts[1])
                    if method:
                        return [(method, INFERRED_CONFIDENCE)]
        resolved = self._resolve_chain(pf, sym, parts)
        if resolved:
            return resolved
        # Heuristic: method name unique across the project and receiver is not an external lib
        method_name = parts[-1]
        if len(parts) >= 2 and method_name not in COMMON_METHOD_NAMES and len(method_name) > 3:
            head = parts[0]
            if head not in ("<call>", "<expr>", "self", "cls", "<super>"):
                bound = self._binding(pf.module, head)
                if bound and bound[0] == "external":
                    return []
            candidates = self._methods_by_name.get(method_name, [])
            if len(candidates) == 1:
                return [(candidates[0], HEURISTIC_CONFIDENCE)]
        return []

    # ---- queries ------------------------------------------------------------------------
    def symbol(self, node_id: str) -> SymbolInfo | None:
        return self._symbols.get(node_id)

    def module_for_path(self, path: str) -> str | None:
        pf = self.files.get(path)
        return pf.module if pf else None

    def symbols_in_file(self, path: str) -> list[SymbolInfo]:
        pf = self.files.get(path)
        return list(pf.symbols.values()) if pf else []

    def touched_symbols(self, changed: ChangedLines, *, innermost: bool = True
                        ) -> list[SymbolInfo]:
        """Symbols whose source range intersects the changed lines.

        With ``innermost=True`` a class is dropped when one of its methods is touched, and
        the module symbol is only included for changes outside any definition.
        """
        result: list[SymbolInfo] = []
        for path, lines in changed.items():
            pf = self.files.get(path)
            if pf is None:
                continue
            syms = [s for s in pf.symbols.values() if s.kind is not SymbolKind.MODULE]
            if lines is None:
                result.extend(syms)
                if MODULE_QUALNAME in pf.symbols:
                    result.append(pf.symbols[MODULE_QUALNAME])
                continue
            hit = [s for s in syms if s.intersects(lines)]
            if innermost:
                hit = [s for s in hit if not any(
                    o is not s and o.qualname.startswith(s.qualname + ".") and
                    o.intersects({ln for ln in lines if s.contains_line(ln)}) for o in hit
                )]
            outside = {ln for ln in lines if not any(s.contains_line(ln) for s in syms)}
            if outside and MODULE_QUALNAME in pf.symbols:
                hit.append(pf.symbols[MODULE_QUALNAME])
            result.extend(hit)
        return result

    def _call_view(self) -> nx.MultiDiGraph:
        return nx.subgraph_view(
            self.graph, filter_edge=lambda u, v, k: k in _CALL_EDGE_KINDS  # noqa: ARG005
        )

    @staticmethod
    def _bfs(graph: nx.MultiDiGraph, seeds: Iterable[str], hops: int, reverse: bool
             ) -> dict[str, int]:
        dist: dict[str, int] = {}
        frontier = deque((s, 0) for s in seeds)
        seen = set(s for s, _ in frontier)
        while frontier:
            node, d = frontier.popleft()
            if d >= hops:
                continue
            neighbours = graph.predecessors(node) if reverse else graph.successors(node)
            for nb in neighbours:
                if nb in seen:
                    continue
                seen.add(nb)
                dist[nb] = d + 1
                frontier.append((nb, d + 1))
        return dist

    def blast_radius(self, changed: ChangedLines, hops: int = 2, *, max_paths: int = 25
                     ) -> BlastRadius:
        """N-hop upstream (callers / entry points) and downstream (callees / sinks) slice."""
        seeds = [s.node_id for s in self.touched_symbols(changed) if s.node_id in self.graph]
        seed_set = set(seeds)
        view = self._call_view()
        upstream = {n: d for n, d in self._bfs(view, seeds, hops, reverse=True).items()
                    if n not in seed_set}
        downstream = {n: d for n, d in self._bfs(view, seeds, hops, reverse=False).items()
                      if n not in seed_set}
        slice_nodes = list(dict.fromkeys([*seeds, *upstream, *downstream]))
        slice_set = set(slice_nodes)

        entry_points = [n for n in slice_nodes
                        if (n in seed_set or n in upstream) and self._symbols[n].is_entry_point]
        sinks: list[dict[str, Any]] = []
        sink_nodes: list[str] = []
        for n in slice_nodes:
            if n in upstream and n not in downstream:
                continue
            sym = self._symbols[n]
            if sym.sinks:
                sink_nodes.append(n)
                for s in sym.sinks:
                    sinks.append({"node": n, "file_path": sym.file_path, **s.to_dict()})

        sub = view.subgraph(slice_set)
        raw_paths: list[tuple[str, ...]] = []
        seen_paths: set[tuple[str, ...]] = set()
        for entry in entry_points:
            for seed in seeds:
                try:
                    head = nx.shortest_path(sub, entry, seed)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                for sink in sink_nodes:
                    try:
                        tail = nx.shortest_path(sub, seed, sink)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
                    path = (*head, *tail[1:])
                    if len(set(path)) != len(path) or path in seen_paths:
                        continue  # cycles are not meaningful flows
                    seen_paths.add(path)
                    raw_paths.append(path)

        taint_paths = sorted((self._describe_path(p) for p in raw_paths),
                             key=lambda p: (not p["args_flow"], not p["sink_tainted"],
                                            len(p["nodes"])))[:max_paths]

        edges: list[dict[str, Any]] = []
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            if u in slice_set and v in slice_set and k in _CALL_EDGE_KINDS | {EdgeKind.INHERITS}:
                edges.append({"source": u, "target": v, "kind": data["kind"],
                              "lineno": data["lineno"], "confidence": data["confidence"]})

        changed_modules = {self.files[p].module for p in changed if p in self.files}
        dependent_modules = sorted({
            u.split(":", 1)[0]
            for m in changed_modules
            for u, _v, k in self.graph.in_edges(f"{m}:{MODULE_QUALNAME}", keys=True)
            if k == EdgeKind.IMPORT and u.split(":", 1)[0] not in changed_modules
        }) if changed_modules else []

        nodes = []
        for n in slice_nodes:
            sym = self._symbols[n]
            role = "seed" if n in seed_set else ("upstream" if n in upstream else "downstream")
            hop = 0 if role == "seed" else (upstream.get(n) if role == "upstream"
                                             else downstream.get(n))
            nodes.append({
                "id": n, "name": sym.name, "qualname": sym.qualname, "kind": sym.kind.value,
                "file_path": sym.file_path, "lineno": sym.lineno, "end_lineno": sym.end_lineno,
                "role": role, "hop": hop, "is_entry_point": sym.is_entry_point,
                "framework": sym.framework, "route_path": sym.route_path,
                "http_methods": sym.http_methods, "sources": sym.sources,
                "sinks": [s.to_dict() for s in sym.sinks],
            })

        return BlastRadius(
            seeds=seeds, upstream=upstream, downstream=downstream, edges=edges,
            entry_points=entry_points, sinks=sinks, taint_paths=taint_paths,
            impacted_files=sorted({self._symbols[n].file_path for n in slice_nodes}),
            dependent_modules=dependent_modules, nodes=nodes,
        )

    def _edge_tainted(self, u: str, v: str) -> bool:
        data = self.graph.get_edge_data(u, v) or {}
        return any(d.get("tainted_args") for k, d in data.items() if k in _CALL_EDGE_KINDS)

    def _describe_path(self, path: tuple[str, ...]) -> dict[str, Any]:
        """Annotate an entry -> ... -> sink path with whether caller-controlled data flows."""
        entry, sink = self._symbols[path[0]], self._symbols[path[-1]]
        args_flow = all(self._edge_tainted(u, v) for u, v in zip(path, path[1:], strict=False))
        return {
            "nodes": list(path),
            "files": [self._symbols[n].file_path for n in path],
            "cross_file": len({self._symbols[n].file_path for n in path}) > 1,
            "entry_route": " ".join(filter(None, [",".join(entry.http_methods),
                                                  entry.route_path])) or None,
            "entry_sources": list(entry.sources),
            "sink_kinds": sorted({s.kind.value for s in sink.sinks}),
            "sink_tainted": any(s.tainted for s in sink.sinks),
            "args_flow": args_flow and len(path) > 1,
        }

    def taint_flow_steps(self, nodes: list[str], sink: SinkSite | None = None
                         ) -> list[dict[str, Any]]:
        """Step list for ``Finding.taint_flow`` / the blast-radius viewer."""
        steps: list[dict[str, Any]] = []
        for i, n in enumerate(nodes):
            sym = self._symbols[n]
            role = "source" if i == 0 else ("sink" if i == len(nodes) - 1 else "propagator")
            line = sink.lineno if role == "sink" and sink else sym.lineno
            pf = self.files[sym.file_path]
            snippet = pf.source.split("\n")[line - 1].strip() if 0 < line <= pf.line_count else ""
            steps.append({"file": sym.file_path, "line": line, "symbol": n, "role": role,
                          "snippet": snippet[:300]})
        return steps

    _CROSS_FILE_SEVERITY: dict[SinkKind, tuple[Severity, str, str]] = {
        SinkKind.SQL: (Severity.HIGH, "CWE-89", "SQL injection"),
        SinkKind.COMMAND: (Severity.HIGH, "CWE-78", "OS command injection"),
        SinkKind.CODE_EXEC: (Severity.HIGH, "CWE-95", "Code injection"),
        SinkKind.DESERIALIZATION: (Severity.HIGH, "CWE-502", "Unsafe deserialization"),
        SinkKind.FILE: (Severity.MEDIUM, "CWE-22", "Path traversal"),
        SinkKind.NETWORK: (Severity.MEDIUM, "CWE-918", "Server-side request forgery"),
        SinkKind.TEMPLATE: (Severity.MEDIUM, "CWE-79", "Template injection / XSS"),
        SinkKind.REDIRECT: (Severity.LOW, "CWE-601", "Open redirect"),
        SinkKind.DB_ORM: (Severity.LOW, "CWE-639", "Possible IDOR"),
    }

    def cross_file_candidates(self, radius: BlastRadius) -> list[StaticFinding]:
        """Candidate vulnerabilities where request input flows across calls into a sink.

        These are deliberately *candidates*: the inter-procedural check is argument-level
        (every hop passes a parameter/source-derived argument), not value-precise, so the
        skeptic verifier must confirm them before they affect anyone's score.
        """
        existing = {(f.file_path, f.line) for pf in self.files.values() for f in pf.findings
                    if f.category is FindingCategory.SECURITY}
        out: list[StaticFinding] = []
        seen: set[tuple[str, int, SinkKind]] = set()
        for path in radius.taint_paths:
            if not (path["args_flow"] and path["sink_tainted"]):
                continue
            entry = self._symbols[path["nodes"][0]]
            if not entry.sources and entry.framework not in {"fastapi", "flask", "django", "drf"}:
                continue
            sink_sym = self._symbols[path["nodes"][-1]]
            for site in sink_sym.sinks:
                if not site.tainted:
                    continue
                key = (sink_sym.file_path, site.lineno, site.kind)
                if key in seen or (sink_sym.file_path, site.lineno) in existing:
                    continue
                if site.kind is SinkKind.SQL and not site.unsafe_construction:
                    continue  # parameterized query: driver escapes it
                seen.add(key)
                sev, cwe, label = self._CROSS_FILE_SEVERITY[site.kind]
                chain = " -> ".join(f"{self._symbols[n].qualname} ({self._symbols[n].file_path})"
                                    for n in path["nodes"])
                route = f" `{path['entry_route']}`" if path["entry_route"] else ""
                out.append(StaticFinding(
                    rule_id="PY-SEC-100", category=FindingCategory.SECURITY, severity=sev,
                    cwe=cwe, title=f"Cross-file {label}: request data reaches `{site.call}`",
                    message=f"Input received by entry point{route} flows through {chain} into "
                            f"`{site.call}` at {sink_sym.file_path}:{site.lineno} "
                            f"(tainted by {', '.join(site.tainted_by) or 'caller arguments'}).",
                    remediation="Validate/normalize the value at the entry point and use the "
                                "safe API at the sink (parameterized query, argument list, "
                                "allow-listed path/host).",
                    file_path=sink_sym.file_path, line=site.lineno, end_line=site.lineno,
                    symbol=sink_sym.node_id,
                    taint_flow=self.taint_flow_steps(path["nodes"], site),
                ))
        return out

    def slice_prompt_context(self, radius: BlastRadius, *, max_chars: int = 60_000,
                             max_symbol_chars: int = 6_000) -> str:
        """Render the slice's source code for the LLM, most relevant symbols first."""
        on_path = {n for p in radius.taint_paths for n in p["nodes"]}
        order = sorted(
            radius.all_nodes,
            key=lambda n: (
                0 if n in radius.seeds else (1 if n in on_path else 2),
                radius.upstream.get(n, radius.downstream.get(n, 0)),
            ),
        )
        chunks: list[str] = []
        used = 0
        for n in order:
            sym = self._symbols[n]
            if n in radius.seeds:
                role = "CHANGED"
            elif n in radius.upstream:
                role = f"UPSTREAM caller, hop {radius.upstream[n]}"
            else:
                role = f"DOWNSTREAM callee, hop {radius.downstream[n]}"
            tags = []
            if sym.is_entry_point:
                methods = ",".join(sym.http_methods)
                tags.append(f"ENTRY POINT {sym.framework or ''} {methods} {sym.route_path or ''}"
                            .strip())
            if sym.sources:
                tags.append("sources=" + ",".join(sym.sources))
            if sym.sinks:
                tags.append("sinks=" + ",".join(
                    f"{s.kind.value}:{s.call}@L{s.lineno}{'(tainted)' if s.tainted else ''}"
                    for s in sym.sinks))
            if sym.dependencies:
                tags.append("depends=" + ",".join(sym.dependencies))
            header = f"### [{role}] {sym.file_path}:{sym.lineno}-{sym.end_lineno} `{n}`"
            if tags:
                header += "\n# " + " | ".join(tags)
            code = sym.source_code if sym.kind is not SymbolKind.MODULE else \
                f"# module-level code of {sym.file_path} (see file)"
            if len(code) > max_symbol_chars:
                code = code[:max_symbol_chars] + "\n# ... truncated ..."
            numbered = "\n".join(f"{sym.decorator_lineno + i:>5}| {line}"
                                 for i, line in enumerate(code.split("\n"))) \
                if sym.kind is not SymbolKind.MODULE else code
            chunk = f"{header}\n```python\n{numbered}\n```\n"
            if used + len(chunk) > max_chars:
                chunks.append(f"# ... {len(order) - len(chunks)} more symbols omitted ...\n")
                break
            chunks.append(chunk)
            used += len(chunk)
        if radius.taint_paths:
            paths = "\n".join(
                "  " + "  ->  ".join(p["nodes"])
                + f"   [sinks={','.join(p['sink_kinds'])}; "
                  f"caller-controlled args at every hop={p['args_flow']}]"
                for p in radius.taint_paths[:10])
            chunks.insert(0, f"## Candidate entry -> change -> sink paths\n{paths}\n")
        return "\n".join(chunks)

    # ---- findings & quality ----------------------------------------------------------
    def findings_for_change(self, changed: ChangedLines
                            ) -> tuple[list[StaticFinding], list[StaticFinding]]:
        """Split static findings into (introduced on changed lines, pre-existing context)."""
        introduced: list[StaticFinding] = []
        context: list[StaticFinding] = []
        for path, lines in changed.items():
            pf = self.files.get(path)
            if pf is None:
                continue
            for f in pf.findings:
                span = set(range(f.line, f.end_line + 1))
                symbol = self._symbols.get(f.symbol or "")
                if f.rule_id in {"PY-QUAL-001", "PY-QUAL-002", "PY-QUAL-003", "PY-QUAL-004",
                                 "PY-QUAL-005", "PY-QUAL-008", "PY-QUAL-009", "PY-QUAL-011"} \
                        and symbol is not None:
                    span = set(range(symbol.decorator_lineno, symbol.end_lineno + 1))
                if f.rule_id == "PY-QUAL-010":
                    long_changed = pf.long_lines if lines is None else pf.long_lines & lines
                    if long_changed:
                        first = min(long_changed)
                        introduced.append(StaticFinding(
                            rule_id=f.rule_id, category=f.category, severity=f.severity,
                            title=f.title, file_path=f.file_path, line=first, end_line=first,
                            remediation=f.remediation,
                            message=f"{len(long_changed)} changed line(s) longer than "
                                    f"{LINE_LENGTH_LIMIT} chars (first at line {first}).",
                        ))
                    continue
                if lines is None or span & lines:
                    introduced.append(f)
                else:
                    context.append(f)
        return introduced, context

    def quality_report(self, changed: ChangedLines) -> QualityReport:
        """Grade only the touched code. Returns 0-100 docs, readability and type-hint scores."""
        touched = [s for s in self.touched_symbols(changed, innermost=False)
                   if s.kind is not SymbolKind.MODULE]
        funcs = [s for s in touched if s.is_function]
        documentable = [s for s in touched if s.requires_docstring]
        documented = sum(1 for s in documentable if s.docstring)
        docstring_cov = documented / len(documentable) if documentable else 1.0

        params_total = sum(s.params_total for s in funcs)
        params_ann = sum(s.params_annotated for s in funcs)
        returns_total = sum(1 for s in funcs if s.returns_counted)
        returns_ann = sum(1 for s in funcs if s.returns_counted and s.returns_annotated)
        denom = params_total + returns_total
        type_cov = (params_ann + returns_ann) / denom if denom else 1.0

        comment_lines = code_lines = long_lines = 0
        for path, lines in changed.items():
            pf = self.files.get(path)
            if pf is None:
                continue
            scope = set(range(1, pf.line_count + 1)) if lines is None else lines
            # comments directly above/inside changed code count toward the change
            widened = scope | {ln - 1 for ln in scope}
            comment_lines += len(pf.comment_lines & widened)
            code_lines += len(pf.code_lines & scope)
            long_lines += len(pf.long_lines & scope)
        density = comment_lines / code_lines if code_lines else 0.0
        comment_score = min(1.0, density / COMMENT_DENSITY_TARGET) if code_lines else 1.0

        # readability: per-function penalties, weighted by function length
        per_symbol: list[dict[str, Any]] = []
        weighted, weight = 0.0, 0
        naming = long_funcs = deep = 0
        for s in touched:
            if _naming_violation(s):
                naming += 1
        for s in funcs:
            penalty = 0.0
            if s.cyclomatic_complexity > COMPLEXITY_LIMIT:
                penalty += min(30.0, 3.0 * (s.cyclomatic_complexity - COMPLEXITY_LIMIT))
            if s.max_nesting > NESTING_LIMIT:
                deep += 1
                penalty += min(25.0, 10.0 * (s.max_nesting - NESTING_LIMIT))
            if s.length > FUNCTION_LENGTH_LIMIT:
                long_funcs += 1
                penalty += min(20.0, (s.length - FUNCTION_LENGTH_LIMIT) / 3.0)
            if s.params_total > PARAM_LIMIT:
                penalty += min(10.0, 3.0 * (s.params_total - PARAM_LIMIT))
            if _naming_violation(s):
                penalty += 8.0
            score = max(0.0, 100.0 - penalty)
            w = max(1, s.length)
            weighted += score * w
            weight += w
            per_symbol.append({
                "node_id": s.node_id, "file_path": s.file_path, "lineno": s.lineno,
                "complexity": s.cyclomatic_complexity, "nesting": s.max_nesting,
                "length": s.length, "type_hint_coverage": round(s.type_hint_coverage, 3),
                "has_docstring": bool(s.docstring), "readability": round(score, 1),
            })
        readability = weighted / weight if weight else 100.0
        long_ratio = long_lines / code_lines if code_lines else 0.0
        readability -= min(20.0, 200.0 * long_ratio)
        if not funcs:  # class-only/module-level changes: only naming & line length matter
            readability -= min(15.0, 5.0 * naming)
        readability = max(0.0, readability)

        # best practices from findings on touched lines
        introduced, _ = self.findings_for_change(changed)
        bp_weights = {"PY-QUAL-006": 1.0, "PY-QUAL-007": 0.5, "PY-QUAL-008": 1.0,
                      "PY-QUAL-012": 1.0, "PY-QUAL-000": 2.0}
        bp_counts: Counter[str] = Counter(f.rule_id for f in introduced if f.rule_id in bp_weights)
        bp_penalty = sum(bp_weights[r] * c for r, c in bp_counts.items())
        best_practices = max(0.0, 1.0 - 0.2 * bp_penalty)

        complexities = [s.cyclomatic_complexity for s in funcs]
        docs_score = round(100.0 * (0.7 * docstring_cov + 0.3 * comment_score), 1)
        types_score = round(100.0 * (0.75 * type_cov + 0.25 * best_practices), 1)
        return QualityReport(
            graded_symbols=len(touched), documentable=len(documentable), documented=documented,
            docstring_coverage=docstring_cov, params_total=params_total,
            params_annotated=params_ann, returns_total=returns_total,
            returns_annotated=returns_ann, type_hint_coverage=type_cov,
            comment_lines=comment_lines, code_lines=code_lines, comment_density=density,
            avg_complexity=sum(complexities) / len(complexities) if complexities else 1.0,
            max_complexity=max(complexities, default=1), long_functions=long_funcs,
            deep_nesting=deep, long_lines=long_lines, naming_violations=naming,
            best_practice_violations=dict(bp_counts), docs_score=docs_score,
            readability_score=round(readability, 1), type_hints_score=types_score,
            per_symbol=per_symbol,
        )

    # ---- persistence ------------------------------------------------------------------
    def symbol_records(self) -> list[dict[str, Any]]:
        """Rows for :class:`app.models.CodeSymbol` (add ``repository_id`` / ``commit_sha``)."""
        return [sym.to_record(self.files[sym.file_path].module) for sym in self._symbols.values()]

    def edge_records(self) -> list[dict[str, Any]]:
        """Rows for :class:`app.models.CodeEdge` (add ``repository_id``)."""
        return [
            {"source": u, "target": v, "kind": k, "file_path": d["file_path"],
             "lineno": d["lineno"], "confidence": d["confidence"]}
            for u, v, k, d in self.graph.edges(keys=True, data=True)
        ]

    def stats(self) -> dict[str, int]:
        kinds = Counter(k.value for _, _, k in self.graph.edges(keys=True))
        return {
            "files": len(self.files),
            "symbols": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "entry_points": sum(1 for s in self._symbols.values() if s.is_entry_point),
            "parse_errors": sum(1 for pf in self.files.values() if pf.syntax_error),
            "skipped": len(self.skipped),
            **{f"edges_{k}": v for k, v in kinds.items()},
        }
