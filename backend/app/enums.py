"""Shared enumerations used by the DB models, the AST engine and the scoring engine.

Kept dependency-free so the analyzers can be imported without a database.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        """Fault weight `w_i` used by the average-based security score."""
        return SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Higher is more severe; useful for sorting."""
        return _SEVERITY_RANK[self]

    @property
    def blocks_merge(self) -> bool:
        return self in (Severity.CRITICAL, Severity.HIGH)


SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.15,
    Severity.INFO: 0.0,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingCategory(str, Enum):
    SECURITY = "security"
    QUALITY = "quality"


class FindingSource(str, Enum):
    STATIC = "static"  # deterministic AST pass
    AI = "ai"  # LLM pass 1


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"  # not yet verified
    VERIFIED = "verified"  # survived the skeptic verifier
    REJECTED = "rejected"  # false positive per verifier


class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    METHOD = "method"
    ASYNC_METHOD = "async_method"


class EdgeKind(str, Enum):
    CALL = "call"
    IMPORT = "import"
    INHERITS = "inherits"
    ROUTE = "route"  # Django urls.py -> view


class SinkKind(str, Enum):
    SQL = "sql"
    COMMAND = "command"
    CODE_EXEC = "code_exec"
    DESERIALIZATION = "deserialization"
    FILE = "file"
    NETWORK = "network"
    TEMPLATE = "template"
    REDIRECT = "redirect"
    DB_ORM = "db_orm"


class EventType(str, Enum):
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    BASELINE = "baseline"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class CheckConclusion(str, Enum):
    SUCCESS = "success"
    NEUTRAL = "neutral"
    FAILURE = "failure"


class MemberRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
