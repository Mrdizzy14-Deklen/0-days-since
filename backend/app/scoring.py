"""Average-based scoring engine.

Security Reliability (0-700)
    Every scored push increments ``total_pushes``. A push with verified vulnerabilities
    increments ``faulty_pushes`` and adds its fault weight to ``weighted_fault_sum``:

        push_weight    = min(1.0, sum(w_i for each verified vulnerability))
                         w: CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.15
        fault_rate     = min(1.0, weighted_fault_sum / max(1, total_pushes))
        security_score = round(700 * (1 - fault_rate))

    The cap keeps one push from counting as more than one fully faulty push, so clean pushes
    can always dilute it. A CRITICAL on push 2 of 2 costs 350 pts; on push 10 of 10, 70 pts.

Code Craft (0-300)
    Exact rolling average over graded pushes of docs (0-100) + readability (0-100) +
    type hints & best practices (0-100). Pushes that touch no gradable symbol leave it as is.

Composite = Security + Craft (0-1000).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from app.ai_scanner import CraftAdjustment, ScanFinding
from app.ast_engine import QualityReport
from app.enums import CheckConclusion, FindingCategory, Severity
from app.models import MAX_CRAFT_SCORE, MAX_SECURITY_SCORE, Developer

SMELL_NAMES: dict[str, str] = {
    "PY-QUAL-000": "Syntax errors",
    "PY-QUAL-001": "Missing docstrings",
    "PY-QUAL-002": "Missing type hints",
    "PY-QUAL-003": "High complexity",
    "PY-QUAL-004": "Deep nesting",
    "PY-QUAL-005": "Long functions",
    "PY-QUAL-006": "Bare except",
    "PY-QUAL-007": "Swallowed exceptions",
    "PY-QUAL-008": "Mutable defaults",
    "PY-QUAL-009": "PEP 8 naming",
    "PY-QUAL-010": "Long lines",
    "PY-QUAL-011": "Too many parameters",
    "PY-QUAL-012": "Wildcard imports",
    "AI-READABILITY": "Readability",
}


@dataclass(slots=True)
class CraftSubscores:
    docs: float
    readability: float
    type_hints: float

    @property
    def total(self) -> float:
        return round(self.docs + self.readability + self.type_hints, 1)


@dataclass(slots=True)
class PushScore:
    fault_weight: float
    is_faulty: bool
    conclusion: CheckConclusion
    craft: CraftSubscores | None
    security_before: int
    security_after: int
    craft_before: int
    craft_after: int
    composite_before: int
    composite_after: int

    @property
    def points_delta(self) -> int:
        return self.composite_after - self.composite_before


def push_fault_weight(vulns: Iterable[ScanFinding]) -> float:
    return round(min(1.0, sum(f.severity.weight for f in vulns if f.counted_in_score)), 4)


def security_score(total_pushes: int, weighted_fault_sum: float) -> int:
    fault_rate = min(1.0, weighted_fault_sum / max(1, total_pushes))
    return round(MAX_SECURITY_SCORE * (1.0 - fault_rate))


def craft_subscores(report: QualityReport, adjustment: CraftAdjustment | None = None
                    ) -> CraftSubscores | None:
    """Deterministic sub-scores plus the bounded AI adjustment, or None if nothing to grade."""
    if report.graded_symbols == 0 and report.code_lines == 0:
        return None
    adj = adjustment or CraftAdjustment()

    def clamp(v: float) -> float:
        return round(max(0.0, min(100.0, v)), 1)

    return CraftSubscores(docs=clamp(report.docs_score + adj.docs),
                          readability=clamp(report.readability_score + adj.readability),
                          type_hints=clamp(report.type_hints_score + adj.type_hints))


def craft_score(dev: Developer) -> int:
    if dev.craft_samples == 0:
        return MAX_CRAFT_SCORE
    total = (dev.craft_docs_sum + dev.craft_readability_sum + dev.craft_types_sum) / \
        dev.craft_samples
    return round(max(0.0, min(float(MAX_CRAFT_SCORE), total)))


def determine_conclusion(vulns: Iterable[ScanFinding], craft: CraftSubscores | None, *,
                         readability_threshold: float = 180.0) -> CheckConclusion:
    counted = [f for f in vulns if f.counted_in_score]
    if any(f.severity.blocks_merge for f in counted):
        return CheckConclusion.FAILURE
    if counted or (craft is not None and craft.total < readability_threshold):
        return CheckConclusion.NEUTRAL
    return CheckConclusion.SUCCESS


def _top(counts: dict[str, int]) -> str | None:
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0] if counts else None


def apply_push(dev: Developer, findings: list[ScanFinding], craft: CraftSubscores | None, *,
               readability_threshold: float = 180.0, now: datetime | None = None) -> PushScore:
    """Update the developer's aggregates in place for one scanned push."""
    security_before, craft_before = dev.security_score, dev.craft_score
    composite_before = dev.composite_score
    vulns = [f for f in findings if f.counted_in_score]
    weight = push_fault_weight(vulns)
    conclusion = determine_conclusion(vulns, craft, readability_threshold=readability_threshold)

    dev.total_pushes += 1
    if vulns:
        dev.faulty_pushes += 1
        dev.weighted_fault_sum = round(dev.weighted_fault_sum + weight, 4)
    dev.security_score = security_score(dev.total_pushes, dev.weighted_fault_sum)

    if craft is not None:
        dev.craft_samples += 1
        dev.craft_docs_sum += craft.docs
        dev.craft_readability_sum += craft.readability
        dev.craft_types_sum += craft.type_hints
    dev.craft_score = craft_score(dev)
    dev.composite_score = dev.security_score + dev.craft_score

    if vulns:
        dev.clean_streak = 0
    elif conclusion is CheckConclusion.SUCCESS:
        dev.clean_streak += 1
        dev.best_clean_streak = max(dev.best_clean_streak, dev.clean_streak)

    # Reassign (not mutate) JSON columns so SQLAlchemy detects the change.
    cwe_counts = dict(dev.cwe_counts or {})
    for f in vulns:
        if f.cwe:
            cwe_counts[f.cwe] = cwe_counts.get(f.cwe, 0) + 1
    smell_counts = dict(dev.smell_counts or {})
    for f in findings:
        if f.category is FindingCategory.QUALITY and f.severity is not Severity.INFO:
            name = SMELL_NAMES.get(f.rule_id, f.rule_id)
            smell_counts[name] = smell_counts.get(name, 0) + 1
    dev.cwe_counts, dev.smell_counts = cwe_counts, smell_counts
    dev.top_cwe, dev.top_smell = _top(cwe_counts), _top(smell_counts)
    dev.last_push_at = now or datetime.now(timezone.utc)

    return PushScore(
        fault_weight=weight, is_faulty=bool(vulns), conclusion=conclusion, craft=craft,
        security_before=security_before, security_after=dev.security_score,
        craft_before=craft_before, craft_after=dev.craft_score,
        composite_before=composite_before, composite_after=dev.composite_score,
    )
