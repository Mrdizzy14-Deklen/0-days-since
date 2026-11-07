"""Average-based scoring formula, conclusions and streaks."""

from __future__ import annotations

from app.ai_scanner import ScanFinding
from app.enums import CheckConclusion, FindingCategory, FindingSource, FindingStatus, Severity
from app.models import Developer
from app.scoring import (
    CraftSubscores,
    apply_push,
    determine_conclusion,
    push_fault_weight,
    security_score,
)

GOOD = CraftSubscores(docs=90, readability=95, type_hints=85)  # 270/300
POOR = CraftSubscores(docs=40, readability=60, type_hints=50)  # 150/300


def vuln(sev: Severity, cwe: str = "CWE-89", status: FindingStatus = FindingStatus.VERIFIED
         ) -> ScanFinding:
    return ScanFinding(category=FindingCategory.SECURITY, source=FindingSource.STATIC,
                       status=status, severity=sev, rule_id="PY-SEC-003", title="x",
                       description="x", file_path="a.py", start_line=1, end_line=1, cwe=cwe)


def test_security_score_examples_from_spec() -> None:
    # 1 fully faulty push out of 2 -> 50% fault rate; out of 10 -> 10%
    assert security_score(2, 1.0) == 350
    assert security_score(10, 1.0) == 630
    assert security_score(0, 0.0) == 700
    assert security_score(1, 5.0) == 0  # capped


def test_push_weight_sums_and_caps_and_ignores_unverified() -> None:
    assert push_fault_weight([vuln(Severity.MEDIUM), vuln(Severity.LOW)]) == 0.55
    assert push_fault_weight([vuln(Severity.CRITICAL), vuln(Severity.HIGH)]) == 1.0
    assert push_fault_weight([vuln(Severity.HIGH, status=FindingStatus.REJECTED),
                              vuln(Severity.HIGH, status=FindingStatus.CANDIDATE)]) == 0.0


def test_conclusions() -> None:
    assert determine_conclusion([vuln(Severity.HIGH)], GOOD) is CheckConclusion.FAILURE
    assert determine_conclusion([vuln(Severity.LOW)], GOOD) is CheckConclusion.NEUTRAL
    assert determine_conclusion([], POOR) is CheckConclusion.NEUTRAL
    assert determine_conclusion([], GOOD) is CheckConclusion.SUCCESS
    assert determine_conclusion([], None) is CheckConclusion.SUCCESS


def test_faulty_push_then_clean_pushes_recover_average() -> None:
    dev = Developer(team_id=1, github_login="alice")
    s1 = apply_push(dev, [], GOOD)
    assert s1.conclusion is CheckConclusion.SUCCESS and dev.clean_streak == 1
    assert dev.security_score == 700 and dev.craft_score == 270 and dev.composite_score == 970
    assert s1.points_delta == -30  # craft average replaces the 300 starting value

    s2 = apply_push(dev, [vuln(Severity.CRITICAL)], GOOD)  # 1 faulty of 2
    assert s2.conclusion is CheckConclusion.FAILURE
    assert dev.security_score == 350 and s2.points_delta == -350
    assert dev.clean_streak == 0 and dev.faulty_pushes == 1 and dev.top_cwe == "CWE-89"

    for _ in range(8):  # 1 faulty of 10
        apply_push(dev, [], GOOD)
    assert dev.total_pushes == 10 and dev.security_score == 630
    assert dev.clean_streak == 8 and dev.best_clean_streak == 8


def test_craft_rolling_average_and_untouched_pushes() -> None:
    dev = Developer(team_id=1, github_login="bob")
    apply_push(dev, [], GOOD)
    apply_push(dev, [], POOR)
    assert dev.craft_score == round((270 + 150) / 2)
    before = dev.craft_score
    apply_push(dev, [], None)  # nothing gradable: craft unchanged, still counts as a push
    assert dev.craft_score == before and dev.total_pushes == 3


def test_readability_only_neutral_keeps_streak() -> None:
    dev = Developer(team_id=1, github_login="carol")
    apply_push(dev, [], GOOD)
    s = apply_push(dev, [], POOR)
    assert s.conclusion is CheckConclusion.NEUTRAL and dev.clean_streak == 1
    apply_push(dev, [vuln(Severity.LOW, cwe="CWE-328")], GOOD)
    assert dev.clean_streak == 0
    assert dev.cwe_counts == {"CWE-328": 1}
