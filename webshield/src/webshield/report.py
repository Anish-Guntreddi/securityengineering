"""Graded reporting for WebShield findings.

Produces a per-check verdict listing plus an overall letter grade (A-F) derived
from the mix of pass/warn/fail verdicts weighted by severity.
"""

from __future__ import annotations

import json
from typing import Iterable

from .models import Finding


# Severity weights used to penalize the overall score.
_SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 6,
}

# A failing verdict applies the full severity weight; a warning applies half.
_VERDICT_MULTIPLIER = {"pass": 0.0, "warn": 0.5, "fail": 1.0}


def _verdict_symbol(verdict: str) -> str:
    return {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}.get(verdict, verdict.upper())


def compute_score(findings: Iterable[Finding]) -> int:
    """Compute a 0-100 score from findings (100 = no penalties)."""
    penalty = 0.0
    for finding in findings:
        weight = _SEVERITY_WEIGHT.get(finding.severity, 1)
        multiplier = _VERDICT_MULTIPLIER.get(finding.verdict, 0.0)
        penalty += weight * multiplier
    score = max(0.0, 100.0 - penalty * 3.0)
    return int(round(score))


def grade_for_score(score: int) -> str:
    """Map a 0-100 score onto a letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def overall_grade(findings: Iterable[Finding]) -> str:
    """Convenience: letter grade for a set of findings."""
    findings = list(findings)
    # Any critical failure caps the grade at F regardless of score.
    for finding in findings:
        if finding.verdict == "fail" and finding.severity == "critical":
            return "F"
    return grade_for_score(compute_score(findings))


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    """Count verdicts."""
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for finding in findings:
        if finding.verdict in counts:
            counts[finding.verdict] += 1
    return counts


def to_text(findings: Iterable[Finding]) -> str:
    """Render a human-readable graded report."""
    findings = list(findings)
    score = compute_score(findings)
    grade = overall_grade(findings)
    counts = summarize(findings)

    lines: list[str] = []
    lines.append("WebShield security configuration report")
    lines.append("=" * 40)
    lines.append(f"Overall grade: {grade}  (score {score}/100)")
    lines.append(
        f"Checks: {counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail"
    )
    lines.append("")

    for finding in findings:
        lines.append(f"[{_verdict_symbol(finding.verdict)}] {finding.title} ({finding.severity})")
        lines.append(f"    id: {finding.check_id}")
        lines.append(f"    {finding.detail}")
        if finding.remediation and finding.verdict != "pass":
            lines.append(f"    remediation: {finding.remediation}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def to_json(findings: Iterable[Finding]) -> str:
    """Render the graded report as a JSON string."""
    findings = list(findings)
    payload = {
        "overall_grade": overall_grade(findings),
        "score": compute_score(findings),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
