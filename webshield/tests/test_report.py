"""Tests for graded reporting."""

from __future__ import annotations

import json

from webshield.models import Finding
from webshield.report import (
    to_text,
    to_json,
    overall_grade,
    compute_score,
    grade_for_score,
    summarize,
)
from webshield.runner import run_all


def _passing_findings():
    return [
        Finding("a", "A", "info", "pass", "ok"),
        Finding("b", "B", "info", "pass", "ok"),
    ]


def _failing_findings():
    return [
        Finding("a", "A", "critical", "fail", "bad", "fix it"),
        Finding("b", "B", "high", "fail", "bad", "fix it"),
    ]


def test_grade_for_score_boundaries():
    assert grade_for_score(100) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
    assert grade_for_score(0) == "F"


def test_all_pass_is_grade_a():
    findings = _passing_findings()
    assert compute_score(findings) == 100
    assert overall_grade(findings) == "A"


def test_critical_fail_caps_at_f():
    findings = _failing_findings()
    assert overall_grade(findings) == "F"


def test_summarize_counts():
    findings = [
        Finding("a", "A", "info", "pass", "ok"),
        Finding("b", "B", "low", "warn", "meh"),
        Finding("c", "C", "high", "fail", "bad"),
    ]
    counts = summarize(findings)
    assert counts == {"pass": 1, "warn": 1, "fail": 1}


def test_to_text_contains_grade_and_findings():
    findings = [
        Finding("a", "Header Check", "high", "fail", "missing", "add it"),
    ]
    text = to_text(findings)
    assert "Overall grade:" in text
    assert "Header Check" in text
    assert "FAIL" in text
    assert "remediation: add it" in text


def test_to_text_pass_omits_remediation():
    findings = [Finding("a", "OK", "info", "pass", "all good", "should not show")]
    text = to_text(findings)
    assert "remediation:" not in text


def test_to_json_structure():
    findings = [
        Finding("a", "A", "high", "fail", "bad", "fix"),
        Finding("b", "B", "info", "pass", "ok"),
    ]
    payload = json.loads(to_json(findings))
    assert "overall_grade" in payload
    assert "score" in payload
    assert payload["summary"] == {"pass": 1, "warn": 0, "fail": 1}
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["check_id"] == "a"


def test_secure_probe_grades_well(secure_probe):
    findings = run_all(secure_probe)
    grade = overall_grade(findings)
    assert grade in ("A", "B"), grade


def test_insecure_probe_grades_poorly(insecure_probe):
    findings = run_all(insecure_probe)
    assert overall_grade(insecure_probe and findings) == "F"
