"""Tests for JSON and SARIF reporters and SARIF schema validation."""

import copy

import pytest

from secrethawk.models import Finding
from secrethawk.reporters import (
    SarifValidationError,
    is_valid_sarif,
    to_json,
    to_sarif,
    validate_sarif,
)
from tests._assembly import AWS_ACCESS_KEY, HIGH_ENTROPY_TOKEN


def _sample_findings():
    return [
        Finding.from_match(
            rule_id="aws-access-key-id",
            description="AWS Access Key ID",
            severity="high",
            file_path="config.py",
            line=4,
            column=21,
            raw_match=AWS_ACCESS_KEY,
            detector="rule",
        ),
        Finding.from_match(
            rule_id="high-entropy-string",
            description="High-entropy string",
            severity="medium",
            file_path="config.py",
            line=8,
            column=23,
            raw_match=HIGH_ENTROPY_TOKEN,
            detector="entropy",
        ),
    ]


def test_to_json_well_formed():
    doc = to_json(_sample_findings())
    assert doc["tool"] == "SecretHawk"
    assert doc["finding_count"] == 2
    assert len(doc["findings"]) == 2
    # No raw secret leaks into JSON.
    assert AWS_ACCESS_KEY not in str(doc)


def test_to_json_empty():
    doc = to_json([])
    assert doc["finding_count"] == 0
    assert doc["findings"] == []


def test_to_sarif_validates():
    doc = to_sarif(_sample_findings(), "0.1.0")
    assert validate_sarif(doc) is True
    assert is_valid_sarif(doc) is True


def test_to_sarif_structure():
    doc = to_sarif(_sample_findings(), "0.1.0")
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecretHawk"
    assert run["results"][0]["ruleId"] == "aws-access-key-id"
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config.py"
    assert loc["region"]["startLine"] == 4


def test_to_sarif_empty_validates():
    doc = to_sarif([], "0.1.0")
    assert validate_sarif(doc) is True


def test_malformed_wrong_version_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    bad["version"] = "1.0.0"
    with pytest.raises(SarifValidationError):
        validate_sarif(bad)
    assert is_valid_sarif(bad) is False


def test_malformed_missing_runs_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    del bad["runs"]
    assert is_valid_sarif(bad) is False


def test_malformed_missing_driver_name_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    del bad["runs"][0]["tool"]["driver"]["name"]
    assert is_valid_sarif(bad) is False


def test_malformed_missing_tool_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    del bad["runs"][0]["tool"]
    assert is_valid_sarif(bad) is False


def test_malformed_result_missing_message_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    del bad["runs"][0]["results"][0]["message"]
    assert is_valid_sarif(bad) is False


def test_malformed_missing_schema_rejected():
    doc = to_sarif(_sample_findings(), "0.1.0")
    bad = copy.deepcopy(doc)
    del bad["$schema"]
    assert is_valid_sarif(bad) is False
