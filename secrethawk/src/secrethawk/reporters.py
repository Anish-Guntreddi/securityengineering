"""Output reporters for SecretHawk: JSON and SARIF 2.1.0.

``to_sarif`` produces a SARIF 2.1.0 document that validates against a
vendored JSON Schema (see :func:`validate_sarif`).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from jsonschema import Draft7Validator
from jsonschema import ValidationError as _ValidationError

from .models import Finding

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Map our internal severities onto SARIF result levels.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


class SarifValidationError(Exception):
    """Raised when a SARIF document fails schema validation."""


def to_json(findings: list[Finding]) -> dict:
    """Return a plain JSON-serialisable summary of ``findings``."""
    return {
        "tool": "SecretHawk",
        "version": _tool_version_or_default(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def _tool_version_or_default() -> str:
    try:
        from . import __version__

        return __version__
    except Exception:  # pragma: no cover
        return "0.0.0"


def _level_for(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def to_sarif(findings: list[Finding], tool_version: str) -> dict:
    """Build a SARIF 2.1.0 document for ``findings``.

    The document contains a single run whose driver is ``SecretHawk``, with a
    ``rules`` table derived from the distinct rule ids present in ``findings``
    and a ``results`` array describing each finding.
    """
    # Build a stable, de-duplicated rule table.
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append(
                {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.description},
                    "defaultConfiguration": {"level": _level_for(f.severity)},
                    "properties": {"detector": f.detector, "severity": f.severity},
                }
            )

    results: list[dict] = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _level_for(f.severity),
                "message": {
                    "text": (
                        f"{f.description} detected (preview: {f.match_preview})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column,
                            },
                        }
                    }
                ],
                "properties": {
                    "detector": f.detector,
                    "severity": f.severity,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretHawk",
                        "version": tool_version,
                        "informationUri": "https://example.com/secrethawk",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


@lru_cache(maxsize=1)
def _load_schema() -> dict:
    """Load and cache the vendored SARIF JSON Schema."""
    with resources.files("secrethawk.schemas").joinpath(
        "sarif-2.1.0.json"
    ).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_sarif(doc: dict) -> bool:
    """Validate ``doc`` against the vendored SARIF schema.

    Returns True on success. Raises :class:`SarifValidationError` on failure.
    """
    schema = _load_schema()
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        raise SarifValidationError(
            f"SARIF validation failed: {first.message} (path: {list(first.path)})"
        )
    return True


def is_valid_sarif(doc: dict) -> bool:
    """Return True/False instead of raising (convenience for tests)."""
    try:
        return validate_sarif(doc)
    except SarifValidationError:
        return False
    except _ValidationError:  # pragma: no cover - defensive
        return False
