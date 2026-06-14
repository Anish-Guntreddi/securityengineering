"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webshield.models import Probe


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_probe(name: str) -> Probe:
    """Load a recorded Probe fixture by base name (without .json)."""
    path = FIXTURES_DIR / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return Probe.from_dict(data)


@pytest.fixture
def secure_probe() -> Probe:
    return load_probe("secure")


@pytest.fixture
def insecure_probe() -> Probe:
    return load_probe("insecure")
