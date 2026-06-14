"""Pytest fixtures for SecretHawk's test suite.

The sample fixture repo that the walker / CLI tests scan from disk is *built
at runtime* into a temporary directory (see :func:`sample_repo`). This keeps
contiguous, provider-shaped credential literals out of version control while
preserving identical scan coverage: the scanner reads exactly the same bytes
it would have read from a committed fixture, only those bytes now originate
from :mod:`tests._assembly` instead of a checked-in file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests._assembly import build_sample_repo, secret  # noqa: F401  (re-export)


@pytest.fixture(scope="session")
def sample_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the planted sample repo once per session; return its root path.

    The tree mirrors the historical ``tests/fixtures/sample_repo`` layout
    (planted ``config.py`` and ``keys/id_rsa``, benign/allowlisted
    ``benign.txt``, a ``.secrethawk.toml`` allowlist, and a clean ``clean/``
    subtree) with all secrets assembled at runtime.
    """
    root = tmp_path_factory.mktemp("sample_repo")
    return build_sample_repo(root)


@pytest.fixture(scope="session")
def clean_subtree(sample_repo: Path) -> Path:
    """Return the clean subtree of the generated sample repo."""
    return sample_repo / "clean"
