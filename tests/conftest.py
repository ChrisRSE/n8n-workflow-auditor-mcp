"""Shared pytest fixtures and helpers."""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a workflow fixture JSON by filename (with or without .json extension)."""
    if not name.endswith(".json"):
        name = f"{name}.json"
    path = FIXTURES_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def clean_workflow() -> dict:
    return load_fixture("clean_workflow")


@pytest.fixture
def hardcoded_secrets_workflow() -> dict:
    return load_fixture("hardcoded_secrets")
