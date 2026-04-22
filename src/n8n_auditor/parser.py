"""Workflow JSON ingestion — accepts a file path or raw JSON string and returns a parsed dict."""

import json
import os
from pathlib import Path


class WorkflowParseError(Exception):
    pass


def parse_workflow(source: str) -> dict:
    """Parse an n8n workflow from a file path or raw JSON string.

    Args:
        source: Absolute/relative file path OR raw JSON string.

    Returns:
        Parsed workflow dict with at minimum a ``nodes`` key.

    Raises:
        WorkflowParseError: If the input cannot be parsed or is structurally invalid.
    """
    raw: str

    # Detect file path: either an existing file or a string that ends with .json
    # and doesn't start with '{' / '['
    source_stripped = source.strip()
    is_path = not source_stripped.startswith(("{", "[")) and (
        os.path.exists(source_stripped) or source_stripped.endswith(".json")
    )

    if is_path:
        path = Path(source_stripped)
        if not path.exists():
            raise WorkflowParseError(f"File not found: {path}")
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise WorkflowParseError(f"Cannot read file {path}: {exc}") from exc
    else:
        raw = source_stripped

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WorkflowParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise WorkflowParseError("Workflow JSON must be an object (dict), not a list or scalar.")

    if "nodes" not in data:
        raise WorkflowParseError("Workflow JSON is missing required key: 'nodes'.")

    if not isinstance(data["nodes"], list):
        raise WorkflowParseError("'nodes' must be a list.")

    return data
