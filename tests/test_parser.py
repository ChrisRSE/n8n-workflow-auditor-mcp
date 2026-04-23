"""Unit tests for workflow parser edge cases."""

import json
import tempfile
from pathlib import Path

import pytest

from n8n_auditor.parser import WorkflowParseError, parse_workflow


def test_parse_workflow_file_not_found():
    with pytest.raises(WorkflowParseError, match="File not found"):
        parse_workflow("/nonexistent/path/workflow.json")


def test_parse_workflow_invalid_json():
    with pytest.raises(WorkflowParseError, match="Invalid JSON"):
        parse_workflow("{invalid json}")


def test_parse_workflow_json_is_list():
    with pytest.raises(WorkflowParseError, match="must be an object"):
        parse_workflow("[1, 2, 3]")


def test_parse_workflow_nodes_not_list():
    with pytest.raises(WorkflowParseError, match="'nodes' must be a list"):
        parse_workflow('{"nodes": {"not": "a list"}}')


def test_parse_workflow_valid_file():
    workflow = {"nodes": [], "connections": {}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(workflow, f)
        tmp_path = f.name
    result = parse_workflow(tmp_path)
    assert result["nodes"] == []
    Path(tmp_path).unlink()
