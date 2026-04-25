"""Integration tests for MCP tool functions."""

import json
from pathlib import Path
from unittest.mock import patch

import httpx

from n8n_auditor.tools import (
    analyse_instance,
    audit_workflow,
    check_webhooks,
    detect_deprecations,
    error_handling_coverage,
    generate_audit_report,
    scan_credentials,
    suggest_fixes,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_path(name: str) -> str:
    if not name.endswith(".json"):
        name = f"{name}.json"
    return str(FIXTURES_DIR / name)


def _workflow_as_raw_json(name: str) -> str:
    return (FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# audit_workflow
# ---------------------------------------------------------------------------


def test_audit_workflow_returns_correct_keys():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    assert {"findings", "summary", "total"} <= result.keys()


def test_audit_workflow_total_matches_findings_length():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    assert result["total"] == len(result["findings"])


def test_audit_workflow_finds_cred001():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "CRED001" in rule_ids


def test_audit_workflow_finding_has_expected_keys():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    assert result["findings"]
    finding = result["findings"][0]
    assert {"rule_id", "severity", "node_id", "node_name", "message", "evidence"} <= finding.keys()


def test_audit_workflow_error_on_missing_nodes_key():
    result = audit_workflow('{"not_a_workflow": true}')
    assert "error" in result
    assert result["findings"] == []
    assert result["total"] == 0


def test_audit_workflow_accepts_raw_json_string():
    raw = _workflow_as_raw_json("hardcoded_secrets")
    result = audit_workflow(raw)
    assert result["total"] > 0


# ---------------------------------------------------------------------------
# detect_deprecations
# ---------------------------------------------------------------------------


def test_detect_deprecations_returns_correct_keys():
    result = detect_deprecations(_fixture_path("deprecated_nodes"))
    assert {"findings", "summary", "total"} <= result.keys()


def test_detect_deprecations_returns_depr_findings():
    result = detect_deprecations(_fixture_path("deprecated_nodes"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(rid.startswith("DEPR") for rid in rule_ids)


def test_detect_deprecations_only_returns_depr_rules():
    result = detect_deprecations(_fixture_path("deprecated_nodes"))
    for f in result["findings"]:
        assert f["rule_id"].startswith("DEPR"), f"Unexpected rule: {f['rule_id']}"


def test_detect_deprecations_error_on_bad_input():
    result = detect_deprecations('{"not_a_workflow": true}')
    assert "error" in result


# ---------------------------------------------------------------------------
# error_handling_coverage
# ---------------------------------------------------------------------------


def test_error_handling_coverage_has_coverage_block():
    result = error_handling_coverage(_fixture_path("no_error_handling"))
    assert "coverage" in result
    coverage = result["coverage"]
    assert "auditable_nodes" in coverage
    assert "nodes_with_error_routing" in coverage
    assert "coverage_percent" in coverage


def test_error_handling_coverage_percent_is_float():
    result = error_handling_coverage(_fixture_path("no_error_handling"))
    assert isinstance(result["coverage"]["coverage_percent"], float)


def test_error_handling_coverage_finds_err_findings():
    result = error_handling_coverage(_fixture_path("no_error_handling"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(rid.startswith("ERR") for rid in rule_ids)


def test_error_handling_coverage_error_on_bad_input():
    result = error_handling_coverage('{"not_a_workflow": true}')
    assert "error" in result
    assert result["findings"] == []
    assert result["coverage"]["auditable_nodes"] == 0
    assert result["coverage"]["coverage_percent"] == 0.0


# ---------------------------------------------------------------------------
# check_webhooks
# ---------------------------------------------------------------------------


def test_check_webhooks_returns_correct_keys():
    result = check_webhooks(_fixture_path("unauth_webhook"))
    assert {"findings", "summary", "total"} <= result.keys()


def test_check_webhooks_finds_webhook001():
    result = check_webhooks(_fixture_path("unauth_webhook"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "WEBHOOK001" in rule_ids


def test_check_webhooks_clean_workflow_no_webhook_findings():
    result = check_webhooks(_fixture_path("clean_workflow"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert not any(rid.startswith("WEBHOOK") for rid in rule_ids)


def test_check_webhooks_error_on_bad_input():
    result = check_webhooks('{"not_a_workflow": true}')
    assert "error" in result
    assert result["findings"] == []
    assert result["total"] == 0


# ---------------------------------------------------------------------------
# suggest_fixes
# ---------------------------------------------------------------------------


def test_suggest_fixes_returns_correct_keys():
    result = suggest_fixes(["WEBHOOK001"], _fixture_path("unauth_webhook"))
    assert {"fixes", "total"} <= result.keys()


def test_suggest_fixes_webhook001_returns_diff():
    result = suggest_fixes(["WEBHOOK001"], _fixture_path("unauth_webhook"))
    assert result["total"] > 0
    fix = result["fixes"][0]
    assert fix["fix_type"] == "modify_node"
    assert "before" in fix and "after" in fix


def test_suggest_fixes_after_has_header_auth():
    result = suggest_fixes(["WEBHOOK001"], _fixture_path("unauth_webhook"))
    fix = result["fixes"][0]
    assert fix["after"]["parameters"]["authentication"] == "headerAuth"


def test_suggest_fixes_error_on_bad_workflow():
    result = suggest_fixes(["WEBHOOK001"], '{"not_a_workflow": true}')
    assert "error" in result


def test_suggest_fixes_empty_on_unknown_rule_ids():
    result = suggest_fixes(["UNKNOWN999"], _fixture_path("clean_workflow"))
    assert result["fixes"] == []
    assert result["total"] == 0


def test_suggest_fixes_rel001_on_deprecated_nodes():
    result = suggest_fixes(["REL001"], _fixture_path("deprecated_nodes"))
    assert result["total"] > 0
    fix = result["fixes"][0]
    assert fix["after"]["parameters"]["retryOnFail"] is True


# ---------------------------------------------------------------------------
# generate_audit_report
# ---------------------------------------------------------------------------


def test_generate_audit_report_returns_correct_keys():
    findings = audit_workflow(_fixture_path("hardcoded_secrets"))["findings"]
    result = generate_audit_report(findings)
    assert {"report", "format", "total_findings"} <= result.keys()


def test_generate_audit_report_returns_markdown_string():
    findings = audit_workflow(_fixture_path("hardcoded_secrets"))["findings"]
    result = generate_audit_report(findings)
    assert isinstance(result["report"], str)
    assert "# Audit Report" in result["report"]


def test_generate_audit_report_total_findings_matches():
    findings = audit_workflow(_fixture_path("hardcoded_secrets"))["findings"]
    result = generate_audit_report(findings)
    assert result["total_findings"] == len(findings)


def test_generate_audit_report_unsupported_format_returns_error():
    result = generate_audit_report([], format="pdf")
    assert "error" in result


def test_generate_audit_report_empty_findings():
    result = generate_audit_report([])
    assert result["total_findings"] == 0
    assert "No findings" in result["report"]


def test_generate_audit_report_uses_workflow_name():
    result = generate_audit_report([], workflow_name="My Test Flow")
    assert "My Test Flow" in result["report"]


# ---------------------------------------------------------------------------
# scan_credentials
# ---------------------------------------------------------------------------


def test_scan_credentials_returns_correct_keys():
    result = scan_credentials(_fixture_path("hardcoded_secrets"))
    assert {"findings", "summary", "total"} <= result.keys()


def test_scan_credentials_finds_cred001():
    result = scan_credentials(_fixture_path("hardcoded_secrets"))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "CRED001" in rule_ids


def test_scan_credentials_only_cred_rules():
    result = scan_credentials(_fixture_path("hardcoded_secrets"))
    for f in result["findings"]:
        assert f["rule_id"].startswith("CRED"), f"Unexpected rule: {f['rule_id']}"


def test_scan_credentials_total_matches_findings():
    result = scan_credentials(_fixture_path("hardcoded_secrets"))
    assert result["total"] == len(result["findings"])


def test_scan_credentials_error_on_bad_input():
    result = scan_credentials('{"not_a_workflow": true}')
    assert "error" in result


# ---------------------------------------------------------------------------
# analyse_instance
# ---------------------------------------------------------------------------


def test_analyse_instance_http_error_returns_error_key():
    with patch("n8n_auditor.tools.N8nConnector") as MockConnector:
        MockConnector.return_value.fetch_all_workflows.side_effect = httpx.HTTPError("timeout")
        result = analyse_instance("https://n8n.example.com", "fake-key")
    assert "error" in result
    assert result["findings"] == []
    assert result["workflow_count"] == 0


def test_analyse_instance_empty_instance_returns_zero_totals():
    with patch("n8n_auditor.tools.N8nConnector") as MockConnector:
        MockConnector.return_value.fetch_all_workflows.return_value = []
        result = analyse_instance("https://n8n.example.com", "fake-key")
    assert result["total"] == 0
    assert result["workflow_count"] == 0
    assert result["findings"] == []


def test_analyse_instance_aggregates_findings_across_workflows():
    workflow = json.loads((FIXTURES_DIR / "hardcoded_secrets.json").read_text(encoding="utf-8"))
    with patch("n8n_auditor.tools.N8nConnector") as MockConnector:
        MockConnector.return_value.fetch_all_workflows.return_value = [workflow]
        result = analyse_instance("https://n8n.example.com", "fake-key")
    assert result["workflow_count"] == 1
    assert result["total"] > 0
    assert any(f["rule_id"] == "CRED001" for f in result["findings"])


# ---------------------------------------------------------------------------
# text_summary
# ---------------------------------------------------------------------------


def test_audit_workflow_returns_text_summary():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    assert "text_summary" in result
    assert isinstance(result["text_summary"], str)


def test_audit_workflow_text_summary_issues_found():
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    assert "ISSUES FOUND" in result["text_summary"]


def test_audit_workflow_text_summary_clean():
    from n8n_auditor.report import build_text_summary

    summary = build_text_summary([], workflow_name="My Workflow")
    assert "CLEAN" in summary
    assert "ISSUES FOUND" not in summary


def test_audit_workflow_text_summary_contains_workflow_name():
    workflow = json.loads((FIXTURES_DIR / "hardcoded_secrets.json").read_text(encoding="utf-8"))
    name = workflow.get("name", "")
    result = audit_workflow(_fixture_path("hardcoded_secrets"))
    if name:
        assert name in result["text_summary"]


def test_scan_credentials_returns_text_summary():
    result = scan_credentials(_fixture_path("hardcoded_secrets"))
    assert "text_summary" in result
    assert "ISSUES FOUND" in result["text_summary"]


def test_check_webhooks_returns_text_summary():
    result = check_webhooks(_fixture_path("unauth_webhook"))
    assert "text_summary" in result
    assert isinstance(result["text_summary"], str)


def test_detect_deprecations_returns_text_summary():
    result = detect_deprecations(_fixture_path("deprecated_nodes"))
    assert "text_summary" in result
    assert isinstance(result["text_summary"], str)


def test_error_handling_coverage_returns_text_summary():
    result = error_handling_coverage(_fixture_path("no_error_handling"))
    assert "text_summary" in result
    assert "ISSUES FOUND" in result["text_summary"]


def test_error_handling_coverage_text_summary_includes_coverage():
    result = error_handling_coverage(_fixture_path("no_error_handling"))
    assert "Coverage:" in result["text_summary"]


def test_text_summary_error_path():
    result = audit_workflow('{"not_a_workflow": true}')
    assert "text_summary" in result
    assert "Error" in result["text_summary"]
