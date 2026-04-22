"""Unit tests for the markdown report builder."""

from n8n_auditor.report import build_markdown_report


def _finding(
    rule_id: str, severity: str, node_name: str = "Node", message: str = "msg", evidence: str = "ev"
) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "node_id": "n1",
        "node_name": node_name,
        "message": message,
        "evidence": evidence,
    }


def test_empty_findings_returns_valid_report():
    result = build_markdown_report([])
    assert "# Audit Report" in result
    assert "No findings" in result


def test_report_contains_rule_id():
    result = build_markdown_report([_finding("WEBHOOK001", "high")])
    assert "WEBHOOK001" in result


def test_report_critical_section_present():
    result = build_markdown_report([_finding("CRED001", "critical")])
    assert "Critical" in result


def test_severity_order_critical_before_low():
    findings = [
        _finding("REL001", "low"),
        _finding("CRED001", "critical"),
    ]
    result = build_markdown_report(findings)
    assert result.index("Critical") < result.index("Low")


def test_report_contains_remediation_text():
    result = build_markdown_report([_finding("WEBHOOK001", "high")])
    assert "headerAuth" in result


def test_report_summary_section_present():
    result = build_markdown_report([_finding("CRED001", "critical")])
    assert "## Summary" in result


def test_report_title_uses_workflow_name():
    result = build_markdown_report([], workflow_name="My Workflow")
    assert "My Workflow" in result


def test_report_finding_message_included():
    result = build_markdown_report(
        [_finding("ERR001", "medium", message="No error routing configured")]
    )
    assert "No error routing configured" in result
