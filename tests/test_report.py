"""Unit tests for the markdown and HTML report builders."""

from n8n_auditor.report import build_html_report, build_markdown_report


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


# ---------------------------------------------------------------------------
# HTML report tests
# ---------------------------------------------------------------------------


class TestBuildHtmlReport:
    def test_html_is_valid_structure(self):
        result = build_html_report([])
        assert result.startswith("<!DOCTYPE html>")
        assert "</html>" in result

    def test_html_contains_workflow_name(self):
        result = build_html_report([], workflow_name="My Test Workflow")
        assert "My Test Workflow" in result

    def test_html_contains_finding_rule_id(self):
        result = build_html_report([_finding("WEBHOOK001", "high")])
        assert "WEBHOOK001" in result

    def test_html_contains_severity_label(self):
        result = build_html_report([_finding("CRED001", "critical")])
        assert "CRITICAL" in result

    def test_html_with_no_findings_shows_clean(self):
        result = build_html_report([])
        assert "No actionable findings" in result

    def test_html_shows_clean_status_badge_when_no_actionable_findings(self):
        result = build_html_report([])
        assert "CLEAN" in result

    def test_html_shows_issues_badge_when_actionable_findings_present(self):
        result = build_html_report([_finding("CRED001", "critical")])
        assert "ISSUES FOUND" in result

    def test_html_passes_count_reflects_unfired_rules(self):
        result = build_html_report([])
        assert "15/15" in result

    def test_html_passes_count_excludes_info_findings(self):
        # INFO finding should not reduce the pass count
        result = build_html_report([_finding("CRED002", "info")])
        assert "15/15" in result

    def test_html_passes_count_decreases_with_actionable_findings(self):
        result = build_html_report([_finding("CRED001", "critical")])
        assert "14/15" in result

    def test_html_info_findings_appear_in_notes_section(self):
        result = build_html_report([_finding("CRED002", "info")])
        assert "Notes" in result
        assert "Informational only" in result

    def test_html_info_findings_not_in_findings_section_header(self):
        # Findings section should say 0 actionable, not count INFO
        result = build_html_report([_finding("CRED002", "info")])
        assert "No actionable findings" in result

    def test_html_escapes_special_characters(self):
        result = build_html_report(
            [_finding("ERR001", "medium", node_name="<script>alert(1)</script>")]
        )
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_html_contains_remediation_text(self):
        result = build_html_report([_finding("WEBHOOK001", "high")])
        assert "headerAuth" in result
