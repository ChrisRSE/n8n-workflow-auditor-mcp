"""Tests for deprecation rules DEPR001–DEPR002."""

from n8n_auditor.rules.base import Severity
from n8n_auditor.rules.deprecations import NodeDeprecatedVersion, NodeTypeRemoved
from tests.conftest import load_fixture

# ---------------------------------------------------------------------------
# DEPR001 — Node using a deprecated typeVersion
# ---------------------------------------------------------------------------


class TestDepr001:
    rule = NodeDeprecatedVersion()

    def test_fires_on_deprecated_type_version(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "DEPR001"]
        assert len(rule_findings) >= 1

    def test_fires_on_correct_node(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_name == "Old HTTP"

    def test_does_not_fire_on_current_version(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "typeVersion": 4,
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_when_no_typeversion_field(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_unlisted_type(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Slack",
                    "type": "n8n-nodes-base.slack",
                    "typeVersion": 1,
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_medium(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_evidence_contains_version_info(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "typeVersion" in findings[0].evidence
        assert "1" in findings[0].evidence


# ---------------------------------------------------------------------------
# DEPR002 — Node type removed in current n8n version
# ---------------------------------------------------------------------------


class TestDepr002:
    rule = NodeTypeRemoved()

    def test_fires_on_removed_node_type(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "DEPR002"]
        assert len(rule_findings) >= 1

    def test_fires_on_correct_node(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_name == "Legacy Function"

    def test_does_not_fire_on_current_type(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Code",
                    "type": "n8n-nodes-base.code",
                    "typeVersion": 2,
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_high(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_evidence_names_replacement_type(self):
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "n8n-nodes-base.code" in findings[0].evidence
