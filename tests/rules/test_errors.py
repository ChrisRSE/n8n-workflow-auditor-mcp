"""Tests for error handling coverage rules ERR001–ERR003."""

from n8n_auditor.rules.base import Severity
from n8n_auditor.rules.errors import (
    ErrorBranchSilentFailure,
    NodeNoErrorRouting,
    WorkflowNoErrorTrigger,
)
from tests.conftest import load_fixture

# ---------------------------------------------------------------------------
# ERR001 — Node has no error output connection
# ---------------------------------------------------------------------------


class TestErr001:
    rule = NodeNoErrorRouting()

    def test_fires_on_node_without_error_routing(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "ERR001"]
        assert len(rule_findings) >= 1

    def test_fires_exactly_once_for_transform_data_node(self):
        # Fetch Data has error routing; only Transform Data (set) does not.
        # Schedule Trigger and Silent Error Handler (noOp) are excluded.
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_name == "Transform Data"

    def test_does_not_fire_on_trigger_nodes(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        node_names = [f.node_name for f in findings]
        assert "Schedule Trigger" not in node_names

    def test_does_not_fire_on_noop_nodes(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        node_names = [f.node_name for f in findings]
        assert "Silent Error Handler" not in node_names

    def test_does_not_fire_on_node_with_error_routing(self):
        # HTTP Request has error routing — it should not be flagged.
        # Slack has no error routing, so ERR001 fires for it (expected);
        # we assert only that HTTP Request is NOT in the findings.
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "Notify Slack",
                    "type": "n8n-nodes-base.slack",
                    "parameters": {},
                },
            ],
            "connections": {
                "HTTP Request": {
                    "error": [[{"node": "Notify Slack", "type": "main", "index": 0}]]
                }
            },
        }
        findings = self.rule.check(workflow)
        node_names = [f.node_name for f in findings]
        assert "HTTP Request" not in node_names

    def test_severity_is_medium(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_finding_names_node_and_type(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "Transform Data" in findings[0].message
        assert "n8n-nodes-base.set" in findings[0].message


# ---------------------------------------------------------------------------
# ERR002 — Workflow has no top-level Error Trigger
# ---------------------------------------------------------------------------


class TestErr002:
    rule = WorkflowNoErrorTrigger()

    def test_fires_when_no_error_trigger(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "ERR002"

    def test_fires_on_clean_workflow(self):
        # clean_workflow has no errorTrigger node either
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_when_error_trigger_present(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Error Trigger",
                    "type": "n8n-nodes-base.errorTrigger",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "Notify",
                    "type": "n8n-nodes-base.slack",
                    "parameters": {},
                },
            ],
            "connections": {
                "Error Trigger": {"main": [[{"node": "Notify", "type": "main", "index": 0}]]}
            },
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_finding_is_workflow_level(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_id is None
        assert findings[0].node_name is None

    def test_severity_is_high(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# ERR003 — Error branch leads to silent failure (noOp)
# ---------------------------------------------------------------------------


class TestErr003:
    rule = ErrorBranchSilentFailure()

    def test_fires_when_error_branch_leads_to_noop(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "ERR003"

    def test_fires_on_correct_source_node(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert findings[0].node_name == "Fetch Data"

    def test_does_not_fire_when_error_branch_leads_to_slack(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "Notify Slack",
                    "type": "n8n-nodes-base.slack",
                    "parameters": {},
                },
            ],
            "connections": {
                "HTTP Request": {
                    "error": [[{"node": "Notify Slack", "type": "main", "index": 0}]]
                }
            },
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_clean_workflow(self):
        # clean_workflow has no error connections at all
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_when_noop_on_main_not_error(self):
        # noOp reached via "main" output should not trigger ERR003
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "No Op",
                    "type": "n8n-nodes-base.noOp",
                    "parameters": {},
                },
            ],
            "connections": {
                "HTTP Request": {"main": [[{"node": "No Op", "type": "main", "index": 0}]]}
            },
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_medium(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_evidence_names_source_and_noop(self):
        workflow = load_fixture("no_error_handling")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "Fetch Data" in findings[0].message
        assert "Silent Error Handler" in findings[0].message
