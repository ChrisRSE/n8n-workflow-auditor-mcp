"""Tests for reliability rules REL001–REL002."""

from n8n_auditor.rules.base import Severity
from n8n_auditor.rules.reliability import HttpRequestNoRetry, WorkflowHasUnboundedLoop
from tests.conftest import load_fixture

# ---------------------------------------------------------------------------
# REL001 — HTTP Request node without retry configuration
# ---------------------------------------------------------------------------


class TestRel001:
    rule = HttpRequestNoRetry()

    def test_fires_when_retry_absent(self):
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
        assert len(findings) == 1
        assert findings[0].rule_id == "REL001"

    def test_fires_when_retry_false(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {"retryOnFail": False},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_when_retry_on(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {"retryOnFail": True},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_non_http_node(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Set",
                    "type": "n8n-nodes-base.set",
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_fires_on_deprecated_nodes_fixture(self):
        # deprecated_nodes.json has an httpRequest with no retryOnFail
        workflow = load_fixture("deprecated_nodes")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_name == "Old HTTP"

    def test_severity_is_low(self):
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
        assert all(f.severity == Severity.LOW for f in findings)


# ---------------------------------------------------------------------------
# REL002 — Batch loop without a Stop and Error node
# ---------------------------------------------------------------------------


class TestRel002:
    rule = WorkflowHasUnboundedLoop()

    def test_fires_when_split_and_no_stop(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Loop Over Items",
                    "type": "n8n-nodes-base.splitInBatches",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "Process",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                },
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "REL002"

    def test_does_not_fire_when_stop_and_error_present(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Loop Over Items",
                    "type": "n8n-nodes-base.splitInBatches",
                    "parameters": {},
                },
                {
                    "id": "n2",
                    "name": "Stop on Error",
                    "type": "n8n-nodes-base.stopAndError",
                    "parameters": {},
                },
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_without_loop_node(self):
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

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_finding_names_loop_node(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Batch Processor",
                    "type": "n8n-nodes-base.splitInBatches",
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].node_name == "Batch Processor"

    def test_severity_is_medium(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Loop Over Items",
                    "type": "n8n-nodes-base.splitInBatches",
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.MEDIUM for f in findings)
