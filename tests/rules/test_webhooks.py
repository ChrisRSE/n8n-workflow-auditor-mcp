"""Tests for webhook security rules WEBHOOK001–WEBHOOK004."""

from n8n_auditor.rules.base import Severity
from n8n_auditor.rules.webhooks import (
    WebhookDirectToCode,
    WebhookExposesInternalData,
    WebhookNoAuth,
    WebhookNoRateLimit,
)
from tests.conftest import load_fixture

# ---------------------------------------------------------------------------
# WEBHOOK001 — Inbound webhook without authentication
# ---------------------------------------------------------------------------


class TestWebhook001:
    rule = WebhookNoAuth()

    def test_fires_when_auth_is_none(self):
        workflow = load_fixture("unauth_webhook")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "WEBHOOK001"

    def test_fires_when_auth_key_missing(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"path": "hook"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_when_header_auth(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"authentication": "headerAuth"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_when_basic_auth(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"authentication": "basicAuth"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_non_webhook_node(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_high(self):
        workflow = load_fixture("unauth_webhook")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_finding_includes_parameter_evidence(self):
        workflow = load_fixture("unauth_webhook")
        findings = self.rule.check(workflow)
        assert any("authentication" in f.evidence for f in findings)


# ---------------------------------------------------------------------------
# WEBHOOK002 — Webhook connects directly to Code node
# ---------------------------------------------------------------------------


class TestWebhook002:
    rule = WebhookDirectToCode()

    def test_fires_on_direct_webhook_to_code(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "WEBHOOK002"

    def test_does_not_fire_when_if_node_between(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"authentication": "headerAuth"},
                },
                {
                    "id": "n2",
                    "name": "Validate Input",
                    "type": "n8n-nodes-base.if",
                    "parameters": {},
                },
                {
                    "id": "n3",
                    "name": "Run Script",
                    "type": "n8n-nodes-base.code",
                    "parameters": {},
                },
            ],
            "connections": {
                "Webhook": {"main": [[{"node": "Validate Input", "type": "main", "index": 0}]]},
                "Validate Input": {"main": [[{"node": "Run Script", "type": "main", "index": 0}]]},
            },
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_when_webhook_to_set(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Webhook",
                    "type": "n8n-nodes-base.webhook",
                    "parameters": {"authentication": "headerAuth"},
                },
                {"id": "n2", "name": "Set", "type": "n8n-nodes-base.set", "parameters": {}},
            ],
            "connections": {
                "Webhook": {"main": [[{"node": "Set", "type": "main", "index": 0}]]},
            },
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_high(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_evidence_names_both_nodes(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "Webhook" in findings[0].message
        assert "Run Script" in findings[0].message


# ---------------------------------------------------------------------------
# WEBHOOK003 — Webhook without rate limiting
# ---------------------------------------------------------------------------


class TestWebhook003:
    rule = WebhookNoRateLimit()

    def test_fires_on_unauth_webhook_fixture(self):
        workflow = load_fixture("unauth_webhook")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "WEBHOOK003"

    def test_fires_on_authenticated_webhook(self):
        # Rate limiting fires regardless of auth status
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_workflow_with_no_webhook(self):
        workflow = {
            "nodes": [
                {"id": "n1", "name": "Set", "type": "n8n-nodes-base.set", "parameters": {}}
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_low(self):
        workflow = load_fixture("unauth_webhook")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.LOW for f in findings)


# ---------------------------------------------------------------------------
# WEBHOOK004 — Webhook response exposes internal data
# ---------------------------------------------------------------------------


class TestWebhook004:
    rule = WebhookExposesInternalData()

    def test_fires_on_json_dollar_expression(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "WEBHOOK004"

    def test_fires_on_respond_with_all_entries(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Respond",
                    "type": "n8n-nodes-base.respondToWebhook",
                    "parameters": {"respondWith": "allEntries"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "allEntries" in findings[0].evidence

    def test_does_not_fire_when_specific_field_selected(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Respond",
                    "type": "n8n-nodes-base.respondToWebhook",
                    "parameters": {
                        "respondWith": "json",
                        "responseBody": "={{ $json.id }}",
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_non_respond_node(self):
        workflow = {
            "nodes": [
                {"id": "n1", "name": "Set", "type": "n8n-nodes-base.set", "parameters": {}}
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_medium(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_evidence_contains_offending_value(self):
        workflow = load_fixture("webhook_ssrf_chain")
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "$json" in findings[0].evidence
