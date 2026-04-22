"""Unit tests for the fix suggestion engine."""

from n8n_auditor.fix_suggester import generate_fixes
from n8n_auditor.rules.base import Finding, Severity


def _finding(
    rule_id: str, severity: Severity, node_id: str | None, node_name: str | None
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message="test message",
        evidence="test evidence",
        node_id=node_id,
        node_name=node_name,
    )


def _webhook_workflow(auth: str = "none") -> dict:
    return {
        "nodes": [
            {
                "id": "n1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "parameters": {"authentication": auth},
            }
        ]
    }


def _http_workflow() -> dict:
    return {
        "nodes": [
            {
                "id": "n1",
                "name": "HTTP Request",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {},
            }
        ]
    }


def _depr001_workflow() -> dict:
    return {
        "nodes": [
            {
                "id": "n1",
                "name": "Old HTTP",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 1,
                "parameters": {},
            }
        ]
    }


def _depr002_workflow() -> dict:
    return {
        "nodes": [
            {
                "id": "n2",
                "name": "Legacy Function",
                "type": "n8n-nodes-base.function",
                "typeVersion": 1,
                "parameters": {},
            }
        ]
    }


class TestWebhook001Fix:
    def test_returns_modify_node_fix_type(self):
        finding = _finding("WEBHOOK001", Severity.HIGH, "n1", "Webhook")
        fixes = generate_fixes([finding], _webhook_workflow())
        assert fixes[0]["fix_type"] == "modify_node"

    def test_before_has_original_auth(self):
        finding = _finding("WEBHOOK001", Severity.HIGH, "n1", "Webhook")
        fixes = generate_fixes([finding], _webhook_workflow(auth="none"))
        assert fixes[0]["before"]["parameters"]["authentication"] == "none"

    def test_after_sets_header_auth(self):
        finding = _finding("WEBHOOK001", Severity.HIGH, "n1", "Webhook")
        fixes = generate_fixes([finding], _webhook_workflow())
        assert fixes[0]["after"]["parameters"]["authentication"] == "headerAuth"

    def test_before_and_after_are_independent_copies(self):
        finding = _finding("WEBHOOK001", Severity.HIGH, "n1", "Webhook")
        fixes = generate_fixes([finding], _webhook_workflow())
        fixes[0]["after"]["parameters"]["authentication"] = "MUTATED"
        assert fixes[0]["before"]["parameters"]["authentication"] != "MUTATED"


class TestRel001Fix:
    def test_returns_modify_node_fix_type(self):
        finding = _finding("REL001", Severity.LOW, "n1", "HTTP Request")
        fixes = generate_fixes([finding], _http_workflow())
        assert fixes[0]["fix_type"] == "modify_node"

    def test_after_enables_retry(self):
        finding = _finding("REL001", Severity.LOW, "n1", "HTTP Request")
        fixes = generate_fixes([finding], _http_workflow())
        assert fixes[0]["after"]["parameters"]["retryOnFail"] is True

    def test_after_sets_max_tries(self):
        finding = _finding("REL001", Severity.LOW, "n1", "HTTP Request")
        fixes = generate_fixes([finding], _http_workflow())
        assert fixes[0]["after"]["parameters"]["maxTries"] == 3


class TestDepr001Fix:
    def test_upgrades_typeversion_to_current(self):
        finding = _finding("DEPR001", Severity.MEDIUM, "n1", "Old HTTP")
        fixes = generate_fixes([finding], _depr001_workflow())
        assert fixes[0]["after"]["typeVersion"] == 4

    def test_before_has_old_version(self):
        finding = _finding("DEPR001", Severity.MEDIUM, "n1", "Old HTTP")
        fixes = generate_fixes([finding], _depr001_workflow())
        assert fixes[0]["before"]["typeVersion"] == 1

    def test_fix_type_is_modify_node(self):
        finding = _finding("DEPR001", Severity.MEDIUM, "n1", "Old HTTP")
        fixes = generate_fixes([finding], _depr001_workflow())
        assert fixes[0]["fix_type"] == "modify_node"


class TestDepr002Fix:
    def test_changes_type_to_replacement(self):
        finding = _finding("DEPR002", Severity.HIGH, "n2", "Legacy Function")
        fixes = generate_fixes([finding], _depr002_workflow())
        assert fixes[0]["after"]["type"] == "n8n-nodes-base.code"

    def test_before_has_removed_type(self):
        finding = _finding("DEPR002", Severity.HIGH, "n2", "Legacy Function")
        fixes = generate_fixes([finding], _depr002_workflow())
        assert fixes[0]["before"]["type"] == "n8n-nodes-base.function"

    def test_fix_type_is_modify_node(self):
        finding = _finding("DEPR002", Severity.HIGH, "n2", "Legacy Function")
        fixes = generate_fixes([finding], _depr002_workflow())
        assert fixes[0]["fix_type"] == "modify_node"


class TestAdvisoryFallback:
    def test_cred001_returns_advisory(self):
        finding = _finding("CRED001", Severity.CRITICAL, "n1", "Node")
        workflow = {
            "nodes": [{"id": "n1", "name": "Node", "type": "n8n-nodes-base.set", "parameters": {}}]
        }
        fixes = generate_fixes([finding], workflow)
        assert fixes[0]["fix_type"] == "advisory"
        assert fixes[0]["before"] is None
        assert fixes[0]["after"] is None

    def test_unknown_rule_returns_advisory(self):
        finding = _finding("UNKNOWN999", Severity.INFO, None, None)
        fixes = generate_fixes([finding], {"nodes": []})
        assert fixes[0]["fix_type"] == "advisory"

    def test_missing_node_id_falls_back_to_advisory(self):
        finding = _finding("WEBHOOK001", Severity.HIGH, "nonexistent-id", "Webhook")
        fixes = generate_fixes([finding], {"nodes": []})
        assert fixes[0]["fix_type"] == "advisory"

    def test_advisory_has_instructions(self):
        finding = _finding("CRED001", Severity.CRITICAL, None, None)
        fixes = generate_fixes([finding], {"nodes": []})
        assert isinstance(fixes[0]["instructions"], str)
        assert len(fixes[0]["instructions"]) > 10


def test_empty_findings_returns_empty_list():
    assert generate_fixes([], {"nodes": []}) == []


def test_multiple_findings_returns_one_fix_each():
    findings = [
        _finding("WEBHOOK001", Severity.HIGH, "n1", "Webhook"),
        _finding("REL001", Severity.LOW, "n2", "HTTP"),
    ]
    workflow = {
        "nodes": [
            {
                "id": "n1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "parameters": {"authentication": "none"},
            },
            {"id": "n2", "name": "HTTP", "type": "n8n-nodes-base.httpRequest", "parameters": {}},
        ]
    }
    fixes = generate_fixes(findings, workflow)
    assert len(fixes) == 2
