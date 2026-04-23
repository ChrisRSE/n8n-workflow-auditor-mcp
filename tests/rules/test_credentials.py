"""Tests for credential hygiene rules CRED001–CRED004."""

from n8n_auditor.rules.base import Severity
from n8n_auditor.rules.credentials import (
    CredentialHardcoded,
    CredentialNotConfigured,
    CredentialOAuthExpiry,
    CredentialOverPermissiveScope,
)
from tests.conftest import load_fixture

# ---------------------------------------------------------------------------
# CRED001 — Hardcoded credentials
# ---------------------------------------------------------------------------


class TestCred001:
    rule = CredentialHardcoded()

    def test_fires_on_openai_key(self):
        workflow = load_fixture("hardcoded_secrets")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "CRED001"]
        assert len(rule_findings) >= 1
        # At least one finding should point to the sk- prefixed value
        assert any("sk-" in f.evidence for f in rule_findings)

    def test_fires_on_github_token(self):
        workflow = load_fixture("hardcoded_secrets")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "CRED001"]
        assert any("ghp_" in f.evidence for f in rule_findings)

    def test_fires_on_secret_param_name(self):
        workflow = load_fixture("hardcoded_secrets")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "CRED001"]
        assert any("password" in f.evidence.lower() for f in rule_findings)

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_expression_values(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {
                        "headerParameters": {
                            "parameters": [
                                {"name": "Authorization", "value": "={{ $json.apiKey }}"}
                            ]
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_finding_severity_is_critical(self):
        workflow = load_fixture("hardcoded_secrets")
        findings = self.rule.check(workflow)
        rule_findings = [f for f in findings if f.rule_id == "CRED001"]
        assert all(f.severity == Severity.CRITICAL for f in rule_findings)

    def test_evidence_redacts_secret_value(self):
        workflow = load_fixture("hardcoded_secrets")
        findings = self.rule.check(workflow)
        # Ensure the full secret value is not exposed
        full_key = "sk-abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret
        for f in findings:
            assert full_key not in f.evidence
            assert full_key not in f.message


# ---------------------------------------------------------------------------
# CRED002 — OAuth expiry
# ---------------------------------------------------------------------------


class TestCred002:
    rule = CredentialOAuthExpiry()

    def test_fires_info_on_oauth_credential(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Google Sheets",
                    "type": "n8n-nodes-base.googleSheets",
                    "parameters": {},
                    "credentials": {
                        "googleSheetsOAuth2Api": {
                            "id": "cred-1",
                            "name": "My Sheets Cred",
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "CRED002"
        assert findings[0].severity == Severity.INFO

    def test_fires_critical_on_expired_token(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Gmail",
                    "type": "n8n-nodes-base.gmail",
                    "parameters": {},
                    "credentials": {
                        "gmailOAuth2": {
                            "id": "cred-2",
                            "name": "My Gmail",
                            "oauthTokenData": {
                                "expiration_date": 1000000000000,  # year 2001 — expired
                            },
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_does_not_fire_on_non_oauth_credential(self):
        workflow = load_fixture("clean_workflow")
        # clean_workflow uses httpHeaderAuth — not an OAuth type
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_node_without_credentials(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Set",
                    "type": "n8n-nodes-base.set",
                    "parameters": {"value": "hello"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []


# ---------------------------------------------------------------------------
# CRED003 — Credential not configured
# ---------------------------------------------------------------------------


class TestCred003:
    rule = CredentialNotConfigured()

    def test_fires_when_id_is_empty_string(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                    "credentials": {
                        "httpHeaderAuth": {
                            "id": "",
                            "name": "Unconfigured Auth",
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "CRED003"
        assert findings[0].severity == Severity.HIGH

    def test_fires_when_id_is_null(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                    "credentials": {
                        "httpHeaderAuth": {
                            "id": None,
                            "name": "Null ID Auth",
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_when_id_present(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_node_without_credentials_key(self):
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


# ---------------------------------------------------------------------------
# CRED004 — Over-permissive scope
# ---------------------------------------------------------------------------


class TestCred004:
    rule = CredentialOverPermissiveScope()

    def test_fires_on_google_sheets_using_broad_cred(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Google Sheets",
                    "type": "n8n-nodes-base.googleSheets",
                    "parameters": {},
                    "credentials": {"googleApi": {"id": "cred-1", "name": "Google API"}},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "CRED004"
        assert findings[0].severity == Severity.MEDIUM
        assert "googleSheetsOAuth2Api" in findings[0].message

    def test_fires_on_gmail_using_broad_cred(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Gmail",
                    "type": "n8n-nodes-base.gmail",
                    "parameters": {},
                    "credentials": {"googleApi": {"id": "cred-1", "name": "Google API"}},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert "gmailOAuth2" in findings[0].message

    def test_does_not_fire_on_preferred_credential_type(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Google Sheets",
                    "type": "n8n-nodes-base.googleSheets",
                    "parameters": {},
                    "credentials": {
                        "googleSheetsOAuth2Api": {"id": "cred-1", "name": "Sheets Cred"}
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_non_google_node(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_clean_workflow(self):
        workflow = load_fixture("clean_workflow")
        findings = self.rule.check(workflow)
        assert findings == []


# ---------------------------------------------------------------------------
# Edge cases — non-dict credential shapes
# ---------------------------------------------------------------------------


class TestCred002EdgeCases:
    rule = CredentialOAuthExpiry()

    def test_credentials_not_dict_is_skipped(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.gmail",
                    "credentials": "not_a_dict",
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_cred_ref_not_dict_is_handled(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.gmail",
                    "credentials": {"gmailOAuth2": "string_not_dict"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        rule_ids = [f.rule_id for f in findings]
        assert "CRED002" in rule_ids

    def test_invalid_expiry_format_does_not_raise(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.gmail",
                    "credentials": {
                        "gmailOAuth2": {
                            "name": "cred1",
                            "oauthTokenData": {"expirationDate": "not-a-valid-date"},
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert isinstance(findings, list)


class TestCred003EdgeCases:
    rule = CredentialNotConfigured()

    def test_credentials_not_dict_is_skipped(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.gmail",
                    "credentials": "not_a_dict",
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_cred_ref_not_dict_is_skipped(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.gmail",
                    "credentials": {"gmailOAuth2": "string_not_dict"},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []


class TestCred004EdgeCases:
    rule = CredentialOverPermissiveScope()

    def test_credentials_not_dict_is_skipped(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Node",
                    "type": "n8n-nodes-base.googleSheets",
                    "credentials": "not_a_dict",
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []
