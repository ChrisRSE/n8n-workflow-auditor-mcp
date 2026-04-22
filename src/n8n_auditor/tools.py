"""MCP tool implementations.

scan_credentials is fully implemented.
All other tools are stubs that return {status: not_implemented} so the
server starts cleanly and Claude Desktop can discover the full tool list.
"""

from .parser import WorkflowParseError, parse_workflow
from .rules.credentials import (
    CredentialHardcoded,
    CredentialNotConfigured,
    CredentialOAuthExpiry,
    CredentialOverPermissiveScope,
)

# ---------------------------------------------------------------------------
# Implemented tools
# ---------------------------------------------------------------------------


def scan_credentials(workflow_input: str) -> dict:
    """Scan an n8n workflow for credential hygiene issues.

    Runs rules CRED001–CRED004:
    - CRED001: Hardcoded credentials in node parameters
    - CRED002: OAuth credential expiry / unverifiable tokens
    - CRED003: Credential referenced but not configured
    - CRED004: Over-permissive Google OAuth scope

    Args:
        workflow_input: Absolute file path to a workflow JSON file, OR the raw
            workflow JSON string.

    Returns:
        Dict with keys:
        - ``findings``: list of finding dicts (rule_id, severity, node_id,
          node_name, message, evidence)
        - ``summary``: counts by severity
        - ``total``: total finding count
    """
    try:
        workflow = parse_workflow(workflow_input)
    except WorkflowParseError as exc:
        return {"error": str(exc), "findings": [], "summary": {}, "total": 0}

    rules = [
        CredentialHardcoded(),
        CredentialOAuthExpiry(),
        CredentialNotConfigured(),
        CredentialOverPermissiveScope(),
    ]

    findings = []
    for rule in rules:
        findings.extend(rule.check(workflow))

    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

    return {
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        "total": len(findings),
    }


# ---------------------------------------------------------------------------
# Stub tools — to be implemented in Sessions 3–5
# ---------------------------------------------------------------------------

_NOT_IMPLEMENTED = {"status": "not_implemented"}


def audit_workflow(workflow_input: str) -> dict:
    """Run all audit rules against a workflow. (Implemented in Session 4.)"""
    return _NOT_IMPLEMENTED


def check_webhooks(workflow_input: str) -> dict:
    """Check webhook nodes for security issues. (Implemented in Session 3.)"""
    return _NOT_IMPLEMENTED


def detect_deprecations(workflow_input: str, n8n_version: str = "") -> dict:
    """Detect deprecated or removed node types. (Implemented in Session 4.)"""
    return _NOT_IMPLEMENTED


def error_handling_coverage(workflow_input: str) -> dict:
    """Report error-handling coverage across all nodes. (Implemented in Session 3.)"""
    return _NOT_IMPLEMENTED


def analyse_instance(base_url: str, api_key: str) -> dict:
    """Audit all workflows in a live n8n instance. (Implemented in Session 4.)"""
    return _NOT_IMPLEMENTED


def suggest_fixes(finding_ids: list[str], workflow_input: str) -> dict:
    """Generate before/after node diffs for listed finding IDs. (Implemented in Session 5.)"""
    return _NOT_IMPLEMENTED


def generate_audit_report(findings: list[dict], format: str = "md") -> dict:
    """Generate a client-ready audit report. (Implemented in Session 5.)"""
    return _NOT_IMPLEMENTED
