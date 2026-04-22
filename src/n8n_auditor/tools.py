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
from .rules.errors import (
    ErrorBranchSilentFailure,
    NodeNoErrorRouting,
    WorkflowNoErrorTrigger,
    _is_auditable_node,
)
from .rules.webhooks import (
    WebhookDirectToCode,
    WebhookExposesInternalData,
    WebhookNoAuth,
    WebhookNoRateLimit,
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
    """Check webhook nodes for security issues.

    Runs rules WEBHOOK001–WEBHOOK004:
    - WEBHOOK001: Inbound webhook without authentication
    - WEBHOOK002: Webhook connects directly to Code node without validation
    - WEBHOOK003: Webhook node has no rate limiting (advisory)
    - WEBHOOK004: Webhook response exposes internal data

    Args:
        workflow_input: Absolute file path to a workflow JSON file, OR the raw
            workflow JSON string.

    Returns:
        Dict with keys:
        - ``findings``: list of finding dicts
        - ``summary``: counts by severity
        - ``total``: total finding count
    """
    try:
        workflow = parse_workflow(workflow_input)
    except WorkflowParseError as exc:
        return {"error": str(exc), "findings": [], "summary": {}, "total": 0}

    rules = [
        WebhookNoAuth(),
        WebhookDirectToCode(),
        WebhookNoRateLimit(),
        WebhookExposesInternalData(),
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


def detect_deprecations(workflow_input: str, n8n_version: str = "") -> dict:
    """Detect deprecated or removed node types. (Implemented in Session 4.)"""
    return _NOT_IMPLEMENTED


def error_handling_coverage(workflow_input: str) -> dict:
    """Report error-handling coverage across all nodes.

    Runs rules ERR001–ERR003:
    - ERR001: Node has no error output routing
    - ERR002: Workflow has no top-level Error Trigger node
    - ERR003: Error branch leads to silent failure (noOp)

    Args:
        workflow_input: Absolute file path to a workflow JSON file, OR the raw
            workflow JSON string.

    Returns:
        Dict with keys:
        - ``findings``: list of finding dicts
        - ``summary``: counts by severity
        - ``total``: total finding count
        - ``coverage``: dict with auditable_nodes, nodes_with_error_routing,
          coverage_percent
    """
    try:
        workflow = parse_workflow(workflow_input)
    except WorkflowParseError as exc:
        return {
            "error": str(exc),
            "findings": [],
            "summary": {},
            "total": 0,
            "coverage": {
                "auditable_nodes": 0,
                "nodes_with_error_routing": 0,
                "coverage_percent": 0.0,
            },
        }

    rules = [
        NodeNoErrorRouting(),
        WorkflowNoErrorTrigger(),
        ErrorBranchSilentFailure(),
    ]

    findings = []
    for rule in rules:
        findings.extend(rule.check(workflow))

    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

    connections = workflow.get("connections", {})
    auditable_nodes = [
        n for n in workflow.get("nodes", []) if _is_auditable_node(n.get("type", ""))
    ]
    nodes_with_error_routing = [
        n for n in auditable_nodes if connections.get(n.get("name", ""), {}).get("error")
    ]
    auditable_count = len(auditable_nodes)
    routed_count = len(nodes_with_error_routing)
    coverage_pct = (routed_count / auditable_count * 100.0) if auditable_count > 0 else 0.0

    return {
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        "total": len(findings),
        "coverage": {
            "auditable_nodes": auditable_count,
            "nodes_with_error_routing": routed_count,
            "coverage_percent": round(coverage_pct, 1),
        },
    }


def analyse_instance(base_url: str, api_key: str) -> dict:
    """Audit all workflows in a live n8n instance. (Implemented in Session 4.)"""
    return _NOT_IMPLEMENTED


def suggest_fixes(finding_ids: list[str], workflow_input: str) -> dict:
    """Generate before/after node diffs for listed finding IDs. (Implemented in Session 5.)"""
    return _NOT_IMPLEMENTED


def generate_audit_report(findings: list[dict], format: str = "md") -> dict:
    """Generate a client-ready audit report. (Implemented in Session 5.)"""
    return _NOT_IMPLEMENTED
