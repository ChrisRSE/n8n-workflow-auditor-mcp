"""MCP tool implementations."""

import httpx

from .connector import N8nConnector
from .engine import run_audit
from .parser import WorkflowParseError, parse_workflow
from .rules.credentials import (
    CredentialHardcoded,
    CredentialNotConfigured,
    CredentialOAuthExpiry,
    CredentialOverPermissiveScope,
)
from .rules.deprecations import NodeDeprecatedVersion, NodeTypeRemoved
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

def audit_workflow(workflow_input: str) -> dict:
    """Run all 15 audit rules against a workflow.

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
    return run_audit(workflow).to_dict()


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
    """Detect deprecated or removed node types.

    Runs rules DEPR001–DEPR002:
    - DEPR001: Node using a deprecated typeVersion
    - DEPR002: Node type removed in current n8n version

    Args:
        workflow_input: Absolute file path to a workflow JSON file, OR the raw
            workflow JSON string.
        n8n_version: Optional n8n version string (currently unused; reserved for
            future version-gated deprecation checks).

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
    return run_audit(workflow, rules=[NodeDeprecatedVersion(), NodeTypeRemoved()]).to_dict()


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
    """Audit all workflows in a live n8n instance.

    Fetches all workflows via the n8n REST API and runs the full rule set
    against each. Does not call n8n's built-in /audit endpoint (see DECISION-003).

    Args:
        base_url: Base URL of the n8n instance (e.g. "https://n8n.example.com").
        api_key: n8n API key (set via Settings → API in the n8n UI).

    Returns:
        Dict with keys:
        - ``findings``: aggregated findings across all workflows
        - ``summary``: counts by severity
        - ``total``: total finding count
        - ``workflow_count``: number of workflows audited
    """
    try:
        workflows = N8nConnector(base_url, api_key).fetch_all_workflows()
    except httpx.HTTPError as exc:
        return {"error": str(exc), "findings": [], "summary": {}, "total": 0, "workflow_count": 0}

    all_findings = []
    for wf in workflows:
        all_findings.extend(run_audit(wf).findings)

    summary: dict[str, int] = {}
    for f in all_findings:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

    return {
        "findings": [f.to_dict() for f in all_findings],
        "summary": summary,
        "total": len(all_findings),
        "workflow_count": len(workflows),
    }


def suggest_fixes(finding_ids: list[str], workflow_input: str) -> dict:
    """Generate before/after node diffs for listed finding IDs. (Implemented in Session 5.)"""
    return {"status": "not_implemented"}


def generate_audit_report(findings: list[dict], format: str = "md") -> dict:
    """Generate a client-ready audit report. (Implemented in Session 5.)"""
    return {"status": "not_implemented"}
