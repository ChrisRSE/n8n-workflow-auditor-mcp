"""Fix suggestion engine — generates before/after node diffs for audit findings."""

import copy
from collections.abc import Callable
from pathlib import Path

import yaml

from .rules.base import Finding

_DEPR_CATALOGUE: dict = yaml.safe_load(
    (Path(__file__).parent / "rules" / "definitions" / "deprecations.yaml").read_text(
        encoding="utf-8"
    )
)

_ADVISORY_TEXT: dict[str, str] = {
    "CRED001": (
        "Move the hardcoded value into n8n's credential manager. "
        "Create a credential of the appropriate type and reference it in the node — "
        "never paste raw API keys into node parameter fields."
    ),
    "CRED002": (
        "Re-authenticate the OAuth credential in the n8n credential manager to refresh the token. "
        "Use analyse_instance for live expiry checks when n8n API access is available."
    ),
    "CRED003": (
        "Open n8n Settings → Credentials and configure this credential. "
        "Then link it to the node via the credential selector in the node editor."
    ),
    "CRED004": (
        "Replace the 'googleApi' credential with the service-specific OAuth2 credential "
        "(e.g. googleSheetsOAuth2Api for Google Sheets). "
        "This enforces least-privilege scope."
    ),
    "WEBHOOK002": (
        "Insert an IF, Switch, or Set node between the Webhook and Code nodes "
        "to validate and sanitise incoming data before it reaches executable code."
    ),
    "WEBHOOK003": (
        "Implement rate limiting at the infrastructure layer "
        "(reverse proxy, API gateway, or cloud load balancer) in front of the n8n instance. "
        "See https://docs.n8n.io/hosting/securing-n8n/ for guidance."
    ),
    "WEBHOOK004": (
        "Construct an explicit response object using a Set node before RespondToWebhook, "
        "selecting only the fields the caller requires. Avoid returning $json wholesale."
    ),
    "ERR001": (
        "Add an error output connection from this node to a notification node (Slack, email) "
        "or logging node. Configure it via the node's 'On Error' settings in the n8n editor."
    ),
    "ERR002": (
        "Add an Error Trigger node connected to a notification or logging action. "
        "This can live in a separate workflow designated as the instance-level error handler."
    ),
    "ERR003": (
        "Replace the noOp terminal with a notification node (Slack, email, PagerDuty) "
        "or a logging action so errors are not silently discarded."
    ),
    "REL002": (
        "Add a Stop and Error node inside or after the SplitInBatches loop as a circuit breaker. "
        "Alternatively, add an IF node with a counter check to break the loop under unexpected conditions."
    ),
}


def _find_node_by_id(workflow: dict, node_id: str | None) -> dict | None:
    if not node_id:
        return None
    return next((n for n in workflow.get("nodes", []) if n.get("id") == node_id), None)


def _deep_update(base: dict, patch: dict) -> None:
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v


def _node_diff_fix(
    finding: Finding,
    workflow: dict,
    patch: dict,
    description: str,
    instructions: str,
) -> dict:
    node = _find_node_by_id(workflow, finding.node_id)
    if node is None:
        return _advisory_fix(finding, instructions)
    before = copy.deepcopy(node)
    after = copy.deepcopy(node)
    _deep_update(after, patch)
    return {
        "rule_id": finding.rule_id,
        "node_id": finding.node_id,
        "node_name": finding.node_name,
        "description": description,
        "fix_type": "modify_node",
        "before": before,
        "after": after,
        "instructions": instructions,
    }


def _advisory_fix(finding: Finding, instructions: str) -> dict:
    return {
        "rule_id": finding.rule_id,
        "node_id": finding.node_id,
        "node_name": finding.node_name,
        "description": "Manual action required",
        "fix_type": "advisory",
        "before": None,
        "after": None,
        "instructions": instructions,
    }


def _fix_webhook001(finding: Finding, workflow: dict) -> dict:
    return _node_diff_fix(
        finding,
        workflow,
        patch={"parameters": {"authentication": "headerAuth"}},
        description="Add header authentication to the Webhook node",
        instructions=(
            "In the n8n editor, open this Webhook node and set Authentication to 'Header Auth'. "
            "Create a Header Auth credential with a strong, random token and share it only with trusted callers."
        ),
    )


def _fix_rel001(finding: Finding, workflow: dict) -> dict:
    return _node_diff_fix(
        finding,
        workflow,
        patch={"parameters": {"retryOnFail": True, "maxTries": 3, "waitBetweenTries": 1000}},
        description="Enable retry on failure (3 attempts, 1 s back-off)",
        instructions=(
            "In the HTTP Request node settings, enable 'Retry On Fail', set Max Tries to 3, "
            "and Wait Between Tries to 1000 ms. Adjust based on the upstream API's rate limits."
        ),
    )


def _fix_depr001(finding: Finding, workflow: dict) -> dict:
    node = _find_node_by_id(workflow, finding.node_id)
    if node is None:
        return _advisory_fix(finding, "Update the node typeVersion to the latest supported version.")
    node_type = node.get("type", "")
    entry = next(
        (e for e in _DEPR_CATALOGUE.get("deprecated_type_versions", []) if e["type"] == node_type),
        None,
    )
    if entry is None:
        return _advisory_fix(finding, "Update the node typeVersion to the latest supported version.")
    current_version = entry["current_version"]
    return _node_diff_fix(
        finding,
        workflow,
        patch={"typeVersion": current_version},
        description=f"Upgrade typeVersion to {current_version}",
        instructions=(
            f"Open this node in the n8n editor and upgrade to typeVersion {current_version}. "
            "n8n may offer a migration dialog when you open an outdated node."
        ),
    )


def _fix_depr002(finding: Finding, workflow: dict) -> dict:
    node = _find_node_by_id(workflow, finding.node_id)
    if node is None:
        return _advisory_fix(finding, "Replace this removed node type with the recommended replacement.")
    node_type = node.get("type", "")
    entry = next(
        (e for e in _DEPR_CATALOGUE.get("removed_node_types", []) if e["type"] == node_type),
        None,
    )
    if entry is None:
        return _advisory_fix(finding, "Replace this removed node type with the recommended replacement.")
    replacement = entry["replacement"]
    return _node_diff_fix(
        finding,
        workflow,
        patch={"type": replacement},
        description=f"Replace removed node type with {replacement}",
        instructions=(
            f"Delete this node and replace it with a '{replacement}' node. "
            "Recreate the node's logic using the Code node editor."
        ),
    )


_FIX_DISPATCH: dict[str, Callable[[Finding, dict], dict]] = {
    "WEBHOOK001": _fix_webhook001,
    "REL001": _fix_rel001,
    "DEPR001": _fix_depr001,
    "DEPR002": _fix_depr002,
}


def generate_fixes(findings: list[Finding], workflow: dict) -> list[dict]:
    """Generate fix suggestions for a list of audit findings.

    Returns one fix dict per finding. Rules with mechanical parameter changes
    return ``fix_type="modify_node"`` with before/after node snapshots. All
    other rules return ``fix_type="advisory"`` with human-readable instructions.
    """
    result = []
    for f in findings:
        fn = _FIX_DISPATCH.get(f.rule_id)
        if fn:
            result.append(fn(f, workflow))
        else:
            instructions = _ADVISORY_TEXT.get(
                f.rule_id,
                "Refer to the n8n documentation and rule catalogue for remediation guidance.",
            )
            result.append(_advisory_fix(f, instructions))
    return result
