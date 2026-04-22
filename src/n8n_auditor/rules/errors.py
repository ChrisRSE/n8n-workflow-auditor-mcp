"""Error handling coverage rules: ERR001–ERR003."""

from .base import Finding, Rule, Severity

# Node types that do not need error output routing.
# Trigger nodes can't "fail" in the actionable sense; noOp nodes are
# terminal placeholders that also don't need their own error routing.
_EXCLUDED_TYPES_EXACT: frozenset[str] = frozenset(
    {
        "n8n-nodes-base.noOp",
        "n8n-nodes-base.manualTrigger",
        "n8n-nodes-base.errorTrigger",
    }
)


def _is_auditable_node(node_type: str) -> bool:
    """Return True if this node type should be checked for error output routing."""
    if node_type in _EXCLUDED_TYPES_EXACT:
        return False
    if "trigger" in node_type.lower():
        return False
    return True


class NodeNoErrorRouting(Rule):
    """ERR001 — Node has no error output connection.

    Every non-trigger, non-noOp node that fails at runtime will halt the
    workflow silently if it has no error output branch configured.
    """

    rule_id = "ERR001"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        connections = workflow.get("connections", {})

        for node in workflow.get("nodes", []):
            node_type = node.get("type", "")
            if not _is_auditable_node(node_type):
                continue
            node_id = node.get("id", "")
            node_name = node.get("name", "")

            node_connections = connections.get(node_name, {})
            has_error_routing = bool(node_connections.get("error"))

            if not has_error_routing:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        node_id=node_id,
                        node_name=node_name,
                        message=f"Node '{node_name}' ({node_type}) has no error output connection.",
                        evidence=f"Node '{node_name}' ({node_type}) has no error output connection",
                    )
                )
        return findings


class WorkflowNoErrorTrigger(Rule):
    """ERR002 — Workflow has no top-level Error Trigger node.

    Without an Error Trigger, failures in sub-workflows or uncaught errors
    have no centralised handler, making silent failure the default outcome.
    """

    rule_id = "ERR002"

    def check(self, workflow: dict) -> list[Finding]:
        has_error_trigger = any(
            node.get("type") == "n8n-nodes-base.errorTrigger" for node in workflow.get("nodes", [])
        )
        if has_error_trigger:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                node_id=None,
                node_name=None,
                message="Workflow has no Error Trigger node.",
                evidence="No Error Trigger node found in workflow",
            )
        ]


class ErrorBranchSilentFailure(Rule):
    """ERR003 — Error branch leads to silent failure.

    An error output connection that terminates at a noOp node silently
    discards the failure with no notification or logging.
    """

    rule_id = "ERR003"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        name_to_type = {
            node.get("name", ""): node.get("type", "") for node in workflow.get("nodes", [])
        }
        connections = workflow.get("connections", {})

        for source_name, source_connections in connections.items():
            error_slots = source_connections.get("error", [])
            for slot in error_slots:
                for target_ref in slot:
                    target_name = target_ref.get("node", "")
                    target_type = name_to_type.get(target_name, "")
                    if target_type == "n8n-nodes-base.noOp":
                        source_node_id = next(
                            (
                                n.get("id", "")
                                for n in workflow.get("nodes", [])
                                if n.get("name") == source_name
                            ),
                            None,
                        )
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                node_id=source_node_id,
                                node_name=source_name,
                                message=(
                                    f"Error branch from '{source_name}' terminates at noOp node "
                                    f"'{target_name}' — no notification or logging."
                                ),
                                evidence=(
                                    f"Error branch from '{source_name}' → noOp '{target_name}'"
                                ),
                            )
                        )
        return findings
