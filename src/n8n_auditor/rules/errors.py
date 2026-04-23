"""Error handling coverage rules: ERR001–ERR003."""

from .base import Finding, Rule, Severity, _build_name_to_type

# Node types that do not need error output routing.
# Trigger nodes can't "fail" in the actionable sense; noOp nodes are
# terminal placeholders that also don't need their own error routing.
_EXCLUDED_TYPES_EXACT: frozenset[str] = frozenset(
    {
        "n8n-nodes-base.noOp",
        "n8n-nodes-base.manualTrigger",
        "n8n-nodes-base.errorTrigger",
        "n8n-nodes-base.stickyNote",  # UI annotation — cannot fail at runtime
        "n8n-nodes-base.stopAndError",  # terminal node — halts execution by design
    }
)

# LangChain sub-nodes connect to AI Agent via sub-node connectors (ai_languageModel,
# ai_memory, ai_tool, etc.) rather than the main execution graph. n8n does not expose
# independent error outputs for them — errors bubble up to the parent AI Agent root node.
# The agent itself (@n8n/n8n-nodes-langchain.agent) is NOT excluded and should fire ERR001.
_EXCLUDED_LANGCHAIN_PREFIXES: tuple[str, ...] = (
    "@n8n/n8n-nodes-langchain.lm",
    "@n8n/n8n-nodes-langchain.memory",
    "@n8n/n8n-nodes-langchain.embeddings",
    "@n8n/n8n-nodes-langchain.outputParser",
    "@n8n/n8n-nodes-langchain.tool",
    "@n8n/n8n-nodes-langchain.documentLoader",
    "@n8n/n8n-nodes-langchain.textSplitter",
    "@n8n/n8n-nodes-langchain.vectorStore",
    "@n8n/n8n-nodes-langchain.retriever",
)


def _is_auditable_node(node_type: str) -> bool:
    """Return True if this node type should be checked for error output routing."""
    if node_type in _EXCLUDED_TYPES_EXACT:
        return False
    if "trigger" in node_type.lower():
        return False
    if any(node_type.startswith(prefix) for prefix in _EXCLUDED_LANGCHAIN_PREFIXES):
        return False
    # n8n-nodes-base.*Tool variants are sub-nodes for AI Agents (ai_tool connector)
    # and cannot have independent error outputs
    if node_type.startswith("n8n-nodes-base.") and node_type.endswith("Tool"):
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
            # Traditional error output: separate "error" key in connections
            has_error_key = bool(node_connections.get("error"))
            # n8n "Continue (using error output)" mode: stores the error branch
            # as main[1] and sets onError = "continueErrorOutput" on the node
            on_error_mode = node.get("onError") == "continueErrorOutput"
            main_slots = node_connections.get("main", [])
            has_continue_output = on_error_mode and len(main_slots) > 1 and bool(main_slots[1])
            has_error_routing = has_error_key or has_continue_output

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
        name_to_type = _build_name_to_type(workflow)
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
