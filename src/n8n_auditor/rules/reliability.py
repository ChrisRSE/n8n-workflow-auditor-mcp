"""Reliability rules: REL001–REL002."""

from .base import Finding, Rule, Severity


class HttpRequestNoRetry(Rule):
    """REL001 — HTTP Request node without retry configuration.

    n8n HTTP Request nodes default to no retry on failure. Production workflows
    hitting external APIs should configure retryOnFail to handle transient errors.
    """

    rule_id = "REL001"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.httpRequest":
                continue
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            retry_on_fail = node.get("parameters", {}).get("retryOnFail")
            if not retry_on_fail:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.LOW,
                        node_id=node_id,
                        node_name=node_name,
                        message=(
                            f"HTTP Request node '{node_name}' has no retry configuration. "
                            f"Transient errors will cause immediate failure."
                        ),
                        evidence=f"parameters.retryOnFail = {retry_on_fail!r}",
                    )
                )
        return findings


class WorkflowHasUnboundedLoop(Rule):
    """REL002 — Batch loop without a Stop and Error node.

    A SplitInBatches node without a StopAndError node in the workflow has no
    circuit breaker — runaway loops can exhaust execution capacity.
    """

    rule_id = "REL002"

    def check(self, workflow: dict) -> list[Finding]:
        nodes = workflow.get("nodes", [])
        node_types = {n.get("type") for n in nodes}

        if "n8n-nodes-base.stopAndError" in node_types:
            return []

        findings: list[Finding] = []
        for node in nodes:
            if node.get("type") != "n8n-nodes-base.splitInBatches":
                continue
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    node_id=node_id,
                    node_name=node_name,
                    message=(
                        f"Loop node '{node_name}' (SplitInBatches) has no Stop and Error "
                        f"node in the workflow. Without a circuit breaker, runaway loops "
                        f"can exhaust execution capacity."
                    ),
                    evidence="No n8n-nodes-base.stopAndError node found in workflow",
                )
            )
        return findings
