"""Webhook security rules: WEBHOOK001–WEBHOOK004."""

from .base import Finding, Rule, Severity


def _build_name_to_type(workflow: dict) -> dict[str, str]:
    """Return {node_name: node_type} lookup from workflow nodes list."""
    return {node.get("name", ""): node.get("type", "") for node in workflow.get("nodes", [])}


class WebhookNoAuth(Rule):
    """WEBHOOK001 — Inbound webhook without authentication."""

    rule_id = "WEBHOOK001"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.webhook":
                continue
            auth = node.get("parameters", {}).get("authentication")
            if auth is None or auth == "none":
                node_id = node.get("id", "")
                node_name = node.get("name", "")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        node_id=node_id,
                        node_name=node_name,
                        message=(
                            f"Webhook node '{node_name}' accepts requests without authentication."
                        ),
                        evidence=f"parameters.authentication = {auth!r}",
                    )
                )
        return findings


class WebhookDirectToCode(Rule):
    """WEBHOOK002 — Webhook connects directly to a Code node without input validation."""

    rule_id = "WEBHOOK002"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        name_to_type = _build_name_to_type(workflow)
        connections = workflow.get("connections", {})

        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.webhook":
                continue
            node_name = node.get("name", "")
            node_id = node.get("id", "")

            main_slots = connections.get(node_name, {}).get("main", [])
            for slot in main_slots:
                for target_ref in slot:
                    target_name = target_ref.get("node", "")
                    target_type = name_to_type.get(target_name, "")
                    if target_type == "n8n-nodes-base.code":
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                node_id=node_id,
                                node_name=node_name,
                                message=(
                                    f"Webhook '{node_name}' connects directly to Code node "
                                    f"'{target_name}' with no validation node between them."
                                ),
                                evidence=(
                                    f"Webhook '{node_name}' → Code '{target_name}' "
                                    f"(direct 1-hop connection, no validation)"
                                ),
                            )
                        )
        return findings


class WebhookNoRateLimit(Rule):
    """WEBHOOK003 — Webhook without rate limiting (advisory).

    n8n does not provide native rate limiting on Webhook nodes.
    Every webhook endpoint is potentially vulnerable to high-volume abuse.
    """

    rule_id = "WEBHOOK003"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.webhook":
                continue
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.LOW,
                    node_id=node_id,
                    node_name=node_name,
                    message=(
                        f"Webhook node '{node_name}' has no rate limiting. "
                        f"n8n does not provide native rate limiting on Webhook nodes."
                    ),
                    evidence="n8n does not provide native rate limiting on Webhook nodes",
                )
            )
        return findings


class WebhookExposesInternalData(Rule):
    """WEBHOOK004 — Webhook response exposes internal data.

    Fires when a RespondToWebhook node returns the full $json payload or all
    entries rather than a filtered response.
    """

    rule_id = "WEBHOOK004"

    # Exact response body expressions that pass through the entire item JSON
    _BROAD_EXPRESSIONS: frozenset[str] = frozenset({"={{ $json }}", "{{ $json }}"})

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.respondToWebhook":
                continue
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            params = node.get("parameters", {})

            respond_with = params.get("respondWith", "")
            response_body = params.get("responseBody", "")

            flagged = False
            evidence_value = ""

            if respond_with == "allEntries":
                flagged = True
                evidence_value = f"respondWith = {respond_with!r}"
            elif isinstance(response_body, str) and response_body.strip() in self._BROAD_EXPRESSIONS:
                flagged = True
                evidence_value = f"responseBody = {response_body!r}"

            if flagged:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        node_id=node_id,
                        node_name=node_name,
                        message=(
                            f"RespondToWebhook node '{node_name}' may expose internal data "
                            f"in its response."
                        ),
                        evidence=evidence_value,
                    )
                )
        return findings
