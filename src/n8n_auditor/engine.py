"""Rule engine orchestrator — runs all registered rules and aggregates findings."""

from dataclasses import dataclass

from .rules.base import Finding, Rule
from .rules.credentials import (
    CredentialHardcoded,
    CredentialNotConfigured,
    CredentialOAuthExpiry,
    CredentialOverPermissiveScope,
)
from .rules.deprecations import NodeDeprecatedVersion, NodeTypeRemoved
from .rules.errors import ErrorBranchSilentFailure, NodeNoErrorRouting, WorkflowNoErrorTrigger
from .rules.reliability import HttpRequestNoRetry, WorkflowHasUnboundedLoop
from .rules.webhooks import (
    WebhookDirectToCode,
    WebhookExposesInternalData,
    WebhookNoAuth,
    WebhookNoRateLimit,
)

ALL_RULES: list[Rule] = [
    CredentialHardcoded(),
    CredentialOAuthExpiry(),
    CredentialNotConfigured(),
    CredentialOverPermissiveScope(),
    WebhookNoAuth(),
    WebhookDirectToCode(),
    WebhookNoRateLimit(),
    WebhookExposesInternalData(),
    NodeNoErrorRouting(),
    WorkflowNoErrorTrigger(),
    ErrorBranchSilentFailure(),
    HttpRequestNoRetry(),
    WorkflowHasUnboundedLoop(),
    NodeDeprecatedVersion(),
    NodeTypeRemoved(),
]

RULES_BY_ID: dict[str, Rule] = {rule.rule_id: rule for rule in ALL_RULES}


@dataclass
class AuditResult:
    findings: list[Finding]
    summary: dict[str, int]
    total: int

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "total": self.total,
        }


def run_audit(workflow: dict, rules: list[Rule] | None = None) -> AuditResult:
    """Run all (or specified) rules against a parsed workflow dict.

    Args:
        workflow: Parsed n8n workflow dict.
        rules: Optional list of Rule instances to run. Defaults to ALL_RULES.

    Returns:
        AuditResult with deduplicated findings, summary, and total count.
    """
    active_rules = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for rule in active_rules:
        for f in rule.check(workflow):
            key = (f.rule_id, f.node_id, f.node_name)
            if key not in seen:
                seen.add(key)
                findings.append(f)

    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

    return AuditResult(findings=findings, summary=summary, total=len(findings))
