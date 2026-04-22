"""Markdown audit report builder."""

from collections import Counter
from datetime import date
from pathlib import Path

import yaml

_DEFS_DIR = Path(__file__).parent / "rules" / "definitions"
_RULE_DESCRIPTOR_FILES = ["credentials.yaml", "webhooks.yaml", "errors.yaml", "reliability.yaml"]

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_DEPR_REMEDIATIONS = {
    "DEPR001": (
        "Upgrade the node to the current typeVersion using the n8n node editor. "
        "n8n may offer a migration dialog when you open an outdated node."
    ),
    "DEPR002": (
        "Delete this node and replace it with the recommended replacement type. "
        "Check the n8n changelog for migration guidance."
    ),
}


def _load_remediations() -> dict[str, str]:
    remediations: dict[str, str] = {}
    for fname in _RULE_DESCRIPTOR_FILES:
        data = yaml.safe_load((_DEFS_DIR / fname).read_text(encoding="utf-8"))
        for rule in data.get("rules", []):
            remediations[rule["id"]] = rule.get("remediation", "").strip()
    remediations.update(_DEPR_REMEDIATIONS)
    return remediations


_REMEDIATIONS: dict[str, str] = _load_remediations()


def build_markdown_report(findings: list[dict], workflow_name: str = "n8n Workflow") -> str:
    """Generate a Markdown audit report from a list of finding dicts.

    Args:
        findings: List of finding dicts as returned by audit tool ``findings`` keys.
        workflow_name: Display name used in the report title.

    Returns:
        A Markdown string ready to write to a file or return to the caller.
    """
    today = date.today().isoformat()
    total = len(findings)
    counts = Counter(f.get("severity", "info") for f in findings)

    lines: list[str] = [
        f"# Audit Report: {workflow_name}",
        "",
        f"**Date:** {today}  ",
        f"**Total findings:** {total}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]

    for sev in _SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

    if total == 0:
        lines += ["| — | 0 |", "", "_No findings. Workflow passed all checks._", ""]
        return "\n".join(lines)

    lines.append("")

    by_severity: dict[str, list[dict]] = {sev: [] for sev in _SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    for sev in _SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue

        lines += [
            f"## {sev.capitalize()} Findings",
            "",
        ]

        for f in group:
            rule_id = f.get("rule_id", "")
            node_name = f.get("node_name") or "Workflow"
            message = f.get("message", "")
            evidence = f.get("evidence", "")
            remediation = _REMEDIATIONS.get(
                rule_id, "Refer to the n8n documentation for remediation guidance."
            )

            lines += [
                f"### {rule_id}: {node_name}",
                "",
                f"**Message:** {message}",
                "",
                f"**Evidence:** `{evidence}`",
                "",
                f"**Remediation:** {remediation}",
                "",
                "---",
                "",
            ]

    return "\n".join(lines)
