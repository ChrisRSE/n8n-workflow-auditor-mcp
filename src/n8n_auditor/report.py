"""Markdown and HTML audit report builders."""

import html as _html
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


def build_text_summary(findings: list[dict], workflow_name: str = "n8n Workflow") -> str:
    """Return a compact, consistently-formatted plain-text audit summary.

    Designed to be embedded in every audit tool's return dict so Claude can
    present it directly without interpreting raw JSON.
    """
    actionable = [f for f in findings if f.get("severity") != "info"]
    notes = [f for f in findings if f.get("severity") == "info"]

    fired_rule_ids = {f.get("rule_id") for f in actionable}
    passes = len(_ALL_RULES) - len(fired_rule_ids)

    header = f"── Audit: {workflow_name} ──"
    lines: list[str] = [header]

    if actionable:
        counts = Counter(f.get("severity") for f in actionable)
        parts = [f"{n} {sev}" for sev in _SEVERITY_ORDER[:-1] if (n := counts.get(sev, 0))]
        status = "✗ ISSUES FOUND  (" + " · ".join(parts) + ")"
    else:
        status = "✓ CLEAN"

    notes_suffix = f" · {len(notes)} info note{'s' if len(notes) != 1 else ''}" if notes else ""
    lines.append(f"Status  : {status}")
    lines.append(f"Rules   : {passes}/15 passed{notes_suffix}")

    if actionable:
        lines.append("")
        lines.append("Findings:")
        sev_label = {
            "critical": "CRITICAL",
            "high": "HIGH    ",
            "medium": "MEDIUM  ",
            "low": "LOW     ",
        }
        for f in sorted(actionable, key=lambda x: _SEVERITY_ORDER.index(x.get("severity", "info"))):
            sev = f.get("severity", "info")
            label = sev_label.get(sev, sev.upper().ljust(8))
            rule_id = f.get("rule_id", "").ljust(10)
            node = (f.get("node_name") or "(workflow)").ljust(18)[:18]
            msg = f.get("message", "")
            if len(msg) > 80:
                msg = msg[:77] + "..."
            lines.append(f"  [{label}]  {rule_id}  {node}  {msg}")
    else:
        lines.append("")
        lines.append("No actionable findings.")

    if notes:
        lines.append("")
        lines.append("Notes (informational only):")
        for f in notes:
            rule_id = f.get("rule_id", "")
            node = f.get("node_name") or "(workflow)"
            evidence = f.get("evidence", "")
            cred_type = ""
            if "Credential type:" in evidence:
                cred_type = (
                    " (" + evidence.split("Credential type:")[-1].split("|")[0].strip() + ")"
                )
            lines.append(f"  {rule_id}  {node}{cred_type}")

    return "\n".join(lines)


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


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_ALL_RULES: list[tuple[str, str, str]] = [
    # (rule_id, category, short title)
    ("CRED001", "Credentials", "Hardcoded credential in node parameters"),
    ("CRED002", "Credentials", "OAuth credential cannot be verified statically"),
    ("CRED003", "Credentials", "Credential referenced but not configured"),
    ("CRED004", "Credentials", "Over-permissive Google OAuth scope"),
    ("WEBHOOK001", "Webhooks", "Inbound webhook without authentication"),
    ("WEBHOOK002", "Webhooks", "Webhook connects directly to Code node"),
    ("WEBHOOK003", "Webhooks", "Webhook node has no rate limiting"),
    ("WEBHOOK004", "Webhooks", "Webhook response exposes internal data"),
    ("ERR001", "Error Handling", "Node has no error output routing"),
    ("ERR002", "Error Handling", "Workflow has no Error Trigger node"),
    ("ERR003", "Error Handling", "Error branch terminates at noOp"),
    ("DEPR001", "Deprecations", "Node using deprecated typeVersion"),
    ("DEPR002", "Deprecations", "Node type removed in current n8n version"),
    ("REL001", "Reliability", "HTTP Request node without retry configuration"),
    ("REL002", "Reliability", "Batch loop without a Stop and Error node"),
]

_SEV_COLOUR: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#b45309",
    "low": "#2563eb",
    "info": "#6b7280",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f9fafb; color: #111827; padding: 2rem; }
.container { max-width: 860px; margin: 0 auto; }
header { margin-bottom: 1.5rem; }
header h1 { font-size: 1.6rem; font-weight: 700; color: #111827; }
header p  { color: #6b7280; margin-top: .25rem; font-size: .95rem; }
.summary { display: flex; flex-wrap: wrap; align-items: center;
           gap: .5rem; margin-bottom: 2rem; }
.status-badge { display: inline-flex; align-items: center; gap: .35rem;
                padding: .35rem .9rem; border-radius: .4rem; font-size: .85rem;
                font-weight: 700; color: #fff; }
.pill { padding: .3rem .75rem; border-radius: 9999px; font-size: .8rem;
        font-weight: 600; color: #fff; }
.pill.coverage { background: #4b5563; }
.divider { color: #d1d5db; font-size: 1.2rem; }
h2 { font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; color: #374151; }
h3 { font-size: .9rem; font-weight: 600; text-transform: uppercase;
     letter-spacing: .05em; color: #9ca3af; margin: 1.25rem 0 .5rem; }
.card { background: #fff; border-radius: .5rem; border: 1px solid #e5e7eb;
        border-left-width: 4px; padding: 1rem 1.25rem; margin-bottom: .75rem; }
.card.note { border-left-color: #d1d5db; opacity: .85; }
.card-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; }
.badge { font-size: .72rem; font-weight: 700; padding: .15rem .5rem;
         border-radius: .25rem; color: #fff; }
.node-name { font-size: .85rem; color: #6b7280; }
.card-msg { font-size: .9rem; margin-bottom: .5rem; }
.fix-label { font-size: .75rem; font-weight: 600; text-transform: uppercase;
             letter-spacing: .05em; color: #9ca3af; margin-bottom: .2rem; }
.fix-text { font-size: .85rem; color: #374151; line-height: 1.5; }
.pass-list { list-style: none; }
.pass-list li { font-size: .88rem; padding: .25rem 0; color: #374151; }
.pass-list li::before { content: "\\2713\\0020"; color: #16a34a; font-weight: 700; }
.section { margin-bottom: 2rem; }
.clean-msg { color: #16a34a; font-weight: 600; }
"""


def _esc(value: object) -> str:
    return _html.escape(str(value))


def _make_card(f: dict, extra_class: str = "") -> str:
    sev = f.get("severity", "info")
    colour = _SEV_COLOUR.get(sev, "#6b7280")
    rule_id = _esc(f.get("rule_id", ""))
    node = _esc(f.get("node_name") or "Workflow-level")
    msg = _esc(f.get("message", ""))
    fix = _esc(
        _REMEDIATIONS.get(
            f.get("rule_id", ""),
            "Refer to the n8n documentation for remediation guidance.",
        )
    )
    cls = f"card {extra_class}".strip()
    return f"""
<div class="{cls}" style="border-left-color:{colour}">
  <div class="card-header">
    <span class="badge" style="background:{colour}">{rule_id}</span>
    <span class="badge" style="background:{colour}">{_esc(sev.upper())}</span>
    <span class="node-name">{node}</span>
  </div>
  <p class="card-msg">{msg}</p>
  <p class="fix-label">How to fix</p>
  <p class="fix-text">{fix}</p>
</div>"""


def build_html_report(findings: list[dict], workflow_name: str = "n8n Workflow") -> str:
    """Generate a self-contained HTML audit report.

    Returns a complete HTML string with inline CSS. No external resources required.

    Args:
        findings: List of finding dicts as returned by any audit tool's ``findings`` key.
        workflow_name: Display name used in the report title.
    """
    today = date.today().isoformat()

    actionable = [f for f in findings if f.get("severity") != "info"]
    notes = [f for f in findings if f.get("severity") == "info"]
    all_fired_ids = {f.get("rule_id") for f in findings}
    actionable_fired_ids = {f.get("rule_id") for f in actionable}
    passes = len(_ALL_RULES) - len(actionable_fired_ids)

    # --- status badge + summary bar ---
    has_issues = bool(actionable)
    if has_issues:
        status_colour = "#dc2626"
        status_label = "&#x2717; ISSUES FOUND"
    else:
        status_colour = "#16a34a"
        status_label = "&#x2713; CLEAN"

    summary_html = (
        f'<span class="status-badge" style="background:{status_colour}">'
        f"{status_label}</span>"
        '<span class="divider">|</span>'
    )

    actionable_counts = Counter(f.get("severity") for f in actionable)
    for sev in _SEVERITY_ORDER[:-1]:  # skip "info"
        n = actionable_counts.get(sev, 0)
        if n:
            colour = _SEV_COLOUR[sev]
            summary_html += (
                f'<span class="pill" style="background:{colour}">'
                f"{_esc(sev.capitalize())} {n}</span>"
            )

    summary_html += (
        f'<span class="divider">|</span><span class="pill coverage">{passes}/15 rules passed</span>'
    )
    if notes:
        summary_html += (
            f'<span class="pill" style="background:#6b7280">'
            f"{len(notes)} note{'s' if len(notes) != 1 else ''}</span>"
        )

    # --- findings section (actionable only) ---
    if actionable:
        cards = "".join(_make_card(f) for f in actionable)
        findings_section = (
            f'<div class="section"><h2>Findings ({len(actionable)})</h2>{cards}</div>'
        )
    else:
        findings_section = (
            '<div class="section"><h2>Findings</h2>'
            '<p class="clean-msg">No actionable findings — workflow passed all checks.</p>'
            "</div>"
        )

    # --- notes section (INFO only) ---
    notes_section = ""
    if notes:
        note_cards = "".join(_make_card(f, extra_class="note") for f in notes)
        notes_section = (
            f'<div class="section"><h2>Notes ({len(notes)})</h2>'
            f'<p style="font-size:.85rem;color:#6b7280;margin-bottom:.75rem">'
            f"Informational only &mdash; no action required.</p>"
            f"{note_cards}</div>"
        )

    # --- passes section ---
    by_cat: dict[str, list[tuple[str, str]]] = {}
    for rule_id, category, title in _ALL_RULES:
        if rule_id not in all_fired_ids:
            by_cat.setdefault(category, []).append((rule_id, title))

    passes_html = ""
    for cat, rules in by_cat.items():
        items = "".join(
            f"<li><strong>{_esc(rid)}</strong> &mdash; {_esc(title)}</li>" for rid, title in rules
        )
        passes_html += f"<h3>{_esc(cat)}</h3><ul class='pass-list'>{items}</ul>"

    passes_section = (
        f'<div class="section"><h2>Passed Checks ({len(by_cat and [r for rules in by_cat.values() for r in rules])})</h2>{passes_html}</div>'
        if by_cat
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>n8n Audit Report &mdash; {_esc(workflow_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1>n8n Audit Report</h1>
    <p>{_esc(workflow_name)} &mdash; {_esc(today)}</p>
  </header>
  <div class="summary">{summary_html}</div>
  {findings_section}
  {notes_section}
  {passes_section}
</div>
</body>
</html>"""
