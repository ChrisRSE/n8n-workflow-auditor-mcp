# DECISIONS.md — n8n Workflow Auditor MCP

Append-only log of architectural decisions made during this build. One entry per decision. Never delete or edit past entries — add a superseding entry if a decision changes.

---

## Entry template

```
## [DECISION-NNN] <Short title>

- **Date:** YYYY-MM-DD
- **Decision:** <One sentence — what was decided>
- **Context:** <What problem were we solving? What constraints existed?>
- **Alternatives considered:** <What else was on the table?>
- **Rationale:** <Why this option over the others?>
- **Consequences:** <What does this decision close off? What does it open up?>
```

---

## Decisions

## [DECISION-001] Credential scanning limited to literal/raw parameter values in v1

- **Date:** 2026-04-22
- **Decision:** CRED001 scans only literal string values in node parameters. n8n expression syntax (`{{ $json.x }}`) is out of scope for v1.
- **Context:** n8n node parameters can contain either raw values or n8n expressions. Parsing expressions to determine whether they resolve to a secret requires expression AST walking.
- **Alternatives considered:** (a) Full expression parsing with AST walker. (b) Regex heuristics inside expression strings (partial coverage, high false-positives). (c) Literal-only (chosen).
- **Rationale:** Literal scanning covers the highest-impact cases (copy-pasted secrets, hardcoded tokens) and can ship in Session 2 without blocking the release. Expression parsing significantly increases scope, implementation time, and false-positive risk. Deferred to a future rule batch.
- **Consequences:** CRED001 will not catch secrets embedded inside expressions. Known limitation; to be documented in ruleset.md.

---

## [DECISION-002] suggest_fixes uses n8n-native node diff format (before/after JSON snapshot)

- **Date:** 2026-04-22
- **Decision:** `suggest_fixes` returns a `{node_id, before: {...}, after: {...}}` structure — a snapshot of the affected node's JSON before and after the proposed fix.
- **Context:** Patch format determines who can apply the fix and how. Three options were evaluated.
- **Alternatives considered:** (a) JSON Patch RFC 6902 — machine-applicable but requires a jsonpatch consumer; not directly usable in Claude Desktop without a follow-up tool call. (b) Annotated markdown — most readable, zero machine-applicability. (c) n8n-native node diff (chosen).
- **Rationale:** Optimises for the Loom demo (viewer can visually see the change) and for real user workflow (copy-paste the `after` JSON into the n8n node editor). Both JSON Patch and annotated markdown are deferred.
- **Consequences:** Fixes are not machine-applicable in v1. A future `apply_fix` tool could accept this format and patch the workflow JSON programmatically.

---

## [DECISION-003] analyse_instance uses custom rules only; does not call n8n's /audit endpoint

- **Date:** 2026-04-22
- **Decision:** `analyse_instance` fetches workflow JSON via the n8n REST API and runs our custom rules only. It does not call n8n's built-in `/audit` endpoint.
- **Context:** n8n added a `/audit` endpoint in v0.234.0 that checks some overlapping concerns. Integration would require schema normalisation and creates a version dependency.
- **Alternatives considered:** (a) Call n8n `/audit` and merge findings — avoids reimplementing what n8n already does, but creates version coupling (≥0.234.0) and schema normalisation overhead. (b) Custom rules only (chosen).
- **Rationale:** Keeps the integration simple and version-agnostic. Users on older n8n instances are not excluded. Merging n8n `/audit` findings logged as a future enhancement.
- **Consequences:** We may miss findings that n8n's internal audit catches via privileged access (e.g., credential vault state). Document this limitation in README.

---

## [DECISION-004] Deprecation catalogue is a static YAML with a snapshot_date field; no network access at rule-check time

- **Date:** 2026-04-22
- **Decision:** DEPR001 and DEPR002 use a static `deprecations.yaml` file maintained manually in the repo. The file includes a `snapshot_date` field. No HTTP calls are made at rule-check time.
- **Context:** Deprecation data could come from a static file, a scraped/fetched source, or a live instance query. CLAUDE.md flags network access in rules as a "ask first" concern.
- **Alternatives considered:** (a) Fetch from n8n GitHub releases at check time — always fresh, but requires internet and violates the "ask first for network" rule. (b) Queried from live instance — only relevant for `analyse_instance`, useless for static auditing. (c) Static YAML (chosen).
- **Rationale:** Keeps the repo hermetic. Tests run without internet access. Community PRs can update the catalogue over time. The `snapshot_date` field makes staleness visible to users.
- **Consequences:** Catalogue will go stale between sessions. Must include `snapshot_date` and a note in README encouraging contributors to submit PRs when new deprecations are announced.

---

## [DECISION-005] PDF output cut from v1; generate_audit_report produces Markdown only

- **Date:** 2026-04-22
- **Decision:** `generate_audit_report` outputs Markdown only. PDF generation is not included in v1.
- **Context:** PDF from Python typically requires weasyprint (heavy, OS libs), reportlab, fpdf2, or shelling to pandoc — each adding installation complexity.
- **Alternatives considered:** (a) weasyprint — good CSS→PDF, but requires OS-level Cairo/Pango libs; complicates install instructions. (b) fpdf2 — lighter, but programmatic layout is verbose. (c) Markdown only (chosen).
- **Rationale:** PDF adds heavy OS-level dependencies without adding demo value. The Loom checklist marks PDF as "Optional." Users who need PDF can pipe MD through pandoc themselves.
- **Consequences:** CLAUDE.md tool table references "optional PDF" — to be updated manually after Session 1. Future enhancement: add `--pdf` flag once install story is cleaner.

---

## [DECISION-006] reliability.py added to rules/ directory; CLAUDE.md file structure patched in Session 1

- **Date:** 2026-04-22
- **Decision:** `src/n8n_auditor/rules/reliability.py` and `src/n8n_auditor/rules/definitions/reliability.yaml` are added to the project structure. CLAUDE.md's file listing is patched now (Session 1) to reflect this.
- **Context:** CLAUDE.md's original project structure diagram listed only `credentials.py`, `webhooks.py`, `errors.py`, and `deprecations.py` in the rules directory. However, REL001 and REL002 are in the 15-rule catalogue and have no home without a `reliability.py`. Session 2 will scaffold the rules directory from CLAUDE.md's layout.
- **Alternatives considered:** (a) Bundle REL001/REL002 into `deprecations.py` — wrong semantically and harder to find. (b) Defer the fix to Session 4 when the file is created — creates a window where CLAUDE.md is wrong and Session 2 scaffolding would be inconsistent. (c) Patch CLAUDE.md now (chosen).
- **Rationale:** CLAUDE.md is the source of truth for project structure. Fix it before any session reads it to scaffold files.
- **Consequences:** CLAUDE.md is now accurate. Sessions 2–5 can scaffold from it without retrofitting.
