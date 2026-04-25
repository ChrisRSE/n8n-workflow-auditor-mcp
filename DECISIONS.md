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

## [DECISION-005] PDF output cut from v1; generate_audit_report produces Markdown and HTML

- **Date:** 2026-04-22 (updated 2026-04-24)
- **Decision:** `generate_audit_report` outputs Markdown (`format="md"`) or self-contained HTML (`format="html"`). PDF is not included in v1.
- **Context:** PDF from Python typically requires weasyprint (heavy, OS libs), reportlab, fpdf2, or shelling to pandoc — each adding installation complexity. HTML was added as a richer client-facing format without extra dependencies.
- **Alternatives considered:** (a) weasyprint — good CSS→PDF, but requires OS-level Cairo/Pango libs; complicates install instructions. (b) fpdf2 — lighter, but programmatic layout is verbose. (c) Markdown + HTML (chosen).
- **Rationale:** PDF adds heavy OS-level dependencies without adding demo value. HTML covers the client-facing report use case cleanly with zero extra dependencies.
- **Consequences:** Future enhancement: add `--pdf` flag once install story is cleaner.

## [DECISION-011] HTML reports do not auto-open in the browser

- **Date:** 2026-04-24 (updated 2026-04-25)
- **Decision:** `generate_audit_report` writes the HTML file and returns `report_path`. No browser launch is attempted. Audit results are presented as inline text in Claude's response.
- **Context:** Three browser-open approaches were attempted and all failed: (a) `webbrowser.open()` — silently no-ops from a headless subprocess. (b) `os.startfile()` — same, no desktop session. (c) `subprocess.Popen(["cmd", "/c", "start", ...])` and Claude running `start` via Bash — also failed; both the MCP server process and Claude Code's Bash tool run in a context isolated from the user's desktop session.
- **Alternatives considered:** (a) Local HTTP server serving reports on a fixed port — viable but adds complexity for marginal gain. (b) Save to Desktop for easy manual access — considered but not pursued. (c) Inline text output (chosen) — simpler, always works, no file management needed.
- **Rationale:** The sandbox restrictions in Claude Code's VSCode extension make GUI launches unreliable. Inline markdown output in the chat is more immediate and universally accessible.
- **Consequences:** HTML report generation still works and returns a `report_path`, but the primary output path is inline text. The HTML file can be opened manually if needed.

---

## [DECISION-006] reliability.py added to rules/ directory; CLAUDE.md file structure patched in Session 1

- **Date:** 2026-04-22
- **Decision:** `src/n8n_auditor/rules/reliability.py` and `src/n8n_auditor/rules/definitions/reliability.yaml` are added to the project structure. CLAUDE.md's file listing is patched now (Session 1) to reflect this.
- **Context:** CLAUDE.md's original project structure diagram listed only `credentials.py`, `webhooks.py`, `errors.py`, and `deprecations.py` in the rules directory. However, REL001 and REL002 are in the 15-rule catalogue and have no home without a `reliability.py`. Session 2 will scaffold the rules directory from CLAUDE.md's layout.
- **Alternatives considered:** (a) Bundle REL001/REL002 into `deprecations.py` — wrong semantically and harder to find. (b) Defer the fix to Session 4 when the file is created — creates a window where CLAUDE.md is wrong and Session 2 scaffolding would be inconsistent. (c) Patch CLAUDE.md now (chosen).
- **Rationale:** CLAUDE.md is the source of truth for project structure. Fix it before any session reads it to scaffold files.
- **Consequences:** CLAUDE.md is now accurate. Sessions 2–5 can scaffold from it without retrofitting.

---

## [DECISION-007] Pre-commit hooks with detect-secrets set up before any Python code is written

- **Date:** 2026-04-22
- **Decision:** Install pre-commit hooks (detect-secrets + standard safety checks) as a one-off setup task before Session 2, rather than waiting until secrets are first introduced in the codebase.
- **Context:** The project will handle real n8n API keys and will audit workflows for credential hygiene. A secret leak in the repo would be an embarrassing contradiction for a project whose entire purpose is catching credential mistakes. Pre-commit hooks are cheap to add before there is any code and expensive to retrofit after a leak.
- **Alternatives considered:** (a) Defer until Session 4 when the first real secrets (connector.py, .env) are introduced — lower urgency but misses the window when the cost is lowest. (b) Rely on .gitignore alone — passive protection only, no active scanning.
- **Rationale:** Asymmetric downside: 15 minutes now prevents secret leaks that could take hours to scrub from git history and rotate credentials. Also serves as a portfolio signal — the repo demonstrates security-first practice from commit one.
- **Consequences:** All future commits are scanned by detect-secrets against a baseline. New legitimate high-entropy strings (e.g., test fixture tokens) must be added to .secrets.baseline explicitly.

---

## [DECISION-008] Consolidate dev dependencies into pyproject.toml; retire requirements-dev.txt

- **Date:** 2026-04-22
- **Decision:** Dev dependencies live in `pyproject.toml`'s `[project.optional-dependencies].dev` only. `requirements-dev.txt` is deleted.
- **Context:** `requirements-dev.txt` was created in the security setup task before `pyproject.toml` existed. Now that Session 2 has introduced proper Python packaging, two dependency files is inconsistent and confusing.
- **Alternatives considered:** (a) Keep both files in sync manually — error-prone, violates single-source-of-truth. (b) Use `requirements-dev.txt` as primary, auto-generate from `pyproject.toml` — overkill for a solo project. (c) `pyproject.toml` only (chosen).
- **Rationale:** `pyproject.toml` is the modern Python packaging standard. Makes the project installable via `pip install -e ".[dev]"`. Eliminates dependency drift between two files.
- **Consequences:** Anyone cloning the repo uses `pip install -e ".[dev]"`. `detect-secrets` and `pre-commit` now available inside the venv rather than relying on global installs.

## [DECISION-009] ERR001 node classification: sub-nodes, tool nodes, and terminal nodes are excluded

- **Date:** 2026-04-23
- **Decision:** ERR001 excludes three categories of nodes from error routing checks: (1) terminal nodes (`stopAndError`, `noOp`) that halt execution by design, (2) LangChain sub-nodes (`lmChat*`, `memory*`, `outputParser*`, `tool*`, `embeddings*`, etc.) that connect to AI Agents via sub-node connectors (`ai_languageModel`, `ai_memory`, `ai_tool`), and (3) `n8n-nodes-base.*Tool` nodes (e.g. `googleSheetsTool`, `notionTool`) which are base-node AI tool wrappers also connected via `ai_tool`. Additionally, `onError: continueErrorOutput` with a wired `main[1]` output is recognised as valid error routing alongside the traditional `error` connection key.
- **Context:** Discovered during first real-world workflow test (Session 9). All three categories produced false positives the user could not act on — n8n's UI does not expose independent error outputs for sub-nodes or tool nodes, and terminal nodes are not expected to have downstream routing. The `continueErrorOutput` mode stores the error branch differently in the JSON than traditional error routing, causing ERR001 to miss it entirely.
- **Alternatives considered:** (a) Hardcode a full list of excluded type names — brittle, breaks when n8n adds new sub-node types. (b) Detect sub-node status dynamically by inspecting connection types (`ai_tool`, `ai_memory`) — correct but complex; prefix/suffix matching covers the same ground more simply. (c) Chosen: prefix matching for LangChain sub-nodes, `endswith("Tool")` for base-node tool wrappers, exact match for terminal nodes.
- **Rationale:** False positives that users cannot fix erode trust in the auditor. The exclusion logic is documented here and in `docs/ruleset.md` so future contributors understand the intent.
- **Consequences:** ERR001 now only fires on nodes that genuinely support error output routing in n8n's UI. The AI Agent root node (`@n8n/n8n-nodes-langchain.agent`) remains in scope — it is a real execution point where error routing matters.
