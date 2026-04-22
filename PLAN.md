# PLAN.md — n8n Workflow Auditor MCP

> Updated after each session. Read this + the last 5 git commits to reconstruct context.

## Build overview

| Session | Goal | Rules | Tools exposed |
|---------|------|-------|---------------|
| 1 (done) | Planning only | — | — |
| 2 | Scaffold + parser + credential rules | CRED001–004 | `scan_credentials` |
| 3 | Webhook + error handling rules | WEBHOOK001–004, ERR001–003 | `check_webhooks`, `error_handling_coverage` |
| 4 | Deprecation + reliability + engine orchestrator + live instance connector | DEPR001–002, REL001–002 | `audit_workflow`, `detect_deprecations`, `analyse_instance` |
| 5 | suggest_fixes + report generator + README + docs + polish + submissions | — | `suggest_fixes`, `generate_audit_report` |

---

## Session 2: Scaffold + Parser + Credential Rules

**Goal:** Bootstrap a working Python project with FastMCP and implement 4 credential hygiene rules with full test coverage.

### Files created
- `pyproject.toml` — project metadata, dependencies (fastmcp, pydantic, pyyaml, pytest, ruff)
- `.env.example` — template for local n8n API credentials
- `src/n8n_auditor/__init__.py`
- `src/n8n_auditor/server.py` — FastMCP entry point, all 8 tools registered as stubs
- `src/n8n_auditor/tools.py` — `scan_credentials` tool implemented; remaining 7 as NotImplemented stubs
- `src/n8n_auditor/parser.py` — workflow JSON ingestion (path or raw JSON string → parsed dict)
- `src/n8n_auditor/rules/__init__.py`
- `src/n8n_auditor/rules/base.py` — `Rule` base class: `check(workflow: dict) -> list[Finding]`; `Finding` dataclass (rule_id, severity, node_id, node_name, message, evidence)
- `src/n8n_auditor/rules/credentials.py` — CRED001–004 implementations
- `src/n8n_auditor/rules/definitions/credentials.yaml` — YAML descriptors for CRED001–004
- `tests/conftest.py` — shared fixtures (load_fixture helper)
- `tests/fixtures/clean_workflow.json` — workflow with no violations
- `tests/fixtures/hardcoded_secrets.json` — workflow triggering CRED001
- `tests/rules/test_credentials.py` — pytest suite for CRED001–004

### Rules implemented and order rationale
1. **CRED001** — Hardcoded credentials in node parameters  
   Rationale: Highest user impact, clearest regex-based detection, validates the Rule base class pattern end-to-end.
2. **CRED002** — Expired OAuth token detected  
   Rationale: Requires understanding credential node structure (`credentials` key in node JSON), builds on CRED001's node iteration.
3. **CRED003** — Credential referenced but not configured  
   Rationale: Cross-references `nodes[].credentials` against `workflow.credentials` map; natural extension of CRED002's credential traversal.
4. **CRED004** — Over-permissive API scope  
   Rationale: Most complex credential rule (node-type-aware scope lookup); placed last so the simpler rules are battle-tested first.

### MCP tools exposed
- `scan_credentials` (fully implemented)
- Remaining 7 tools registered as stubs returning `{"status": "not_implemented"}` so the server starts cleanly

### Tests written
- Fixture: `tests/fixtures/clean_workflow.json` (zero findings expected across all rules)
- Fixture: `tests/fixtures/hardcoded_secrets.json` (triggers CRED001)
- `tests/rules/test_credentials.py` — minimum 2 tests per rule (fires / does not fire)

### Expected commits
```
feat: bootstrap project scaffold with pyproject.toml and FastMCP server entry point
feat(rules): implement credential hygiene rules CRED001–004 with YAML descriptors
test(credentials): add fixture workflows and pytest suite for all credential rules
feat(tools): expose scan_credentials MCP tool
```

### Stop conditions
- Context window approaches 60% — stop, commit what's working, end session
- CRED004 scope detection requires more node-type research than estimated — defer to Session 3, document in DECISIONS.md
- pyproject.toml dependency resolution produces conflicts — resolve before proceeding; do not skip

### Done criteria
- `pytest tests/rules/test_credentials.py` exits 0 (all tests pass)
- `python -m n8n_auditor.server` starts without errors
- `scan_credentials` callable and returns structured findings on `hardcoded_secrets.json`
- `ruff check .` exits 0

---

## Session 3: Webhook + Error Handling Rules

**Goal:** Add 7 rules covering webhook security (WEBHOOK001–004) and error handling coverage (ERR001–003), with full test coverage and 2 more MCP tools.

### Files created/modified
- `src/n8n_auditor/rules/webhooks.py` — WEBHOOK001–004
- `src/n8n_auditor/rules/errors.py` — ERR001–003
- `src/n8n_auditor/rules/definitions/webhooks.yaml`
- `src/n8n_auditor/rules/definitions/errors.yaml`
- `src/n8n_auditor/tools.py` — promote `check_webhooks` and `error_handling_coverage` from stubs to implemented
- `tests/fixtures/unauth_webhook.json` — triggers WEBHOOK001
- `tests/fixtures/no_error_handling.json` — triggers ERR001 and ERR002
- `tests/rules/test_webhooks.py` — pytest suite for WEBHOOK001–004
- `tests/rules/test_errors.py` — pytest suite for ERR001–003
- `docs/ruleset.md` — credential + webhook + error sections populated

### Rules implemented and order rationale
1. **WEBHOOK001** — Inbound webhook without authentication  
   Rationale: Most common real-world issue; detected by checking Webhook node for absent `authentication` config.
2. **WEBHOOK002** — Webhook → Code node chain without input validation  
   Rationale: SSRF/RCE pattern; requires graph traversal (follow edges from Webhook node to Code node). Builds the graph-traversal utility other rules will reuse.
3. **WEBHOOK003** — Webhook without rate limiting  
   Rationale: Config-key check on the Webhook node; fast once graph traversal exists.
4. **WEBHOOK004** — Webhook response exposes internal data  
   Rationale: Inspects the Respond to Webhook node's response body parameters for `$json` pass-through patterns.
5. **ERR001** — Node has no error output routing  
   Rationale: Per-node check; simplest error rule, high signal-to-noise.
6. **ERR002** — Workflow has no top-level Error Trigger  
   Rationale: Workflow-level check (scan `nodes` for `n8n-nodes-base.errorTrigger`).
7. **ERR003** — Error branch leads to silent failure  
   Rationale: Graph traversal from error outputs; reuses traversal utility from WEBHOOK002.

### MCP tools exposed
- `check_webhooks` (fully implemented)
- `error_handling_coverage` (fully implemented, returns coverage % + per-node breakdown)

### Tests written
- Fixture: `tests/fixtures/unauth_webhook.json` (triggers WEBHOOK001; remaining webhook rules need targeted sub-fixtures or parameterised test data)
- Fixture: `tests/fixtures/no_error_handling.json` (triggers ERR001 + ERR002)
- `tests/rules/test_webhooks.py` — minimum 2 tests per rule (fires / does not fire)
- `tests/rules/test_errors.py` — minimum 2 tests per rule (fires / does not fire)

### Expected commits
```
feat(rules): implement webhook security rules WEBHOOK001–004 with YAML descriptors
test(webhooks): add fixture workflows and pytest suite for all webhook rules
feat(rules): implement error handling coverage rules ERR001–003
test(errors): add fixture workflows and pytest suite for all error handling rules
feat(tools): expose check_webhooks and error_handling_coverage MCP tools
```

### Stop conditions
- Context > 60%
- WEBHOOK002 graph traversal complexity significantly exceeds estimate — defer WEBHOOK002 + ERR003 together (both need graph traversal); complete the other 5 rules and commit
- If graph traversal is deferred: document in DECISIONS.md; Session 4 picks them up before starting deprecation work

### Done criteria
- `pytest tests/rules/test_webhooks.py tests/rules/test_errors.py` exits 0
- `check_webhooks` and `error_handling_coverage` callable from Claude Desktop
- 11/15 rules complete (CRED001–004, WEBHOOK001–004, ERR001–003)
- `ruff check .` exits 0

---

## Session 4: Deprecations + Reliability + Engine + Connector

**Goal:** Complete all 15 rules, wire the rule engine orchestrator, and add the live instance connector with 3 MCP tools exposed.

### Files created/modified
- `src/n8n_auditor/rules/deprecations.py` — DEPR001–002
- `src/n8n_auditor/rules/reliability.py` — REL001–002
- `src/n8n_auditor/rules/definitions/deprecations.yaml` — static catalogue with `snapshot_date` field at top
- `src/n8n_auditor/rules/definitions/reliability.yaml`
- `src/n8n_auditor/engine.py` — rule engine orchestrator: loads all rule classes, runs them against a parsed workflow, aggregates + deduplicates findings, returns structured `AuditResult`
- `src/n8n_auditor/connector.py` — n8n REST API client: `GET /workflows` (list), `GET /workflows/{id}` (fetch single); uses `base_url` + `api_key` from params
- `src/n8n_auditor/tools.py` — promote `audit_workflow`, `detect_deprecations`, `analyse_instance` from stubs to implemented
- `tests/fixtures/deprecated_nodes.json` — triggers DEPR001
- `tests/rules/test_deprecations.py`
- `tests/rules/test_reliability.py`
- `tests/test_tools.py` — integration test: `audit_workflow` end-to-end on a fixture JSON

### Rules implemented and order rationale
1. **REL001** — HTTP Request node without retry config  
   Rationale: Config-key check on `n8n-nodes-base.httpRequest` nodes; fast, no graph traversal. Good warm-up.
2. **REL002** — Long-running workflow without explicit timeout  
   Rationale: Heuristic — flag workflows with HTTP Request or DB nodes in a loop without a Stop and Error node. Scoped conservatively.
3. **DEPR001** — Node using deprecated `typeVersion`  
   Rationale: Static YAML lookup; straightforward once catalogue exists.
4. **DEPR002** — Node type removed in current n8n version  
   Rationale: Static YAML lookup; same mechanism as DEPR001.

### MCP tools exposed
- `audit_workflow` — calls engine.py, runs all registered rules, returns full `AuditResult`
- `detect_deprecations` — calls DEPR001+DEPR002 in isolation
- `analyse_instance` — calls connector.py to fetch all workflow JSONs, runs engine.py on each, aggregates

### Tests written
- `tests/fixtures/deprecated_nodes.json`
- `tests/rules/test_deprecations.py` — fires/does not fire for DEPR001, DEPR002
- `tests/rules/test_reliability.py` — fires/does not fire for REL001, REL002
- `tests/test_tools.py` — `audit_workflow` returns findings dict with expected keys; `AuditResult` shape validated

### Expected commits
```
feat(rules): add deprecation catalogue YAML and implement DEPR001–002
feat(rules): implement reliability rules REL001–002 with YAML descriptors
test(rules): add fixtures and pytest suites for deprecation and reliability rules
feat(engine): wire rule engine orchestrator across all 15 rules
feat(connector): add live n8n instance API client for analyse_instance
feat(tools): expose audit_workflow, detect_deprecations, analyse_instance
```

### Stop conditions
- Context > 60%
- connector.py auth flow requires more API research than estimated — stub it with a clear `TODO` and complete in Session 5
- engine.py finding deduplication edge cases require significant iteration — timebox to 45 min, then move on

### Done criteria
- All 15 rules implemented
- `pytest` (full suite) exits 0
- `audit_workflow` runs end-to-end on `hardcoded_secrets.json` and returns CRED001 finding
- `ruff check .` exits 0

---

## Session 5: suggest_fixes + Report Generator + README + Docs + Polish + Submissions

**Goal:** Implement the two remaining tools, complete all documentation, and deliver the demo-ready public repo.

### Files created/modified
- `src/n8n_auditor/fix_suggester.py` — takes a `Finding`, returns before/after node JSON snapshot (n8n-native diff format)
- `src/n8n_auditor/report.py` — `generate_audit_report`: takes `AuditResult`, renders structured Markdown report (summary, findings by severity, per-node breakdown)
- `src/n8n_auditor/tools.py` — promote `suggest_fixes` and `generate_audit_report` from stubs to implemented (all 8 tools now live)
- `tests/test_tools.py` — add tests for `suggest_fixes` (returns valid `{node_id, before, after}` shape) and `generate_audit_report` (returns valid Markdown string)
- `README.md` — what it does, install instructions (uv + pip fallback), Claude Desktop config snippet, how to run tests, rule catalogue table, contributing pointer
- `docs/ruleset.md` — complete (all 15 rules with rationale, updated)
- `docs/extending.md` — how to add a new rule (YAML descriptor + Python class pattern)
- `CONTRIBUTING.md` — fork, branch, add rule + test + YAML + ruleset.md entry, PR
- `LICENSE` — MIT
- `pyproject.toml` — version set to `0.1.0`, PyPI classifiers added

### MCP tools exposed
- `suggest_fixes` — accepts one or more finding IDs from a prior audit result, returns before/after node diffs
- `generate_audit_report` — all 8 tools now fully implemented

### Tests written
- `tests/test_tools.py` additions: `suggest_fixes` returns `{node_id, before, after}` for a known CRED001 finding; `generate_audit_report` returns a non-empty Markdown string containing the finding severity

### Expected commits
```
feat(fix-suggester): implement suggest_fixes with n8n-native before/after node diff format
feat(report): implement generate_audit_report tool with Markdown output
test(tools): add integration tests for suggest_fixes and generate_audit_report
docs: add full README with install instructions and test documentation
docs: add CONTRIBUTING guide, extending.md for rule authors, MIT LICENSE
chore: finalise pyproject.toml metadata for 0.1.0 and pre-submission polish
```

### Stop conditions
- Context > 60%
- README install instructions fail on a simulated clean-machine test — fix before moving to submissions
- Any test failing — do not submit with a red test suite

### Done criteria (= "what done looks like" from CLAUDE.md)
- All 8 MCP tools callable end-to-end
- `pytest` 20+ tests, all green
- `ruff check .` exits 0
- `python -m n8n_auditor.server` starts; Claude Desktop can call `audit_workflow`
- Loom demo checklist: all 5 steps work smoothly
- README install instructions verified on clean machine (or virtual env from scratch)
- Smithery and MCP Registry submission PRs/forms drafted
- Zero hardcoded credentials in codebase
