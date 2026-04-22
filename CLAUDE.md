# CLAUDE.md — n8n Workflow Auditor MCP

## What this project is

An MCP (Model Context Protocol) server that audits n8n workflows for security issues, reliability anti-patterns, deprecated nodes, missing error handling, and credential hygiene — then generates AI-assisted fix suggestions Claude can apply.

**Audience:** any Claude Desktop or Claude Code user who works with n8n. Primary user types are n8n consultants, AI automation agency operators, security-conscious developers, and iPaaS specialists.

**Why it exists:** every existing n8n MCP server is either a build-helper (`czlonkowski/n8n-mcp`) or a thin REST proxy. No MCP currently does diagnostic auditing. This is the empty niche we're filling.

**Non-goals (things this project is NOT):**
- NOT a workflow builder. We don't create workflows, only analyse them.
- NOT a runtime monitor. We don't tail live execution logs in real-time.
- NOT a full credential vault. We flag issues, we don't store secrets.
- NOT a multi-tenant SaaS. Single-tenant, local-first design.

---

## Build discipline (non-negotiable)

### Session hygiene

- **Every session starts in plan mode.** Confirm the plan before writing code.
- **Keep sessions under 60% of context window.** When approaching 120k tokens on a 200k window (or equivalent on larger windows), stop. Summarise progress into a commit message and end the session.
- **Never rely on auto-compact.** Manual handoff is always cleaner than automatic compaction at 95%.
- **Git-commit every working unit.** Commits are the handoff mechanism between sessions. Future sessions read git log to reconstruct context.
- **Write DECISIONS.md notes when choosing between approaches.** Don't let future sessions re-debate closed decisions.

### Testing discipline (on-brand for a QA engineer — this matters for the portfolio)

- **Every audit rule has a pytest test before it's considered done.** Tests live in `tests/rules/`.
- **Use fixture workflows in `tests/fixtures/` to demonstrate each rule firing and not firing.** One "violating" and one "clean" fixture per rule minimum.
- **Run `pytest` before every commit.** Any failing test blocks the commit.
- **The README must document how to run tests.** This is the portfolio signal — the repo demonstrates its own testing practice.

### Code discipline

- **Python 3.11+.** Use `uv` if available, `pip` + `venv` otherwise.
- **FastMCP as the framework.** Standard choice, best Claude Code support, handles stdio + Streamable HTTP transports.
- **Type hints everywhere.** Pydantic models for all MCP tool inputs and outputs.
- **Rules are YAML-configured, Python-implemented.** Each rule has a YAML descriptor (id, severity, description) and a Python class implementing a `check(workflow) -> findings` method. This makes the rule set contributor-friendly later.
- **No secrets in code, ever.** Use `.env` for any local dev credentials.

### What Claude should NOT do automatically

- Don't add unnecessary dependencies. Every new package goes in DECISIONS.md with a reason.
- Don't rewrite existing rules "for consistency" without asking.
- Don't introduce async patterns unless there's a clear performance reason. The auditor is I/O-light.
- Don't generate speculative fix suggestions. A finding must be concrete and pointable to specific workflow JSON.

---

## Project structure

```
n8n-workflow-auditor-mcp/
├── CLAUDE.md                    # this file
├── README.md                    # user-facing documentation
├── PLAN.md                      # current build plan (updated each session)
├── DECISIONS.md                 # why-we-chose-X notes (append-only)
├── pyproject.toml
├── .env.example
├── .gitignore
├── .claudeignore                # tells Claude what to skip reading
├── src/
│   └── n8n_auditor/
│       ├── __init__.py
│       ├── server.py            # FastMCP server entry point
│       ├── tools.py             # MCP tool implementations (8 tools)
│       ├── engine.py            # rule engine orchestrator
│       ├── parser.py            # n8n workflow JSON parsing
│       ├── connector.py         # live n8n instance API client
│       ├── report.py            # audit report generation (MD/PDF)
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py          # Rule base class
│       │   ├── credentials.py   # credential hygiene rules
│       │   ├── webhooks.py      # webhook security rules
│       │   ├── errors.py        # error handling coverage rules
│       │   ├── deprecations.py  # deprecated node/version rules
│       │   ├── reliability.py   # reliability rules
│       │   └── definitions/     # YAML rule descriptors
│       │       ├── credentials.yaml
│       │       ├── webhooks.yaml
│       │       ├── errors.yaml
│       │       ├── deprecations.yaml
│       │       └── reliability.yaml
│       └── fix_suggester.py    # Claude-assisted fix generation
├── tests/
│   ├── conftest.py
│   ├── fixtures/                # example workflow JSONs
│   │   ├── clean_workflow.json
│   │   ├── hardcoded_secrets.json
│   │   ├── unauth_webhook.json
│   │   ├── no_error_handling.json
│   │   └── deprecated_nodes.json
│   ├── rules/
│   │   ├── test_credentials.py
│   │   ├── test_webhooks.py
│   │   ├── test_errors.py
│   │   └── test_deprecations.py
│   └── test_tools.py
└── docs/
    ├── ruleset.md               # catalogue of every rule with rationale
    └── extending.md             # how to add new rules
```

---

## The 8 MCP tools (what gets exposed to Claude Desktop/Code)

| Tool | Input | Output | Notes |
|------|-------|--------|-------|
| `audit_workflow` | workflow JSON path or raw JSON | Findings list, severity breakdown, summary | Main entry point |
| `scan_credentials` | workflow JSON | Credential-specific findings | Hardcoded secrets, expired OAuth, over-permissive scopes |
| `check_webhooks` | workflow JSON | Webhook-specific findings | Unauth inbound, SSRF-prone chains, missing validation |
| `detect_deprecations` | workflow JSON, n8n_version (optional) | Deprecated node/version findings | Compares against current n8n node catalogue |
| `error_handling_coverage` | workflow JSON | Coverage % + per-node breakdown | Counts nodes with error output routing |
| `analyse_instance` | base_url, api_key | Findings across all workflows in instance | Uses n8n's `/audit` + custom rules |
| `suggest_fixes` | finding IDs | Patch-shaped JSON edits | Claude-assisted, requires finding context |
| `generate_audit_report` | findings list, format (md/pdf) | Client-ready report file | Branded MD by default, optional PDF |

---

## The initial 15-rule catalogue

Credentials (4 rules):
- `CRED001` — Hardcoded credentials in node parameters
- `CRED002` — Expired OAuth token detected
- `CRED003` — Credential referenced but not configured
- `CRED004` — Over-permissive API scope (where detectable)

Webhooks (4 rules):
- `WEBHOOK001` — Inbound webhook without authentication
- `WEBHOOK002` — Webhook → Code node chain without input validation (SSRF/RCE pattern)
- `WEBHOOK003` — Webhook without rate limiting configured
- `WEBHOOK004` — Webhook response exposes internal data

Error handling (3 rules):
- `ERR001` — Node has no error output routing
- `ERR002` — Workflow has no top-level Error Trigger
- `ERR003` — Error branch leads to silent failure (no notification/log)

Deprecations (2 rules):
- `DEPR001` — Node using deprecated `typeVersion`
- `DEPR002` — Node type removed in current n8n version

Reliability (2 rules):
- `REL001` — HTTP Request node without retry configuration
- `REL002` — Long-running workflow without explicit timeout

---

## Common commands

Bootstrap:
```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Test:
```bash
pytest                          # run all tests
pytest tests/rules/             # just rule tests
pytest -v -k credentials        # rule category filter
```

Local MCP server (stdio):
```bash
python -m n8n_auditor.server
```

Lint/format:
```bash
ruff check . && ruff format .
```

Package for Claude Desktop (once stable):
```bash
mcpb pack .                     # produces .mcpb bundle
```

---

## Claude Desktop connection

Users add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "n8n-auditor": {
      "command": "python",
      "args": ["-m", "n8n_auditor.server"],
      "cwd": "/path/to/n8n-workflow-auditor-mcp"
    }
  }
}
```

---

## Demo-ability checklist (what the Loom must show)

By end of build, a 2-minute Loom must demonstrate:

1. User drags a real n8n workflow JSON into Claude Desktop
2. Claude calls `audit_workflow` and returns structured findings
3. One critical finding (e.g., hardcoded API key) is highlighted
4. Claude calls `suggest_fixes` and shows the proposed patch
5. Optional: `generate_audit_report` produces a client-ready Markdown

If any step doesn't work smoothly, the Loom doesn't ship and the build isn't done.

---

## Session handoff protocol

End every session with a commit that includes:

```
<summary of what changed>

Session notes:
- Decisions made: <link to DECISIONS.md or inline>
- Open questions: <any unresolved items>
- Next session should: <concrete next action>
- Blockers: <any dependency issues>
```

Start every new session with: "Read CLAUDE.md and PLAN.md, show me the last 5 git commits, then propose today's plan."

---

## Things Claude should ask about before doing

- Adding any new Python dependency not already in `pyproject.toml`
- Introducing async/await into a module that's currently sync
- Writing a rule that requires network access beyond the n8n instance
- Any architectural change to the rules engine structure
- Publishing/registering with external directories (Smithery, MCP registry)

---

## Red flags — stop and ask if you encounter

- A rule requires parsing inside expressions (`{{ $json.x }}`) — complex, scope carefully
- Request to add non-audit features ("can it also build workflows?") — out of scope, reject
- Request to skip tests "to move faster" — never skip tests on this project; the tests are the portfolio signal
- Session approaching 60% context — stop, summarise, commit, end session

---

## What done looks like (end state)

- Public GitHub repo with README, LICENSE (MIT), contribution guide
- 15+ audit rules implemented and tested
- 20+ pytest tests all passing
- Loom walkthrough under 3 minutes, publicly linked
- Submitted to Smithery and the official MCP Registry
- README has install instructions that work on a fresh machine
- Zero hardcoded credentials anywhere in the codebase
- DECISIONS.md populated with real decisions made during the build
