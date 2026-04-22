# n8n Workflow Auditor MCP

**Find the security holes, missing error handling, and sloppy patterns in your n8n workflows — then let Claude suggest the fixes.**

An MCP (Model Context Protocol) server that plugs into Claude Desktop or Claude Code and gives Claude the tools to audit n8n workflows: scanning for hardcoded credentials, unauthenticated webhooks, missing error handling, deprecated nodes, and reliability anti-patterns — then generating concrete, copy-pasteable fix suggestions.

> **Status:** Active development. Session 1 (planning) complete. Core audit rules coming in Session 2.

---

## What it does

Point Claude at a workflow JSON file (or a live n8n instance) and ask it to audit. Claude calls the auditor's tools and returns structured findings with severity levels, affected node names, and suggested fixes in n8n-native format.

```
You: audit this workflow for security issues
Claude: [calls audit_workflow] Found 3 issues:
  • CRED001 [CRITICAL] — Hardcoded API key in HTTP Request node "Send to Slack"
  • WEBHOOK001 [HIGH] — Inbound webhook "/payment-hook" has no authentication
  • ERR001 [MEDIUM] — 4 nodes have no error output routing
```

---

## The 15 audit rules

### Credentials (4 rules)
| ID | Rule |
|----|------|
| CRED001 | Hardcoded credentials in node parameters |
| CRED002 | Expired OAuth token detected |
| CRED003 | Credential referenced but not configured |
| CRED004 | Over-permissive API scope |

### Webhooks (4 rules)
| ID | Rule |
|----|------|
| WEBHOOK001 | Inbound webhook without authentication |
| WEBHOOK002 | Webhook → Code node chain without input validation (SSRF/RCE pattern) |
| WEBHOOK003 | Webhook without rate limiting configured |
| WEBHOOK004 | Webhook response exposes internal data |

### Error handling (3 rules)
| ID | Rule |
|----|------|
| ERR001 | Node has no error output routing |
| ERR002 | Workflow has no top-level Error Trigger |
| ERR003 | Error branch leads to silent failure |

### Deprecations (2 rules)
| ID | Rule |
|----|------|
| DEPR001 | Node using deprecated `typeVersion` |
| DEPR002 | Node type removed in current n8n version |

### Reliability (2 rules)
| ID | Rule |
|----|------|
| REL001 | HTTP Request node without retry configuration |
| REL002 | Long-running workflow without explicit timeout |

---

## The 8 MCP tools

| Tool | What it does |
|------|-------------|
| `audit_workflow` | Run all rules against a workflow JSON — main entry point |
| `scan_credentials` | Credential hygiene check only |
| `check_webhooks` | Webhook security check only |
| `detect_deprecations` | Flag deprecated node types and versions |
| `error_handling_coverage` | Coverage % + per-node error routing breakdown |
| `analyse_instance` | Audit all workflows on a live n8n instance |
| `suggest_fixes` | Get before/after node JSON for each finding |
| `generate_audit_report` | Produce a client-ready Markdown report |

---

## Installation

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Claude Desktop or Claude Code

### Install

```bash
git clone https://github.com/ChrisRSE/n8n-workflow-auditor-mcp.git
cd n8n-workflow-auditor-mcp

# With uv (recommended)
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# With pip
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Connect to Claude Desktop

Add to your `claude_desktop_config.json`:

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

## Running tests

```bash
pytest                          # full suite
pytest tests/rules/             # rule tests only
pytest -v -k credentials        # single category
```

All commits are gated on a passing test suite. If the badge is green, the rules work.

---

## For contributors

After cloning, activate the pre-commit hooks so secret scanning and safety checks run on every commit:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

To run the hooks manually against all files:

```bash
pre-commit run --all-files
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. The short version: add a rule, add a YAML descriptor, add a test with a violating fixture and a clean fixture, update [docs/ruleset.md](docs/ruleset.md), open a PR.

---

## Licence

MIT
