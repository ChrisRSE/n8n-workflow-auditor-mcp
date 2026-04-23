# Rule Catalogue

This document lists all 15 audit rules included in n8n Workflow Auditor MCP.

> **Deprecation catalogue note:** DEPR001 and DEPR002 use a static YAML catalogue
> (`src/n8n_auditor/rules/definitions/deprecations.yaml`) with a `snapshot_date` field.
> If you find an entry is outdated, please open a PR to update the catalogue.

---

## Credentials (CRED001–004)

| Rule ID | Severity | Title | Remediation summary |
|---------|----------|-------|---------------------|
| CRED001 | Critical | Hardcoded credential in node parameters | Move the value into n8n's credential manager; never paste raw API keys into node fields |
| CRED002 | Info | OAuth credential cannot be verified statically | Re-authenticate the OAuth credential in n8n to refresh the token |
| CRED003 | High | Credential referenced but not configured | Open the node in n8n and configure or link the correct credential |
| CRED004 | Medium | Over-permissive Google OAuth credential scope | Replace `googleApi` with the service-specific OAuth2 credential type |

---

## Webhooks (WEBHOOK001–004)

| Rule ID | Severity | Title | Remediation summary |
|---------|----------|-------|---------------------|
| WEBHOOK001 | High | Inbound webhook without authentication | Set `authentication` to `headerAuth` or `basicAuth`; rotate the webhook path |
| WEBHOOK002 | High | Webhook connects directly to Code node without input validation | Insert an IF, Switch, or Set node between Webhook and Code nodes |
| WEBHOOK003 | Low | Webhook node has no rate limiting | Implement rate limiting at the infrastructure layer (reverse proxy / API gateway) |
| WEBHOOK004 | Medium | Webhook response exposes internal data | Construct an explicit response with a Set node; avoid returning `$json` wholesale |

---

## Error Handling (ERR001–003)

| Rule ID | Severity | Title | Remediation summary |
|---------|----------|-------|---------------------|
| ERR001 | Medium | Node has no error output connection | Add an error output branch to a notification or logging node. **Excluded:** trigger nodes, `noOp`, `stickyNote`, `stopAndError`, LangChain sub-nodes (`lmChat*`, `memory*`, `outputParser*`, `tool*`, etc.), and `n8n-nodes-base.*Tool` AI agent tool nodes. **Satisfied by:** a wired `error` output, or `onError: continueErrorOutput` with a connected second main output. |
| ERR002 | High | Workflow has no Error Trigger node | Add an Error Trigger node connected to a notification action |
| ERR003 | Medium | Error branch terminates at a noOp node | Replace the noOp with a notification or logging action |

---

## Deprecations (DEPR001–002)

| Rule ID | Severity | Title | Remediation summary |
|---------|----------|-------|---------------------|
| DEPR001 | Medium | Node using deprecated typeVersion | Upgrade the node to the current typeVersion in the n8n editor |
| DEPR002 | High | Node type removed in current n8n version | Replace the removed node type with its documented replacement |

---

## Reliability (REL001–002)

| Rule ID | Severity | Title | Remediation summary |
|---------|----------|-------|---------------------|
| REL001 | Low | HTTP Request node without retry configuration | Enable Retry On Fail with 2–3 retries and appropriate back-off |
| REL002 | Medium | Batch loop without a Stop and Error node | Add a Stop and Error node as a circuit breaker inside or after the loop |

---

## Fixture cross-reference

| Fixture | Rules fired |
|---------|-------------|
| `clean_workflow.json` | ERR001 (×2), ERR002, REL001 |
| `hardcoded_secrets.json` | CRED001, ERR001, ERR002, REL001 |
| `unauth_webhook.json` | WEBHOOK001, WEBHOOK003, ERR002 |
| `webhook_ssrf_chain.json` | WEBHOOK002, WEBHOOK003, WEBHOOK004, ERR002 |
| `no_error_handling.json` | ERR001, ERR002, ERR003 |
| `deprecated_nodes.json` | DEPR001, DEPR002, ERR002, REL001 |
