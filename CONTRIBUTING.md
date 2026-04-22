# Contributing to n8n Workflow Auditor MCP

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip + venv

## Setup

```bash
git clone https://github.com/ChrisRSE/n8n-workflow-auditor-mcp.git
cd n8n-workflow-auditor-mcp
uv venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"
pre-commit install
```

## Running tests

```bash
pytest                          # full suite
pytest tests/rules/             # rule tests only
pytest -v -k credentials        # filter by keyword
pytest --cov=n8n_auditor        # with coverage
```

All tests must pass before submitting a PR. `ruff check .` must also exit 0.

## How to add a new audit rule

Every new rule needs five things — do them in this order:

1. **YAML descriptor** — add an entry to the relevant file in
   `src/n8n_auditor/rules/definitions/`. Use the existing entries as a template.
   Required fields: `id`, `severity`, `title`, `description`, `remediation`.

2. **Python class** — add a class to the relevant module in
   `src/n8n_auditor/rules/` that inherits from `Rule` (defined in `base.py`).
   Implement `rule_id` (class attribute matching the YAML `id`) and
   `check(workflow: dict) -> list[Finding]`.

3. **Test file** — add a test class in `tests/rules/` covering at minimum:
   - one test that the rule fires on a violating workflow
   - one test that the rule does NOT fire on a clean/conformant workflow
   - one test for the expected severity

4. **Fixture** — add or extend a JSON fixture in `tests/fixtures/` to
   demonstrate the violation. Document which rules the fixture triggers in
   `docs/ruleset.md`.

5. **Register in engine** — add an instance of your new rule class to the
   `ALL_RULES` list in `src/n8n_auditor/engine.py`. The `RULES_BY_ID` dict
   is built automatically from `ALL_RULES`.

See [docs/extending.md](docs/extending.md) for a worked example.

## Pull request checklist

- [ ] `pytest` exits 0
- [ ] `ruff check .` exits 0
- [ ] New rule has YAML descriptor, Python class, test class, and fixture
- [ ] `DECISIONS.md` updated if you made an architectural choice
- [ ] `docs/ruleset.md` updated with the new rule entry
- [ ] No secrets or API keys in any committed file
