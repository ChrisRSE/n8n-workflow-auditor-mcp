# Adding a New Audit Rule

This guide walks through adding a hypothetical rule **REL003 — Set node with no fields configured**, which fires when a Set node has an empty `assignments` parameter.

---

## Step 1 — YAML descriptor

Add an entry to `src/n8n_auditor/rules/definitions/reliability.yaml`:

```yaml
  - id: REL003
    severity: low
    title: Set node with no fields configured
    description: >
      A Set node has no field assignments configured. An empty Set node passes
      items through unchanged and is likely a placeholder left over from
      development rather than intentional workflow logic.
    remediation: >
      Either configure the Set node with the intended field assignments, or
      delete it if it serves no purpose.
```

---

## Step 2 — Python class

Add the class to `src/n8n_auditor/rules/reliability.py`:

```python
class SetNodeNoFields(Rule):
    rule_id = "REL003"

    def check(self, workflow: dict) -> list[Finding]:
        findings = []
        for node in workflow.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.set":
                continue
            assignments = node.get("parameters", {}).get("assignments", {})
            if not assignments or not assignments.get("assignments"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.LOW,
                        node_id=node.get("id"),
                        node_name=node.get("name"),
                        message="Set node has no field assignments configured",
                        evidence=f"parameters.assignments = {assignments!r}",
                    )
                )
        return findings
```

`Rule` and `Finding` are imported from `.base`; `Severity` from `.base` too. Both are already imported at the top of `reliability.py`.

---

## Step 3 — Test class

Create or add to `tests/rules/test_reliability.py`:

```python
class TestRel003:
    rule = SetNodeNoFields()

    def test_fires_when_assignments_empty(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Set",
                    "type": "n8n-nodes-base.set",
                    "parameters": {"assignments": {"assignments": []}},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1
        assert findings[0].rule_id == "REL003"

    def test_fires_when_assignments_absent(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Set",
                    "type": "n8n-nodes-base.set",
                    "parameters": {},
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert len(findings) == 1

    def test_does_not_fire_when_fields_configured(self):
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "name": "Set",
                    "type": "n8n-nodes-base.set",
                    "parameters": {
                        "assignments": {
                            "assignments": [
                                {"id": "a1", "name": "status", "value": "active", "type": "string"}
                            ]
                        }
                    },
                }
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_does_not_fire_on_non_set_node(self):
        workflow = {
            "nodes": [
                {"id": "n1", "name": "HTTP", "type": "n8n-nodes-base.httpRequest", "parameters": {}}
            ]
        }
        findings = self.rule.check(workflow)
        assert findings == []

    def test_severity_is_low(self):
        workflow = {
            "nodes": [
                {"id": "n1", "name": "Set", "type": "n8n-nodes-base.set", "parameters": {}}
            ]
        }
        findings = self.rule.check(workflow)
        assert all(f.severity == Severity.LOW for f in findings)
```

---

## Step 4 — Fixture (optional)

If the rule adds meaningful demo value, add a fixture to `tests/fixtures/`. Update the cross-reference table in `docs/ruleset.md`.

---

## Step 5 — Register in engine

Open `src/n8n_auditor/engine.py` and add an instance to `ALL_RULES`:

```python
from .rules.reliability import HttpRequestNoRetry, SetNodeNoFields, WorkflowHasUnboundedLoop

ALL_RULES: list[Rule] = [
    # ... existing rules ...
    HttpRequestNoRetry(),
    SetNodeNoFields(),       # ← add here
    WorkflowHasUnboundedLoop(),
    NodeDeprecatedVersion(),
    NodeTypeRemoved(),
]
```

`RULES_BY_ID` is derived automatically from `ALL_RULES`, so no further changes are needed.

---

## API reference

### `Rule` base class (`src/n8n_auditor/rules/base.py`)

```python
class Rule(ABC):
    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def check(self, workflow: dict) -> list[Finding]: ...
```

- `check` must never raise — return `[]` if the workflow structure is unexpected.
- `rule_id` must match the `id` in the YAML descriptor.

### `Finding` dataclass

```python
@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    evidence: str
    node_id: str | None = None
    node_name: str | None = None
```

`Severity` values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
