"""Deprecation rules: DEPR001–DEPR002."""

from pathlib import Path

import yaml

from .base import Finding, Rule, Severity

_CATALOGUE_PATH = Path(__file__).parent / "definitions" / "deprecations.yaml"


def _load_catalogue() -> dict:
    return yaml.safe_load(_CATALOGUE_PATH.read_text(encoding="utf-8"))


class NodeDeprecatedVersion(Rule):
    """DEPR001 — Node using a deprecated typeVersion.

    Checks each node's typeVersion against the static deprecation catalogue.
    Fires when the node's typeVersion is below the catalogue's deprecated_below
    threshold for that node type.
    """

    rule_id = "DEPR001"

    def __init__(self) -> None:
        catalogue = _load_catalogue()
        self._deprecated: dict[str, dict] = {
            entry["type"]: entry for entry in catalogue.get("deprecated_type_versions", [])
        }

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_type = node.get("type", "")
            entry = self._deprecated.get(node_type)
            if entry is None:
                continue

            type_version = node.get("typeVersion")
            if type_version is None:
                continue

            if type_version < entry["deprecated_below"]:
                node_id = node.get("id", "")
                node_name = node.get("name", "")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        node_id=node_id,
                        node_name=node_name,
                        message=(
                            f"Node '{node_name}' ({node_type}) uses deprecated "
                            f"typeVersion {type_version}. Current version is "
                            f"{entry['current_version']}."
                        ),
                        evidence=(
                            f"Node type: {node_type} | "
                            f"typeVersion: {type_version} | "
                            f"Deprecated below: {entry['deprecated_below']} | "
                            f"Current: {entry['current_version']} | "
                            f"Reason: {entry['reason']}"
                        ),
                    )
                )
        return findings


class NodeTypeRemoved(Rule):
    """DEPR002 — Node type removed in current n8n version.

    Checks each node's type against the static list of removed node types.
    Fires when an exact match is found.
    """

    rule_id = "DEPR002"

    def __init__(self) -> None:
        catalogue = _load_catalogue()
        self._removed: dict[str, dict] = {
            entry["type"]: entry for entry in catalogue.get("removed_node_types", [])
        }

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_type = node.get("type", "")
            entry = self._removed.get(node_type)
            if entry is None:
                continue

            node_id = node.get("id", "")
            node_name = node.get("name", "")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    node_id=node_id,
                    node_name=node_name,
                    message=(
                        f"Node '{node_name}' uses removed node type '{node_type}' "
                        f"(removed in n8n {entry['removed_in']}). "
                        f"Replace with '{entry['replacement']}'."
                    ),
                    evidence=(
                        f"Node type: {node_type} | "
                        f"Removed in: {entry['removed_in']} | "
                        f"Replacement: {entry['replacement']} | "
                        f"Reason: {entry['reason']}"
                    ),
                )
            )
        return findings
