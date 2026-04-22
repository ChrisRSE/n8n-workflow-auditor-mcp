"""Base classes shared by all audit rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    evidence: str
    node_id: str | None = field(default=None)
    node_name: str | None = field(default=None)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "message": self.message,
            "evidence": self.evidence,
        }


class Rule(ABC):
    """Base class for all audit rules.

    Subclasses implement ``check`` and return a (possibly empty) list of
    :class:`Finding` objects.  The rule should never raise — catch exceptions
    internally and return an empty list if the workflow structure is unexpected.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def check(self, workflow: dict) -> list[Finding]: ...
