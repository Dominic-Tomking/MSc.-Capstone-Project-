"""Severity normalisation.

Tools report severity on incompatible scales: Slither reports an *impact*
(High/Medium/Low/Informational) plus a *confidence*, SmartCheck reports an
integer *severity* (1/2/3), and CodeBERT produces a class probability.  All are
mapped onto the common four-point scale (critical/high/medium/low) through the
fixed tables below.  The tables are frozen before evaluation begins and
published with the dataset (proposal S4.4.2).
"""
from __future__ import annotations

from enum import IntEnum

from .taxonomy import VulnType


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, s: str) -> "Severity":
        return {
            "low": cls.LOW, "medium": cls.MEDIUM,
            "high": cls.HIGH, "critical": cls.CRITICAL,
        }[str(s).strip().lower()]


# --- Slither: impact -> severity -------------------------------------------
SLITHER_IMPACT = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
    "optimization": Severity.LOW,
}

# --- SmartCheck: integer severity 1/2/3 -> severity -------------------------
SMARTCHECK_SEVERITY = {
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
}

# --- Canonical baseline severity per vulnerability type ---------------------
# Used for CodeBERT findings (which carry only a probability) and as the
# severity attached to the aggregated report row.  Mirrors the severity map
# used by the aggregation layer in the NLP evaluation (Ch.3 Table on severity).
TYPE_BASELINE = {
    VulnType.REENTRANCY: Severity.CRITICAL,
    VulnType.ACCESS_CONTROL: Severity.CRITICAL,
    VulnType.ARITHMETIC: Severity.HIGH,
    VulnType.BAD_RANDOMNESS: Severity.HIGH,
    VulnType.UNCHECKED_CALLS: Severity.MEDIUM,
    VulnType.DENIAL_OF_SERVICE: Severity.MEDIUM,
    VulnType.FRONT_RUNNING: Severity.MEDIUM,
    VulnType.TIME_MANIPULATION: Severity.MEDIUM,
    VulnType.SHORT_ADDRESS: Severity.LOW,
    VulnType.OTHER: Severity.LOW,
    VulnType.BENIGN: Severity.LOW,
}


def baseline(vt: VulnType) -> Severity:
    return TYPE_BASELINE.get(vt, Severity.LOW)
